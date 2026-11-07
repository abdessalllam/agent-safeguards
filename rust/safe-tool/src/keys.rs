use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::LazyLock;

use guard_common::env;
use guard_common::shlex::Lexer;
use guard_common::sys::{self, EmbeddedNul};
use regex::Regex;

use crate::consts;

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\A([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)\z")
        .unwrap_or_else(|_| std::process::abort())
});
static HEREDOC_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<<(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z_][A-Za-z0-9_]*))"#)
        .unwrap_or_else(|_| std::process::abort())
});
static KEYWORD_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A-[A-Za-z]+\z").unwrap_or_else(|_| std::process::abort()));
static SUBSTITUTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\([^()]*\)|`[^`]*`").unwrap_or_else(|_| std::process::abort()));

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(at) => path.get(..at).unwrap_or(""),
        None => "",
    }
}

pub fn startup_key_file(requested: Option<&str>) -> Result<Option<String>, EmbeddedNul> {
    let requested = requested.unwrap_or("~/.zshrc");
    let home = env::user_home();
    let expanded = requested
        .strip_prefix("~/")
        .map_or_else(|| requested.to_owned(), |rest| format!("{home}/{rest}"));
    if !expanded.starts_with('/')
        || sys::try_realpath(dirname(&expanded))? != home
        || !consts::STARTUP_KEY_FILES.contains(&basename(&expanded))
    {
        return Ok(None);
    }
    if std::fs::symlink_metadata(&expanded).is_ok() {
        let target = sys::try_realpath(&expanded)?;
        if !format!("{target}/").starts_with(&format!("{home}/"))
            || !consts::STARTUP_KEY_FILES.iter().any(|name| {
                basename(&target)
                    .to_lowercase()
                    .contains(name.trim_start_matches('.'))
            })
        {
            return Ok(None);
        }
    }
    Ok(Some(expanded))
}

pub fn apply_command(words: &[String], found: &mut HashSet<String>) {
    let mut words = words;
    while words
        .first()
        .is_some_and(|word| ["then", "do", "else", "!"].contains(&word.as_str()))
    {
        words = words.get(1..).unwrap_or(&[]);
    }
    let Some(first) = words.first() else {
        return;
    };
    if first == "unset" {
        for word in words.iter().skip(1).filter(|word| !word.starts_with('-')) {
            found.remove(word);
        }
        return;
    }
    let keyword = ["export", "readonly", "declare", "typeset"].contains(&first.as_str());
    let mut rest = if keyword {
        words.get(1..).unwrap_or(&[])
    } else {
        words
    };
    while keyword
        && rest
            .first()
            .is_some_and(|word| KEYWORD_OPTION.is_match(word))
    {
        rest = rest.get(1..).unwrap_or(&[]);
    }
    let mut assignments = Vec::new();
    for token in rest {
        if let Some(captures) = ASSIGNMENT.captures(token) {
            let name = captures.get(1).map_or("", |part| part.as_str());
            let value = captures.get(2).map_or("", |part| part.as_str());
            assignments.push((name, value));
        } else if !keyword {
            return;
        }
    }
    for (name, value) in assignments {
        if value.is_empty() {
            found.remove(name);
        } else {
            found.insert(name.to_owned());
        }
    }
}

pub fn apply_line(line: &str, found: &mut HashSet<String>) {
    let replaced = SUBSTITUTION.replace_all(line, "x");
    let Ok(tokens) = Lexer::new(&replaced)
        .posix(true)
        .punctuation_chars(";&|")
        .whitespace_split(true)
        .commenters("#")
        .tokens()
    else {
        return;
    };
    let mut command = Vec::new();
    for token in tokens {
        if !token.is_empty() && token.chars().all(|ch| ";&|".contains(ch)) {
            apply_command(&command, found);
            command.clear();
        } else {
            command.push(token);
        }
    }
    apply_command(&command, found);
}

// Python opens the file in text mode, so CR and CRLF end a line like LF does.
fn read_universal_line(reader: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let Some(at) = buffer.iter().position(|byte| matches!(byte, b'\n' | b'\r')) else {
            let length = buffer.len();
            line.extend_from_slice(buffer);
            reader.consume(length);
            continue;
        };
        let ending = buffer.get(at).copied();
        line.extend_from_slice(buffer.get(..at).unwrap_or(&[]));
        reader.consume(at.saturating_add(1));
        if ending == Some(b'\r') && reader.fill_buf()?.first() == Some(&b'\n') {
            reader.consume(1);
        }
        line.push(b'\n');
        return Ok(Some(line));
    }
}

pub enum LineRead {
    Missing,
    Unreadable,
    Truncated,
    Complete,
}

pub fn each_logical_line(path: &str, mut each: impl FnMut(&str)) -> Result<LineRead, EmbeddedNul> {
    if path.contains('\0') {
        return Err(EmbeddedNul);
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(LineRead::Missing),
        Err(_) => return Ok(LineRead::Unreadable),
    };
    let mut reader = BufReader::new(file);
    let mut pending = String::new();
    let mut number = 0usize;
    loop {
        let bytes = match read_universal_line(&mut reader) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break,
            Err(_) => return Ok(LineRead::Unreadable),
        };
        if number >= consts::MAX_STARTUP_FILE_LINES
            || pending.chars().count() > consts::MAX_STARTUP_LINE_CHARS
        {
            return Ok(LineRead::Truncated);
        }
        number = number.saturating_add(1);
        let line = format!("{pending}{}", String::from_utf8_lossy(&bytes));
        if let Some(continued) = line.strip_suffix("\\\n") {
            pending = continued.to_owned();
        } else {
            pending.clear();
            each(&line);
        }
    }
    Ok(LineRead::Complete)
}

pub fn keys_set_in(path: &str) -> Result<(HashSet<String>, bool), EmbeddedNul> {
    let mut found = HashSet::new();
    Ok(match each_logical_line(path, |line| apply_line(line, &mut found))? {
        LineRead::Missing => (HashSet::new(), true),
        LineRead::Unreadable => (HashSet::new(), false),
        LineRead::Truncated => (found, false),
        LineRead::Complete => (found, true),
    })
}

// Alias bodies and fish set values join assignments: each can hold a credential.
fn command_values(words: &[String], out: &mut Vec<(bool, String)>) {
    let mut words = words;
    while words
        .first()
        .is_some_and(|word| ["then", "do", "else", "!"].contains(&word.as_str()))
    {
        words = words.get(1..).unwrap_or(&[]);
    }
    let Some(first) = words.first() else {
        return;
    };
    let rest = words.get(1..).unwrap_or(&[]);
    if first == "alias" {
        for token in rest.iter().filter(|word| !word.starts_with('-')) {
            if let Some((name, body)) = token.split_once('=') {
                if !name.is_empty() {
                    out.push((true, body.to_owned()));
                }
            }
        }
        return;
    }
    if first == "set" {
        let mut operands = rest.iter().filter(|word| !word.starts_with('-'));
        if operands
            .next()
            .is_some_and(|name| consts::KEY_NAME_PATTERN_FULL.is_match(name))
        {
            out.extend(operands.map(|value| (false, value.clone())));
        }
        return;
    }
    let keyword = ["export", "readonly", "declare", "typeset"].contains(&first.as_str());
    let mut tokens = if keyword { rest } else { words };
    while keyword
        && tokens
            .first()
            .is_some_and(|word| KEYWORD_OPTION.is_match(word))
    {
        tokens = tokens.get(1..).unwrap_or(&[]);
    }
    for token in tokens {
        match ASSIGNMENT.captures(token) {
            Some(captures) => out.push((false, captures.get(2).map_or("", |part| part.as_str()).to_owned())),
            None if keyword => {}
            None => break,
        }
    }
}

pub fn line_values(line: &str, out: &mut Vec<(bool, String)>) {
    let Ok(tokens) = Lexer::new(line)
        .posix(true)
        .punctuation_chars(";&|")
        .whitespace_split(true)
        .commenters("#")
        .tokens()
    else {
        return;
    };
    let mut command = Vec::new();
    for token in tokens {
        if !token.is_empty() && token.chars().all(|ch| ";&|".contains(ch)) {
            command_values(&command, out);
            command.clear();
        } else {
            command.push(token);
        }
    }
    command_values(&command, out);
}

fn push_char(out: &mut Vec<u8>, value: u32) {
    if let Some(ch) = char::from_u32(value) {
        let mut buffer = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
    }
}

fn digits(chars: &[char], at: &mut usize, radix: u32, limit: usize) -> Option<u32> {
    let mut value = 0u32;
    let mut count = 0usize;
    while count < limit {
        let Some(digit) = chars.get(*at).and_then(|ch| ch.to_digit(radix)) else {
            break;
        };
        value = value.saturating_mul(radix).saturating_add(digit);
        *at = at.saturating_add(1);
        count = count.saturating_add(1);
    }
    (count > 0).then_some(value)
}

// Bash `$'...'` escapes, so the literal the shell stores is what gets protected.
fn decode_ansi_c(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0usize;
    while let Some(&ch) = chars.get(at) {
        at = at.saturating_add(1);
        if ch != '\\' {
            push_char(&mut out, u32::from(ch));
            continue;
        }
        let Some(&next) = chars.get(at) else {
            out.push(b'\\');
            break;
        };
        at = at.saturating_add(1);
        match next {
            'a' => out.push(7),
            'b' => out.push(8),
            'e' | 'E' => out.push(27),
            'f' => out.push(12),
            'n' => out.push(10),
            'r' => out.push(13),
            't' => out.push(9),
            'v' => out.push(11),
            '\\' | '\'' | '"' | '?' => push_char(&mut out, u32::from(next)),
            'x' => match digits(&chars, &mut at, 16, 2) {
                Some(value) => out.push(u8::try_from(value & 0xff).unwrap_or(0)),
                None => out.extend_from_slice(b"\\x"),
            },
            'u' | 'U' => {
                let limit = if next == 'u' { 4 } else { 8 };
                match digits(&chars, &mut at, 16, limit) {
                    Some(value) => push_char(&mut out, value),
                    None => push_char(&mut out, u32::from(next)),
                }
            }
            '0'..='7' => {
                at = at.saturating_sub(1);
                let value = digits(&chars, &mut at, 8, 3).unwrap_or(0);
                out.push(u8::try_from(value & 0xff).unwrap_or(0));
            }
            other => {
                out.push(b'\\');
                push_char(&mut out, u32::from(other));
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// `$'...'` becomes the single-quoted text it stands for; `$"..."` loses its `$`.
fn rewrite_dollar_quotes(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut at = 0usize;
    let mut quote: Option<char> = None;
    while let Some(&ch) = chars.get(at) {
        match quote {
            Some(open) => {
                out.push(ch);
                at = at.saturating_add(1);
                if ch == '\\' && open == '"' {
                    if let Some(&escaped) = chars.get(at) {
                        out.push(escaped);
                        at = at.saturating_add(1);
                    }
                } else if ch == open {
                    quote = None;
                }
            }
            None => {
                if ch == '\\' {
                    out.push(ch);
                    at = at.saturating_add(1);
                    if let Some(&escaped) = chars.get(at) {
                        out.push(escaped);
                        at = at.saturating_add(1);
                    }
                    continue;
                }
                let following = chars.get(at.saturating_add(1)).copied();
                if ch == '$' && following == Some('\'') {
                    let mut end = at.saturating_add(2);
                    let mut raw = String::new();
                    while let Some(&inner) = chars.get(end) {
                        if inner == '\\' {
                            raw.push(inner);
                            if let Some(&escaped) = chars.get(end.saturating_add(1)) {
                                raw.push(escaped);
                            }
                            end = end.saturating_add(2);
                            continue;
                        }
                        if inner == '\'' {
                            break;
                        }
                        raw.push(inner);
                        end = end.saturating_add(1);
                    }
                    if chars.get(end) == Some(&'\'') {
                        out.push('\'');
                        out.push_str(&decode_ansi_c(&raw).replace('\'', "'\\''"));
                        out.push('\'');
                        at = end.saturating_add(1);
                        continue;
                    }
                } else if ch == '$' && following == Some('"') {
                    at = at.saturating_add(1);
                    continue;
                }
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                }
                out.push(ch);
                at = at.saturating_add(1);
            }
        }
    }
    out
}

fn heredoc_end(line: &str) -> Option<(String, bool)> {
    let found = HEREDOC_START
        .captures_iter(line)
        .filter(|found| {
            found
                .get(0)
                .is_some_and(|whole| !line.get(..whole.start()).unwrap_or("").ends_with('<'))
        })
        .last()?;
    let word = found
        .get(2)
        .or_else(|| found.get(3))
        .or_else(|| found.get(4))?
        .as_str();
    let dash = found.get(1).is_some_and(|part| !part.as_str().is_empty());
    (!word.is_empty()).then(|| (word.to_owned(), dash))
}

#[derive(Default)]
pub struct ValueScanner {
    ending: Option<(String, bool)>,
    skipped: Vec<String>,
}

impl ValueScanner {
    pub fn scan(&mut self, line: &str, out: &mut Vec<(bool, String)>) {
        if let Some((word, dash)) = &self.ending {
            let body = line.trim_end_matches(['\n', '\r']);
            let candidate = if *dash { body.trim_start_matches('\t') } else { body };
            if candidate == word {
                self.ending = None;
                self.skipped.clear();
            } else {
                self.skipped.push(line.to_owned());
            }
            return;
        }
        line_values(&rewrite_dollar_quotes(line), out);
        self.ending = heredoc_end(line);
    }

    // A here-document that never ends was not one: its lines are read as ordinary ones.
    pub fn finish(&mut self, out: &mut Vec<(bool, String)>) {
        while !self.skipped.is_empty() {
            self.ending = None;
            for line in std::mem::take(&mut self.skipped) {
                self.scan(&line, out);
            }
        }
        self.ending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str, bytes: &[u8]) -> String {
        let path = std::env::temp_dir().join(format!("keys-newlines-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).expect("write fixture");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn carriage_returns_end_lines_like_python_text_mode() {
        let crlf = scratch("crlf", b"A=\\\r\n\"\"\r\n");
        assert_eq!(keys_set_in(&crlf).expect("read"), (HashSet::new(), true));
        let bare = scratch("bare", b"export A=one\runset A\nB=two\r");
        let (found, readable) = keys_set_in(&bare).expect("read");
        assert!(readable && found == HashSet::from(["B".to_owned()]), "{found:?}");
        let _ = std::fs::remove_file(crlf);
        let _ = std::fs::remove_file(bare);
    }

    #[test]
    fn assignments_and_unset() {
        let mut found = HashSet::new();
        apply_line("export A=1 B=2; unset B", &mut found);
        assert!(found.contains("A"));
        assert!(!found.contains("B"));
        apply_line("A=", &mut found);
        assert!(found.is_empty());
    }
}
