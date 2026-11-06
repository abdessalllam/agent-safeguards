use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;
use std::sync::LazyLock;

use regex::Regex;

use crate::shlex;

pub const COMMAND_BOUNDARY: &str = " \t\n;&|(";
pub const OPERAND_END: &str = " \t\n;&|<>()";
pub const REDIRECTION_SUFFIX: &str = "&|-!";
pub const REDIRECTION_MARKER: &str = "\u{1f}";
pub const OPENING_QUOTE_MARKER: &str = "\u{01}";
pub const HEREDOC_DELIMITER_END: &str = " \t\n;&|()<>";
pub const MAX_HEREDOCS: usize = 16;
pub const MAX_HEREDOC_NESTING: usize = 8;
pub const MAX_SPLIT_STRING_EXPANSIONS: usize = 64;
pub const MAX_COMMAND_CHARS: usize = 256 * 1024;
pub const MAX_GLOB_VARIANTS: usize = 256;
pub const MAX_GLOB_MATCHES: usize = 2000;

pub static ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?s)\A[A-Za-z_][A-Za-z0-9_]*=.*\z"));
pub static DURATION: LazyLock<Regex> = LazyLock::new(|| compile(r"\A[0-9.]+[smhd]?\z"));
static COMMAND_KEYWORD_TAIL: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?:\A|[\s;&|(){}])(?:if|then|elif|else|while|until|do|time|!)(?:\n)?\z")
});
static BRACE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"\{([^{}]*,[^{}]*)\}|\{(-?\d{1,30}|[A-Za-z])\.\.(-?\d{1,30}|[A-Za-z])(?:\.\.(-?\d{1,30}))?\}",
    )
});

pub static GIT_VALUE_OPTIONS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    set(&[
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--config-env",
        "--attr-source",
    ])
});
pub static SHELL_KEYWORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    set(&[
        "if", "then", "else", "elif", "do", "while", "until", "!", "{", "}",
    ])
});
pub static DIRECTORY_OPTIONS: LazyLock<HashMap<&'static str, HashSet<&'static str>>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        map.insert("env", set(&["-C", "--chdir"]));
        map.insert("sudo", set(&["-D", "--chdir", "-R", "--chroot"]));
        map
    });
pub static CHROOT_OPTIONS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| set(&["-R", "--chroot"]));
pub static SPLIT_STRING_OPTIONS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| set(&["-S", "--split-string"]));
pub static WRAPPER_VALUE_OPTIONS: LazyLock<HashMap<&'static str, HashSet<&'static str>>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        map.insert("builtin", set(&[]));
        map.insert("caffeinate", set(&["-t", "-w"]));
        map.insert("command", set(&[]));
        map.insert(
            "env",
            set(&["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]),
        );
        map.insert("exec", set(&["-a"]));
        map.insert("gtimeout", set(&["-s", "--signal", "-k", "--kill-after"]));
        map.insert("nice", set(&["-n", "--adjustment"]));
        map.insert("nohup", set(&[]));
        map.insert("rtk", set(&[]));
        map.insert(
            "stdbuf",
            set(&["-i", "-o", "-e", "--input", "--output", "--error"]),
        );
        map.insert(
            "sudo",
            set(&[
                "-u",
                "-g",
                "-h",
                "-p",
                "-C",
                "-D",
                "-R",
                "-T",
                "-U",
                "--user",
                "--group",
                "--host",
                "--prompt",
                "--close-from",
                "--chdir",
                "--chroot",
                "--command-timeout",
                "--other-user",
            ]),
        );
        map.insert("time", set(&["-f", "-o", "--format", "--output"]));
        map.insert("timeout", set(&["-s", "--signal", "-k", "--kill-after"]));
        map
    });

#[derive(Debug, Clone, Copy)]
pub struct HeredocForbidden;

impl HeredocForbidden {
    pub fn is_match(self, text: &str) -> bool {
        self.search(text).is_some()
    }

    pub fn search(self, text: &str) -> Option<(usize, usize)> {
        let chars: Vec<char> = text.chars().collect();
        for index in 0..chars.len() {
            if let Some(end) = forbidden_at(&chars, index) {
                return Some((index, end));
            }
        }
        None
    }
}

pub static HEREDOC_FORBIDDEN: HeredocForbidden = HeredocForbidden;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvableCommand;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unplaceable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HereDocument {
    pub line_start: usize,
    pub marker_start: usize,
    pub delimiter_end: usize,
    pub line_end: usize,
    pub body_start: usize,
    pub body_end: usize,
    pub end: usize,
    pub quoted: bool,
    pub outer: Option<(i64, i64, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHere {
    pub line_start: usize,
    pub marker_start: usize,
    pub delimiter_end: usize,
    pub delimiter: String,
    pub strip_tabs: bool,
    pub quoted: bool,
    pub outer: Option<(i64, i64, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BraceError {
    NoMatch,
    ValueError,
}

pub fn closing_quote(command: &str, index: usize) -> Result<Option<usize>, IndexError> {
    let chars = chars_of(command);
    if index >= chars.len() {
        return Err(IndexError);
    }
    Ok(closing_quote_chars(&chars, index))
}

pub fn skip_quoted(command: &str, index: usize) -> Result<usize, IndexError> {
    let chars = chars_of(command);
    if index >= chars.len() {
        return Err(IndexError);
    }
    Ok(skip_quoted_chars(&chars, index))
}

pub fn skip_operand(command: &str, index: usize) -> usize {
    skip_operand_chars(&chars_of(command), index)
}

pub fn at_command_start(kept: &[String]) -> bool {
    let start = kept.len().saturating_sub(24);
    let tail_src = match kept.get(start..) {
        Some(part) => part,
        None => &[],
    };
    let mut tail = rstrip_space_tab(&tail_src.concat()).to_string();
    if tail_is_blank(&tail) && kept.len() > 24 {
        tail = rstrip_space_tab(&kept.concat()).to_string();
    }
    if tail_is_blank(&tail) {
        return true;
    }
    if matches!(tail.chars().next_back(), Some(ch) if ";&|({\n".contains(ch)) {
        return true;
    }
    COMMAND_KEYWORD_TAIL.is_match(&tail)
}

pub fn test_end(command: &str, index: usize) -> Option<usize> {
    test_end_chars(&chars_of(command), index)
}

pub fn expression_end(
    command: &str,
    index: usize,
    at_word_start: bool,
    kept: &[String],
) -> Option<usize> {
    expression_end_chars(&chars_of(command), index, at_word_start, kept)
}

pub fn double_parenthesis_end(command: &str, index: usize) -> Option<usize> {
    double_parenthesis_end_chars(&chars_of(command), index)
}

pub fn drop_descriptor(kept: &mut Vec<String>) -> String {
    let mut digits = 0usize;
    while digits < kept.len() {
        let Some(piece) = kept.get(kept.len() - 1 - digits) else {
            break;
        };
        let mut piece_chars = piece.chars();
        let Some(ch) = piece_chars.next() else {
            break;
        };
        if piece_chars.next().is_some() || !ch.is_ascii_digit() {
            break;
        }
        digits = digits.saturating_add(1);
    }
    if digits == 0 {
        return String::new();
    }
    let preceded = if digits == kept.len() {
        true
    } else {
        match kept.get(kept.len() - 1 - digits) {
            Some(piece) => single_boundary(piece),
            None => false,
        }
    };
    if !preceded {
        return String::new();
    }
    let at = kept.len() - digits;
    kept.split_off(at).concat()
}

pub fn first_operand<T>(words: &[String], value_letters: &str, value_options: &HashSet<T>) -> Option<usize>
where
    T: Borrow<str> + Eq + Hash,
{
    let mut index = 0usize;
    while index < words.len() {
        let Some(word) = words.get(index) else {
            break;
        };
        if word == "--" {
            return if index.saturating_add(1) < words.len() {
                Some(index.saturating_add(1))
            } else {
                None
            };
        }
        if word.starts_with("--") {
            index = index.saturating_add(if !word.contains('=') && value_options.contains(word.as_str()) {
                2
            } else {
                1
            });
        } else if word.starts_with('-') && word.chars().count() > 1 {
            index = index.saturating_add(if short_takes_next(word, value_letters) { 2 } else { 1 });
        } else {
            return Some(index);
        }
    }
    None
}

pub fn split_options<T>(words: &[String], value_letters: &str, value_options: &HashSet<T>) -> Vec<String>
where
    T: Borrow<str> + Eq + Hash,
{
    let mut operands = Vec::new();
    let mut index = 0usize;
    while index < words.len() {
        let Some(word) = words.get(index) else {
            break;
        };
        if word == "--" {
            if let Some(rest) = words.get(index.saturating_add(1)..) {
                operands.extend(rest.iter().cloned());
            }
            break;
        }
        if word.starts_with("--") {
            index = index.saturating_add(if !word.contains('=') && value_options.contains(word.as_str()) {
                2
            } else {
                1
            });
        } else if word.starts_with('-') && word.chars().count() > 1 {
            index = index.saturating_add(if short_takes_next(word, value_letters) { 2 } else { 1 });
        } else {
            operands.push(word.clone());
            index = index.saturating_add(1);
        }
    }
    operands
}

pub fn normalize_command(
    command: &str,
    mut redirects: Option<&mut Vec<(String, String, String)>>,
) -> String {
    let chars = chars_of(command);
    let mut kept = Vec::new();
    let mut index = 0usize;
    let mut at_word_start = true;
    let length = chars.len();
    while index < length {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        let span = if matches!(character, '$' | '(' | '[') {
            expression_end_chars(&chars, index, at_word_start, &kept)
        } else {
            None
        };
        if character == '\'' || character == '"' {
            let end = skip_quoted_chars(&chars, index);
            kept.push(slice_chars(&chars, index, end));
            index = end;
            at_word_start = false;
        } else if character == '\\' {
            if chars.get(index.saturating_add(1)).copied() != Some('\n') {
                kept.push(slice_chars(&chars, index, index.saturating_add(2)));
                at_word_start = false;
            }
            index = index.saturating_add(2);
        } else if character == '#' && at_word_start {
            while index < length && chars.get(index).copied() != Some('\n') {
                index = index.saturating_add(1);
            }
        } else if character == '&' && chars.get(index.saturating_add(1)).copied() == Some('>') {
            index = index.saturating_add(1);
        } else if let Some(span_end) = span {
            kept.push(slice_chars(&chars, index, span_end));
            index = span_end;
            at_word_start = false;
        } else if character == '<' || character == '>' {
            let descriptor = drop_descriptor(&mut kept);
            let mut end = index;
            while end < length && matches!(chars.get(end).copied(), Some('<' | '>')) {
                end = end.saturating_add(1);
            }
            if end < length && matches!(chars.get(end).copied(), Some(ch) if REDIRECTION_SUFFIX.contains(ch)) {
                end = end.saturating_add(1);
            }
            if end > 0 && slice_chars(&chars, end - 1, end) == "&" && chars.get(end).copied() == Some('!') {
                end = end.saturating_add(1);
            }
            let operator_text = slice_chars(&chars, index, end);
            let operand_end = skip_operand_chars(&chars, end);
            if let Some(list) = redirects.as_deref_mut() {
                let raw = slice_chars(&chars, end, operand_end).replace("\\\n", "");
                list.push((descriptor, operator_text, python_strip(&raw).to_string()));
            }
            index = operand_end;
            kept.push(format!(" {REDIRECTION_MARKER} "));
            at_word_start = true;
        } else {
            kept.push(character.to_string());
            at_word_start = COMMAND_BOUNDARY.contains(character);
            index = index.saturating_add(1);
        }
    }
    kept.concat()
}

pub fn unquoted_text(command: &str) -> String {
    let chars = chars_of(command);
    let mut kept = Vec::new();
    let mut index = 0usize;
    let mut at_word_start = true;
    let length = chars.len();
    while index < length {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        let closing = if character == '\'' || character == '"' {
            closing_quote_chars(&chars, index)
        } else {
            None
        };
        if let Some(closing) = closing {
            kept.push(" ".to_string());
            index = closing.saturating_add(1);
            at_word_start = false;
        } else if character == '\\' {
            if chars.get(index.saturating_add(1)).copied() != Some('\n') {
                kept.push("_".to_string());
                at_word_start = false;
            }
            index = index.saturating_add(2);
        } else if character == '#' && at_word_start {
            while index < length && chars.get(index).copied() != Some('\n') {
                index = index.saturating_add(1);
            }
        } else {
            kept.push(character.to_string());
            at_word_start = COMMAND_BOUNDARY.contains(character);
            index = index.saturating_add(1);
        }
    }
    kept.concat()
}

pub fn unquoted_lines(command: &str) -> Vec<String> {
    command
        .replace("\\\n", "")
        .split('\n')
        .map(unquoted_text)
        .collect()
}

pub fn mark_opening_quotes(command: &str) -> String {
    let chars = chars_of(command);
    let mut kept = Vec::new();
    let mut index = 0usize;
    let length = chars.len();
    while index < length {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        let closing = if character == '\'' || character == '"' {
            closing_quote_chars(&chars, index)
        } else {
            None
        };
        if let Some(closing) = closing {
            let mut piece = String::from(OPENING_QUOTE_MARKER);
            piece.push_str(&slice_chars(&chars, index.saturating_add(1), closing.saturating_add(1)));
            kept.push(piece);
            index = closing.saturating_add(1);
        } else if character == '\\' {
            kept.push(slice_chars(&chars, index, index.saturating_add(2)));
            index = index.saturating_add(2);
        } else {
            kept.push(character.to_string());
            index = index.saturating_add(1);
        }
    }
    kept.concat()
}

pub fn read_delimiter(command: &str, index: usize) -> Option<(String, bool, usize)> {
    read_delimiter_chars(&chars_of(command), index)
}

pub fn find_terminator(
    command: &str,
    start: usize,
    delimiter: &str,
    strip_tabs: bool,
) -> Option<(usize, usize)> {
    find_terminator_chars(&chars_of(command), start, delimiter, strip_tabs)
}

pub fn read_bodies(
    command: &str,
    newline: usize,
    pending: &[PendingHere],
) -> Result<(usize, Vec<HereDocument>), Unplaceable> {
    let chars = chars_of(command);
    let mut found = Vec::new();
    let position = read_bodies_chars(&chars, newline, pending, &mut found)?;
    Ok((position, found))
}

pub fn scan_double_quoted(
    command: &str,
    index: usize,
    depth: usize,
    line_start: usize,
) -> Result<(usize, Vec<HereDocument>), Unplaceable> {
    let chars = chars_of(command);
    let mut found = Vec::new();
    let end = scan_double_quoted_chars(&chars, index, &mut found, depth, line_start)?;
    Ok((end, found))
}

pub fn scan_code(
    command: &str,
    index: usize,
    nested: bool,
    depth: usize,
    outer: Option<(i64, i64, String)>,
) -> Result<(usize, Vec<HereDocument>), Unplaceable> {
    let chars = chars_of(command);
    let mut found = Vec::new();
    let end = scan_code_chars(&chars, index, nested, &mut found, depth, outer)?;
    Ok((end, found))
}

pub fn heredocs(command: &str) -> Vec<HereDocument> {
    let chars = chars_of(command);
    let mut found = Vec::new();
    if scan_code_chars(&chars, 0, false, &mut found, 0, None).is_err() {
        return Vec::new();
    }
    found.sort_by(|left, right| left.body_start.cmp(&right.body_start));
    if found.len() > MAX_HEREDOCS {
        Vec::new()
    } else {
        found
    }
}

pub fn closing_parenthesis(command: &str, start: usize) -> usize {
    closing_parenthesis_chars(&chars_of(command), start)
}

pub fn closing_backtick(command: &str, start: usize) -> usize {
    closing_backtick_chars(&chars_of(command), start)
}

pub fn command_substitutions(command: &str) -> Vec<String> {
    command_substitutions_chars(&chars_of(command))
}

pub fn brace_options(word: &str) -> Result<Option<Vec<String>>, BraceError> {
    let Some(found) = BRACE_PATTERN.captures(word) else {
        return Err(BraceError::NoMatch);
    };
    brace_groups(&found)
}

pub fn expand_braces(word: &str) -> Result<Option<Vec<String>>, ValueError> {
    let mut pending = vec![word.to_string()];
    let mut done = Vec::new();
    while !pending.is_empty() {
        if done.len().saturating_add(pending.len()) > MAX_GLOB_VARIANTS {
            return Ok(None);
        }
        let Some(current) = pending.pop() else {
            break;
        };
        let Some(found) = BRACE_PATTERN.captures(&current) else {
            done.push(current);
            continue;
        };
        let options = match brace_groups(&found) {
            Ok(Some(options)) => options,
            Ok(None) => return Ok(None),
            Err(BraceError::ValueError) => return Err(ValueError),
            Err(BraceError::NoMatch) => {
                done.push(current);
                continue;
            }
        };
        let (start, end) = match found.get(0) {
            Some(whole) => (whole.start(), whole.end()),
            None => {
                done.push(current);
                continue;
            }
        };
        let prefix = piece(&current, 0, start);
        let suffix = piece(&current, end, current.len());
        for option in options {
            let mut next = String::new();
            next.push_str(prefix);
            next.push_str(&option);
            next.push_str(suffix);
            pending.push(next);
        }
    }
    Ok(Some(done))
}

pub fn option_names<T>(option: &str, value_options: &HashSet<T>) -> (Vec<String>, bool)
where
    T: Borrow<str> + Eq + Hash,
{
    if option.starts_with("--") {
        let name = option.split_once('=').map(|(name, _)| name).unwrap_or(option);
        let takes_next = value_options.contains(name) && !option.contains('=');
        return (vec![name.to_string()], takes_next);
    }
    let mut names = Vec::new();
    let letters: Vec<char> = option.chars().skip(1).collect();
    for (position, letter) in letters.iter().copied().enumerate() {
        let name = format!("-{letter}");
        names.push(name.clone());
        if value_options.contains(name.as_str()) {
            return (names, position.saturating_add(1) == letters.len());
        }
    }
    (names, false)
}

pub fn option_value(
    option: &str,
    name: &str,
    words: &[String],
    index: usize,
) -> Result<String, ValueError> {
    if option.starts_with("--") {
        if let Some((_, value)) = option.split_once('=') {
            return Ok(value.to_string());
        }
        return Ok(words.get(index.saturating_add(1)).cloned().unwrap_or_default());
    }
    let needle: Vec<char> = name.chars().skip(1).collect();
    let hay: Vec<char> = option.chars().collect();
    let Some(found) = find_chars(&hay, &needle) else {
        return Err(ValueError);
    };
    let position = found.saturating_add(1);
    if position < hay.len() {
        return Ok(hay.iter().skip(position).collect());
    }
    Ok(words.get(index.saturating_add(1)).cloned().unwrap_or_default())
}

pub fn strip_wrappers_with_directory<K>(
    words: &[String],
    keep: &HashSet<K>,
) -> Result<(Vec<String>, Vec<String>), UnresolvableCommand>
where
    K: Borrow<str> + Eq + Hash,
{
    let mut words = words.to_vec();
    let mut moved = Vec::new();
    let mut expansions = 0usize;
    let mut index = 0usize;
    while index < words.len() {
        let Some(word) = words.get(index).cloned() else {
            break;
        };
        let base = base_name(&word);
        if ASSIGNMENT.is_match(&word) || SHELL_KEYWORDS.contains(word.as_str()) {
            index = index.saturating_add(1);
            continue;
        }
        if !WRAPPER_VALUE_OPTIONS.contains_key(base) || keep.contains(base) {
            break;
        }
        if base == "command" && command_verbose(&words, index) {
            break;
        }
        index = index.saturating_add(1);
        if base == "rtk" && words.get(index).map(String::as_str) == Some("proxy") {
            index = index.saturating_add(1);
        }
        let Some(value_options) = WRAPPER_VALUE_OPTIONS.get(base) else {
            break;
        };
        let mut after_dashes = false;
        let mut chosen: Option<String> = None;
        let mut root_changed = false;
        while index < words.len() {
            let Some(option) = words.get(index).cloned() else {
                break;
            };
            if option == "--" && !after_dashes {
                after_dashes = true;
                index = index.saturating_add(1);
            } else if !after_dashes && option.starts_with('-') && option.chars().count() > 1 {
                let (names, takes_next) = option_names(&option, value_options);
                if let Some(name) = directory_choice(base, &names) {
                    if CHROOT_OPTIONS.contains(name) {
                        root_changed = true;
                    } else if let Ok(value) = option_value(&option, name, &words, index) {
                        chosen = Some(value);
                    } else {
                        return Err(UnresolvableCommand);
                    }
                }
                if base == "env" && names.iter().any(|name| SPLIT_STRING_OPTIONS.contains(name.as_str())) {
                    expansions = expansions.saturating_add(1);
                    if expansions > MAX_SPLIT_STRING_EXPANSIONS {
                        return Err(UnresolvableCommand);
                    }
                    let mut attached = split_attached(&option);
                    let mut consumed = 1usize;
                    if attached.is_none() {
                        if let Some(next) = words.get(index.saturating_add(1)) {
                            attached = Some(next.clone());
                            consumed = 2;
                        }
                    }
                    let expanded = shlex::split(attached.as_deref().unwrap_or("")).unwrap_or_default();
                    let end = index.saturating_add(consumed).min(words.len());
                    let tail = words.split_off(end);
                    words.truncate(index);
                    words.extend(expanded);
                    words.extend(tail);
                    continue;
                }
                index = index.saturating_add(if takes_next { 2 } else { 1 });
            } else if DURATION.is_match(&option) {
                index = index.saturating_add(1);
            } else {
                break;
            }
        }
        if root_changed {
            moved.push(String::new());
        } else if let Some(folder) = chosen {
            moved.push(folder);
        }
    }
    let rest = match words.get(index..) {
        Some(part) => part.to_vec(),
        None => Vec::new(),
    };
    Ok((rest, moved))
}

pub fn strip_wrappers<K>(words: &[String], keep: &HashSet<K>) -> Result<Vec<String>, UnresolvableCommand>
where
    K: Borrow<str> + Eq + Hash,
{
    Ok(strip_wrappers_with_directory(words, keep)?.0)
}

fn compile(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(_) => match Regex::new("a^") {
            Ok(regex) => regex,
            Err(_) => std::process::abort(),
        },
    }
}

fn set(items: &[&'static str]) -> HashSet<&'static str> {
    items.iter().copied().collect()
}

fn chars_of(text: &str) -> Vec<char> {
    text.chars().collect()
}

fn slice_chars(chars: &[char], start: usize, end: usize) -> String {
    chars.iter().skip(start).take(end.saturating_sub(start)).collect()
}

fn starts_with_at(chars: &[char], index: usize, prefix: &str) -> bool {
    prefix.chars().enumerate().all(|(offset, expected)| {
        chars.get(index.saturating_add(offset)).copied() == Some(expected)
    })
}

fn piece(text: &str, start: usize, end: usize) -> &str {
    text.get(start..end).unwrap_or_default()
}

fn rstrip_space_tab(text: &str) -> &str {
    text.trim_end_matches([' ', '\t'])
}

// Python treats U+001C..=U+001F as whitespace, including the redirect marker.
fn python_isspace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(python_isspace)
}

fn tail_is_blank(text: &str) -> bool {
    text.chars().all(python_isspace)
}

fn single_boundary(piece: &str) -> bool {
    let mut chars = piece.chars();
    match (chars.next(), chars.next()) {
        (Some(ch), None) => COMMAND_BOUNDARY.contains(ch),
        _ => false,
    }
}

fn short_takes_next(word: &str, value_letters: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    for (offset, letter) in chars.iter().copied().skip(1).enumerate() {
        if value_letters.contains(letter) {
            let position = offset.saturating_add(1);
            return position.saturating_add(1) >= chars.len();
        }
    }
    false
}

fn closing_quote_chars(chars: &[char], mut index: usize) -> Option<usize> {
    let quote = chars.get(index).copied()?;
    index = index.saturating_add(1);
    while index < chars.len() && chars.get(index).copied() != Some(quote) {
        let jump = if chars.get(index).copied() == Some('\\') && quote == '"' {
            2
        } else {
            1
        };
        index = index.saturating_add(jump);
    }
    if index < chars.len() {
        Some(index)
    } else {
        None
    }
}

fn skip_quoted_chars(chars: &[char], index: usize) -> usize {
    match closing_quote_chars(chars, index) {
        Some(closing) => closing.saturating_add(1),
        None => chars.len(),
    }
}

fn skip_operand_chars(chars: &[char], mut index: usize) -> usize {
    let length = chars.len();
    while index < length
        && (matches!(chars.get(index).copied(), Some(' ' | '\t')) || starts_with_at(chars, index, "\\\n"))
    {
        let jump = if chars.get(index).copied() == Some('\\') { 2 } else { 1 };
        index = index.saturating_add(jump);
    }
    if chars.get(index).copied() == Some('(') {
        return index;
    }
    while index < length {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        if OPERAND_END.contains(character) {
            break;
        }
        if character == '\'' || character == '"' {
            index = skip_quoted_chars(chars, index);
        } else {
            let jump = if character == '\\' { 2 } else { 1 };
            index = index.saturating_add(jump);
        }
    }
    index.min(length)
}

fn expression_end_chars(
    chars: &[char],
    index: usize,
    at_word_start: bool,
    kept: &[String],
) -> Option<usize> {
    if starts_with_at(chars, index, "$((") {
        return double_parenthesis_end_chars(chars, index.saturating_add(3));
    }
    if !at_word_start || !at_command_start(kept) {
        return None;
    }
    if starts_with_at(chars, index, "((") {
        return double_parenthesis_end_chars(chars, index.saturating_add(2));
    }
    if starts_with_at(chars, index, "[[")
        && matches!(chars.get(index.saturating_add(2)).copied(), Some(' ' | '\t' | '\n'))
    {
        return test_end_chars(chars, index);
    }
    None
}

fn test_end_chars(chars: &[char], index: usize) -> Option<usize> {
    let length = chars.len();
    let mut position = index.saturating_add(2);
    while position < length {
        let character = chars.get(position).copied()?;
        if character == '\'' || character == '"' {
            position = skip_quoted_chars(chars, position);
        } else if character == '\\' {
            position = position.saturating_add(2);
        } else if character == ']' && starts_with_at(chars, position, "]]") {
            let prev_ok = matches!(chars.get(position.saturating_sub(1)).copied(), Some(' ' | '\t' | '\n'));
            let followed = position.saturating_add(2) >= length
                || matches!(chars.get(position.saturating_add(2)).copied(), Some(ch) if " \t\n;&|)<>".contains(ch));
            if prev_ok && followed {
                return Some(position.saturating_add(2));
            }
            position = position.saturating_add(1);
        } else {
            position = position.saturating_add(1);
        }
    }
    None
}

fn double_parenthesis_end_chars(chars: &[char], mut index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let length = chars.len();
    while index < length {
        let character = chars.get(index).copied()?;
        if character == '\'' || character == '"' {
            index = skip_quoted_chars(chars, index);
            continue;
        }
        if character == '\\' {
            index = index.saturating_add(2);
            continue;
        }
        if character == '(' {
            depth = depth.saturating_add(1);
        } else if character == ')' {
            if depth > 0 {
                depth = depth.saturating_sub(1);
            } else if chars.get(index.saturating_add(1)).copied() == Some(')') {
                return Some(index.saturating_add(2));
            } else {
                return None;
            }
        }
        index = index.saturating_add(1);
    }
    None
}

fn as_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn read_delimiter_chars(chars: &[char], mut index: usize) -> Option<(String, bool, usize)> {
    let length = chars.len();
    let mut pieces = Vec::new();
    let mut quoted = false;
    while index < length {
        let character = chars.get(index).copied()?;
        if HEREDOC_DELIMITER_END.contains(character) {
            break;
        }
        if character == '$' || character == '`' {
            return None;
        }
        if character == '\'' || character == '"' {
            let closing = closing_quote_chars(chars, index)?;
            let interior = slice_chars(chars, index.saturating_add(1), closing);
            let piece = if character == '"' {
                unescape_double(&interior)
            } else {
                interior
            };
            pieces.push(piece);
            quoted = true;
            index = closing.saturating_add(1);
        } else if character == '\\' {
            if index.saturating_add(1) >= length {
                return None;
            }
            let next = chars.get(index.saturating_add(1)).copied()?;
            if next == '\n' {
                index = index.saturating_add(2);
                continue;
            }
            pieces.push(next.to_string());
            quoted = true;
            index = index.saturating_add(2);
        } else {
            pieces.push(character.to_string());
            index = index.saturating_add(1);
        }
    }
    Some((pieces.concat(), quoted, index))
}

fn unescape_double(interior: &str) -> String {
    let chars = chars_of(interior);
    let mut out = String::new();
    let mut index = 0usize;
    while index < chars.len() {
        if chars.get(index).copied() == Some('\\') {
            match chars.get(index.saturating_add(1)).copied() {
                Some('\n') => {
                    index = index.saturating_add(2);
                    continue;
                }
                Some(ch) if matches!(ch, '$' | '`' | '"' | '\\') => {
                    out.push(ch);
                    index = index.saturating_add(2);
                    continue;
                }
                _ => {}
            }
        }
        if let Some(ch) = chars.get(index).copied() {
            out.push(ch);
        }
        index = index.saturating_add(1);
    }
    out
}

fn find_char(chars: &[char], needle: char, start: usize) -> Option<usize> {
    chars.iter().enumerate().skip(start).find(|(_, ch)| **ch == needle).map(|(index, _)| index)
}

fn find_terminator_chars(
    chars: &[char],
    mut position: usize,
    delimiter: &str,
    strip_tabs: bool,
) -> Option<(usize, usize)> {
    let length = chars.len();
    let delim = chars_of(delimiter);
    while position < length {
        let newline = find_char(chars, '\n', position);
        let line_end = newline.unwrap_or(length);
        let mut line: Vec<char> = chars.iter().skip(position).take(line_end.saturating_sub(position)).copied().collect();
        if strip_tabs {
            let skip = line.iter().take_while(|ch| **ch == '\t').count();
            line = line.iter().skip(skip).copied().collect();
        }
        if line == delim {
            let end = match newline {
                Some(at) => at.saturating_add(1),
                None => length,
            };
            return Some((position, end));
        }
        let at = newline?;
        position = at.saturating_add(1);
    }
    None
}

fn read_bodies_chars(
    chars: &[char],
    newline: usize,
    pending: &[PendingHere],
    found: &mut Vec<HereDocument>,
) -> Result<usize, Unplaceable> {
    let mut position = newline.saturating_add(1);
    let mut documents = Vec::new();
    for item in pending {
        let Some((terminator_start, end)) = find_terminator_chars(chars, position, &item.delimiter, item.strip_tabs) else {
            return Err(Unplaceable);
        };
        documents.push(HereDocument {
            line_start: item.line_start,
            marker_start: item.marker_start,
            delimiter_end: item.delimiter_end,
            line_end: newline,
            body_start: position,
            body_end: terminator_start,
            end,
            quoted: item.quoted,
            outer: item.outer.clone(),
        });
        position = end;
    }
    found.extend(documents);
    Ok(position)
}

fn scan_double_quoted_chars(
    chars: &[char],
    mut index: usize,
    found: &mut Vec<HereDocument>,
    depth: usize,
    line_start: usize,
) -> Result<usize, Unplaceable> {
    let length = chars.len();
    while index < length {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        if character == '\\' {
            index = index.saturating_add(2);
        } else if character == '"' {
            return Ok(index.saturating_add(1));
        } else if starts_with_at(chars, index, "$(") {
            index = scan_code_chars(
                chars,
                index.saturating_add(2),
                true,
                found,
                depth.saturating_add(1),
                Some((as_i64(line_start), as_i64(index), "\"".to_string())),
            )?;
        } else if character == '`' {
            index = closing_backtick_chars(chars, index.saturating_add(1)).saturating_add(1);
        } else {
            index = index.saturating_add(1);
        }
    }
    Ok(length)
}

fn prev_comment_boundary(chars: &[char], index: usize) -> bool {
    if index == 0 {
        return false;
    }
    matches!(chars.get(index - 1).copied(), Some(ch) if " \t;&|(".contains(ch))
}

fn scan_code_chars(
    chars: &[char],
    mut index: usize,
    nested: bool,
    found: &mut Vec<HereDocument>,
    depth: usize,
    outer: Option<(i64, i64, String)>,
) -> Result<usize, Unplaceable> {
    let length = chars.len();
    if depth > MAX_HEREDOC_NESTING {
        return Ok(length);
    }
    let mut line_start = index;
    let mut pending: Vec<PendingHere> = Vec::new();
    let mut parentheses = 0usize;
    while index < length {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        if character == '\n' {
            let newline = index;
            index = index.saturating_add(1);
            if !pending.is_empty() {
                index = read_bodies_chars(chars, newline, &pending, found)?;
                pending.clear();
            }
            line_start = index;
        } else if character == '\'' {
            index = match closing_quote_chars(chars, index) {
                Some(closing) => closing.saturating_add(1),
                None => length,
            };
        } else if character == '"' {
            index = scan_double_quoted_chars(chars, index.saturating_add(1), found, depth, line_start)?;
        } else if character == '\\' {
            index = index.saturating_add(2);
        } else if character == '`' {
            index = closing_backtick_chars(chars, index.saturating_add(1)).saturating_add(1);
        } else if character == '#' && (index == line_start || prev_comment_boundary(chars, index)) {
            while index < length && chars.get(index).copied() != Some('\n') {
                index = index.saturating_add(1);
            }
        } else if starts_with_at(chars, index, "$(") {
            index = scan_code_chars(
                chars,
                index.saturating_add(2),
                true,
                found,
                depth.saturating_add(1),
                Some((as_i64(line_start), as_i64(index), String::new())),
            )?;
        } else if character == '(' {
            parentheses = parentheses.saturating_add(1);
            index = index.saturating_add(1);
        } else if character == ')' {
            if nested && parentheses == 0 {
                return Ok(index.saturating_add(1));
            }
            parentheses = parentheses.saturating_sub(1);
            index = index.saturating_add(1);
        } else if starts_with_at(chars, index, "<<<") {
            index = index.saturating_add(3);
        } else if starts_with_at(chars, index, "<<") {
            let mut cursor = index.saturating_add(2);
            let strip_tabs = chars.get(cursor).copied() == Some('-');
            if strip_tabs {
                cursor = cursor.saturating_add(1);
            }
            while matches!(chars.get(cursor).copied(), Some(' ' | '\t')) {
                cursor = cursor.saturating_add(1);
            }
            let parsed = read_delimiter_chars(chars, cursor);
            let unusable = match &parsed {
                None => true,
                Some((delimiter, quoted, _)) => delimiter.is_empty() && !*quoted,
            };
            if unusable {
                index = index.saturating_add(2);
            } else if let Some((delimiter, quoted, delimiter_end)) = parsed {
                let recorded = if parentheses == 0 {
                    outer.clone()
                } else {
                    Some((-1, -1, String::new()))
                };
                pending.push(PendingHere {
                    line_start,
                    marker_start: index,
                    delimiter_end,
                    delimiter,
                    strip_tabs,
                    quoted,
                    outer: recorded,
                });
                index = delimiter_end;
            }
        } else {
            index = index.saturating_add(1);
        }
    }
    Ok(length)
}

fn closing_parenthesis_chars(chars: &[char], start: usize) -> usize {
    let mut depth = 1usize;
    let mut quote = None;
    let mut index = start;
    while index < chars.len() {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        if character == '\\' && quote != Some('\'') {
            index = index.saturating_add(1);
        } else if let Some(open) = quote {
            if character == open {
                quote = None;
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '(' {
            depth = depth.saturating_add(1);
        } else if character == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return index;
            }
        }
        index = index.saturating_add(1);
    }
    chars.len()
}

fn closing_backtick_chars(chars: &[char], start: usize) -> usize {
    let mut index = start;
    while index < chars.len() {
        if chars.get(index).copied() == Some('\\') {
            index = index.saturating_add(1);
        } else if chars.get(index).copied() == Some('`') {
            return index;
        }
        index = index.saturating_add(1);
    }
    chars.len()
}

fn command_substitutions_chars(chars: &[char]) -> Vec<String> {
    let mut bodies = Vec::new();
    let length = chars.len();
    let mut quote: Option<char> = None;
    let mut index = 0usize;
    while index < length {
        let Some(character) = chars.get(index).copied() else {
            break;
        };
        if quote == Some('\'') {
            if character == '\'' {
                quote = None;
            }
            index = index.saturating_add(1);
        } else if character == '\\' {
            index = index.saturating_add(2);
        } else if character == '\'' && quote.is_none() {
            quote = Some('\'');
            index = index.saturating_add(1);
        } else if character == '"' {
            quote = if quote == Some('"') { None } else { Some('"') };
            index = index.saturating_add(1);
        } else if character == '`' {
            let end = closing_backtick_chars(chars, index.saturating_add(1));
            bodies.push(slice_chars(chars, index.saturating_add(1), end));
            index = end.saturating_add(1);
        } else if starts_with_at(chars, index, "$((") {
            if let Some(arithmetic_end) = double_parenthesis_end_chars(chars, index.saturating_add(3)) {
                let inner = slice_chars(chars, index.saturating_add(3), arithmetic_end.saturating_sub(2));
                bodies.extend(command_substitutions(&inner));
                index = arithmetic_end;
            } else {
                let end = closing_parenthesis_chars(chars, index.saturating_add(2));
                bodies.push(slice_chars(chars, index.saturating_add(2), end));
                index = end.saturating_add(1);
            }
        } else if starts_with_at(chars, index, "$(")
            || (quote.is_none()
                && (starts_with_at(chars, index, "<(") || starts_with_at(chars, index, ">(")))
        {
            let end = closing_parenthesis_chars(chars, index.saturating_add(2));
            bodies.push(slice_chars(chars, index.saturating_add(2), end));
            index = end.saturating_add(1);
        } else {
            index = index.saturating_add(1);
        }
    }
    bodies
}

fn forbidden_at(chars: &[char], index: usize) -> Option<usize> {
    let ch = chars.get(index).copied()?;
    if ch == '$' {
        let next = chars.get(index.saturating_add(1)).copied();
        if matches!(next, Some('\'' | '"' | '[')) {
            return Some(index.saturating_add(2));
        }
        if next == Some('(') && chars.get(index.saturating_add(2)).copied() == Some('(') {
            return Some(index.saturating_add(3));
        }
        if next == Some('{') && !simple_brace_name(chars, index.saturating_add(2)) {
            return Some(index.saturating_add(2));
        }
        return None;
    }
    if ch == '`' {
        return Some(index.saturating_add(1));
    }
    if matches!(ch, '<' | '>' | '(' | '[') {
        let next = chars.get(index.saturating_add(1)).copied();
        if (ch == '<' || ch == '>') && next == Some('(') {
            return Some(index.saturating_add(2));
        }
        if ch == '(' && (next == Some('(') || next == Some(')')) {
            return Some(index.saturating_add(2));
        }
        if ch == '[' && next == Some('[') {
            return Some(index.saturating_add(2));
        }
    }
    None
}

fn simple_brace_name(chars: &[char], mut index: usize) -> bool {
    let Some(first) = chars.get(index).copied() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    index = index.saturating_add(1);
    while matches!(chars.get(index).copied(), Some(ch) if ch.is_ascii_alphanumeric() || ch == '_') {
        index = index.saturating_add(1);
    }
    chars.get(index).copied() == Some('}')
}

fn brace_groups(found: &regex::Captures<'_>) -> Result<Option<Vec<String>>, BraceError> {
    if let Some(list) = found.get(1) {
        return Ok(Some(list.as_str().split(',').map(str::to_string).collect()));
    }
    let Some(start) = found.get(2).map(|item| item.as_str()) else {
        return Err(BraceError::NoMatch);
    };
    let Some(end) = found.get(3).map(|item| item.as_str()) else {
        return Err(BraceError::NoMatch);
    };
    let step = found.get(4).map(|item| item.as_str()).unwrap_or("1");
    let start_numeric = py_isdigit(start.trim_start_matches('-'));
    let end_numeric = py_isdigit(end.trim_start_matches('-'));
    if start_numeric != end_numeric {
        return Ok(Some(vec!["_".to_string()]));
    }
    if !start_numeric {
        return letter_range(start, end, step);
    }
    let first = parse_int(start).ok_or(BraceError::ValueError)?;
    let last = parse_int(end).ok_or(BraceError::ValueError)?;
    let step_value = parse_int(step).ok_or(BraceError::ValueError)?;
    let mut increment = step_value.abs();
    if increment.is_zero() {
        increment = Big::small(1);
    }
    if first.abs_diff(&last).cmp_abs(&increment.mul_u32(MAX_GLOB_VARIANTS as u32)) != Ordering::Less {
        return Ok(None);
    }
    let values = signed_range(&first, &last, &increment);
    let mut widths = BTreeSet::new();
    let width = if padded(start) || padded(end) {
        start.chars().count().max(end.chars().count())
    } else {
        0
    };
    widths.insert(width);
    if padded(step) {
        widths.insert(start.chars().count().max(end.chars().count()).max(step.chars().count()));
    }
    let mut formatted = BTreeSet::new();
    for each in widths {
        for value in &values {
            formatted.insert(value.format_width(each));
        }
    }
    Ok(Some(formatted.into_iter().collect()))
}

fn letter_range(start: &str, end: &str, step: &str) -> Result<Option<Vec<String>>, BraceError> {
    let first = start.chars().next().ok_or(BraceError::ValueError)? as i64;
    let last = end.chars().next().ok_or(BraceError::ValueError)? as i64;
    let step_value = parse_int(step).ok_or(BraceError::ValueError)?;
    let abs = step_value.abs();
    let increment = if abs.is_zero() {
        1
    } else if let Some(value) = abs.to_i64() {
        value
    } else {
        let Some(ch) = u32::try_from(first).ok().and_then(char::from_u32) else {
            return Err(BraceError::ValueError);
        };
        return Ok(Some(vec![ch.to_string()]));
    };
    let gap = (last - first).unsigned_abs();
    if increment > 0 && gap / (increment as u64) >= MAX_GLOB_VARIANTS as u64 {
        return Ok(None);
    }
    let direction = if last >= first { increment } else { -increment };
    let stop = if last >= first { last + 1 } else { last - 1 };
    let mut values = Vec::new();
    let mut current = first;
    while if direction >= 0 { current < stop } else { current > stop } {
        values.push(current);
        current += direction;
        if values.len() > MAX_GLOB_VARIANTS {
            return Ok(None);
        }
    }
    let mut out = Vec::new();
    for value in values {
        let Some(ch) = u32::try_from(value).ok().and_then(char::from_u32) else {
            return Err(BraceError::ValueError);
        };
        out.push(ch.to_string());
    }
    Ok(Some(out))
}

// Python str.isdigit() is true for Unicode decimal digits. char::is_numeric()
// also accepts numeric letters, so values go through to_digit(10), the set int() reads.
fn py_isdigit(text: &str) -> bool {
    let mut seen = false;
    for ch in text.chars() {
        if ch.to_digit(10).is_none() {
            return false;
        }
        seen = true;
    }
    seen
}

fn padded(text: &str) -> bool {
    let digits = text.trim_start_matches('-');
    digits.chars().count() > 1 && digits.starts_with('0')
}

fn base_name(word: &str) -> &str {
    match word.rfind('/') {
        Some(pos) => word.get(pos.saturating_add(1)..).unwrap_or_default(),
        None => word,
    }
}

fn command_verbose(words: &[String], index: usize) -> bool {
    let mut lookahead = Vec::new();
    let rest = match words.get(index.saturating_add(1)..) {
        Some(part) => part,
        None => &[],
    };
    for candidate in rest {
        if !candidate.starts_with('-') || candidate == "--" || candidate.chars().count() < 2 {
            break;
        }
        lookahead.push(candidate.as_str());
    }
    lookahead.iter().filter(|option| !option.starts_with("--")).any(|option| {
        option.chars().skip(1).any(|ch| ch == 'v' || ch == 'V')
    })
}

fn directory_choice<'a>(base: &str, names: &'a [String]) -> Option<&'a str> {
    let directory = DIRECTORY_OPTIONS.get(base)?;
    names
        .iter()
        .filter(|name| directory.contains(name.as_str()))
        .map(String::as_str)
        .max()
}

fn split_attached(option: &str) -> Option<String> {
    if option.starts_with("--") {
        let value = option.split_once('=').map(|(_, value)| value)?;
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    } else {
        let rest: String = option.chars().skip(1).collect();
        let (_, value) = rest.split_once('S')?;
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    }
}

fn find_chars(hay: &[char], needle: &[char]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if hay.len() < needle.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    for start in 0..=last {
        let mut same = true;
        for (offset, expected) in needle.iter().copied().enumerate() {
            if hay.get(start.saturating_add(offset)).copied() != Some(expected) {
                same = false;
                break;
            }
        }
        if same {
            return Some(start);
        }
    }
    None
}

#[derive(Clone, Debug, Eq)]
struct Big {
    neg: bool,
    d: Vec<u8>,
}

impl Big {
    fn zero() -> Self {
        Self { neg: false, d: Vec::new() }
    }

    fn small(value: u8) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self { neg: false, d: vec![value] }
        }
    }

    fn is_zero(&self) -> bool {
        self.d.iter().all(|digit| *digit == 0)
    }

    fn abs(&self) -> Self {
        Self { neg: false, d: self.d.clone() }
    }

    fn mul_u32(&self, factor: u32) -> Self {
        if self.is_zero() || factor == 0 {
            return Self::zero();
        }
        let mut d = Vec::new();
        let mut carry = 0u32;
        for digit in &self.d {
            let prod = carry + u32::from(*digit) * factor;
            d.push((prod % 10) as u8);
            carry = prod / 10;
        }
        while carry > 0 {
            d.push((carry % 10) as u8);
            carry /= 10;
        }
        Self { neg: self.neg, d: normalize_digits(d) }
    }

    fn cmp_abs(&self, other: &Self) -> Ordering {
        cmp_digits(&self.d, &other.d)
    }

    fn abs_diff(&self, other: &Self) -> Self {
        add_signed(self, &other.flipped()).abs()
    }

    fn flipped(&self) -> Self {
        if self.is_zero() {
            Self::zero()
        } else {
            Self { neg: !self.neg, d: self.d.clone() }
        }
    }

    fn to_i64(&self) -> Option<i64> {
        if self.d.len() > 18 {
            return None;
        }
        let mut value = 0i64;
        for digit in self.d.iter().rev() {
            value = value.checked_mul(10)?.checked_add(i64::from(*digit))?;
        }
        if self.neg {
            value = value.checked_neg()?;
        }
        Some(value)
    }

    fn format_width(&self, width: usize) -> String {
        let digits = if self.is_zero() {
            "0".to_string()
        } else {
            self.d.iter().rev().map(|digit| char::from(b'0' + *digit)).collect()
        };
        let sign = if self.neg { "-" } else { "" };
        let body = sign.len() + digits.len();
        if width <= body {
            return format!("{sign}{digits}");
        }
        let pad = "0".repeat(width - body);
        format!("{sign}{pad}{digits}")
    }
}

impl PartialEq for Big {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_signed(other) == Ordering::Equal
    }
}

impl Big {
    fn cmp_signed(&self, other: &Self) -> Ordering {
        if self.is_zero() && other.is_zero() {
            return Ordering::Equal;
        }
        match (self.neg, other.neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.cmp_abs(other),
            (true, true) => other.cmp_abs(self),
        }
    }
}

fn normalize_digits(mut digits: Vec<u8>) -> Vec<u8> {
    while digits.last() == Some(&0) {
        digits.pop();
    }
    digits
}

fn cmp_digits(left: &[u8], right: &[u8]) -> Ordering {
    let left = trim_zeros(left);
    let right = trim_zeros(right);
    match left.len().cmp(&right.len()) {
        Ordering::Equal => {
            for index in (0..left.len()).rev() {
                let ord = left.get(index).cmp(&right.get(index));
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            Ordering::Equal
        }
        other => other,
    }
}

fn trim_zeros(digits: &[u8]) -> &[u8] {
    let mut end = digits.len();
    while end > 0 && digits.get(end - 1) == Some(&0) {
        end -= 1;
    }
    match digits.get(..end) {
        Some(part) => part,
        None => &[],
    }
}

fn add_abs(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut carry = 0u8;
    let count = left.len().max(right.len());
    for index in 0..count {
        let sum = carry
            + left.get(index).copied().unwrap_or(0)
            + right.get(index).copied().unwrap_or(0);
        out.push(sum % 10);
        carry = sum / 10;
    }
    if carry > 0 {
        out.push(carry);
    }
    normalize_digits(out)
}

fn sub_abs(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut borrow = 0i16;
    for index in 0..left.len() {
        let mut diff = i16::from(left.get(index).copied().unwrap_or(0))
            - i16::from(right.get(index).copied().unwrap_or(0))
            - borrow;
        if diff < 0 {
            diff += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push(diff as u8);
    }
    normalize_digits(out)
}

fn add_signed(left: &Big, right: &Big) -> Big {
    if left.is_zero() {
        return right.clone();
    }
    if right.is_zero() {
        return left.clone();
    }
    if left.neg == right.neg {
        return Big { neg: left.neg, d: add_abs(&left.d, &right.d) };
    }
    match cmp_digits(&left.d, &right.d) {
        Ordering::Equal => Big::zero(),
        Ordering::Greater => Big { neg: left.neg, d: sub_abs(&left.d, &right.d) },
        Ordering::Less => Big { neg: right.neg, d: sub_abs(&right.d, &left.d) },
    }
}

fn parse_int(text: &str) -> Option<Big> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return None;
    }
    let mut neg = false;
    let mut start = 0usize;
    if chars.first() == Some(&'-') {
        neg = true;
        start = 1;
    }
    if start >= chars.len() {
        return None;
    }
    let mut d = Vec::new();
    for ch in chars.iter().skip(start) {
        d.push(u8::try_from(ch.to_digit(10)?).ok()?);
    }
    d.reverse();
    let d = normalize_digits(d);
    if d.is_empty() {
        neg = false;
    }
    Some(Big { neg, d })
}

fn signed_range(first: &Big, last: &Big, increment: &Big) -> Vec<Big> {
    let positive = last.cmp_signed(first) != Ordering::Less;
    let direction = if positive { increment.clone() } else { increment.flipped() };
    let stop = if positive {
        add_signed(last, &Big::small(1))
    } else {
        add_signed(last, &Big::small(1).flipped())
    };
    let mut current = first.clone();
    let mut values = Vec::new();
    loop {
        let inside = if direction.neg {
            current.cmp_signed(&stop) == Ordering::Greater
        } else {
            current.cmp_signed(&stop) == Ordering::Less
        };
        if !inside {
            break;
        }
        values.push(current.clone());
        current = add_signed(&current, &direction);
        if values.len() > MAX_GLOB_VARIANTS {
            break;
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{
        at_command_start, command_substitutions, expand_braces, first_operand, heredocs,
        normalize_command, option_names, split_options, strip_wrappers_with_directory,
        unquoted_lines, unquoted_text, HereDocument, ASSIGNMENT, DURATION, HEREDOC_FORBIDDEN,
    };
    use std::collections::HashSet;

    fn owned(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    fn norm(command: &str) -> (String, Vec<(String, String, String)>) {
        let mut redirects = Vec::new();
        let text = normalize_command(command, Some(&mut redirects));
        (text, redirects)
    }

    #[test]
    fn comparison_and_shift_operators_open_no_file() {
        let (text, redirects) = norm("[[ 2 > 1 ]]");
        assert_eq!(text, "[[ 2 > 1 ]]");
        assert!(redirects.is_empty());
        let (text, redirects) = norm("echo $((2 >> 1))");
        assert_eq!(text, "echo $((2 >> 1))");
        assert!(redirects.is_empty());
        let (text, redirects) = norm("(( x > 1 ))");
        assert_eq!(text, "(( x > 1 ))");
        assert!(redirects.is_empty());
    }

    #[test]
    fn a_redirection_next_to_an_expression_still_counts() {
        let (text, redirects) = norm("echo $((1+1)) > /dev/review-disk");
        assert_eq!(text, "echo $((1+1))  \u{1f} ");
        assert_eq!(redirects, vec![("".to_string(), ">".to_string(), "/dev/review-disk".to_string())]);
        let (text, redirects) = norm("((echo hi) > /dev/review-disk)");
        assert_eq!(text, "((echo hi)  \u{1f} )");
        assert_eq!(redirects, vec![("".to_string(), ">".to_string(), "/dev/review-disk".to_string())]);
    }

    #[test]
    fn a_redirect_marker_is_blank_so_double_parentheses_stay_whole() {
        assert!(at_command_start(&[" \u{1f} ".to_string()]));
        assert!(at_command_start(&[
            "\u{1c}".to_string(),
            "\u{1d}".to_string(),
            "\u{1e}".to_string(),
            "\u{1f}".to_string(),
        ]));
        assert!(!at_command_start(&["echo".to_string(), " \u{1f} ".to_string()]));

        let (text, redirects) = norm(">|((\n2>))");
        assert_eq!(text, " \u{1f} ((\n2>))");
        assert_eq!(redirects, vec![("".to_string(), ">|".to_string(), "".to_string())]);

        let (text, redirects) = norm(">>((rm--chdir=/w{1..3}<<'EOF'cat\t&>time\t))");
        assert_eq!(
            text,
            " \u{1f} ((rm--chdir=/w{1..3}<<'EOF'cat\t&>time\t))"
        );
        assert_eq!(redirects, vec![("".to_string(), ">>".to_string(), "".to_string())]);

        let (text, redirects) = norm(">&--chdir=/wcommand((\\\n))\t5s-rf*.py'-rf\\\nenvbcat~/xcommand");
        assert_eq!(
            text,
            " \u{1f} ((\\\n))\t5s-rf*.py'-rf\\\nenvbcat~/xcommand"
        );
        assert_eq!(
            redirects,
            vec![("".to_string(), ">&".to_string(), "--chdir=/wcommand".to_string())]
        );

        let (text, redirects) = norm("echo>((\n2>))");
        assert_eq!(text, "echo \u{1f} ((\n \u{1f} ))");
        assert_eq!(
            redirects,
            vec![
                ("".to_string(), ">".to_string(), "".to_string()),
                ("2".to_string(), ">".to_string(), "".to_string()),
            ]
        );

        let (text, _) = norm(&format!("{}>((2>1))", " ".repeat(30)));
        assert!(text.contains("((2>1))"), "{text:?}");
        let (text, redirects) = norm(&format!("{}>((2>1))", "a".repeat(30)));
        assert!(text.contains("(( \u{1f} ))"), "{text:?}");
        assert_eq!(redirects.len(), 2);

        let (_, redirects) = norm(">\u{1f}file\u{1f}");
        assert_eq!(redirects, vec![("".to_string(), ">".to_string(), "file".to_string())]);
        let (_, redirects) = norm(">\u{1c}file\u{1d}");
        assert_eq!(redirects, vec![("".to_string(), ">".to_string(), "file".to_string())]);
    }

    #[test]
    fn the_force_suffix_of_zsh_is_part_of_the_operator() {
        let (_, redirects) = norm("printf x >! /dev/review-disk");
        assert_eq!(redirects[0].1, ">!");
        let (_, redirects) = norm("printf x >&! /dev/review-disk");
        assert_eq!(redirects[0].1, ">&!");
        let (_, redirects) = norm("printf x &>! /dev/review-disk");
        assert_eq!(redirects[0].1, ">!");
        let (_, redirects) = norm("printf x >!/dev/review-disk");
        assert_eq!(redirects, vec![("".to_string(), ">!".to_string(), "/dev/review-disk".to_string())]);
    }

    #[test]
    fn quote_removal_in_a_double_quoted_delimiter_matches_the_shell() {
        let command = "cat <<\"E\\$D\"\nDATA\nE$D\n";
        let docs = heredocs(command);
        assert_eq!(docs.len(), 1);
        let doc = &docs[0];
        assert!(doc.quoted);
        assert_eq!(&command[doc.body_start..doc.body_end], "DATA\n");
        assert_eq!(
            doc,
            &HereDocument {
                line_start: 0,
                marker_start: 4,
                delimiter_end: 12,
                line_end: 12,
                body_start: 13,
                body_end: 18,
                end: 22,
                quoted: true,
                outer: None,
            }
        );
    }

    #[test]
    fn an_empty_quoted_delimiter_is_a_delimiter() {
        let command = "cat > /tmp/x.txt <<''\nit's harmless text\n\n";
        let docs = heredocs(command);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].quoted);
        assert_eq!(&command[docs[0].body_start..docs[0].body_end], "it's harmless text\n");
    }

    #[test]
    fn an_apostrophe_in_a_here_document_does_not_hide_the_commands_after_it() {
        let command = "cat <<EOF\nit's text\nEOF\nenv\n";
        let docs = heredocs(command);
        assert_eq!(docs.len(), 1);
        assert_eq!(&command[docs[0].end..], "env\n");
        let lines = unquoted_lines(command);
        assert!(lines.iter().any(|line| line.contains("env")));
    }

    #[test]
    fn a_continued_line_and_a_command_substitution_count() {
        assert_eq!(unquoted_lines("echo a\\\nb\n'c'\n"), vec!["echo ab", " ", ""]);
        assert_eq!(command_substitutions("echo $(ls)"), vec!["ls"]);
        assert_eq!(command_substitutions("echo '$(ls)'"), Vec::<String>::new());
        assert_eq!(command_substitutions("echo \"$(ls)\""), vec!["ls"]);
        assert_eq!(command_substitutions("echo $(a $(b))"), vec!["a $(b)"]);
        assert_eq!(command_substitutions("echo $((1+$(ls)))"), vec!["ls"]);
        assert_eq!(command_substitutions("echo <(ls)"), vec!["ls"]);
    }

    #[test]
    fn wrappers_and_full_paths_do_not_lose_the_command() {
        let keep = HashSet::<&str>::new();
        let (words, moved) = strip_wrappers_with_directory(&owned(&["env", "-C", "/tmp", "cmd"]), &keep).unwrap();
        assert_eq!(words, owned(&["cmd"]));
        assert_eq!(moved, vec!["/tmp".to_string()]);
        let (words, moved) =
            strip_wrappers_with_directory(&owned(&["/usr/bin/sudo", "-R", "/chroot", "cmd"]), &keep).unwrap();
        assert_eq!(words, owned(&["cmd"]));
        assert_eq!(moved, vec!["".to_string()]);
        let (words, moved) = strip_wrappers_with_directory(&owned(&["FOO=1", "cmd"]), &keep).unwrap();
        assert_eq!(words, owned(&["cmd"]));
        assert!(moved.is_empty());
        let (words, _) = strip_wrappers_with_directory(&owned(&["command", "-v", "ls"]), &keep).unwrap();
        assert_eq!(words, owned(&["command", "-v", "ls"]));
        let (words, _) = strip_wrappers_with_directory(&owned(&["env", "-S", "echo hi"]), &keep).unwrap();
        assert_eq!(words, owned(&["echo", "hi"]));
        let (words, _) = strip_wrappers_with_directory(&owned(&["nice", "-n", "5", "cmd"]), &keep).unwrap();
        assert_eq!(words, owned(&["cmd"]));
    }

    #[test]
    fn assignments_are_read_the_way_the_shell_reads_them() {
        assert!(ASSIGNMENT.is_match("FOO=1"));
        assert!(ASSIGNMENT.is_match("A="));
        assert!(!ASSIGNMENT.is_match("=1"));
        assert!(!ASSIGNMENT.is_match("1=x"));
        assert!(DURATION.is_match("5s"));
        assert!(DURATION.is_match("."));
        assert!(!DURATION.is_match("s"));
        assert!(HEREDOC_FORBIDDEN.is_match("$(("));
        assert!(HEREDOC_FORBIDDEN.is_match("${1}"));
        assert!(!HEREDOC_FORBIDDEN.is_match("${name}"));
        assert!(HEREDOC_FORBIDDEN.is_match("`date`"));
    }

    #[test]
    fn brace_expansion_follows_the_shell_order() {
        assert_eq!(expand_braces("{1..3}").unwrap().unwrap(), owned(&["3", "2", "1"]));
        assert_eq!(expand_braces("{8..10}").unwrap().unwrap(), owned(&["9", "8", "10"]));
        assert_eq!(expand_braces("{01..03}").unwrap().unwrap(), owned(&["03", "02", "01"]));
        assert_eq!(expand_braces("{1..10..2}").unwrap().unwrap(), owned(&["9", "7", "5", "3", "1"]));
        assert_eq!(expand_braces("{8..10..08}").unwrap().unwrap(), owned(&["8", "08"]));
        assert_eq!(expand_braces("{a..c}").unwrap().unwrap(), owned(&["c", "b", "a"]));
        assert_eq!(expand_braces("{c..a}").unwrap().unwrap(), owned(&["a", "b", "c"]));
        assert_eq!(expand_braces("{a..1}").unwrap().unwrap(), owned(&["_"]));
        assert_eq!(expand_braces("pre{1..2}post").unwrap().unwrap(), owned(&["pre2post", "pre1post"]));
        assert_eq!(expand_braces("{a,b}{1..2}").unwrap().unwrap(), owned(&["b2", "b1", "a2", "a1"]));
        assert_eq!(expand_braces("{01..03..02}").unwrap().unwrap(), owned(&["03", "01"]));
        assert_eq!(expand_braces("plain").unwrap().unwrap(), owned(&["plain"]));
        assert!(expand_braces("{1..300}").unwrap().is_none());
    }

    #[test]
    fn option_scanning_skips_values_and_keeps_operands() {
        let options = HashSet::from(["--target-directory"]);
        assert_eq!(
            split_options(&owned(&["-t", "dest", "src", "-n"]), "t", &options),
            owned(&["src"])
        );
        assert_eq!(first_operand(&owned(&["-t", "dest", "src"]), "t", &options), Some(2));
        assert_eq!(split_options(&owned(&["--", "-n"]), "", &HashSet::<&str>::new()), owned(&["-n"]));
        let values = HashSet::from(["-u", "--chdir"]);
        assert_eq!(option_names("-ufile", &values), (owned(&["-u"]), false));
        assert_eq!(option_names("--chdir=/tmp", &values), (owned(&["--chdir"]), false));
        assert_eq!(option_names("--chdir", &values), (owned(&["--chdir"]), true));
    }

    #[test]
    fn quoted_text_and_comments_do_not_hide_the_next_line() {
        assert_eq!(unquoted_text("echo 'a > b' # comment\nnext"), "echo   \nnext");
    }
}
