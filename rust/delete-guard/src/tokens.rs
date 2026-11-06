use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::LazyLock;

use guard_common::env::user_home;
use guard_common::shell::{normalize_command, REDIRECTION_MARKER, SHELL_KEYWORDS};
use guard_common::shlex::Lexer;
use guard_common::sys::realpath;
use regex::Regex;

use crate::consts::FUNCTION_HEADER;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chunk {
    pub words: Vec<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    pub opened: bool,
    pub redirected: bool,
    pub redirections: Vec<(String, String, String)>,
}

static FUNCTION_HEADER_FULL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\A(?:{})\z", FUNCTION_HEADER.as_str()))
        .unwrap_or_else(|error| panic!("function header regex: {error}"))
});
static COPROC_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[A-Za-z_][\p{L}\p{N}_]*\z")
        .unwrap_or_else(|error| panic!("coproc regex: {error}"))
});
static VARIABLE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A([A-Za-z_][\p{L}\p{N}_]*)\+?=")
        .unwrap_or_else(|error| panic!("assignment regex: {error}"))
});
static HOME_FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?:\$HOME|\$\{HOME\}|~)(?:/|\n?\z)")
        .unwrap_or_else(|error| panic!("home form regex: {error}"))
});
static PLAIN_HOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?:\$HOME|\$\{HOME\})(?:/[^\n]*)?\z")
        .unwrap_or_else(|error| panic!("plain home regex: {error}"))
});
static CHANGED_HOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\A|[^\p{L}\p{N}_$])HOME[\s\x1c-\x1f]*\+?=")
        .unwrap_or_else(|error| panic!("changed home regex: {error}"))
});
static CHANGED_CDPATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\A|[^\p{L}\p{N}_$])CDPATH[\s\x1c-\x1f]*\+?=")
        .unwrap_or_else(|error| panic!("changed CDPATH regex: {error}"))
});

thread_local! {
    static VARIABLES_CHANGED: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

pub fn set_variables_changed(value: HashSet<String>) {
    VARIABLES_CHANGED.with(|slot| *slot.borrow_mut() = value);
}

pub fn variables_changed_state() -> HashSet<String> {
    VARIABLES_CHANGED.with(|slot| slot.borrow().clone())
}

pub fn function_header_length(words: &[String]) -> usize {
    let mut text = String::new();
    let mut length = 0;
    for (index, word) in words.iter().take(6).enumerate() {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(word);
        if FUNCTION_HEADER_FULL.is_match(&text)
            && (text.contains('(') || text.starts_with("function"))
        {
            length = index.saturating_add(1);
        }
    }
    while length > 0 && words.get(length).is_some_and(|word| word == "{") {
        length = length.saturating_add(1);
    }
    length
}

pub fn open_parentheses(mut words: Vec<String>) -> Vec<String> {
    while words.first().is_some_and(|word| word.starts_with('(')) {
        if let Some(first) = words.first_mut() {
            first.remove(0);
        }
        if words.first().is_some_and(String::is_empty) {
            words.remove(0);
        }
    }
    words
}

pub fn without_syntax_prefix(words: &[String]) -> Vec<String> {
    let mut words = open_parentheses(words.to_vec());
    loop {
        let count = words.len();
        let mut skip = 0usize;
        while words
            .get(skip)
            .is_some_and(|word| SHELL_KEYWORDS.contains(word.as_str()) || word == "time")
        {
            skip = skip.saturating_add(1);
        }
        let mut head = words.get(..skip).unwrap_or(&[]).to_vec();
        let mut rest = open_parentheses(words.get(skip..).unwrap_or(&[]).to_vec());
        if rest.first().is_some_and(|word| word == "coproc") {
            rest.remove(0);
            if rest.len() > 1
                && rest
                    .get(1)
                    .is_some_and(|word| word == "{" || word.starts_with('('))
                && rest.first().is_some_and(|word| COPROC_NAME.is_match(word))
            {
                rest.remove(0);
            }
        } else if rest.first().is_some_and(|word| word == "case") {
            if let Some(position) = rest
                .iter()
                .enumerate()
                .skip(2)
                .find_map(|(index, word)| (word == "in").then_some(index))
            {
                rest = rest
                    .get(position.saturating_add(1)..)
                    .unwrap_or(&[])
                    .to_vec();
            }
        } else if rest.len() > 1
            && rest
                .first()
                .is_some_and(|word| word.ends_with(')') && !word.starts_with("$("))
        {
            rest.remove(0);
        }
        head.extend(open_parentheses(rest));
        words = head;
        if words.len() == count {
            return words;
        }
    }
}

pub fn chunk(
    raw_words: &[String],
    before: Option<&str>,
    after: Option<&str>,
    redirected: bool,
    redirections: &[(String, String, String)],
) -> Chunk {
    let mut words: Vec<String> = raw_words
        .iter()
        .filter(|word| !word.is_empty())
        .cloned()
        .collect();
    let header = function_header_length(&words);
    let mut opened = header > 0
        || words
            .first()
            .is_some_and(|word| word.starts_with('(') || word == "{");
    words = without_syntax_prefix(words.get(header..).unwrap_or(&[]));
    opened |= words
        .first()
        .is_some_and(|word| word.starts_with('(') || word == "{");
    if let Some(last) = words.last_mut() {
        if last.ends_with(')') {
            *last = last.trim_end_matches(')').to_owned();
            if last.is_empty() {
                words.pop();
            }
        }
    }
    for word in &mut words {
        *word = word
            .chars()
            .map(|ch| match ch {
                '\u{e010}' => ';',
                '\u{e011}' => '&',
                '\u{e012}' => '|',
                '\u{e013}' => '\n',
                '\u{e014}' => '(',
                '\u{e015}' => ')',
                _ => ch,
            })
            .collect();
    }
    Chunk {
        words,
        before: before.map(str::to_owned),
        after: after.map(str::to_owned),
        opened,
        redirected,
        redirections: redirections.to_vec(),
    }
}

fn separator_private(ch: char) -> Option<char> {
    match ch {
        ';' => Some('\u{e010}'),
        '&' => Some('\u{e011}'),
        '|' => Some('\u{e012}'),
        '\n' => Some('\u{e013}'),
        '(' => Some('\u{e014}'),
        ')' => Some('\u{e015}'),
        _ => None,
    }
}

pub fn protect_escaped_separators(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut quote = None;
    let mut index = 0usize;
    while let Some(character) = chars.get(index).copied() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            } else if active == '"' && character == '\\' {
                let following = chars.get(index.saturating_add(1)).copied();
                if let Some(private) = following
                    .and_then(separator_private)
                    .filter(|_| following != Some('\n'))
                {
                    out.push('\\');
                    out.push(private);
                } else {
                    out.push(character);
                    if let Some(next) = following {
                        out.push(next);
                    }
                }
                index = index.saturating_add(2);
                continue;
            } else if let Some(private) = separator_private(character) {
                out.push(private);
                index = index.saturating_add(1);
                continue;
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '\\' {
            if let Some(private) = chars
                .get(index.saturating_add(1))
                .copied()
                .and_then(separator_private)
            {
                out.push(private);
            } else {
                out.push(character);
                if let Some(next) = chars.get(index.saturating_add(1)) {
                    out.push(*next);
                }
            }
            index = index.saturating_add(2);
            continue;
        }
        out.push(character);
        index = index.saturating_add(1);
    }
    out
}

pub fn tokenize(command: &str) -> Option<Vec<Chunk>> {
    let mut recorded = Vec::new();
    let normalized = normalize_command(command, Some(&mut recorded));
    let protected = protect_escaped_separators(&normalized);
    let tokens = Lexer::new(&protected)
        .posix(true)
        .punctuation_chars(";&|\n")
        .whitespace(" \t\r")
        .whitespace_split(true)
        .commenters("")
        .tokens()
        .ok()?;
    let mut chunks = Vec::new();
    let mut words = Vec::new();
    let mut before: Option<String> = None;
    let mut redirected = false;
    let mut redirections = Vec::new();
    let mut record_index = 0usize;
    for token in tokens {
        if token == REDIRECTION_MARKER {
            redirected = true;
            if let Some(record) = recorded.get(record_index) {
                redirections.push(record.clone());
            }
            record_index = record_index.saturating_add(1);
        } else if !token.is_empty() && token.chars().all(|ch| ";&|\n".contains(ch)) {
            let stripped = token.replace('\n', "");
            let separator = if !stripped.is_empty() && stripped.chars().any(|ch| ch != ';') {
                stripped
            } else {
                ";".to_owned()
            };
            if !words.is_empty() || !redirections.is_empty() {
                chunks.push(chunk(
                    &words,
                    before.as_deref(),
                    Some(&separator),
                    redirected,
                    &redirections,
                ));
                words.clear();
                redirected = false;
                redirections.clear();
            }
            before = Some(separator);
        } else {
            words.push(token);
        }
    }
    if !words.is_empty() || !redirections.is_empty() {
        chunks.push(chunk(
            &words,
            before.as_deref(),
            None,
            redirected,
            &redirections,
        ));
    }
    Some(
        chunks
            .into_iter()
            .filter(|part| !part.words.is_empty() || part.opened || !part.redirections.is_empty())
            .collect(),
    )
}

pub fn base(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or("")
}

pub fn is_computed(path: &str) -> bool {
    (path.contains('$') || path.contains('`')) && !PLAIN_HOME.is_match(path)
}

pub fn home_expanded(path: &str) -> String {
    let expanded = if let Some(rest) = path.strip_prefix("$HOME") {
        format!("{}{rest}", user_home())
    } else if let Some(rest) = path.strip_prefix("${HOME}") {
        format!("{}{rest}", user_home())
    } else {
        path.to_owned()
    };
    if expanded == "~" || expanded.starts_with("~/") {
        format!("{}{}", user_home(), expanded.get(1..).unwrap_or(""))
    } else {
        expanded
    }
}

pub fn variables_changed_by(words: &[String]) -> HashSet<String> {
    let mut found = HashSet::new();
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        let Some(capture) = VARIABLE_ASSIGNMENT.captures(word) else {
            break;
        };
        if let Some(name) = capture.get(1) {
            found.insert(name.as_str().to_owned());
        }
        index = index.saturating_add(1);
    }
    let rest = words.get(index..).unwrap_or(&[]);
    if let Some(first) = rest.first() {
        let name = base(first);
        if [
            "export", "declare", "typeset", "local", "readonly", "env", "sudo", "nohup", "exec",
            "command",
        ]
        .contains(&name)
        {
            for word in rest.iter().skip(1) {
                if let Some(capture) = VARIABLE_ASSIGNMENT.captures(word) {
                    if let Some(name) = capture.get(1) {
                        found.insert(name.as_str().to_owned());
                    }
                }
            }
        } else if ["read", "mapfile", "readarray", "unset", "getopts"].contains(&name) {
            for word in rest.iter().skip(1) {
                if word == "HOME" || word == "CDPATH" {
                    found.insert(word.clone());
                }
            }
        } else if name == "printf" {
            for pair in rest.windows(2) {
                if pair.first().is_some_and(|word| word == "-v") {
                    if let Some(value) = pair.get(1) {
                        found.insert(value.clone());
                    }
                }
            }
        }
    }
    found.retain(|name| name == "HOME" || name == "CDPATH");
    found
}

pub fn variables_changed(command: &str) -> HashSet<String> {
    if !command.contains("HOME") && !command.contains("CDPATH") {
        return HashSet::new();
    }
    if let Some(chunks) = tokenize(command) {
        chunks
            .iter()
            .flat_map(|part| variables_changed_by(&part.words))
            .collect()
    } else {
        let mut changed = HashSet::new();
        if CHANGED_HOME.is_match(command) {
            changed.insert("HOME".to_owned());
        }
        if CHANGED_CDPATH.is_match(command) {
            changed.insert("CDPATH".to_owned());
        }
        changed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpandError {
    ValueError,
}

impl From<ExpandError> for crate::errors::Stop {
    fn from(_: ExpandError) -> Self {
        crate::errors::Stop::Internal
    }
}

pub fn expand(path: &str, cwd: Option<&str>) -> Result<Option<String>, ExpandError> {
    if variables_changed_state().contains("HOME") && HOME_FORM.is_match(path) {
        return Ok(None);
    }
    let path = home_expanded(path);
    if path.starts_with('~') {
        return Ok(None);
    }
    let path = if path.starts_with('/') {
        path
    } else {
        let Some(cwd) = cwd else { return Ok(None) };
        if cwd.is_empty() {
            path
        } else if cwd.ends_with('/') {
            format!("{cwd}{path}")
        } else {
            format!("{cwd}/{path}")
        }
    };
    if path.contains('\0') {
        return Err(ExpandError::ValueError);
    }
    Ok(Some(realpath(&path)))
}

#[cfg(test)]
mod tests {
    use super::{chunk, expand, is_computed, tokenize, variables_changed, ExpandError};

    #[test]
    fn escaped_separator_is_a_word_and_redirect_stays_with_its_chunk() {
        let parts = tokenize("echo \\; >out; rm x").expect("tokens");
        assert_eq!(parts.len(), 2);
        assert_eq!(
            parts
                .first()
                .and_then(|part| part.words.get(1))
                .map(String::as_str),
            Some(";")
        );
        assert_eq!(parts.first().map(|part| part.redirections.len()), Some(1));
        assert_eq!(
            parts.get(1).and_then(|part| part.before.as_deref()),
            Some(";")
        );
    }

    #[test]
    fn quoted_parenthesis_survives_group_cleanup() {
        let part = chunk(
            &["echo".to_owned(), "x\u{e015}".to_owned()],
            None,
            None,
            false,
            &[],
        );
        assert_eq!(part.words.get(1).map(String::as_str), Some("x)"));
    }

    #[test]
    fn changed_home_makes_expansion_unknown() {
        super::set_variables_changed(["HOME".to_owned()].into_iter().collect());
        assert_eq!(expand("$HOME/x", Some("/tmp")), Ok(None));
        super::set_variables_changed(Default::default());
        assert_eq!(expand("\0", Some("/tmp")), Err(ExpandError::ValueError));
        assert!(is_computed("$HOME/\nx"));
        assert!(variables_changed("export HOME=x").contains("HOME"));
    }
}
