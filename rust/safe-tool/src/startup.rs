use std::sync::LazyLock;

use guard_common::sys::EmbeddedNul;
use guard_common::{env, pyglob, shell};
use regex::Regex;

use crate::{chunk, consts, paths};

static QUOTED_HOME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""\$\{?HOME\}?""#).unwrap_or_else(|_| std::process::abort()));
static GLOB_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[^\s\u{001c}-\u{001f};&|()<>"'`]+"#).unwrap_or_else(|_| std::process::abort())
});
static HOME_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\A(?:~|\$HOME|\$\{HOME\})(?:/|\z)").unwrap_or_else(|_| std::process::abort())
});
static CHANGE_DIRECTORY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"cd|pushd").unwrap_or_else(|_| std::process::abort()));
static FIND_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"find").unwrap_or_else(|_| std::process::abort()));
static FIND_ROOTS_PY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"find[ \t]+((?:[^\s\u{001c}-\u{001f};&|()<>`!-][^\s\u{001c}-\u{001f};&|()<>`]*[ \t]+){0,50})")
        .unwrap_or_else(|_| std::process::abort())
});
static PIPELINE_WORD_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<word>xargs|while|for|eval|exec|parallel)|(?P<exec>-exec)|(?P<ok>-ok(?:dir)?)")
        .unwrap_or_else(|_| std::process::abort())
});
static PLAIN_QUOTES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'\\]"#).unwrap_or_else(|_| std::process::abort()));
static DOLLAR_QUOTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\$(['"])"#).unwrap_or_else(|_| std::process::abort()));

fn py_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&ch)
}

// Reuse Python's word boundary rule across find, directory, and pipeline checks.
fn word_boundaries(text: &str, start: usize, end: usize, left: bool, right: bool) -> bool {
    let before = text.get(..start).unwrap_or("").chars().last();
    let after = text.get(end..).unwrap_or("").chars().next();
    (!left || before.is_none_or(|ch| !chunk::python_word(ch)))
        && (!right || after.is_none_or(|ch| !chunk::python_word(ch)))
}

fn bounded_word(text: &str, pattern: &Regex) -> bool {
    pattern
        .find_iter(text)
        .any(|hit| word_boundaries(text, hit.start(), hit.end(), true, true))
}

fn normpath(path: &str) -> String {
    let absolute = path.starts_with('/');
    let double_root = path.starts_with("//") && !path.starts_with("///");
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if parts.last().is_some_and(|last| *last != "..") {
                parts.pop();
            } else if !absolute {
                parts.push(part);
            }
        } else {
            parts.push(part);
        }
    }
    let prefix = if double_root {
        "//"
    } else if absolute {
        "/"
    } else {
        ""
    };
    let result = format!("{prefix}{}", parts.join("/"));
    if result.is_empty() {
        ".".to_owned()
    } else {
        result
    }
}

fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'%' {
            if let (Some(high), Some(low)) = (
                bytes.get(index.saturating_add(1)),
                bytes.get(index.saturating_add(2)),
            ) {
                let hex = |value: u8| -> Option<u8> {
                    match value {
                        b'0'..=b'9' => Some(value - b'0'),
                        b'a'..=b'f' => Some(value - b'a' + 10),
                        b'A'..=b'F' => Some(value - b'A' + 10),
                        _ => None,
                    }
                };
                if let (Some(hi), Some(lo)) = (hex(*high), hex(*low)) {
                    output.push(hi.saturating_mul(16).saturating_add(lo));
                    index = index.saturating_add(3);
                    continue;
                }
            }
        }
        output.push(*byte);
        index = index.saturating_add(1);
    }
    String::from_utf8_lossy(&output).into_owned()
}

pub fn could_name_startup_file(pattern: &str, dotted: bool) -> bool {
    let last = pattern.rsplit('/').next().unwrap_or("").to_lowercase();
    (last.starts_with('.') || dotted)
        && consts::STARTUP_SAMPLE_NAMES
            .iter()
            .any(|sample| pyglob::fnmatchcase(sample, &last))
}

pub fn glob_names_startup_file(text: &str) -> Result<bool, EmbeddedNul> {
    glob_names_startup_file_at(text, env::user_home(), &paths::working_folder())
}

pub fn glob_names_startup_file_at(
    text: &str,
    home: &str,
    working: &str,
) -> Result<bool, EmbeddedNul> {
    let without_home_quotes = QUOTED_HOME.replace_all(text, "~");
    let unquoted = shell::unquoted_lines(&without_home_quotes).join("\n");
    let dotted = consts::DOTGLOB_PATTERN.is_match(text);
    let mut words = Vec::new();
    for found in GLOB_WORD.find_iter(&unquoted) {
        let mut word = found.as_str().to_owned();
        if word.contains('/') {
            word = normpath(&word);
        }
        if !word.starts_with(&['~', '$', '/', '.', '{'][..]) && !word.contains('/') {
            continue;
        }
        if word.chars().count() > consts::MAX_GLOB_WORD_CHARS {
            if word.contains(&['*', '?', '[', '{'][..]) {
                return Ok(true);
            }
        } else if consts::GLOB_SYNTAX_PATTERN.is_match(&word) {
            words.push(word);
        }
    }
    if words.len() > consts::MAX_GLOB_WORDS {
        return Ok(true);
    }
    if words.is_empty() {
        return Ok(false);
    }
    let from_home = bounded_word(text, &CHANGE_DIRECTORY) || working == home;
    for word in words {
        let variants = shell::expand_braces(&word).map_err(|_| EmbeddedNul)?;
        let Some(variants) = variants else {
            return Ok(true);
        };
        for variant in variants {
            let expanded = if let Some(found) = HOME_PREFIX.find(&variant) {
                let prefix_len = if found.as_str().ends_with('/') {
                    found.end().saturating_sub(1)
                } else {
                    found.end()
                };
                format!("{home}{}", variant.get(prefix_len..).unwrap_or(""))
            } else {
                variant
            };
            let candidates = if !expanded.contains(&['*', '?', '['][..]) {
                vec![expanded.clone()]
            } else {
                let mut patterns = vec![expanded.clone()];
                if !expanded.starts_with('/') && from_home {
                    patterns.push(format!("{home}/{expanded}"));
                }
                let mut candidates = Vec::new();
                for pattern in patterns {
                    candidates.extend(pyglob::iglob(&pattern, shell::MAX_GLOB_MATCHES)?);
                }
                let elsewhere = !format!("{expanded}/").starts_with(&format!("{home}/"))
                    && (expanded.starts_with('/')
                        || expanded.starts_with(&['~', '$'][..])
                        || expanded.split('/').any(|part| part == ".."));
                if (elsewhere || dotted) && could_name_startup_file(&expanded, dotted) {
                    return Ok(true);
                }
                candidates
            };
            for candidate in candidates {
                let shown = if std::path::Path::new(&candidate).is_dir() {
                    format!("{candidate}/")
                } else {
                    candidate
                };
                if consts::startup_file_pattern_search(&shown).is_some() {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

pub fn find_names_startup_file(text: &str) -> Result<bool, EmbeddedNul> {
    find_names_startup_file_at(text, env::user_home(), &paths::working_folder())
}

pub fn find_names_startup_file_at(
    text: &str,
    home: &str,
    working: &str,
) -> Result<bool, EmbeddedNul> {
    if !bounded_word(text, &FIND_WORD) || !pipeline_context(text) {
        return Ok(false);
    }
    let mut roots = Vec::new();
    let mut offset = 0usize;
    while let Some(found) = FIND_ROOTS_PY.captures_at(text, offset) {
        let Some(hit) = found.get(0) else {
            break;
        };
        offset = if word_boundaries(
            text,
            hit.start(),
            hit.start().saturating_add(4),
            true,
            false,
        ) {
            hit.end()
        } else {
            hit.start().saturating_add(1)
        };
        if offset != hit.end() {
            continue;
        }
        let captured = found.get(1).map_or("", |hit| hit.as_str());
        let split: Vec<&str> = captured
            .split(py_space)
            .filter(|part| !part.is_empty())
            .collect();
        for word in if split.is_empty() { vec!["."] } else { split } {
            roots.push(word.trim_matches(['\'', '"']).to_owned());
        }
    }
    let mut covers = false;
    for root in roots {
        if paths::covers_home_at(&root, home, working)? {
            covers = true;
            break;
        }
    }
    if !covers {
        return Ok(false);
    }
    if consts::find_uncheckable_search(text).is_some() {
        return Ok(true);
    }
    let mut patterns = Vec::new();
    for found in consts::FIND_NAME_PATTERN.captures_iter(text) {
        let value = (1..=3)
            .find_map(|group| found.get(group))
            .map_or("", |hit| hit.as_str());
        patterns.push(
            value
                .replace('\\', "")
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_lowercase(),
        );
    }
    Ok(patterns.is_empty()
        || patterns.iter().any(|pattern| {
            consts::STARTUP_SAMPLE_NAMES
                .iter()
                .any(|sample| pyglob::fnmatchcase(sample, pattern))
        }))
}

// True when only the find rule fires: no startup file is named or globbed in the text.
pub fn blocked_by_find_alone(text: &str) -> Result<bool, EmbeddedNul> {
    Ok(find_names_startup_file(text)? && !mentions_startup_file(text) && !glob_names_startup_file(text)?)
}

pub fn mentions_startup_file(text:&str) -> bool {
    let joined = text.replace("\\\n", "");
    let stripped_dollar = DOLLAR_QUOTE.replace_all(&joined, "${1}");
    let plain = PLAIN_QUOTES.replace_all(&stripped_dollar, "");
    [text, plain.as_ref()]
        .iter()
        .any(|variant| consts::startup_file_pattern_search(variant).is_some())
        || consts::startup_file_pattern_search(&unquote(&plain)).is_some()
}

pub fn pipeline_context(text: &str) -> bool {
    consts::pipeline_operator_pattern_search(text).is_some()
        || shell::unquoted_lines(text).iter().any(|line| {
            PIPELINE_WORD_CANDIDATE.captures_iter(line).any(|caps| {
                let Some(hit) = caps.get(0) else {
                    return false;
                };
                if caps.name("exec").is_some() {
                    true
                } else if caps.name("ok").is_some() {
                    word_boundaries(line, hit.start(), hit.end(), false, true)
                } else {
                    word_boundaries(line, hit.start(), hit.end(), true, true)
                }
            })
        })
}

pub fn safe_source(token: &str) -> bool {
    !token.contains("..")
        && !token.contains(&['{', '}', '*', '?', '[', ','][..])
        && consts::startup_history_pattern_search(token).is_none()
}

pub fn without_safe_sources(command: &str) -> String {
    let marked = command
        .split('\n')
        .map(shell::mark_opening_quotes)
        .collect::<Vec<_>>()
        .join("\n");
    let chars: Vec<char> = command.chars().collect();
    let mut pieces = String::new();
    let mut end = 0usize;
    for found in consts::source_startup_pattern_finditer(&marked) {
        let start = marked.get(..found.start).unwrap_or("").chars().count();
        let finish = marked.get(..found.end).unwrap_or("").chars().count();
        let token: String = chars.get(start..finish).unwrap_or(&[]).iter().collect();
        if safe_source(&token) {
            pieces.extend(chars.get(end..start).unwrap_or(&[]).iter());
            pieces.push(' ');
            end = finish;
        }
    }
    pieces.extend(chars.get(end..).unwrap_or(&[]).iter());
    pieces
}

pub fn reads_startup_file(command: &str) -> Result<bool, EmbeddedNul> {
    reads_startup_file_at(command, env::user_home(), &paths::working_folder())
}

pub fn reads_startup_file_at(
    command: &str,
    home: &str,
    working: &str,
) -> Result<bool, EmbeddedNul> {
    if !consts::startup_rules() {
        return Ok(false);
    }
    let command = consts::JQ_PROGRAM
        .replace_all(command, |caps: &regex::Captures<'_>| {
            format!("{}x", caps.name("head").map_or("", |hit| hit.as_str()))
        })
        .into_owned();
    if consts::HISTORY_VARIABLE_PATTERN.is_match(&command) {
        return Ok(true);
    }
    if !mentions_startup_file(&command)
        && !glob_names_startup_file_at(&command, home, working)?
        && !find_names_startup_file_at(&command, home, working)?
    {
        return Ok(false);
    }
    if consts::TRACE_ENVIRONMENT_PATTERN.is_match(&command) {
        return Ok(true);
    }
    let mut remainder = command.clone();
    if !consts::SHADOWING_PATTERN.is_match(&command) {
        remainder = consts::HAS_KEY_STARTUP_PATTERN
            .replace_all(&without_safe_sources(&command), " ")
            .into_owned();
        if !pipeline_context(&command) {
            remainder = consts::METADATA_STARTUP_PATTERN
                .replace_all(&remainder, " ")
                .into_owned();
        }
    }
    if mentions_startup_file(&remainder) {
        return Ok(true);
    }
    if glob_names_startup_file_at(&remainder, home, working)? {
        return Ok(true);
    }
    find_names_startup_file_at(&remainder, home, working)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_and_metadata_exemptions() {
        assert!(mentions_startup_file("cat ~/.zshrc"));
        assert!(!safe_source("source ~/.bash_history"));
        assert!(safe_source("source ~/.zshrc"));
        assert_eq!(without_safe_sources("source ~/.zshrc; cat x"), " ; cat x");
    }

    #[test]
    fn percent_escapes_and_find() {
        assert!(mentions_startup_file("cat ~/.zsh%72c"));
        assert!(pipeline_context("find ~ -name '.z*' -exec cat {} \\;"));
    }
}
