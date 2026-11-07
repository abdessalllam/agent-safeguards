use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use guard_common::env;
use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::{consts, keys, output};

const MIN_CHARS: usize = 6;
const MAX_CHARS: usize = 1024;
const MIN_ENCODED: usize = 7;
const MAX_VALUES: usize = 500;
const MAX_FOLDER_FILES: usize = 40;
const SECRET_WORDS: [&str; 6] = ["key", "token", "secret", "pass", "credential", "auth"];
const FOLDERS: [(&str, &[&str]); 4] = [
    (".zsh", &["zsh", "sh"]),
    (".oh-my-zsh/custom", &["zsh", "sh"]),
    (".config/fish", &["fish"]),
    (".config/fish/conf.d", &["fish"]),
];
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

enum Matcher {
    Nothing,
    Ready(Regex),
    Broken,
}

fn startup_paths(home: &str) -> Vec<String> {
    let mut paths: Vec<String> = consts::STARTUP_KEY_FILES
        .iter()
        .map(|name| format!("{home}/{name}"))
        .collect();
    for (folder, extensions) in FOLDERS {
        let Ok(entries) = std::fs::read_dir(format!("{home}/{folder}")) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| {
                name.rsplit_once('.')
                    .is_some_and(|(_, extension)| extensions.contains(&extension))
            })
            .collect();
        names.sort();
        names.truncate(MAX_FOLDER_FILES);
        paths.extend(names.into_iter().map(|name| format!("{home}/{folder}/{name}")));
    }
    paths
}

fn names_existing_path(value: &str, home: &str) -> bool {
    let expanded = value
        .strip_prefix("~/")
        .map_or_else(|| value.to_owned(), |rest| format!("{home}/{rest}"));
    (value.starts_with('/') || value.starts_with("~/")) && Path::new(&expanded).exists()
}

fn numeric(value: &str) -> bool {
    value.chars().count() < 12
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | ':' | '-' | '+' | ','))
}

fn protectable(value: &str, home: &str) -> bool {
    let chars = value.chars().count();
    (MIN_CHARS..=MAX_CHARS).contains(&chars)
        && !value.contains(['\0', '\n', '\r'])
        && !numeric(value)
        && !names_existing_path(value, home)
}

// Alias bodies of plain words stay visible; only shaped ones are protected.
fn shaped(text: &str) -> bool {
    text.chars()
        .any(|ch| ch.is_ascii_digit() || ch.is_ascii_uppercase() || matches!(ch, '@' | ':' | '='))
        || text.split_whitespace().any(|word| word.chars().count() >= 20)
}

fn candidates(is_alias: bool, value: &str) -> Vec<String> {
    if !is_alias {
        return vec![value.to_owned()];
    }
    let mut out = Vec::new();
    if shaped(value) {
        out.push(value.to_owned());
    }
    out.extend(value.split_whitespace().filter(|word| shaped(word)).map(str::to_owned));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn base64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let at = |index: usize| u32::from(chunk.get(index).copied().unwrap_or(0));
        let group = (at(0) << 16) | (at(1) << 8) | at(2);
        for index in 0..chunk.len().saturating_add(1) {
            let shift = 18u32.saturating_sub(6u32.saturating_mul(u32::try_from(index).unwrap_or(0)));
            let place = usize::try_from((group >> shift) & 63).unwrap_or(0);
            out.push(char::from(STANDARD.get(place).copied().unwrap_or(b'A')));
        }
    }
    out
}

// Keeps only characters independent of neighbouring bytes, at all three alignments.
fn base64_forms(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for offset in 0..3usize {
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(bytes);
        let encoded = base64(&padded);
        let total = padded.len();
        let skip = [0usize, 2, 3].get(offset).copied().unwrap_or(0);
        let tail = [0usize, 1, 2].get(total % 3).copied().unwrap_or(0);
        let stable = (total / 3).saturating_mul(4).saturating_add(tail).min(encoded.len());
        if let Some(part) = encoded.get(skip..stable) {
            if part.len() >= MIN_ENCODED {
                out.push(part.to_owned());
                out.push(part.replace('+', "-").replace('/', "_"));
            }
        }
    }
    out
}

fn percent(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(*byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

pub fn forms(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let mut out = vec![
        value.to_owned(),
        value.chars().rev().collect(),
        value.to_lowercase(),
        value.to_uppercase(),
        hex(bytes),
        hex(bytes).to_uppercase(),
    ];
    out.extend(base64_forms(bytes));
    let encoded = percent(bytes);
    if encoded != value {
        out.push(encoded.to_lowercase());
        out.push(encoded);
    }
    if let Ok(quoted) = serde_json::to_string(value) {
        if let Some(inner) = quoted.get(1..quoted.len().saturating_sub(1)) {
            if inner != value {
                out.push(inner.to_owned());
            }
        }
    }
    out.retain(|form| form.chars().count() >= MIN_CHARS);
    out
}

fn build(values: Vec<(bool, String)>, process: Vec<String>, home: &str) -> Matcher {
    let mut seen: HashSet<String> = HashSet::new();
    let mut chosen: Vec<String> = Vec::new();
    let from_files = values
        .into_iter()
        .flat_map(|(is_alias, value)| candidates(is_alias, &value));
    for value in from_files.chain(process) {
        if chosen.len() >= MAX_VALUES {
            break;
        }
        if protectable(&value, home) && seen.insert(value.clone()) {
            chosen.push(value);
        }
    }
    let mut forms_seen: HashSet<String> = HashSet::new();
    let mut alternatives: Vec<String> = Vec::new();
    for value in &chosen {
        for form in forms(value) {
            if forms_seen.insert(form.clone()) {
                alternatives.push(regex::escape(&form));
            }
        }
    }
    if alternatives.is_empty() {
        return Matcher::Nothing;
    }
    match RegexBuilder::new(&alternatives.join("|"))
        .size_limit(256 * 1024 * 1024)
        .build()
    {
        Ok(matcher) => Matcher::Ready(matcher),
        Err(_) => Matcher::Broken,
    }
}

fn from_files(home: &str) -> Vec<(bool, String)> {
    let mut found = Vec::new();
    for path in startup_paths(home) {
        let mut lines = Vec::new();
        let _ = keys::each_logical_line(&path, |line| keys::line_values(line, &mut lines));
        found.extend(lines);
    }
    found
}

fn from_process() -> Vec<String> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.to_str()?.to_lowercase(), value.to_str()?.to_owned())))
        .filter(|(name, _)| SECRET_WORDS.iter().any(|word| name.contains(word)))
        .map(|(_, value)| value)
        .collect()
}

fn matcher() -> &'static Matcher {
    static MATCHER: OnceLock<Matcher> = OnceLock::new();
    MATCHER.get_or_init(|| {
        let home = env::user_home();
        build(from_files(home), from_process(), home)
    })
}

// A matcher that failed to build withholds everything rather than failing open.
pub fn leaks(text: &str) -> bool {
    match matcher() {
        Matcher::Nothing => false,
        Matcher::Ready(found) => found.is_match(text),
        Matcher::Broken => true,
    }
}

pub fn response_leaks(response: &Value) -> Result<bool, output::ResponseTooComplex> {
    Ok(leaks(&output::response_text(response, 0)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher_for(values: &[(bool, &str)], process: &[&str]) -> Regex {
        let values = values.iter().map(|(alias, value)| (*alias, (*value).to_owned())).collect();
        let process = process.iter().map(|value| (*value).to_owned()).collect();
        match build(values, process, "/nonexistent-home") {
            Matcher::Ready(found) => found,
            _ => panic!("expected a matcher"),
        }
    }

    #[test]
    fn the_raw_value_and_simple_rewrites_are_found() {
        let found = matcher_for(&[(false, "value1"), (false, "Hunter2-pass")], &[]);
        assert!(found.is_match("the key is value1."));
        assert!(found.is_match("1eulav"));
        assert!(found.is_match("VALUE1"));
        assert!(found.is_match("76616c756531"));
        assert!(found.is_match("dmFsdWUx"));
        assert!(found.is_match("Hunter2%2Dpass") || found.is_match("Hunter2-pass"));
        assert!(!found.is_match("nothing to see here"));
    }

    #[test]
    fn base64_is_found_at_every_alignment_inside_larger_data() {
        let found = matcher_for(&[(false, "s3cr3t-token-value")], &[]);
        for prefix in ["", "a", "ab", "abc"] {
            let data = format!("{prefix}s3cr3t-token-value::tail");
            assert!(found.is_match(&base64(data.as_bytes())), "prefix {prefix:?}");
        }
    }

    #[test]
    fn short_numeric_and_path_values_are_not_protected() {
        let found = matcher_for(&[(false, "vim"), (false, "100000"), (false, "/tmp"), (false, "plenty-long-secret")], &[]);
        assert!(!found.is_match("vim and 100000 and /tmp"));
        assert!(found.is_match("plenty-long-secret"));
    }

    #[test]
    fn plain_alias_bodies_stay_visible_but_shaped_ones_are_protected() {
        let found = matcher_for(&[(true, "git status"), (true, "value3"), (true, "ssh -i key.pem user@host")], &[]);
        assert!(!found.is_match("use git status to see"));
        assert!(found.is_match("value3"));
        assert!(found.is_match("user@host"));
    }

    #[test]
    fn process_values_are_protected_too() {
        let found = matcher_for(&[], &["from-the-process-env"]);
        assert!(found.is_match("x from-the-process-env y"));
    }

    #[test]
    fn nothing_to_protect_builds_no_matcher() {
        assert!(matches!(build(Vec::new(), Vec::new(), "/nonexistent-home"), Matcher::Nothing));
        assert!(matches!(build(vec![(false, "abc".to_owned())], Vec::new(), "/nonexistent-home"), Matcher::Nothing));
    }
}
