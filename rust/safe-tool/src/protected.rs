use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use guard_common::env;
use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::{consts, keys, output};

const MIN_CHARS: usize = 6;
const MAX_VALUE_CHARS: usize = 4096;
const MAX_TOTAL_CHARS: usize = 65536;
const MIN_ENCODED: usize = 7;
const MAX_FOLDER_FILES: usize = 200;
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
    Incomplete,
}

enum Verdict {
    Skip,
    Keep,
    TooLong,
}

pub struct Collected {
    pub values: Vec<(bool, String)>,
    pub complete: bool,
}

fn startup_paths(home: &str) -> (Vec<String>, bool) {
    let mut complete = true;
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
        if names.len() > MAX_FOLDER_FILES {
            complete = false;
            names.truncate(MAX_FOLDER_FILES);
        }
        paths.extend(names.into_iter().map(|name| format!("{home}/{folder}/{name}")));
    }
    (paths, complete)
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

fn verdict(value: &str, home: &str) -> Verdict {
    let chars = value.chars().count();
    if chars < MIN_CHARS
        || value.contains(['\0', '\n', '\r'])
        || numeric(value)
        || names_existing_path(value, home)
    {
        return Verdict::Skip;
    }
    if chars > MAX_VALUE_CHARS {
        return Verdict::TooLong;
    }
    Verdict::Keep
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

fn percent(bytes: &[u8], lower_hex: bool) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(*byte).to_string()
            } else if lower_hex {
                format!("%{byte:02x}")
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

// Python's default JSON text writes every non-ASCII character as \uXXXX.
fn json_ascii(value: &str, upper_hex: bool) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_ascii() && ch >= ' ' => out.push(ch),
            ch => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    if upper_hex {
                        out.push_str(&format!("\\u{unit:04X}"));
                    } else {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
        }
    }
    out
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
    let encoded = percent(bytes, false);
    if encoded != value {
        out.push(percent(bytes, true));
        out.push(encoded.to_lowercase());
        out.push(encoded);
    }
    if !value.is_ascii() || value.contains(['"', '\\']) {
        out.push(json_ascii(value, false));
        out.push(json_ascii(value, true));
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

fn build(collected: Collected, process: Vec<String>, home: &str) -> Matcher {
    if !collected.complete {
        return Matcher::Incomplete;
    }
    let from_files = collected
        .values
        .into_iter()
        .flat_map(|(is_alias, value)| candidates(is_alias, &value));
    let mut seen: HashSet<String> = HashSet::new();
    let mut chosen: Vec<String> = Vec::new();
    let mut total = 0usize;
    for value in from_files.chain(process) {
        match verdict(&value, home) {
            Verdict::Skip => {}
            Verdict::TooLong => return Matcher::Incomplete,
            Verdict::Keep => {
                if seen.insert(value.clone()) {
                    total = total.saturating_add(value.chars().count());
                    if total > MAX_TOTAL_CHARS {
                        return Matcher::Incomplete;
                    }
                    chosen.push(value);
                }
            }
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
        Err(_) => Matcher::Incomplete,
    }
}

fn from_files(home: &str) -> Collected {
    let (paths, mut complete) = startup_paths(home);
    let mut values = Vec::new();
    for path in paths {
        let mut scanner = keys::ValueScanner::default();
        let read = keys::each_logical_line(&path, |line| scanner.scan(line, &mut values));
        scanner.finish(&mut values);
        if matches!(read, Ok(keys::LineRead::Truncated)) {
            complete = false;
        }
    }
    Collected { values, complete }
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

// An incomplete matcher withholds all output instead of part of it.
pub fn leak_reason(text: &str) -> Option<&'static str> {
    match matcher() {
        Matcher::Nothing => None,
        Matcher::Ready(found) => found.is_match(text).then_some("secret"),
        Matcher::Incomplete => Some("coverage"),
    }
}

fn string_leaves(value: &Value, depth: usize, out: &mut String) -> Result<(), output::ResponseTooComplex> {
    if depth > output::MAX_RESPONSE_DEPTH {
        return Err(output::ResponseTooComplex);
    }
    match value {
        Value::String(text) => {
            out.push_str(text);
            out.push('\n');
        }
        Value::Array(items) => {
            for child in items {
                string_leaves(child, depth.saturating_add(1), out)?;
            }
        }
        Value::Object(fields) => {
            for child in fields.values() {
                string_leaves(child, depth.saturating_add(1), out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// Field names like stderr belong to the tool, so only string content is read.
pub fn response_leak_reason(response: &Value) -> Result<Option<&'static str>, output::ResponseTooComplex> {
    let mut text = String::new();
    string_leaves(response, 0, &mut text)?;
    Ok(leak_reason(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collected(values: &[(bool, &str)]) -> Collected {
        Collected {
            values: values.iter().map(|(alias, value)| (*alias, (*value).to_owned())).collect(),
            complete: true,
        }
    }

    fn matcher_for(values: &[(bool, &str)], process: &[&str]) -> Regex {
        let process = process.iter().map(|value| (*value).to_owned()).collect();
        match build(collected(values), process, "/nonexistent-home") {
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
    fn percent_escapes_match_in_either_hex_case_with_the_literals_unchanged() {
        let found = matcher_for(&[(false, "Garden/piano")], &[]);
        assert!(found.is_match("Garden%2Fpiano"));
        assert!(found.is_match("Garden%2fpiano"));
    }

    #[test]
    fn json_text_with_unicode_escapes_is_found() {
        let found = matcher_for(&[(false, "caf\u{e9}fixture")], &[]);
        assert!(found.is_match("caf\u{e9}fixture"));
        assert!(found.is_match("\"caf\\u00e9fixture\""));
        assert!(found.is_match("\"caf\\u00E9fixture\""));
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
        assert!(matches!(build(collected(&[]), Vec::new(), "/nonexistent-home"), Matcher::Nothing));
        assert!(matches!(build(collected(&[(false, "abc")]), Vec::new(), "/nonexistent-home"), Matcher::Nothing));
    }

    #[test]
    fn many_small_values_are_all_covered() {
        let owned: Vec<String> = (0..600).map(|n| format!("fixtureitem{n:04}")).collect();
        let values: Vec<(bool, &str)> = owned.iter().map(|value| (false, value.as_str())).collect();
        let found = matcher_for(&values, &[]);
        assert!(found.is_match("fixtureitem0000"));
        assert!(found.is_match("fixtureitem0599"));
    }

    #[test]
    fn coverage_that_cannot_be_complete_withholds_everything() {
        let long = "x".repeat(MAX_VALUE_CHARS + 1);
        assert!(matches!(build(collected(&[(false, long.as_str())]), Vec::new(), "/nonexistent-home"), Matcher::Incomplete));
        let owned: Vec<String> = (0..200).map(|n| format!("{n:04}-{}", "y".repeat(400))).collect();
        let values: Vec<(bool, &str)> = owned.iter().map(|value| (false, value.as_str())).collect();
        assert!(matches!(build(collected(&values), Vec::new(), "/nonexistent-home"), Matcher::Incomplete));
        let partial = Collected { values: Vec::new(), complete: false };
        assert!(matches!(build(partial, Vec::new(), "/nonexistent-home"), Matcher::Incomplete));
    }
}
