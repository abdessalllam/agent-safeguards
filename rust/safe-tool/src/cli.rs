use std::io::{Read, Write};

use guard_common::locale::message;
use guard_common::sys::EmbeddedNul;

use crate::{commit, consts, git, hooks, keys, redact, remote, selftest};

fn usage() -> String {
    format!("{}\n", message("safe_tool.cli.usage", &[]))
}

pub fn has_key_result(arguments: &[String]) -> Result<(i32, String, String), EmbeddedNul> {
    let mut names = Vec::new();
    let mut requested = None;
    let mut index = 0usize;
    while let Some(argument) = arguments.get(index) {
        if argument == "--file" && requested.is_none() && index.saturating_add(1) < arguments.len()
        {
            requested = arguments.get(index.saturating_add(1)).map(String::as_str);
            index = index.saturating_add(2);
        } else if consts::KEY_NAME_PATTERN_FULL.is_match(argument) {
            names.push(argument.as_str());
            index = index.saturating_add(1);
        } else {
            names.clear();
            break;
        }
    }
    let path = keys::startup_key_file(requested)?;
    if names.is_empty() || names.len() > consts::MAX_KEY_NAMES || path.is_none() {
        return Ok((2, String::new(), usage()));
    }
    let Some(path) = path else {
        return Ok((2, String::new(), usage()));
    };
    let (found, complete) = keys::keys_set_in(&path)?;
    let mut stdout = String::new();
    for name in names {
        let status = if found.contains(name) {
            "pass"
        } else if complete {
            "fail"
        } else {
            "unknown"
        };
        stdout.push_str(&format!("{name}={status}\n"));
    }
    Ok((0, stdout, String::new()))
}

pub fn has_key(arguments: &[String]) -> Result<i32, EmbeddedNul> {
    let (code, stdout, stderr) = has_key_result(arguments)?;
    let written = guard_common::emit::write_stdout(stdout.as_bytes());
    let _ = std::io::stderr().write_all(stderr.as_bytes());
    Ok(if written == 0 { code } else { written })
}

fn normalize_nonfinite(raw: &[u8]) -> Option<Vec<u8>> {
    let mut normalized = Vec::with_capacity(raw.len());
    let mut index = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut changed = false;
    while let Some(&byte) = raw.get(index) {
        if quoted {
            normalized.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            index = index.saturating_add(1);
            continue;
        }
        if byte == b'"' {
            quoted = true;
        } else if let Some(width) = [b"-Infinity".as_slice(), b"Infinity", b"NaN"]
            .iter()
            .find_map(|word| {
                raw.get(index..)
                    .is_some_and(|tail| tail.starts_with(word))
                    .then_some(word.len())
            })
        {
            normalized.extend_from_slice(b"null");
            index = index.saturating_add(width);
            changed = true;
            continue;
        }
        normalized.push(byte);
        index = index.saturating_add(1);
    }
    changed.then_some(normalized)
}

fn hook(runtime: &str, expected_event: Option<&str>) -> i32 {
    hooks::END_AT_TIMEOUT.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut raw = Vec::new();
    let mut input = std::io::stdin().take(hooks::CONTENT_INPUT_BYTES.saturating_add(1) as u64);
    if input.read_to_end(&mut raw).is_err() {
        hooks::fail_closed_unreadable(runtime, &raw, expected_event);
        return 0;
    }
    if raw.len() <= hooks::CONTENT_INPUT_BYTES {
        if let Some(normalized) = normalize_nonfinite(&raw) {
            return hooks::run_hook_bytes(runtime, expected_event, &normalized);
        }
    }
    hooks::run_hook_bytes(runtime, expected_event, &raw)
}

pub fn main_args(arguments: &[String]) -> i32 {
    let first = arguments.first().map(String::as_str);
    let second = arguments.get(1).map(String::as_str);
    let third = arguments.get(2).map(String::as_str);
    if arguments.len() == 1 && matches!(first, Some("-h" | "--help")) {
        return guard_common::emit::write_stdout(usage().as_bytes());
    }
    if first == Some("hook")
        && (2..=3).contains(&arguments.len())
        && matches!(second, Some("claude" | "codex"))
    {
        if arguments.len() == 2 {
            return hook(second.unwrap_or(""), None);
        }
        if third.is_some_and(|event| consts::HOOK_EVENTS.contains(&event)) {
            return hook(second.unwrap_or(""), third);
        }
    }
    if arguments.len() == 1 && first == Some("self-test") {
        return selftest::self_test();
    }
    if arguments.len() == 2 && first == Some("status") && second == Some("coderabbit") {
        return git::coderabbit_status();
    }
    if arguments.len() == 2 && first == Some("status") && second == Some("rtk") {
        return git::rtk_status();
    }
    if first == Some("has-key") {
        return has_key(arguments.get(1..).unwrap_or(&[])).unwrap_or(1);
    }
    if arguments.len() == 2 && first == Some("remote-readonly") {
        return remote::remote_readonly(second.unwrap_or("")).unwrap_or(1);
    }
    if arguments.len() == 1 && first == Some("redact") {
        return redact::redact();
    }
    if arguments.len() == 2 && first == Some("git") && second == Some("identity") {
        return git::git_identity();
    }
    if first == Some("git") && second == Some("commit") {
        if let Some(messages) = commit::commit_messages(arguments.get(2..).unwrap_or(&[])) {
            return commit::git_commit(&messages);
        }
    }
    let _ = std::io::stderr().write_all(usage().as_bytes());
    2
}

pub fn main() -> i32 {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    main_args(&arguments)
}

#[cfg(test)]
mod tests {
    use super::{has_key_result, normalize_nonfinite};

    #[test]
    fn nonfinite_json_only_outside_quotes() {
        assert_eq!(
            normalize_nonfinite(br#"{"value":NaN,"text":"NaN"}"#),
            Some(br#"{"value":null,"text":"NaN"}"#.to_vec())
        );
    }

    #[test]
    fn invalid_names_get_usage() {
        let arguments = vec!["not-valid".to_owned()];
        assert_eq!(has_key_result(&arguments).map(|item| item.0), Ok(2));
    }
}
