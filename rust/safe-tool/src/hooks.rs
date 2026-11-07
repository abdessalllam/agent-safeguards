use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;

use guard_common::{env, locale, pyglob, secret_scan};
use regex::bytes::Regex;
use serde_json::{Map, Value};

use crate::{command, consts, local_only, output, protected};

pub const READ_DEFAULT_LINES: usize = 2_000;
pub const READ_LINE_CHARACTERS: usize = 2_000;
pub const READ_MAX_LINES: usize = 200_000;
pub const CONTENT_INPUT_BYTES: usize = 16 * 1_024 * 1_024;
const READ_SKIPPED_SUFFIXES: &[&str] = &[".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf"];
const CONTENT_TOOLS: &[&str] = &[
    "Read",
    "Edit",
    "Write",
    "MultiEdit",
    "NotebookEdit",
    "Grep",
    "apply_patch",
];

static TOOL_NAME_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""tool_name"\s*:\s*"([^"]{1,64})""#)
        .unwrap_or_else(|error| panic!("invalid tool name pattern: {error}"))
});

#[derive(Debug)]
pub enum HookError {
    Internal,
    TooSlow,
}

fn py_space(character: char) -> bool {
    character.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&character)
}

const DECIMAL_STARTS: &[u32] = &[
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
    0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
    0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10,
    0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
    0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x16a60, 0x16ac0, 0x16b50,
    0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e950, 0x1fbf0,
];

const DIGIT_EXTRAS: &[u32] = &[
    0xb2, 0xb3, 0xb9, 0x1369, 0x136a, 0x136b, 0x136c, 0x136d, 0x136e, 0x136f, 0x1370, 0x1371,
    0x19da, 0x2070, 0x2074, 0x2075, 0x2076, 0x2077, 0x2078, 0x2079, 0x2080, 0x2081, 0x2082, 0x2083,
    0x2084, 0x2085, 0x2086, 0x2087, 0x2088, 0x2089, 0x2460, 0x2461, 0x2462, 0x2463, 0x2464, 0x2465,
    0x2466, 0x2467, 0x2468, 0x2474, 0x2475, 0x2476, 0x2477, 0x2478, 0x2479, 0x247a, 0x247b, 0x247c,
    0x2488, 0x2489, 0x248a, 0x248b, 0x248c, 0x248d, 0x248e, 0x248f, 0x2490, 0x24ea, 0x24f5, 0x24f6,
    0x24f7, 0x24f8, 0x24f9, 0x24fa, 0x24fb, 0x24fc, 0x24fd, 0x24ff, 0x2776, 0x2777, 0x2778, 0x2779,
    0x277a, 0x277b, 0x277c, 0x277d, 0x277e, 0x2780, 0x2781, 0x2782, 0x2783, 0x2784, 0x2785, 0x2786,
    0x2787, 0x2788, 0x278a, 0x278b, 0x278c, 0x278d, 0x278e, 0x278f, 0x2790, 0x2791, 0x2792,
    0x10a40, 0x10a41, 0x10a42, 0x10a43, 0x10e60, 0x10e61, 0x10e62, 0x10e63, 0x10e64, 0x10e65,
    0x10e66, 0x10e67, 0x10e68, 0x11052, 0x11053, 0x11054, 0x11055, 0x11056, 0x11057, 0x11058,
    0x11059, 0x1105a, 0x1f100, 0x1f101, 0x1f102, 0x1f103, 0x1f104, 0x1f105, 0x1f106, 0x1f107,
    0x1f108, 0x1f109, 0x1f10a,
];

fn decimal_digit(character: char) -> Option<u32> {
    let point = u32::from(character);
    DECIMAL_STARTS.iter().find_map(|start| {
        if point >= *start && point < start.saturating_add(10) {
            Some(point - start)
        } else {
            None
        }
    })
}

pub fn command_of(payload: &Value) -> Option<&str> {
    payload
        .get("tool_input")?
        .as_object()?
        .get("command")?
        .as_str()
}

pub fn content_tool_name(name: &Value) -> bool {
    name.as_str()
        .is_some_and(|name| CONTENT_TOOLS.contains(&name) || name.starts_with("mcp__"))
}

pub fn content_tool(payload: &Value) -> bool {
    payload.get("tool_name").is_some_and(content_tool_name)
}

pub fn redact_keys(
    value: &Value,
    depth: usize,
) -> Result<(Value, bool), output::ResponseTooComplex> {
    if depth > output::MAX_RESPONSE_DEPTH {
        return Err(output::ResponseTooComplex);
    }
    let placeholder = locale::message("safe_tool.withheld.placeholder", &[]);
    match value {
        Value::String(text) => Ok(if secret_scan::contains_key(text) {
            (Value::String(placeholder), true)
        } else {
            (value.clone(), false)
        }),
        Value::Object(fields) => {
            let mut copy = Map::new();
            let mut found = false;
            for (position, (key, child)) in fields.iter().enumerate() {
                let name = if secret_scan::contains_key(key) {
                    found = true;
                    format!("field{position}")
                } else {
                    key.clone()
                };
                if let Value::String(text) = child {
                    let label: String = key.chars().take(256).collect();
                    let short: String = text.chars().take(output::MAX_LABEL_VALUE).collect();
                    if !secret_scan::contains_key(text)
                        && secret_scan::contains_key(&format!("{label}={short}"))
                    {
                        copy.insert(name, Value::String(placeholder.clone()));
                        found = true;
                        continue;
                    }
                }
                let (replacement, changed) = redact_keys(child, depth.saturating_add(1))?;
                copy.insert(name, replacement);
                found |= changed;
            }
            Ok((Value::Object(copy), found))
        }
        Value::Array(items) => {
            let mut copy = Vec::with_capacity(items.len());
            let mut found = false;
            for child in items {
                let (replacement, changed) = redact_keys(child, depth.saturating_add(1))?;
                copy.push(replacement);
                found |= changed;
            }
            Ok((Value::Array(copy), found))
        }
        _ => Ok((value.clone(), false)),
    }
}

pub fn line_number(value: &Value, default: usize) -> Result<Option<usize>, HookError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(Some(default)),
        Value::Number(number) => match guard_common::pyjson::integer_text(number) {
            Some(text) if text.starts_with('-') || text == "0" => Ok(Some(default)),
            Some(text) => Ok(Some(text.parse::<usize>().unwrap_or(usize::MAX))),
            None => Ok(None),
        },
        Value::String(text) => {
            let trimmed = text.trim_matches(py_space);
            if trimmed.is_empty()
                || !trimmed.chars().all(|character| {
                    decimal_digit(character).is_some()
                        || DIGIT_EXTRAS.contains(&u32::from(character))
                })
            {
                return Ok(None);
            }
            if trimmed.chars().count() > 4_300
                || text.chars().any(|character| ('\u{1c}'..='\u{1f}').contains(&character))
            {
                return Err(HookError::Internal);
            }
            let mut value = 0usize;
            for character in trimmed.chars() {
                let Some(digit) = decimal_digit(character) else {
                    return Err(HookError::Internal);
                };
                value = value.saturating_mul(10).saturating_add(digit as usize);
            }
            Ok(Some(if value > 0 { value } else { default }))
        }
        _ => Ok(None),
    }
}

pub fn read_lines(tool_input: &Value, cwd: &Value) -> Result<Option<String>, HookError> {
    let Some(path) = tool_input.get("file_path").and_then(Value::as_str) else {
        return Ok(None);
    };
    if READ_SKIPPED_SUFFIXES
        .iter()
        .any(|suffix| path.to_lowercase().ends_with(suffix))
    {
        return Ok(None);
    }
    let expanded = pyglob::expanduser(path).map_err(|_| HookError::Internal)?;
    let path = if !Path::new(&expanded).is_absolute() {
        if let Some(cwd) = cwd.as_str() {
            Path::new(cwd).join(expanded)
        } else {
            PathBuf::from(expanded)
        }
    } else {
        PathBuf::from(expanded)
    };
    if path.as_os_str().to_string_lossy().contains('\0') {
        return Err(HookError::Internal);
    }
    let first = line_number(tool_input.get("offset").unwrap_or(&Value::Null), 1)?;
    let count = line_number(
        tool_input.get("limit").unwrap_or(&Value::Null),
        READ_DEFAULT_LINES,
    )?;
    let (start, stop) = match (first, count) {
        (Some(first), Some(count)) => (
            first.saturating_sub(1),
            first
                .saturating_add(count)
                .saturating_add(1)
                .min(READ_MAX_LINES),
        ),
        _ => (0, READ_MAX_LINES),
    };
    let handle = match File::open(path) {
        Ok(handle) => handle,
        Err(_) => return Ok(None),
    };
    let mut reader = BufReader::new(handle);
    let mut lines = Vec::new();
    let mut bytes = Vec::new();
    for number in 1usize..=stop {
        command::check_budget().map_err(|_| HookError::TooSlow)?;
        bytes.clear();
        let read = match reader.read_until(b'\n', &mut bytes) {
            Ok(read) => read,
            Err(_) => return Ok(None),
        };
        if read == 0 {
            break;
        }
        if number >= start {
            if bytes.contains(&0) {
                return Ok(None);
            }
            let decoded = String::from_utf8_lossy(&bytes);
            let trimmed = decoded.trim_end_matches(['\r', '\n']);
            lines.push(
                trimmed
                    .chars()
                    .take(READ_LINE_CHARACTERS)
                    .collect::<String>(),
            );
        }
    }
    Ok(Some(lines.join("\n")))
}

pub fn handle_content_tool(runtime: &str, event: &str, payload: &Value) -> Result<(), HookError> {
    if event == "PreToolUse" {
        if payload.get("tool_name").and_then(Value::as_str) == Some("Read") {
            if let Some(tool_input) = payload.get("tool_input").filter(|value| value.is_object()) {
                let lines = read_lines(tool_input, payload.get("cwd").unwrap_or(&Value::Null))?;
                if lines.is_some_and(|lines| secret_scan::contains_key(&lines)) {
                    command::deny_hook("safe_tool.deny.key_file");
                }
            }
        }
        return Ok(());
    }
    let response = payload.get("tool_response").unwrap_or(&Value::Null);
    let values = output::response_values(response, 0).map_err(|_| HookError::Internal)?;
    let labels = output::response_labels(response, 0).map_err(|_| HookError::Internal)?;
    if protected::leaks(&values) || protected::leaks(&labels) {
        output::withhold_post_hook(runtime, response, Some("secret"), None).map_err(|_| HookError::Internal)?;
        return Ok(());
    }
    if secret_scan::contains_key(&values) || secret_scan::contains_key(&labels) {
        let replacement = if runtime == "claude" {
            let (replacement, found) = redact_keys(response, 0).map_err(|_| HookError::Internal)?;
            found.then_some(replacement)
        } else {
            None
        };
        output::withhold_post_hook(runtime, response, Some("secret"), replacement.as_ref())
            .map_err(|_| HookError::Internal)?;
    }
    Ok(())
}

pub fn handle_event(runtime: &str, event: &str, payload: &Value) -> Result<(), HookError> {
    if event == "SessionStart" {
        if runtime == "claude" && env::env_flag("AGENT_SAFEGUARDS_AUTO_EXCLUDE") {
            if let Some(cwd) = payload.get("cwd").and_then(Value::as_str) {
                local_only::ensure_local_excludes(cwd).map_err(|_| HookError::Internal)?;
            }
        }
        return Ok(());
    }
    if event != "PreToolUse" && event != "PostToolUse" {
        return Ok(());
    }
    let command = command_of(payload);
    if command.is_none() && content_tool(payload) {
        return handle_content_tool(runtime, event, payload);
    }
    let Some(text) = command else {
        if event == "PostToolUse" {
            output::withhold_post_hook(
                runtime,
                payload.get("tool_response").unwrap_or(&Value::Null),
                None,
                None,
            )
            .map_err(|_| HookError::Internal)?;
        } else {
            command::deny_hook("safe_tool.deny.sensitive");
        }
        return Ok(());
    };
    if event == "PreToolUse" {
        if command::sensitive_command(text, true).map_err(|_| HookError::Internal)? {
            let reason = if command::blocked_only_by_proxy(text).map_err(|_| HookError::Internal)? {
                "safe_tool.deny.proxy"
            } else if command::blocked_only_by_startup_file(text)
                .map_err(|_| HookError::Internal)?
            {
                "safe_tool.deny.startup_file"
            } else if command::blocked_by_git_format(text).map_err(|_| HookError::Internal)? {
                "safe_tool.deny.git_format"
            } else {
                "safe_tool.deny.sensitive"
            };
            command::deny_hook(reason);
        } else if command::require_rtk() && command::rtk_required(text) {
            command::deny_hook("safe_tool.deny.rtk");
        } else if runtime == "claude"
            && local_only::requires_local_artifact_approval(
                text,
                payload.get("cwd").and_then(Value::as_str),
            )
            .map_err(|_| HookError::Internal)?
        {
            command::ask_local_artifact_hook();
        }
    } else {
        let response = payload.get("tool_response").unwrap_or(&Value::Null);
        let mut reason = output::withheld_because(text, response).map_err(|_| HookError::Internal)?;
        if reason.is_none() && protected::response_leaks(response).map_err(|_| HookError::Internal)? {
            reason = Some("secret".to_owned());
        }
        if let Some(reason) = reason {
            output::withhold_post_hook(runtime, response, Some(&reason), None)
                .map_err(|_| HookError::Internal)?;
        }
    }
    Ok(())
}

pub fn fail_closed_unreadable(runtime: &str, raw_input: &[u8], expected_event: Option<&str>) {
    let event = expected_event.map(str::to_owned).unwrap_or_else(|| {
        consts::EVENT_PATTERN
            .captures(
                raw_input
                    .get(..raw_input.len().min(consts::EVENT_SEARCH_BYTES))
                    .unwrap_or(raw_input),
            )
            .and_then(|found| found.get(1))
            .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
            .unwrap_or("PreToolUse")
            .to_owned()
    });
    if event == "PostToolUse" {
        let _ = output::withhold_post_hook(runtime, &Value::Null, None, None);
    } else if event == "PreToolUse" {
        command::deny_hook("safe_tool.deny.sensitive");
    }
}

pub fn run_hook_bytes(runtime: &str, expected_event: Option<&str>, raw_input: &[u8]) -> i32 {
    command::set_decision_made(false);
    let parsed: Option<Value> = (|| {
        if raw_input.len() > CONTENT_INPUT_BYTES {
            return None;
        }
        if raw_input.len() > consts::MAX_OUTPUT_BYTES {
            let named = TOOL_NAME_PATTERN
                .captures(raw_input.get(..raw_input.len().min(consts::EVENT_SEARCH_BYTES))?)
                .and_then(|found| found.get(1))?;
            let decoded = String::from_utf8_lossy(named.as_bytes());
            if !content_tool_name(&Value::String(decoded.into_owned())) {
                return None;
            }
        }
        guard_common::pyjson::loads(raw_input).filter(Value::is_object)
    })();
    let Some(payload) = parsed else {
        fail_closed_unreadable(runtime, raw_input, expected_event);
        return 0;
    };
    let event = expected_event
        .filter(|event| !event.is_empty())
        .or_else(|| payload.get("hook_event_name").and_then(Value::as_str))
        .unwrap_or("PreToolUse");
    let mut error = None;
    let on_timeout_runtime = runtime.to_owned();
    let on_timeout_event = event.to_owned();
    let on_timeout_payload = payload.clone();
    let timeout_decided = Arc::new(AtomicBool::new(false));
    let timeout_decided_for_callback = Arc::clone(&timeout_decided);
    let outcome = command::run_with_budget(
        consts::hook_budget_seconds(),
        || {
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_event(runtime, event, &payload)
            }));
            error = match checked {
                Ok(result) => result.err(),
                Err(_) => Some(HookError::Internal),
            };
        },
        move || {
            if !env::fail_open() {
                timeout_decided_for_callback.store(true, Ordering::SeqCst);
                refuse_unchecked(
                    &on_timeout_runtime,
                    &on_timeout_event,
                    &on_timeout_payload,
                    "safe_tool.deny.too_slow",
                );
            }
            if END_AT_TIMEOUT.load(Ordering::SeqCst) {
                std::process::exit(0);
            }
        },
    );
    if !env::fail_open() {
        if outcome.is_err() || matches!(error, Some(HookError::Internal)) {
            refuse_unchecked(runtime, event, &payload, "safe_tool.deny.internal");
        } else if matches!(error, Some(HookError::TooSlow))
            && !timeout_decided.load(Ordering::SeqCst)
        {
            refuse_unchecked(runtime, event, &payload, "safe_tool.deny.too_slow");
        }
    }
    0
}

// Only the command line sets this: a check blocked in file I/O cannot be interrupted.
pub static END_AT_TIMEOUT: AtomicBool = AtomicBool::new(false);

pub fn run_hook(runtime: &str, expected_event: Option<&str>) -> i32 {
    let mut raw_input = Vec::new();
    let mut input = std::io::stdin().take(CONTENT_INPUT_BYTES.saturating_add(1) as u64);
    if input.read_to_end(&mut raw_input).is_err() {
        fail_closed_unreadable(runtime, &raw_input, expected_event);
        return 0;
    }
    run_hook_bytes(runtime, expected_event, &raw_input)
}

pub fn refuse_unchecked(runtime: &str, event: &str, payload: &Value, reason_key: &str) {
    if event == "PreToolUse" {
        command::deny_hook(reason_key);
    } else if event == "PostToolUse" {
        let _ = output::withhold_post_hook(
            runtime,
            payload.get("tool_response").unwrap_or(&Value::Null),
            None,
            None,
        );
    }
}

pub fn json_payloads(output: &[u8]) -> Option<Vec<Value>> {
    let text = std::str::from_utf8(output).ok()?;
    if let Some(value) = guard_common::pyjson::loads(text.as_bytes()) {
        return Some(vec![value]);
    }
    let mut payloads = Vec::new();
    for line in text.split(|character| {
        matches!(
            character,
            '\n' | '\r'
                | '\u{000b}'
                | '\u{000c}'
                | '\u{001c}'
                | '\u{001d}'
                | '\u{001e}'
                | '\u{0085}'
                | '\u{2028}'
                | '\u{2029}'
        )
    }) {
        if line.trim_matches(py_space).is_empty() {
            continue;
        }
        payloads.push(guard_common::pyjson::loads(line.as_bytes())?);
    }
    (!payloads.is_empty()).then_some(payloads)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{command_of, content_tool_name, json_payloads, line_number, redact_keys, HookError};

    #[test]
    fn python_int_rules_decide_line_numbers() {
        let number = |text: &str| serde_json::from_str::<serde_json::Value>(text).expect("json");
        assert!(matches!(line_number(&json!("\u{1c}1"), 1), Err(HookError::Internal)));
        assert!(matches!(line_number(&json!("2\u{1f}"), 1), Err(HookError::Internal)));
        assert!(matches!(line_number(&json!(" \u{a0}7\t"), 1), Ok(Some(7))));
        assert!(matches!(line_number(&json!("x"), 1), Ok(None)));
        assert!(matches!(line_number(&number("18446744073709551616"), 1), Ok(Some(usize::MAX))));
        assert!(matches!(line_number(&number("-18446744073709551616"), 4), Ok(Some(4))));
        assert!(matches!(line_number(&number("-0"), 4), Ok(Some(4))));
        assert!(matches!(line_number(&number("0"), 4), Ok(Some(4))));
        assert!(matches!(line_number(&number("1.5"), 4), Ok(None)));
        assert!(matches!(line_number(&number("5.0"), 4), Ok(None)));
        assert!(matches!(line_number(&number("1e2"), 4), Ok(None)));
    }

    #[test]
    fn missing_and_non_string_commands_are_absent() {
        assert_eq!(command_of(&json!({"tool_input": {}})), None);
        assert_eq!(command_of(&json!({"tool_input": {"command": 7}})), None);
        assert_eq!(
            command_of(&json!({"tool_input": {"command": "ls"}})),
            Some("ls")
        );
    }

    #[test]
    fn content_tool_names_include_mcp_prefix() {
        assert!(content_tool_name(&json!("Read")));
        assert!(content_tool_name(&json!("mcp__example")));
        assert!(!content_tool_name(&json!("mcp_")));
    }

    #[test]
    fn line_number_accepts_unicode_decimal_and_rejects_nondecimal_digit() {
        assert!(matches!(line_number(&json!("١٢"), 17), Ok(Some(12))));
        assert!(matches!(line_number(&json!(0), 17), Ok(Some(17))));
        assert!(line_number(&json!("²"), 17).is_err());
    }

    #[test]
    fn nested_keys_are_replaced_in_place() {
        let value = json!({"outer": [{"token": format!("{}{}", "ghp_", "A".repeat(32))}]});
        let (redacted, changed) = redact_keys(&value, 0).expect("bounded response");
        assert!(changed);
        assert_ne!(redacted, value);
    }

    #[test]
    fn json_payloads_accept_lines_and_reject_invalid_utf8() {
        assert_eq!(json_payloads(b"{}\n[]"), Some(vec![json!({}), json!([])]));
        assert_eq!(json_payloads(b"\xff"), None);
    }
}
