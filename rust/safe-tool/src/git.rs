use std::path::Path;

use guard_common::{emit::emit, sys};
use serde_json::{json, Value};

use crate::consts::{
    CODERABBIT_PATH, GIT_PATH, GIT_TIMEOUT_SECONDS, STATUS_TIMEOUT_SECONDS,
};
use crate::process::{self, ProcessResult};

#[cfg(test)]
type MockGitCall = (Vec<String>, Option<ProcessResult>);
#[cfg(test)]
type MockGitCalls = std::collections::VecDeque<MockGitCall>;

#[cfg(test)]
thread_local! {
    static MOCK_GIT: std::cell::RefCell<Option<MockGitCalls>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn mock_git_calls(calls: Vec<MockGitCall>) {
    MOCK_GIT.with(|slot| {
        *slot.borrow_mut() = Some(calls.into());
    });
}

#[cfg(test)]
pub(crate) fn assert_mock_consumed() {
    MOCK_GIT.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot
            .as_ref()
            .is_some_and(std::collections::VecDeque::is_empty));
        *slot = None;
    });
}

#[derive(Debug, PartialEq)]
pub enum AuthNode {
    Object(Vec<(String, AuthNode)>),
    Array(Vec<AuthNode>),
    String(String),
    Bool(bool),
    Other,
}

fn skip_json_space(input: &str, mut at: usize) -> usize {
    while input
        .as_bytes()
        .get(at)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        at = at.saturating_add(1);
    }
    at
}

fn string_end(input: &str, start: usize) -> Option<usize> {
    if input.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let mut at = start.saturating_add(1);
    while let Some(byte) = input.as_bytes().get(at) {
        if *byte == b'\\' {
            at = at.saturating_add(2);
        } else if *byte == b'"' {
            return Some(at.saturating_add(1));
        } else {
            at = at.saturating_add(1);
        }
    }
    None
}

fn parse_node(input: &str, start: usize, depth: usize) -> Option<(AuthNode, usize)> {
    if depth > 1024 {
        return None;
    }
    let mut at = skip_json_space(input, start);
    match *input.as_bytes().get(at)? {
        b'{' => {
            at = skip_json_space(input, at.saturating_add(1));
            let mut entries = Vec::new();
            if input.as_bytes().get(at) == Some(&b'}') {
                return Some((AuthNode::Object(entries), at.saturating_add(1)));
            }
            loop {
                let end = string_end(input, at)?;
                let key = serde_json::from_str::<String>(input.get(at..end)?).ok()?;
                at = skip_json_space(input, end);
                if input.as_bytes().get(at) != Some(&b':') {
                    return None;
                }
                let (child, end) =
                    parse_node(input, at.saturating_add(1), depth.saturating_add(1))?;
                if let Some((_, existing)) = entries.iter_mut().find(|(name, _)| *name == key) {
                    *existing = child;
                } else {
                    entries.push((key, child));
                }
                at = skip_json_space(input, end);
                match input.as_bytes().get(at) {
                    Some(&b',') => at = skip_json_space(input, at.saturating_add(1)),
                    Some(&b'}') => return Some((AuthNode::Object(entries), at.saturating_add(1))),
                    _ => return None,
                }
            }
        }
        b'[' => {
            at = skip_json_space(input, at.saturating_add(1));
            let mut items = Vec::new();
            if input.as_bytes().get(at) == Some(&b']') {
                return Some((AuthNode::Array(items), at.saturating_add(1)));
            }
            loop {
                let (child, end) = parse_node(input, at, depth.saturating_add(1))?;
                items.push(child);
                at = skip_json_space(input, end);
                match input.as_bytes().get(at) {
                    Some(&b',') => at = skip_json_space(input, at.saturating_add(1)),
                    Some(&b']') => return Some((AuthNode::Array(items), at.saturating_add(1))),
                    _ => return None,
                }
            }
        }
        b'"' => {
            let end = string_end(input, at)?;
            let text = serde_json::from_str::<String>(input.get(at..end)?).ok()?;
            Some((AuthNode::String(text), end))
        }
        _ => {
            let end = input
                .as_bytes()
                .iter()
                .enumerate()
                .skip(at)
                .find(|(_, byte)| {
                    matches!(**byte, b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t')
                })
                .map(|(index, _)| index)
                .unwrap_or(input.len());
            let value: Value = serde_json::from_str(input.get(at..end)?).ok()?;
            Some((
                match value {
                    Value::Bool(value) => AuthNode::Bool(value),
                    _ => AuthNode::Other,
                },
                end,
            ))
        }
    }
}

impl AuthNode {
    pub fn parse(input: &str) -> Option<Self> {
        let (node, end) = parse_node(input, 0, 0)?;
        if skip_json_space(input, end) == input.len() {
            Some(node)
        } else {
            None
        }
    }
}

// Preserve JSON object order because the first recognized child determines the status.
pub fn authentication_state(value: &AuthNode) -> Option<&'static str> {
    match value {
        AuthNode::Object(entries) => {
            for (key, child) in entries {
                let name: String = key
                    .to_lowercase()
                    .chars()
                    .filter(char::is_ascii_lowercase)
                    .collect();
                if matches!(
                    name.as_str(),
                    "authenticated" | "isauthenticated" | "loggedin" | "isloggedin"
                ) {
                    if let AuthNode::Bool(ready) = child {
                        return Some(if *ready { "ready" } else { "unauthenticated" });
                    }
                }
                if matches!(name.as_str(), "authstatus" | "state" | "status") {
                    if let AuthNode::String(status) = child {
                        let status: String = status
                            .to_lowercase()
                            .chars()
                            .filter(char::is_ascii_lowercase)
                            .collect();
                        if matches!(status.as_str(), "authenticated" | "loggedin" | "ready") {
                            return Some("ready");
                        }
                        if matches!(
                            status.as_str(),
                            "expired"
                                | "loggedout"
                                | "missing"
                                | "notauthenticated"
                                | "unauthenticated"
                        ) {
                            return Some("unauthenticated");
                        }
                    }
                }
                if let Some(state) = authentication_state(child) {
                    return Some(state);
                }
            }
        }
        AuthNode::Array(items) => {
            for child in items {
                if let Some(state) = authentication_state(child) {
                    return Some(state);
                }
            }
        }
        _ => {}
    }
    None
}

pub fn ordered_json_payloads(output: &[u8]) -> Option<Vec<AuthNode>> {
    let parsed = crate::hooks::json_payloads(output)?;
    let text = std::str::from_utf8(output).ok()?;
    if let Some(node) = AuthNode::parse(text) {
        return Some(vec![node]);
    }
    let mut nodes = Vec::new();
    for line in text
        .split(|character| {
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
        })
        .filter(|line| !python_strip(line).is_empty())
    {
        nodes.push(AuthNode::parse(line)?);
    }
    if nodes.len() == parsed.len() {
        Some(nodes)
    } else {
        None
    }
}

pub fn rtk_status() -> i32 {
    let enforcement = if crate::command::require_rtk() {
        "on"
    } else {
        "off"
    };
    if crate::consts::rtk_path().is_none() {
        emit(&json!({"tool": "rtk", "status": "unavailable", "enforcement": enforcement}));
        return 127;
    }
    let ready = crate::command::rtk_required("git status --short");
    let status = if ready { "ready" } else { "operation_failed" };
    emit(&json!({"tool": "rtk", "status": status, "enforcement": enforcement}));
    if ready {
        0
    } else {
        2
    }
}

pub fn coderabbit_status() -> i32 {
    let Some(path) = CODERABBIT_PATH.as_deref() else {
        emit(&json!({"tool": "coderabbit", "status": "unavailable"}));
        return 127;
    };
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let command = [
        path.to_owned(),
        "auth".into(),
        "status".into(),
        "--agent".into(),
    ];
    let Some(completed) = process::run(&command, &cwd, STATUS_TIMEOUT_SECONDS as u64) else {
        emit(&json!({"tool": "coderabbit", "status": "operation_failed"}));
        return 2;
    };
    let state = ordered_json_payloads(&completed.stdout)
        .as_ref()
        .and_then(|payloads| payloads.iter().find_map(authentication_state));
    let Some(state) = state else {
        emit(&json!({"tool": "coderabbit", "status": "schema_mismatch"}));
        return 2;
    };
    emit(&json!({"tool": "coderabbit", "status": state}));
    if state == "ready" {
        0
    } else {
        1
    }
}

pub fn git(command: &[String], cwd: &str, timeout: u64) -> Option<ProcessResult> {
    #[cfg(test)]
    if let Some(response) = MOCK_GIT.with(|slot| {
        slot.borrow_mut().as_mut().map(|calls| {
            let (expected, response) = calls.pop_front().expect("unexpected Git call");
            assert_eq!(command, expected);
            response
        })
    }) {
        return response;
    }
    let path = GIT_PATH.as_ref()?;
    let mut args = vec![
        path.to_owned(),
        "-c".to_owned(),
        "user.useConfigOnly=true".to_owned(),
    ];
    args.extend_from_slice(command);
    process::run(&args, cwd, timeout)
}

pub fn git_default(command: &[String], cwd: &str) -> Option<ProcessResult> {
    git(command, cwd, GIT_TIMEOUT_SECONDS as u64)
}

pub(crate) fn python_space(character: char) -> bool {
    character.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&character)
}

pub(crate) fn python_strip(text: &str) -> &str {
    text.trim_matches(python_space)
}

pub(crate) fn python_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut previous_cr = false;
    for (index, character) in text.char_indices() {
        if previous_cr && character == '\n' {
            start = index.saturating_add(character.len_utf8());
            previous_cr = false;
            continue;
        }
        let is_break = matches!(
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
        );
        if is_break {
            if let Some(line) = text.get(start..index) {
                out.push(line);
            }
            start = index.saturating_add(character.len_utf8());
            previous_cr = character == '\r';
        } else {
            previous_cr = false;
        }
    }
    if start < text.len() {
        if let Some(line) = text.get(start..) {
            out.push(line);
        }
    }
    out
}

pub fn repository_root(cwd: &str) -> Option<String> {
    let command = ["rev-parse".to_owned(), "--show-toplevel".to_owned()];
    let completed = git(&command, cwd, 20)?;
    if completed.returncode != 0 {
        return None;
    }
    let raw = std::str::from_utf8(&completed.stdout).ok()?;
    let root = sys::try_realpath(python_strip(raw)).ok()?;
    let current = sys::try_realpath(cwd).ok()?;
    if !Path::new(&root).is_dir() || !Path::new(&current).starts_with(&root) {
        return None;
    }
    Some(root)
}

pub fn git_identity_ready(root: &str) -> bool {
    for variable in ["GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"] {
        let command = ["var".to_owned(), variable.to_owned()];
        let Some(completed) = git(&command, root, 20) else {
            return false;
        };
        if completed.returncode != 0
            || completed
                .stdout
                .iter()
                .all(|byte| byte.is_ascii_whitespace())
        {
            return false;
        }
    }
    true
}

pub fn git_identity() -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Some(root) = repository_root(&cwd) else {
        emit(&json!({"tool": "git", "operation": "identity", "status": "not_repository"}));
        return 2;
    };
    let ready = git_identity_ready(&root);
    let status = if ready {
        "configured"
    } else {
        "identity_missing"
    };
    emit(&json!({"tool": "git", "operation": "identity", "status": status}));
    if ready {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assert_mock_consumed, authentication_state, git, git_identity, mock_git_calls,
        ordered_json_payloads, AuthNode,
    };
    use crate::process::ProcessResult;

    #[test]
    fn status_prefers_earliest_recognized_child() {
        assert_eq!(
            authentication_state(
                &AuthNode::parse(r#"[{"other":{"status":"expired"}},{"authenticated":true}]"#)
                    .expect("json")
            ),
            Some("unauthenticated")
        );
        assert_eq!(
            authentication_state(&AuthNode::parse(r#"{"is_logged_in":true}"#).expect("json")),
            Some("ready")
        );
        assert_eq!(
            authentication_state(&AuthNode::parse(r#"{"status":"unknown"}"#).expect("json")),
            None
        );
        assert_eq!(
            authentication_state(
                &AuthNode::parse(r#"{"status":"expired","authenticated":true}"#).expect("json")
            ),
            Some("unauthenticated")
        );
        assert_eq!(
            authentication_state(
                &AuthNode::parse(r#"{"authenticated":true,"status":"expired"}"#).expect("json")
            ),
            Some("ready")
        );
    }

    #[test]
    fn git_wrapper_uses_the_read_only_git_binary() {
        let result = git(&["--version".to_owned()], "/", 20).expect("git version probe");
        assert_eq!(result.returncode, 0);
        assert!(result.stdout.starts_with(b"git version"));
        let config = git(
            &[
                "config".to_owned(),
                "--get".to_owned(),
                "user.useConfigOnly".to_owned(),
            ],
            "/",
            20,
        )
        .expect("Git wrapper config probe");
        assert_eq!(config.returncode, 0);
        assert_eq!(config.stdout, b"true\n");
    }

    #[test]
    fn identity_status_uses_only_configured_or_missing() {
        let root = std::env::current_dir().expect("cwd");
        let root = root.to_str().expect("utf8 path");
        mock_git_calls(vec![
            (
                vec!["rev-parse".into(), "--show-toplevel".into()],
                Some(ProcessResult {
                    returncode: 0,
                    stdout: format!("{root}\n").into_bytes(),
                    stderr: vec![],
                }),
            ),
            (
                vec!["var".into(), "GIT_AUTHOR_IDENT".into()],
                Some(ProcessResult {
                    returncode: 0,
                    stdout: b"configured\n".to_vec(),
                    stderr: vec![],
                }),
            ),
            (
                vec!["var".into(), "GIT_COMMITTER_IDENT".into()],
                Some(ProcessResult {
                    returncode: 0,
                    stdout: b"configured\n".to_vec(),
                    stderr: vec![],
                }),
            ),
        ]);
        assert_eq!(git_identity(), 0);
        assert_mock_consumed();
    }

    #[test]
    fn ordered_payloads_accept_json_lines_and_reject_invalid_input() {
        let payloads =
            ordered_json_payloads(b"{\"status\":\"expired\"}\n{\"authenticated\":true}\n")
                .expect("JSON lines");
        assert_eq!(payloads.len(), 2);
        assert_eq!(
            payloads.first().and_then(authentication_state),
            Some("unauthenticated")
        );
        assert_eq!(
            payloads.get(1).and_then(authentication_state),
            Some("ready")
        );
        assert!(ordered_json_payloads(b"{invalid}").is_none());
    }
}
