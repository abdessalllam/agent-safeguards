#![forbid(unsafe_code)]

pub mod changes;
pub mod comments;
pub mod decision;
pub mod languages;
pub mod locale;

use std::path::PathBuf;

use serde_json::Value;

pub use changes::collect;
pub use decision::{evaluate, Change};

pub const MAX_INPUT: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Claude,
    Codex,
}

pub enum Verdict {
    Allow,
    Deny(String),
    BadInput,
}

pub fn judge(input: &str, provider: Provider) -> Verdict {
    let Ok(value) = serde_json::from_str::<Value>(input) else {
        return Verdict::BadInput;
    };
    let Value::Object(payload) = value else {
        return Verdict::BadInput;
    };
    if let Some(event) = payload.get("hook_event_name") {
        if event.as_str() != Some("PreToolUse") {
            return Verdict::Allow;
        }
    }
    let Some(tool) = payload.get("tool_name").and_then(Value::as_str) else {
        return Verdict::Allow;
    };
    let Some(Value::Object(tool_input)) = payload.get("tool_input") else {
        return Verdict::Allow;
    };
    let base = payload
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let changes = collect(tool, tool_input, provider, &base);
    match evaluate(&changes) {
        Some(reason) => Verdict::Deny(reason),
        None => Verdict::Allow,
    }
}
