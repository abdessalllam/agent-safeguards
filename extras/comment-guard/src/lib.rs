#![forbid(unsafe_code)]

pub mod changes;
pub mod comments;
pub mod decision;
pub mod languages;
pub mod locale;
pub mod post;
pub mod session;
pub mod tree;

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

pub use changes::collect;
pub use decision::{evaluate, Change};
pub use tree::judge_tree;

use decision::comment_lines;
use languages::language_for;
use session::Ledger;

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

fn parse(input: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(input).ok()? {
        Value::Object(payload) => Some(payload),
        _ => None,
    }
}

fn event_is(payload: &Map<String, Value>, wanted: &str) -> bool {
    match payload.get("hook_event_name") {
        Some(event) => event.as_str() == Some(wanted),
        None => true,
    }
}

fn base_of(payload: &Map<String, Value>) -> PathBuf {
    payload
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

fn ledger_of(payload: &Map<String, Value>, state: Option<&Path>) -> Option<Ledger> {
    let session = payload.get("session_id").and_then(Value::as_str)?;
    Ledger::open(state?, session)
}

fn mark_start(payload: &Map<String, Value>, state: Option<&Path>) {
    let Some(id) = payload.get("tool_use_id").and_then(Value::as_str) else {
        return;
    };
    if let Some(ledger) = ledger_of(payload, state) {
        ledger.mark_start(id);
    }
}

fn attach_baselines(ledger: &Ledger, changes: &mut [Change], base: &Path) {
    for change in changes.iter_mut() {
        if change.partial {
            continue;
        }
        let Some(lang) = language_for(&change.file) else {
            continue;
        };
        let id = session::identity(&changes::resolve(base, &change.file));
        let origin = change
            .origin
            .as_deref()
            .filter(|source| language_for(source) == Some(lang))
            .map(|path| session::identity(&changes::resolve(base, path)));
        let baseline = ledger.baseline(&id, || {
            match origin.as_deref().and_then(|source| ledger.read(source)) {
                Some(found) => found,
                None => comment_lines(&change.old, lang),
            }
        });
        change.baseline = Some(baseline);
    }
}

pub fn judge(input: &str, provider: Provider) -> Verdict {
    judge_in(input, provider, session::state_dir().as_deref())
}

pub fn judge_in(input: &str, provider: Provider, state: Option<&Path>) -> Verdict {
    let Some(payload) = parse(input) else {
        return Verdict::BadInput;
    };
    if !event_is(&payload, "PreToolUse") {
        return Verdict::Allow;
    }
    let Some(tool) = payload.get("tool_name").and_then(Value::as_str) else {
        return Verdict::Allow;
    };
    if tool == "Bash" {
        mark_start(&payload, state);
        return Verdict::Allow;
    }
    let Some(Value::Object(tool_input)) = payload.get("tool_input") else {
        return Verdict::Allow;
    };
    let base = base_of(&payload);
    let mut changes = collect(tool, tool_input, provider, &base);
    if !changes.is_empty() {
        if let Some(ledger) = ledger_of(&payload, state) {
            attach_baselines(&ledger, &mut changes, &base);
        }
    }
    match evaluate(&changes) {
        Some(reason) => Verdict::Deny(reason),
        None => Verdict::Allow,
    }
}

pub fn judge_after(input: &str) -> Verdict {
    judge_after_in(input, session::state_dir().as_deref())
}

pub fn judge_after_in(input: &str, state: Option<&Path>) -> Verdict {
    let Some(payload) = parse(input) else {
        return Verdict::BadInput;
    };
    if !event_is(&payload, "PostToolUse") {
        return Verdict::Allow;
    }
    if payload.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return Verdict::Allow;
    }
    match ledger_of(&payload, state) {
        Some(ledger) => post::judge_command(&payload, &ledger),
        None => Verdict::Allow,
    }
}
