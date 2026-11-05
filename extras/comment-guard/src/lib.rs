#![forbid(unsafe_code)]

pub mod changes;
pub mod comments;
pub mod decision;
pub mod git;
pub mod languages;
pub mod locale;
pub mod post;
pub mod session;

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

pub use changes::collect;
pub use decision::{evaluate, Change};

use decision::comment_lines;
use languages::{language_for, Language};
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

pub(crate) fn base_of(payload: &Map<String, Value>) -> PathBuf {
    let current = std::env::current_dir().unwrap_or_default();
    match payload.get("cwd").and_then(Value::as_str).map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        Some(path) => current.join(path),
        None => current,
    }
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

fn translated(old: &str, from: Language, record: &[String], to: Language) -> Vec<String> {
    let mut added: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for line in comment_lines(old, from) {
        *added.entry(line).or_insert(0) += 1;
    }
    for line in record {
        if let Some(count) = added.get_mut(line) {
            *count = count.saturating_sub(1);
        }
    }
    let mut out = Vec::new();
    for line in comment_lines(old, to) {
        match added.get_mut(&line) {
            Some(count) if *count > 0 => *count -= 1,
            _ => out.push(line),
        }
    }
    out
}

fn attach_baselines(ledger: &Ledger, changes: &mut [Change], base: &Path) -> Vec<(String, u64)> {
    let mut accepted = Vec::new();
    for change in changes.iter_mut() {
        if change.partial {
            continue;
        }
        let Some(lang) = language_for(&change.file) else {
            continue;
        };
        let id = session::identity(&changes::resolve(base, &change.file));
        let origin = change.origin.as_deref().and_then(|source| {
            let from = language_for(source)?;
            let record = ledger.read(&session::identity(&changes::resolve(base, source)))?;
            Some((from, record))
        });
        let before = session::content_hash(&change.old);
        let baseline = ledger.baseline_for(&id, before, || match origin {
            Some((from, record)) if from == lang => record,
            Some((from, record)) => translated(&change.old, from, &record, lang),
            None => comment_lines(&change.old, lang),
        });
        change.baseline = Some(baseline);
        accepted.push((id, session::content_hash(&change.new)));
    }
    accepted
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
    let ledger = if changes.is_empty() { None } else { ledger_of(&payload, state) };
    let accepted = match &ledger {
        Some(ledger) => attach_baselines(ledger, &mut changes, &base),
        None => Vec::new(),
    };
    let mut verdict = evaluate(&changes);
    if verdict.is_some() {
        git::drop_marked(&mut changes, &base);
        verdict = evaluate(&changes);
    }
    if verdict.is_none() {
        if let Some(ledger) = &ledger {
            for (id, after) in &accepted {
                ledger.accept(id, &[*after]);
            }
        }
    }
    match verdict {
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
