#![forbid(unsafe_code)]

pub mod changes;
pub mod comments;
pub mod decision;
pub mod git;
pub mod languages;
pub mod limits;
pub mod locale;
pub mod post;
pub mod rewrite;
pub mod session;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

pub use changes::collect;
pub use decision::{evaluate, Change};

use decision::comment_lines;
use languages::{language_for, language_for_text, Language};
use locale::message;
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
    Trimmed { input: Value, note: String },
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
    let Some(ledger) = ledger_of(payload, state) else {
        return;
    };
    if let Some(id) = payload.get("tool_use_id").and_then(Value::as_str) {
        ledger.mark_start(id);
    }
    post::refresh_named(payload, &ledger);
}

struct Prepared {
    id: String,
    before: u64,
    after: session::Seen,
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

fn attach_baselines(ledger: &Ledger, changes: &mut [Change], base: &Path) -> HashMap<String, Prepared> {
    let mut prepared = HashMap::new();
    for change in changes.iter_mut() {
        if change.partial {
            continue;
        }
        let Some(lang) = language_for_text(&change.file, &change.new) else {
            continue;
        };
        let id = session::identity(&changes::resolve(base, &change.file));
        let origin = change.origin.as_deref().and_then(|source| {
            let from = language_for(source)?;
            let record = ledger.read(&session::identity(&changes::resolve(base, source)))?;
            Some((from, record))
        });
        let old_comments = comment_lines(&change.old, lang);
        let before = session::seen_of(&change.old, &old_comments);
        let baseline = ledger.baseline_for(&id, before, || match origin {
            Some((from, record)) if from == lang => record,
            Some((from, record)) => translated(&change.old, from, &record, lang),
            None => old_comments.clone(),
        });
        change.baseline = Some(baseline);
        let after = session::seen_of(&change.new, &comment_lines(&change.new, lang));
        change.carry = ledger.carry(&id, before.hash, after.hash);
        prepared.insert(
            change.file.clone(),
            Prepared {
                id,
                before: before.hash,
                after,
            },
        );
    }
    prepared
}

pub(crate) fn widen_with_head(changes: &mut [Change], base: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
    for change in changes.iter_mut() {
        let Some(lang) = language_for_text(&change.file, &change.new) else {
            continue;
        };
        if change.partial {
            continue;
        }
        let path = changes::resolve(base, &change.file);
        let mut texts: Vec<String> = Vec::new();
        for rev in ["HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD"] {
            if let post::Head::Found(found) = post::rev_text(&path, rev, deadline) {
                texts.push(found);
            }
        }
        if texts.is_empty() {
            continue;
        }
        if change.file.to_ascii_lowercase().ends_with(".ipynb") {
            let codes: Vec<String> = texts.iter().filter_map(|found| changes::notebook_text(found)).collect();
            if codes.len() != texts.len() {
                continue;
            }
            texts = codes;
        }
        let mut merged = change.baseline.clone().unwrap_or_else(|| comment_lines(&change.old, lang));
        let mut held: HashMap<String, usize> = HashMap::new();
        for line in &merged {
            *held.entry(line.clone()).or_insert(0) += 1;
        }
        let mut wanted: HashMap<String, usize> = HashMap::new();
        for text in &texts {
            let mut here: HashMap<String, usize> = HashMap::new();
            for line in comment_lines(text, lang) {
                *here.entry(line).or_insert(0) += 1;
            }
            for (line, count) in here {
                let slot = wanted.entry(line).or_insert(0);
                *slot = (*slot).max(count);
            }
        }
        for (line, count) in wanted {
            for _ in held.get(&line).copied().unwrap_or(0)..count {
                merged.push(line.clone());
            }
        }
        change.baseline = Some(merged);
    }
}

fn settle(ledger: &Ledger, prepared: &HashMap<String, Prepared>, changes: &mut [Change]) -> Option<String> {
    let mut retry: Vec<(String, u64, u64, usize)> = Vec::new();
    let mut committed: Vec<(String, u64, usize, u64)> = Vec::new();
    for change in changes.iter_mut() {
        let Some(item) = prepared.get(&change.file) else {
            continue;
        };
        let net = decision::net_lines(change);
        match ledger.commit_note(&item.id, item.before, item.after.hash, net, change.carry) {
            Ok(Some(noted)) => committed.push((item.id.clone(), item.before, net, noted)),
            Ok(None) => {}
            Err(current) => {
                change.carry = current;
                retry.push((item.id.clone(), item.before, item.after.hash, net));
            }
        }
    }
    let mut verdict = None;
    if !retry.is_empty() {
        verdict = evaluate(changes);
        if verdict.is_none() {
            for (id, before, after, net) in &retry {
                let current = ledger.carry(id, *before, *after);
                let _ = ledger.commit_note(id, *before, *after, *net, current);
            }
        }
    }
    if verdict.is_none() {
        for change in changes.iter() {
            if let Some(item) = prepared.get(&change.file) {
                ledger.accept(&item.id, &[item.after]);
            }
        }
    } else {
        for (id, before, net, noted) in &committed {
            ledger.revoke_note(id, *before, *net, *noted);
        }
    }
    verdict
}

pub fn judge(input: &str, provider: Provider) -> Verdict {
    judge_in(input, provider, session::state_dir().as_deref())
}

pub fn judge_trimming(input: &str, provider: Provider) -> Verdict {
    judge_trimming_in(input, provider, session::state_dir().as_deref())
}

pub fn judge_trimming_in(input: &str, provider: Provider, state: Option<&Path>) -> Verdict {
    let Some(payload) = parse(input) else {
        return Verdict::BadInput;
    };
    judge_payload(&payload, provider, state, true)
}

pub fn judge_in(input: &str, provider: Provider, state: Option<&Path>) -> Verdict {
    let Some(payload) = parse(input) else {
        return Verdict::BadInput;
    };
    judge_payload(&payload, provider, state, false)
}

pub(crate) fn trimmed_note(key: &str, file: &str, removed: &[String], stood_in: usize) -> String {
    let shown: Vec<String> = removed.iter().take(6).map(|line| line.chars().take(70).collect()).collect();
    let mut lines = shown.join(" | ");
    if removed.len() > shown.len() {
        lines.push_str(" ...");
    }
    let count = removed.len().to_string();
    let max_lines = limits::current().lines.to_string();
    let note = message(
        key,
        &[("count", count.as_str()), ("file", file), ("lines", lines.as_str()), ("max_lines", max_lines.as_str())],
    );
    if stood_in == 0 {
        return note;
    }
    let blocks = stood_in.to_string();
    let extra = message("comment_guard.trimmed_pass", &[("count", blocks.as_str()), ("file", file)]);
    format!("{note} {extra}")
}

fn try_trim(
    payload: &Map<String, Value>,
    tool: &str,
    input: &Map<String, Value>,
    changes: &[Change],
    base: &Path,
    state: Option<&Path>,
    provider: Provider,
) -> Option<Verdict> {
    let mut cuts: Vec<Option<decision::Trimmed>> = Vec::with_capacity(changes.len());
    for change in changes {
        if evaluate(std::slice::from_ref(change)).is_some() {
            cuts.push(Some(decision::trimmed(change)?));
        } else {
            cuts.push(None);
        }
    }
    if cuts.iter().all(Option::is_none) {
        return None;
    }
    let new_input = rewrite::rewritten_input(provider, tool, input, changes, &cuts, base)?;
    let after = collect(tool, &new_input, provider, base);
    if after.len() != changes.len() {
        return None;
    }
    for ((found, change), cut) in after.iter().zip(changes).zip(&cuts) {
        let expected = cut.as_ref().map_or(change.new.as_str(), |cut| cut.text.as_str());
        if found.new != expected {
            return None;
        }
    }
    let mut again = payload.clone();
    again.insert("tool_input".to_owned(), Value::Object(new_input.clone()));
    if !matches!(judge_payload(&again, provider, state, false), Verdict::Allow) {
        return None;
    }
    let notes: Vec<String> = changes
        .iter()
        .zip(&cuts)
        .filter_map(|(change, cut)| cut.as_ref().map(|cut| trimmed_note("comment_guard.trimmed", &change.file, &cut.removed, cut.swapped.len())))
        .collect();
    Some(Verdict::Trimmed {
        input: Value::Object(new_input),
        note: notes.join(" "),
    })
}

fn judge_payload(payload: &Map<String, Value>, provider: Provider, state: Option<&Path>, trim: bool) -> Verdict {
    let payload = payload.clone();
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
    let prepared = match &ledger {
        Some(ledger) => attach_baselines(ledger, &mut changes, &base),
        None => HashMap::new(),
    };
    let mut verdict = evaluate(&changes);
    if verdict.is_some() {
        widen_with_head(&mut changes, &base);
        verdict = evaluate(&changes);
    }
    let mut widened: Vec<String> = Vec::new();
    if verdict.is_some() {
        widened = git::widen_with_known(&mut changes, &base);
        verdict = evaluate(&changes);
    }
    if verdict.is_some() {
        git::drop_marked(&mut changes, &base);
        verdict = evaluate(&changes);
    }
    if verdict.is_none() {
        if let Some(ledger) = &ledger {
            verdict = settle(ledger, &prepared, &mut changes);
        }
    }
    if verdict.is_none() {
        if let Some(ledger) = &ledger {
            for change in changes.iter().filter(|change| widened.contains(&change.file)) {
                if let (Some(item), Some(baseline)) = (prepared.get(&change.file), &change.baseline) {
                    ledger.rebaseline(&item.id, baseline.clone(), item.after);
                }
            }
        }
    }
    match verdict {
        Some(reason) => {
            if trim {
                if let Some(trimmed) = try_trim(&payload, tool, tool_input, &changes, &base, state, provider) {
                    return trimmed;
                }
            }
            Verdict::Deny(reason)
        }
        None => Verdict::Allow,
    }
}

pub fn judge_after(input: &str) -> Verdict {
    judge_after_in(input, session::state_dir().as_deref())
}

pub fn judge_after_trimming(input: &str) -> Verdict {
    judge_after_with(input, session::state_dir().as_deref(), true)
}

pub fn judge_after_in(input: &str, state: Option<&Path>) -> Verdict {
    judge_after_with(input, state, false)
}

pub fn judge_after_trimming_in(input: &str, state: Option<&Path>) -> Verdict {
    judge_after_with(input, state, true)
}

fn judge_after_with(input: &str, state: Option<&Path>, trim: bool) -> Verdict {
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
        Some(ledger) => post::judge_command(&payload, &ledger, trim),
        None => Verdict::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::{settle, Prepared};
    use crate::decision::Change;
    use crate::session::{identity, seen_of, Ledger};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("comment-guard-settle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn pair(ledger: &Ledger) -> (HashMap<String, Prepared>, Vec<Change>) {
        let mut prepared = HashMap::new();
        let mut changes = Vec::new();
        for (name, old, new) in [("/t/a.py", "x = 1\n", "# one\nx = 1\n"), ("/t/b.py", "y = 1\n", "# two\n# three\n# four\ny = 1\n")] {
            let id = identity(Path::new(name));
            let before = seen_of(old, &[]);
            ledger.baseline_for(&id, before, Vec::new);
            let comments = crate::decision::comment_lines(new, crate::languages::language_for(name).expect("python"));
            let after = seen_of(new, &comments);
            prepared.insert(name.to_string(), Prepared { id, before: before.hash, after });
            let mut change = Change::whole(name.to_string(), old.to_string(), new.to_string());
            change.baseline = Some(Vec::new());
            changes.push(change);
        }
        (prepared, changes)
    }

    #[test]
    fn a_denied_call_leaves_no_note_behind_for_the_files_it_had_already_noted() {
        let dir = scratch("denied");
        let ledger = Ledger::open(&dir, "settle").expect("ledger");
        let (prepared, mut changes) = pair(&ledger);
        let other = &prepared["/t/b.py"];
        assert!(matches!(ledger.commit_note(&other.id, other.before, 77, 2, 0), Ok(Some(_))));
        let verdict = settle(&ledger, &prepared, &mut changes);
        assert!(verdict.is_some());
        let first = &prepared["/t/a.py"];
        assert_eq!(ledger.carry(&first.id, first.before, 12345), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_denied_call_keeps_the_note_an_identical_earlier_edit_left() {
        let dir = scratch("identical");
        let ledger = Ledger::open(&dir, "settle").expect("ledger");
        let (prepared, mut changes) = pair(&ledger);
        let first = &prepared["/t/a.py"];
        assert!(matches!(ledger.commit_note(&first.id, first.before, first.after.hash, 1, 0), Ok(Some(_))));
        let other = &prepared["/t/b.py"];
        assert!(matches!(ledger.commit_note(&other.id, other.before, 77, 2, 0), Ok(Some(_))));
        let verdict = settle(&ledger, &prepared, &mut changes);
        assert!(verdict.is_some());
        assert_eq!(ledger.carry(&first.id, first.before, 12345), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
