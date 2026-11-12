use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde_json::{Map, Value};

use crate::changes;
use crate::decision::{Change, Trimmed};
use crate::{Provider, MAX_INPUT};

const MAX_TRACKED: usize = 2 * 1024 * 1024;

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)?.as_str()
}

fn with(input: &Map<String, Value>, key: &str, value: String) -> Map<String, Value> {
    let mut out = input.clone();
    out.insert(key.to_owned(), Value::String(value));
    out
}

fn removed_ranges(new: &str, cut: &Trimmed) -> Vec<(usize, usize, bool)> {
    let total = new.len();
    let count = new.split('\n').count();
    let mut offset = 0usize;
    let mut out = Vec::new();
    for (index, line) in new.split('\n').enumerate() {
        let from = offset;
        offset = from.saturating_add(line.len()).saturating_add(1);
        if !cut.dropped.contains(&index) {
            continue;
        }
        let to = offset.min(total);
        let last = index.saturating_add(1) == count;
        if last && from > 0 {
            out.push((from.saturating_sub(1), to, true));
        } else {
            out.push((from, to, false));
        }
    }
    out
}

fn swapped_ranges<'a>(new: &str, cut: &'a Trimmed) -> Vec<(usize, usize, &'a str)> {
    let mut offset = 0usize;
    let mut out = Vec::new();
    for (index, line) in new.split('\n').enumerate() {
        let from = offset;
        offset = from.saturating_add(line.len()).saturating_add(1);
        if let Some(stand_in) = cut.swapped.get(&index) {
            out.push((from, from.saturating_add(line.trim_end_matches('\r').len()), stand_in.as_str()));
        }
    }
    out
}

fn region(change: &Change, cut: &Trimmed, start: usize, end: usize) -> Option<String> {
    let mut inside = 0usize;
    for (a, b, last) in removed_ranges(&change.new, cut) {
        let crlf = !last
            && b == end.saturating_add(2)
            && a > start.saturating_add(1)
            && change.new.get(end..b) == Some("\r\n")
            && change.new.get(a.saturating_sub(2)..a) == Some("\r\n");
        if !((a >= start && b <= end) || (!last && b == end.saturating_add(1) && a > start) || crlf) {
            return None;
        }
        inside = inside.saturating_add(b.saturating_sub(a));
    }
    let mut added = 0usize;
    for (a, b, stand_in) in swapped_ranges(&change.new, cut) {
        if a < start || b > end {
            return None;
        }
        inside = inside.saturating_add(b.saturating_sub(a));
        added = added.saturating_add(stand_in.len());
    }
    cut.text.get(start..end.checked_sub(inside)?.checked_add(added)?).map(str::to_owned)
}

fn write_input(input: &Map<String, Value>, change: &Change, cut: &Trimmed) -> Option<Map<String, Value>> {
    if text(input, "content") != Some(change.new.as_str()) {
        return None;
    }
    Some(with(input, "content", cut.text.clone()))
}

fn edit_input(input: &Map<String, Value>, change: &Change, cut: &Trimmed) -> Option<Map<String, Value>> {
    if input.get("replace_all").and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    let old_string = text(input, "old_string")?;
    let new_string = text(input, "new_string")?;
    let start = change.old.find(old_string)?;
    let end = start.checked_add(new_string.len())?;
    if change.new.get(start..end) != Some(new_string) {
        return None;
    }
    let kept = region(change, cut, start, end)?;
    if kept == old_string {
        return None;
    }
    Some(with(input, "new_string", kept))
}

fn notebook_input(input: &Map<String, Value>, change: &Change, cut: &Trimmed, base: &Path) -> Option<Map<String, Value>> {
    let source = text(input, "new_source")?;
    let start = changes::notebook_offset(input, base)?;
    let end = start.checked_add(source.len())?;
    if change.new.get(start..end) != Some(source) {
        return None;
    }
    Some(with(input, "new_source", region(change, cut, start, end)?))
}

fn apply_first(old: &str, edits: &[(String, String)]) -> Option<String> {
    let mut current = old.to_owned();
    for (from, to) in edits {
        if from.is_empty() {
            if !current.is_empty() {
                return None;
            }
            current.clone_from(to);
            continue;
        }
        let at = current.find(from.as_str())?;
        current.replace_range(at..at.checked_add(from.len())?, to);
        if current.len() > MAX_INPUT {
            return None;
        }
    }
    Some(current)
}

fn multi_edit_input(input: &Map<String, Value>, change: &Change, cut: &Trimmed) -> Option<Map<String, Value>> {
    if change.old.len() > MAX_TRACKED || change.new.len() > MAX_TRACKED || !cut.swapped.is_empty() {
        return None;
    }
    let Some(Value::Array(items)) = input.get("edits") else {
        return None;
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for item in items {
        let map = item.as_object()?;
        if map.get("replace_all").and_then(Value::as_bool).unwrap_or(false) {
            return None;
        }
        pairs.push((text(map, "old_string")?.to_owned(), text(map, "new_string")?.to_owned()));
    }
    let mut current = change.old.clone();
    let mut origin: Vec<(usize, usize)> = vec![(0, 0); current.len()];
    for (index, (from, to)) in pairs.iter().enumerate() {
        let at = if from.is_empty() {
            if !current.is_empty() {
                return None;
            }
            0
        } else {
            current.find(from.as_str())?
        };
        let end = at.checked_add(from.len())?;
        current.replace_range(at..end, to);
        origin.splice(at..end, (0..to.len()).map(|offset| (index.saturating_add(1), offset)));
    }
    if current != change.new {
        return None;
    }
    let mut gone: Vec<HashSet<usize>> = vec![HashSet::new(); pairs.len()];
    let bytes = change.new.as_bytes();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (a, b, _) in removed_ranges(&change.new, cut) {
        match runs.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => runs.push((a, b)),
        }
    }
    for (a, b) in runs {
        let own = |from: usize, to: usize| origin.get(from..to).is_some_and(|run| run.iter().all(|(edit, _)| *edit > 0));
        let (mut from, mut to) = (a, b);
        let before = from.checked_sub(1).and_then(|at| bytes.get(at));
        if !own(from, to) && before == Some(&b'\n') && b.checked_sub(1).and_then(|at| bytes.get(at)) == Some(&b'\n') {
            from = from.saturating_sub(1);
            to = to.saturating_sub(1);
        }
        if !own(from, to) {
            return None;
        }
        for position in from..to {
            let (edit, offset) = *origin.get(position)?;
            gone.get_mut(edit.checked_sub(1)?)?.insert(offset);
        }
    }
    let mut rewritten: Vec<(String, String)> = Vec::new();
    for ((from, to), skip) in pairs.iter().zip(&gone) {
        let kept: Vec<u8> = to.bytes().enumerate().filter(|(offset, _)| !skip.contains(offset)).map(|(_, byte)| byte).collect();
        rewritten.push((from.clone(), String::from_utf8(kept).ok()?));
    }
    if apply_first(&change.old, &rewritten)? != cut.text {
        return None;
    }
    let mut edits: Vec<Value> = Vec::new();
    for (item, (_, to)) in items.iter().zip(&rewritten) {
        let mut map = item.as_object()?.clone();
        map.insert("new_string".to_owned(), Value::String(to.clone()));
        edits.push(Value::Object(map));
    }
    let mut out = input.clone();
    out.insert("edits".to_owned(), Value::Array(edits));
    Some(out)
}

struct Plus {
    line: usize,
    path: String,
    content: String,
}

fn plus_lines(command: &str) -> Vec<Plus> {
    let mut out = Vec::new();
    let mut path: Option<String> = None;
    let mut add = false;
    for (index, raw) in command.split('\n').enumerate() {
        let line = raw.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("*** Add File:") {
            path = Some(rest.trim().to_owned());
            add = true;
        } else if let Some(rest) = line.strip_prefix("*** Update File:") {
            path = Some(rest.trim().to_owned());
            add = false;
        } else if let Some(rest) = line.strip_prefix("*** Move to:") {
            if !add && path.is_some() {
                path = Some(rest.trim().to_owned());
            }
        } else if line.starts_with("*** Delete File:") || line.starts_with("*** End Patch") {
            path = None;
        } else if line.starts_with("***") || line.starts_with("@@") {
        } else if let (Some(found), Some(content)) = (path.as_ref(), line.strip_prefix('+')) {
            out.push(Plus {
                line: index,
                path: found.clone(),
                content: content.to_owned(),
            });
        }
    }
    out
}

fn patch_input(input: &Map<String, Value>, changes: &[Change], cuts: &[Option<Trimmed>]) -> Option<Map<String, Value>> {
    let command = text(input, "command")?;
    let pluses = plus_lines(command);
    let mut remove: HashSet<usize> = HashSet::new();
    for (change, cut) in changes.iter().zip(cuts) {
        let Some(cut) = cut else {
            continue;
        };
        if !cut.swapped.is_empty() {
            return None;
        }
        let lines: Vec<&str> = change.new.split('\n').collect();
        let mut need: HashMap<&str, usize> = HashMap::new();
        for index in &cut.dropped {
            let entry = need.entry(lines.get(*index).copied()?).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        for (content, count) in need {
            let hits: Vec<usize> = pluses
                .iter()
                .filter(|plus| plus.path == change.file && plus.content == content)
                .map(|plus| plus.line)
                .collect();
            if hits.len() != count {
                return None;
            }
            remove.extend(hits);
        }
    }
    let kept: Vec<&str> = command
        .split('\n')
        .enumerate()
        .filter(|(index, _)| !remove.contains(index))
        .map(|(_, line)| line)
        .collect();
    Some(with(input, "command", kept.join("\n")))
}

pub fn rewritten_input(
    provider: Provider,
    tool: &str,
    input: &Map<String, Value>,
    changes: &[Change],
    cuts: &[Option<Trimmed>],
    base: &Path,
) -> Option<Map<String, Value>> {
    if let (Provider::Codex, "apply_patch") = (provider, tool) {
        return patch_input(input, changes, cuts);
    }
    let ([change], [Some(cut)]) = (changes, cuts) else {
        return None;
    };
    match (provider, tool) {
        (Provider::Claude, "Write") => write_input(input, change, cut),
        (Provider::Claude, "Edit") => edit_input(input, change, cut),
        (Provider::Claude, "NotebookEdit") => notebook_input(input, change, cut, base),
        (Provider::Claude, "MultiEdit") => multi_edit_input(input, change, cut),
        _ => None,
    }
}
