use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::decision::Change;
use crate::{Provider, MAX_INPUT};

pub const MAX_OLD_FILE: u64 = 2 * 1024 * 1024;
const MAX_WORK: usize = 64 * 1024 * 1024;
const MAX_HUNKS: usize = 2000;
const MAX_STARTS: usize = 5_000_000;

struct Work {
    left: usize,
    out: bool,
}

impl Work {
    fn new(left: usize) -> Work {
        Work { left, out: false }
    }

    fn spend(&mut self, amount: usize) -> bool {
        if amount > self.left {
            self.out = true;
            return false;
        }
        self.left = self.left.saturating_sub(amount);
        true
    }
}

#[derive(Default)]
struct Hunk {
    old: Vec<String>,
    new: Vec<String>,
    anchors: Vec<String>,
}

struct Section {
    path: String,
    source: Option<String>,
    add: bool,
    hunks: Vec<Hunk>,
}

pub fn collect(
    tool: &str,
    input: &Map<String, Value>,
    provider: Provider,
    base: &Path,
) -> Vec<Change> {
    match (provider, tool) {
        (Provider::Claude, "Edit") => one(edit(input, base)),
        (Provider::Claude, "Write") => one(write(input, base)),
        (Provider::Claude, "MultiEdit") => multi_edit(input, base),
        (Provider::Codex, "apply_patch") => patch(input, base),
        _ => Vec::new(),
    }
}

fn one(change: Option<Change>) -> Vec<Change> {
    match change {
        Some(value) => vec![value],
        None => Vec::new(),
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

pub fn resolve(base: &Path, path: &str) -> PathBuf {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

pub fn read_old(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_OLD_FILE {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_OLD_FILE.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_OLD_FILE {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn current_text(path: &Path) -> Option<String> {
    match std::fs::metadata(path) {
        Ok(_) => read_old(path),
        Err(_) => Some(String::new()),
    }
}

fn replace(current: &str, old: &str, new: &str, all: bool) -> Option<String> {
    if old.is_empty() {
        return current.is_empty().then(|| new.to_owned());
    }
    let count = if all {
        current.matches(old).count()
    } else {
        usize::from(current.contains(old))
    };
    if count == 0 {
        return None;
    }
    let projected = current
        .len()
        .saturating_sub(count.saturating_mul(old.len()))
        .saturating_add(count.saturating_mul(new.len()));
    if projected > MAX_INPUT {
        return None;
    }
    Some(if all {
        current.replace(old, new)
    } else {
        current.replacen(old, new, 1)
    })
}

fn edit(input: &Map<String, Value>, base: &Path) -> Option<Change> {
    let file = text(input, "file_path")?;
    let old = text(input, "old_string")?;
    let new = text(input, "new_string")?;
    let all = input.get("replace_all").and_then(Value::as_bool).unwrap_or(false);
    if let Some(current) = current_text(&resolve(base, file)) {
        if let Some(next) = replace(&current, old, new, all) {
            return Some(Change::whole(file.to_owned(), current, next));
        }
    }
    Some(Change::partial(file.to_owned(), old.to_owned(), new.to_owned()))
}

fn write(input: &Map<String, Value>, base: &Path) -> Option<Change> {
    let file = text(input, "file_path")?;
    let new = text(input, "content")?;
    let old = current_text(&resolve(base, file))?;
    Some(Change::whole(file.to_owned(), old, new.to_owned()))
}

fn multi_edit(input: &Map<String, Value>, base: &Path) -> Vec<Change> {
    let Some(file) = text(input, "file_path") else {
        return Vec::new();
    };
    let Some(Value::Array(edits)) = input.get("edits") else {
        return Vec::new();
    };
    let mut pairs: Vec<(&str, &str, bool)> = Vec::new();
    for item in edits {
        let Some(map) = item.as_object() else {
            continue;
        };
        let (Some(old), Some(new)) = (text(map, "old_string"), text(map, "new_string")) else {
            continue;
        };
        let all = map.get("replace_all").and_then(Value::as_bool).unwrap_or(false);
        pairs.push((old, new, all));
    }
    if let Some(current) = current_text(&resolve(base, file)) {
        let mut work = Work::new(MAX_WORK);
        let mut next = current.clone();
        let mut applied = true;
        for (old, new, all) in &pairs {
            if !work.spend(next.len()) {
                return Vec::new();
            }
            match replace(&next, old, new, *all) {
                Some(done) => next = done,
                None => {
                    applied = false;
                    break;
                }
            }
        }
        if applied {
            return vec![Change::whole(file.to_owned(), current, next)];
        }
    }
    pairs
        .into_iter()
        .map(|(old, new, _)| Change::partial(file.to_owned(), old.to_owned(), new.to_owned()))
        .collect()
}

fn flush(section: &mut Section, hunk: &mut Hunk) {
    let taken = std::mem::take(hunk);
    if !taken.old.is_empty() || !taken.new.is_empty() {
        section.hunks.push(taken);
    }
}

fn finish(out: &mut Vec<Section>, current: &mut Option<Section>, hunk: &mut Hunk) {
    if let Some(mut section) = current.take() {
        flush(&mut section, hunk);
        out.push(section);
    }
}

fn sections(command: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    let mut current: Option<Section> = None;
    let mut hunk = Hunk::default();
    for raw in command.split('\n') {
        let line = raw.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("*** Add File:") {
            finish(&mut out, &mut current, &mut hunk);
            current = Some(Section {
                path: rest.trim().to_owned(),
                source: None,
                add: true,
                hunks: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("*** Update File:") {
            finish(&mut out, &mut current, &mut hunk);
            current = Some(Section {
                path: rest.trim().to_owned(),
                source: Some(rest.trim().to_owned()),
                add: false,
                hunks: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("*** Move to:") {
            if let Some(section) = current.as_mut() {
                if !section.add {
                    section.path = rest.trim().to_owned();
                }
            }
        } else if line.starts_with("*** Delete File:") || line.starts_with("*** End Patch") {
            finish(&mut out, &mut current, &mut hunk);
        } else if line.starts_with("***") {
        } else if let Some(rest) = line.strip_prefix("@@") {
            if let Some(section) = current.as_mut() {
                if !section.add {
                    if !hunk.old.is_empty() || !hunk.new.is_empty() {
                        flush(section, &mut hunk);
                    }
                    let anchor = rest.strip_prefix(' ').unwrap_or(rest);
                    if !anchor.trim().is_empty() {
                        hunk.anchors.push(anchor.to_owned());
                    }
                }
            }
        } else if let Some(section) = current.as_ref() {
            let content = line.get(1..).unwrap_or("").to_owned();
            match (section.add, line.chars().next()) {
                (true, Some('+')) => hunk.new.push(content),
                (true, None) => hunk.new.push(String::new()),
                (false, Some(' ')) => {
                    hunk.old.push(content.clone());
                    hunk.new.push(content);
                }
                (false, Some('-')) => hunk.old.push(content),
                (false, Some('+')) => hunk.new.push(content),
                (false, None) => {
                    hunk.old.push(String::new());
                    hunk.new.push(String::new());
                }
                _ => {}
            }
        }
    }
    finish(&mut out, &mut current, &mut hunk);
    out
}

fn fragments(hunks: &[Hunk], old: bool) -> String {
    hunks
        .iter()
        .map(|hunk| if old { hunk.old.join("\n") } else { hunk.new.join("\n") })
        .collect::<Vec<String>>()
        .join("\n\n")
}

fn find_chunk(lines: &[String], chunk: &[String], from: usize, starts: &mut Work) -> Option<usize> {
    let last = lines.len().checked_sub(chunk.len())?;
    for origin in [from, 0] {
        for level in 0..3u8 {
            let same = |a: &str, b: &str| match level {
                0 => a == b,
                1 => a.trim_end() == b.trim_end(),
                _ => a.trim() == b.trim(),
            };
            let mut at = origin;
            while at <= last {
                if !starts.spend(1) {
                    return None;
                }
                let hit = chunk.iter().enumerate().all(|(offset, line)| {
                    lines
                        .get(at.saturating_add(offset))
                        .is_some_and(|candidate| same(candidate, line))
                });
                if hit {
                    return Some(at);
                }
                at = at.saturating_add(1);
            }
        }
        if from == 0 {
            break;
        }
    }
    None
}

fn apply_hunks(content: &str, hunks: &[Hunk], starts: &mut Work) -> Option<String> {
    if hunks.len() > MAX_HUNKS {
        return None;
    }
    let mut lines: Vec<String> = if content.is_empty() {
        Vec::new()
    } else {
        content.split('\n').map(str::to_owned).collect()
    };
    if content.ends_with('\n') {
        lines.pop();
    }
    let mut cursor = 0usize;
    for hunk in hunks {
        for anchor in &hunk.anchors {
            let at = find_chunk(&lines, std::slice::from_ref(anchor), cursor, starts)?;
            cursor = at.saturating_add(1);
        }
        if hunk.old.is_empty() {
            lines.extend(hunk.new.iter().cloned());
            cursor = lines.len();
            continue;
        }
        let at = find_chunk(&lines, &hunk.old, cursor, starts)?;
        let end = at.saturating_add(hunk.old.len());
        lines.splice(at..end, hunk.new.iter().cloned());
        cursor = at.saturating_add(hunk.new.len());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Some(out)
}

fn assemble(
    changes: &mut Vec<Change>,
    lookup: &mut HashMap<String, usize>,
    section: Section,
    base: &Path,
    budget: &mut (Work, Work),
) {
    if section.add {
        let content = fragments(&section.hunks, false);
        match lookup.get(&section.path).copied().and_then(|at| changes.get_mut(at)) {
            Some(change) => {
                change.new.push_str("\n\n");
                change.new.push_str(&content);
            }
            None => {
                lookup.insert(section.path.clone(), changes.len());
                changes.push(Change::whole(section.path, String::new(), content));
            }
        }
        return;
    }
    let source = section.source.clone().unwrap_or_else(|| section.path.clone());
    let previous = lookup.get(&source).copied();
    let current = match previous.and_then(|at| changes.get(at)) {
        Some(change) if change.partial => None,
        Some(change) => Some(change.new.clone()),
        None => read_old(&resolve(base, &source)),
    };
    if current.as_ref().is_some_and(|text| !budget.0.spend(text.len())) {
        return;
    }
    let applied = current
        .as_deref()
        .and_then(|text| apply_hunks(text, &section.hunks, &mut budget.1));
    if applied.is_none() && budget.1.out {
        return;
    }
    lookup.remove(&source);
    let target = section.path.clone();
    let moved = target != source;
    if let Some(change) = previous.and_then(|at| changes.get_mut(at)) {
        match applied {
            Some(next) => change.new = next,
            None => {
                change.partial = true;
                change.old.push_str("\n\n");
                change.old.push_str(&fragments(&section.hunks, true));
                change.new.push_str("\n\n");
                change.new.push_str(&fragments(&section.hunks, false));
            }
        }
        change.file = target.clone();
        if moved && change.origin.is_none() {
            change.origin = Some(source);
        }
        if let Some(at) = previous {
            lookup.insert(target, at);
        }
        return;
    }
    lookup.insert(target.clone(), changes.len());
    let mut change = match (applied, current) {
        (Some(next), Some(old)) => Change::whole(target, old, next),
        _ => Change::partial(
            target,
            fragments(&section.hunks, true),
            fragments(&section.hunks, false),
        ),
    };
    if moved {
        change.origin = Some(source);
    }
    changes.push(change);
}

fn patch(input: &Map<String, Value>, base: &Path) -> Vec<Change> {
    let Some(command) = text(input, "command") else {
        return Vec::new();
    };
    let mut changes: Vec<Change> = Vec::new();
    let mut lookup: HashMap<String, usize> = HashMap::new();
    let mut budget = (Work::new(MAX_WORK), Work::new(MAX_STARTS));
    for section in sections(command) {
        assemble(&mut changes, &mut lookup, section, base, &mut budget);
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::{replace, Work};

    #[test]
    fn a_replacement_that_would_grow_past_the_input_limit_is_refused() {
        let big = "b".repeat(4 * 1024 * 1024);
        assert!(replace("aaaa", "a", &big, true).is_none());
        assert_eq!(replace("aaaa", "a", "bb", true).as_deref(), Some("bbbbbbbb"));
        assert_eq!(replace("aaaa", "a", "bb", false).as_deref(), Some("bbaaa"));
        assert!(replace("abc", "z", "y", true).is_none());
        assert_eq!(replace("", "", "new", false).as_deref(), Some("new"));
        assert!(replace("x", "", "new", false).is_none());
    }

    #[test]
    fn the_work_budget_is_spent_and_refuses_more() {
        let mut work = Work::new(10);
        assert!(work.spend(6));
        assert!(!work.spend(5));
        assert!(work.spend(4));
        assert!(!work.spend(1));
    }
}
