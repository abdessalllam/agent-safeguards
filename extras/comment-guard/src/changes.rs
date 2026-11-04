use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::decision::Change;
use crate::Provider;

const MAX_OLD_FILE: u64 = 2 * 1024 * 1024;

enum Mode {
    None,
    Add,
    Update,
    Delete,
}

pub fn collect(
    tool: &str,
    input: &Map<String, Value>,
    provider: Provider,
    base: &Path,
) -> Vec<Change> {
    match (provider, tool) {
        (Provider::Claude, "Edit") => one(edit(input)),
        (Provider::Claude, "Write") => one(write(input, base)),
        (Provider::Claude, "MultiEdit") => multi_edit(input),
        (Provider::Codex, "apply_patch") => patch(input),
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

fn edit(input: &Map<String, Value>) -> Option<Change> {
    let file = text(input, "file_path")?;
    let old = text(input, "old_string")?;
    let new = text(input, "new_string")?;
    Some(Change {
        file: file.to_owned(),
        old: old.to_owned(),
        new: new.to_owned(),
    })
}

fn resolve(base: &Path, path: &str) -> PathBuf {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

fn read_old(path: &Path) -> Option<String> {
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

fn write(input: &Map<String, Value>, base: &Path) -> Option<Change> {
    let file = text(input, "file_path")?;
    let new = text(input, "content")?;
    let path = resolve(base, file);
    let old = match std::fs::metadata(&path) {
        Ok(_) => read_old(&path)?,
        Err(_) => String::new(),
    };
    Some(Change {
        file: file.to_owned(),
        old,
        new: new.to_owned(),
    })
}

fn multi_edit(input: &Map<String, Value>) -> Vec<Change> {
    let Some(file) = text(input, "file_path") else {
        return Vec::new();
    };
    let Some(Value::Array(edits)) = input.get("edits") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in edits {
        let Some(map) = item.as_object() else {
            continue;
        };
        let (Some(old), Some(new)) = (text(map, "old_string"), text(map, "new_string")) else {
            continue;
        };
        out.push(Change {
            file: file.to_owned(),
            old: old.to_owned(),
            new: new.to_owned(),
        });
    }
    out
}

fn ensure(changes: &mut Vec<Change>, lookup: &mut HashMap<String, usize>, path: &str) -> usize {
    if let Some(index) = lookup.get(path) {
        return *index;
    }
    let index = changes.len();
    changes.push(Change {
        file: path.to_owned(),
        old: String::new(),
        new: String::new(),
    });
    lookup.insert(path.to_owned(), index);
    index
}

fn push_line(changes: &mut [Change], index: usize, old: Option<&str>, new: Option<&str>) {
    if let Some(change) = changes.get_mut(index) {
        if let Some(line) = old {
            change.old.push_str(line);
            change.old.push('\n');
        }
        if let Some(line) = new {
            change.new.push_str(line);
            change.new.push('\n');
        }
    }
}

fn separate(changes: &mut [Change], lookup: &HashMap<String, usize>, path: &str) {
    if let Some(existing) = lookup.get(path) {
        push_line(changes, *existing, Some(""), Some(""));
    }
}

fn patch(input: &Map<String, Value>) -> Vec<Change> {
    let Some(command) = text(input, "command") else {
        return Vec::new();
    };
    let mut changes: Vec<Change> = Vec::new();
    let mut lookup: HashMap<String, usize> = HashMap::new();
    let mut mode = Mode::None;
    let mut path: Option<String> = None;
    let mut index: Option<usize> = None;
    let mut hunks = 0usize;
    for raw in command.split('\n') {
        let line = raw.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("*** Add File:") {
            mode = Mode::Add;
            let target = rest.trim().to_owned();
            separate(&mut changes, &lookup, &target);
            path = Some(target);
            index = None;
            hunks = 0;
        } else if let Some(rest) = line.strip_prefix("*** Update File:") {
            mode = Mode::Update;
            let target = rest.trim().to_owned();
            separate(&mut changes, &lookup, &target);
            path = Some(target);
            index = None;
            hunks = 0;
        } else if let Some(rest) = line.strip_prefix("*** Move to:") {
            if matches!(mode, Mode::Update) {
                let target = rest.trim().to_owned();
                let current = path.as_deref().and_then(|old| lookup.get(old)).copied();
                if let (Some(old_path), Some(current)) = (path.as_deref(), current) {
                    if let Some(change) = changes.get_mut(current) {
                        change.file = target.clone();
                    }
                    lookup.remove(old_path);
                    lookup.insert(target.clone(), current);
                } else {
                    separate(&mut changes, &lookup, &target);
                }
                path = Some(target);
            }
        } else if let Some(rest) = line.strip_prefix("*** Delete File:") {
            mode = Mode::Delete;
            path = Some(rest.trim().to_owned());
            index = None;
            hunks = 0;
        } else if line.starts_with("*** End Patch") {
            mode = Mode::None;
            path = None;
            index = None;
        } else if line.starts_with("***") {
        } else if line.starts_with("@@") {
            if matches!(mode, Mode::Update) {
                hunks = hunks.saturating_add(1);
                if hunks > 1 {
                    if let Some(current) = index {
                        push_line(&mut changes, current, Some(""), Some(""));
                    }
                }
            }
        } else {
            let content = line.get(1..).unwrap_or("");
            let pair = match mode {
                Mode::Add => match line.chars().next() {
                    Some('+') => Some((None, Some(content))),
                    None => Some((None, Some(""))),
                    _ => None,
                },
                Mode::Update => match line.chars().next() {
                    Some(' ') => Some((Some(content), Some(content))),
                    Some('-') => Some((Some(content), None)),
                    Some('+') => Some((None, Some(content))),
                    None => Some((Some(""), Some(""))),
                    _ => None,
                },
                Mode::Delete | Mode::None => None,
            };
            if let Some((old, new)) = pair {
                let Some(target) = path.as_deref() else {
                    continue;
                };
                let current = ensure(&mut changes, &mut lookup, target);
                index = Some(current);
                push_line(&mut changes, current, old, new);
            }
        }
    }
    changes
}
