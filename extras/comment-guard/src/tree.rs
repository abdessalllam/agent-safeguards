use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::changes::MAX_OLD_FILE;
use crate::decision::{evaluate, Change};
use crate::languages::language_for;
use crate::{Verdict, MAX_INPUT};

const OPERATION_MARKERS: [&str; 6] = [
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "SQUASH_MSG",
    "rebase-merge",
    "rebase-apply",
];

struct Entry {
    old: Option<String>,
    new: String,
}

pub fn judge_tree(tree: &str) -> Verdict {
    if !is_object_id(tree) {
        return Verdict::BadInput;
    }
    if operation_in_progress() {
        return Verdict::Allow;
    }
    let Some(base) = base_tree() else {
        return Verdict::BadInput;
    };
    let Some(raw) = git_output(
        &["diff-tree", "-r", "-z", "--name-status", "--find-renames", &base, tree],
        None,
    ) else {
        return Verdict::BadInput;
    };
    let entries = parse_entries(&raw);
    if entries.is_empty() {
        return Verdict::Allow;
    }
    let Some(changes) = read_changes(tree, &base, &entries) else {
        return Verdict::BadInput;
    };
    match evaluate(&changes) {
        Some(reason) => Verdict::Deny(reason),
        None => Verdict::Allow,
    }
}

fn is_object_id(text: &str) -> bool {
    matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn git_output(args: &[&str], input: Option<Vec<u8>>) -> Option<Vec<u8>> {
    let mut command = Command::new("git");
    command.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    command.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = command.spawn().ok()?;
    let writer = match (input, child.stdin.take()) {
        (Some(bytes), Some(mut stdin)) => Some(std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        })),
        _ => None,
    };
    let output = child.wait_with_output().ok();
    if let Some(handle) = writer {
        let _ = handle.join();
    }
    let output = output?;
    output.status.success().then_some(output.stdout)
}

fn operation_in_progress() -> bool {
    let Some(raw) = git_output(&["rev-parse", "--git-dir"], None) else {
        return false;
    };
    let dir = String::from_utf8_lossy(&raw).trim().to_owned();
    OPERATION_MARKERS
        .iter()
        .any(|name| Path::new(&dir).join(name).exists())
}

fn base_tree() -> Option<String> {
    let raw = git_output(&["rev-parse", "-q", "--verify", "HEAD^{tree}"], None)
        .or_else(|| git_output(&["hash-object", "-t", "tree", "/dev/null"], None))?;
    let id = String::from_utf8(raw).ok()?.trim().to_owned();
    is_object_id(&id).then_some(id)
}

fn readable_path(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    (!text.is_empty() && !text.contains('\n')).then(|| text.to_owned())
}

fn push_entry(entries: &mut Vec<Entry>, old: Option<&[u8]>, new: &[u8]) {
    let Some(new) = readable_path(new) else {
        return;
    };
    let old = match old {
        Some(bytes) => match readable_path(bytes) {
            Some(path) => Some(path),
            None => return,
        },
        None => None,
    };
    if language_for(&new).is_some() {
        entries.push(Entry { old, new });
    }
}

fn parse_entries(raw: &[u8]) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut parts = raw.split(|byte| *byte == 0);
    while let Some(status) = parts.next() {
        let Some(kind) = status.first().copied() else {
            continue;
        };
        match kind {
            b'R' | b'C' => {
                let (Some(old), Some(new)) = (parts.next(), parts.next()) else {
                    break;
                };
                push_entry(&mut entries, Some(old), new);
            }
            b'A' => {
                let Some(new) = parts.next() else {
                    break;
                };
                push_entry(&mut entries, None, new);
            }
            b'M' | b'T' => {
                let Some(path) = parts.next() else {
                    break;
                };
                push_entry(&mut entries, Some(path), path);
            }
            _ => {
                if parts.next().is_none() {
                    break;
                }
            }
        }
    }
    entries
}

fn parse_sizes(report: &[u8]) -> Vec<Option<u64>> {
    String::from_utf8_lossy(report)
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            match fields.as_slice() {
                [_, "blob", size] => size.parse().ok(),
                _ => None,
            }
        })
        .collect()
}

fn parse_batch(raw: &[u8], count: usize) -> Option<Vec<Vec<u8>>> {
    let mut blobs = Vec::new();
    let mut at = 0usize;
    for _ in 0..count {
        let rest = raw.get(at..)?;
        let newline = rest.iter().position(|byte| *byte == b'\n')?;
        let header = std::str::from_utf8(rest.get(..newline)?).ok()?;
        let fields: Vec<&str> = header.split(' ').collect();
        let [_, "blob", size] = fields.as_slice() else {
            return None;
        };
        let size: usize = size.parse().ok()?;
        let start = at.checked_add(newline)?.checked_add(1)?;
        let end = start.checked_add(size)?;
        blobs.push(raw.get(start..end)?.to_vec());
        at = end.checked_add(1)?;
    }
    Some(blobs)
}

fn read_changes(tree: &str, base: &str, entries: &[Entry]) -> Option<Vec<Change>> {
    let mut specs = String::new();
    let mut count = 0usize;
    for entry in entries {
        specs.push_str(&format!("{tree}:{}\n", entry.new));
        count = count.saturating_add(1);
        if let Some(old) = &entry.old {
            specs.push_str(&format!("{base}:{old}\n"));
            count = count.saturating_add(1);
        }
    }
    let report = git_output(&["cat-file", "--batch-check"], Some(specs.into_bytes()))?;
    let sizes = parse_sizes(&report);
    if sizes.len() != count {
        return None;
    }
    let mut sizes = sizes.into_iter();
    let mut budget = MAX_INPUT as u64;
    let mut chosen: Vec<&Entry> = Vec::new();
    let mut fetch = String::new();
    let mut wanted = 0usize;
    for entry in entries {
        let new_size = sizes.next()?;
        let old_size = if entry.old.is_some() {
            sizes.next()?
        } else {
            Some(0)
        };
        let (Some(new_size), Some(old_size)) = (new_size, old_size) else {
            continue;
        };
        let cost = new_size.saturating_add(old_size);
        if new_size > MAX_OLD_FILE || old_size > MAX_OLD_FILE || cost > budget {
            continue;
        }
        budget = budget.saturating_sub(cost);
        chosen.push(entry);
        fetch.push_str(&format!("{tree}:{}\n", entry.new));
        wanted = wanted.saturating_add(1);
        if let Some(old) = &entry.old {
            fetch.push_str(&format!("{base}:{old}\n"));
            wanted = wanted.saturating_add(1);
        }
    }
    if chosen.is_empty() {
        return Some(Vec::new());
    }
    let raw = git_output(&["cat-file", "--batch"], Some(fetch.into_bytes()))?;
    let mut blobs = parse_batch(&raw, wanted)?.into_iter();
    let mut changes = Vec::new();
    for entry in chosen {
        let new = blobs.next()?;
        let old = if entry.old.is_some() {
            Some(blobs.next()?)
        } else {
            None
        };
        let Ok(new) = String::from_utf8(new) else {
            continue;
        };
        let old = match old {
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => continue,
            },
            None => String::new(),
        };
        changes.push(Change::whole(entry.new.clone(), old, new));
    }
    Some(changes)
}

#[cfg(test)]
mod tests {
    use super::{is_object_id, parse_batch, parse_entries, parse_sizes, readable_path};

    fn names(raw: &[u8]) -> Vec<(Option<String>, String)> {
        parse_entries(raw)
            .into_iter()
            .map(|entry| (entry.old, entry.new))
            .collect()
    }

    #[test]
    fn object_ids_are_lowercase_hex_of_a_known_length() {
        assert!(is_object_id(&"a".repeat(40)));
        assert!(is_object_id(&"0".repeat(64)));
        assert!(!is_object_id(&"a".repeat(41)));
        assert!(!is_object_id(&"A".repeat(40)));
        assert!(!is_object_id("HEAD"));
        assert!(!is_object_id(""));
    }

    #[test]
    fn entries_keep_added_modified_and_renamed_source_files() {
        let raw = b"A\0new.py\0M\0keep.rs\0D\0gone.py\0R087\0old.py\0moved.py\0A\0notes.md\0";
        assert_eq!(
            names(raw),
            vec![
                (None, "new.py".to_owned()),
                (Some("keep.rs".to_owned()), "keep.rs".to_owned()),
                (Some("old.py".to_owned()), "moved.py".to_owned()),
            ]
        );
    }

    #[test]
    fn entries_stop_at_a_truncated_record() {
        assert_eq!(names(b"A\0a.py\0R100\0only-one.py").len(), 1);
        assert!(names(b"").is_empty());
    }

    #[test]
    fn paths_with_a_newline_or_bad_bytes_are_skipped() {
        assert!(readable_path(b"a\nb.py").is_none());
        assert!(readable_path(&[0xff, b'.', b'p', b'y']).is_none());
        assert!(readable_path(b"").is_none());
        assert_eq!(readable_path(b"dir/a b.py").as_deref(), Some("dir/a b.py"));
    }

    #[test]
    fn sizes_read_blobs_and_mark_everything_else_unusable() {
        let report = b"abc blob 12\nt:missing.py missing\nabc tree 4\nabc blob x\n";
        assert_eq!(parse_sizes(report), vec![Some(12), None, None, None]);
    }

    #[test]
    fn batch_output_is_cut_by_the_stated_sizes() {
        let raw = b"id1 blob 3\na\nb\nid2 blob 0\n\nid3 blob 2\nxy\n";
        let blobs = parse_batch(raw, 3).unwrap_or_default();
        assert_eq!(
            blobs,
            vec![b"a\nb".to_vec(), Vec::new(), b"xy".to_vec()]
        );
        assert!(parse_batch(raw, 4).is_none());
        assert!(parse_batch(b"id1 blob 99\nshort\n", 1).is_none());
        assert!(parse_batch(b"id1 tree 3\nabc\n", 1).is_none());
    }
}
