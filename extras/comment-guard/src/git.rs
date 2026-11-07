use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::changes::{resolve, MAX_OLD_FILE};
use crate::decision::{comment_lines, Change};
use crate::languages::language_for_text;
use crate::session::content_hash;

const GIT_TIME: Duration = Duration::from_millis(1000);

pub struct Ran {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

fn reader<R: Read + Send + 'static>(source: R, limit: u64) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = source.take(limit).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    receiver
}

pub fn run_git(dir: &Path, args: &[&str], input: Option<&[u8]>, deadline: Instant) -> Option<Ran> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        let data = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let stdout = reader(out, MAX_OLD_FILE.saturating_add(1));
    let stderr = reader(err, 4096);
    let limit = deadline.min(Instant::now() + GIT_TIME);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < limit => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let wait = limit
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(100));
    let stdout = stdout.recv_timeout(wait).ok()?;
    let stderr = stderr.recv_timeout(wait).ok()?;
    Some(Ran {
        success: status.success(),
        stdout,
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

pub fn inside_repository(dir: &Path) -> bool {
    repository_root(dir).is_some()
}

fn repository_root(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .find(|folder| folder.join(".git").exists())
        .map(Path::to_path_buf)
}

fn marked_paths(raw: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    let parts: Vec<&[u8]> = raw.split(|byte| *byte == 0).collect();
    for chunk in parts.chunks(3) {
        let [path, attribute, value] = chunk else {
            continue;
        };
        let skip = matches!(
            (*attribute, *value),
            (b"comment-guard", b"skip" | b"set")
                | (b"linguist-vendored" | b"linguist-generated", b"set" | b"true")
        );
        if !skip {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(path) {
            out.insert(text.to_owned());
        }
    }
    out
}

pub fn drop_marked(changes: &mut Vec<Change>, base: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut absolute: Vec<Option<PathBuf>> = Vec::new();
    let mut by_root: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    for change in changes.iter() {
        let path = std::path::absolute(resolve(base, &change.file)).ok();
        let dir = path
            .as_ref()
            .and_then(|file| file.ancestors().skip(1).find(|folder| folder.is_dir()));
        let root = dir.and_then(repository_root);
        if let (Some(root), Some(file)) = (root, path.as_ref().and_then(|file| file.to_str())) {
            let input = by_root.entry(root).or_default();
            input.extend_from_slice(file.as_bytes());
            input.push(0);
        }
        absolute.push(path);
    }
    let mut marked: HashSet<String> = HashSet::new();
    let args = [
        "check-attr",
        "-z",
        "--stdin",
        "comment-guard",
        "linguist-vendored",
        "linguist-generated",
    ];
    for (root, input) in &by_root {
        if Instant::now() >= deadline {
            break;
        }
        if let Some(ran) = run_git(root, &args, Some(input), deadline) {
            if ran.success {
                marked.extend(marked_paths(&ran.stdout));
            }
        }
    }
    let mut index = 0usize;
    changes.retain(|_| {
        let name = absolute
            .get(index)
            .and_then(|path| path.as_ref())
            .and_then(|path| path.to_str());
        index = index.saturating_add(1);
        match name {
            Some(path) => !marked.contains(path),
            None => true,
        }
    });
}

const KNOWN_MIN: usize = 20;
const KNOWN_FILES: usize = 20000;
const KNOWN_FILE_BYTES: u64 = 1024 * 1024;
const KNOWN_BYTES: u64 = 64 * 1024 * 1024;
const KNOWN_TIME: Duration = Duration::from_secs(3);

fn listed(root: &Path, extension: &str, deadline: Instant) -> Vec<PathBuf> {
    let pattern = format!("*.{extension}");
    let args = ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", pattern.as_str()];
    match run_git(root, &args, None, deadline) {
        Some(ran) if ran.success => ran
            .stdout
            .split(|byte| *byte == 0)
            .filter_map(|part| std::str::from_utf8(part).ok())
            .filter(|name| !name.is_empty())
            .map(|name| root.join(name))
            .collect(),
        _ => Vec::new(),
    }
}

fn known_lines(files: &[PathBuf], skip: &HashSet<PathBuf>, deadline: Instant) -> HashSet<u64> {
    let mut known: HashSet<u64> = HashSet::new();
    let mut spent = 0u64;
    for file in files.iter().take(KNOWN_FILES) {
        if Instant::now() >= deadline || spent >= KNOWN_BYTES {
            break;
        }
        if skip.contains(file) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(file) else {
            continue;
        };
        if !meta.is_file() || meta.len() > KNOWN_FILE_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        spent = spent.saturating_add(bytes.len() as u64);
        for line in String::from_utf8_lossy(&bytes).split('\n') {
            let line = line.trim();
            if line.chars().count() >= KNOWN_MIN {
                known.insert(content_hash(line));
            }
        }
    }
    known
}

fn merge_known(change: &mut Change, known: &HashSet<u64>) -> bool {
    let Some(lang) = language_for_text(&change.file, &change.new) else {
        return false;
    };
    let mut merged = change.baseline.clone().unwrap_or_else(|| comment_lines(&change.old, lang));
    let mut held: HashMap<String, usize> = HashMap::new();
    for line in &merged {
        *held.entry(line.clone()).or_insert(0) += 1;
    }
    let mut grown = false;
    for line in comment_lines(&change.new, lang) {
        if line.chars().count() < KNOWN_MIN || !known.contains(&content_hash(&line)) {
            continue;
        }
        match held.get_mut(&line) {
            Some(count) if *count > 0 => *count -= 1,
            _ => {
                merged.push(line);
                grown = true;
            }
        }
    }
    if grown {
        change.baseline = Some(merged);
    }
    grown
}

pub fn widen_with_known(changes: &mut [Change], base: &Path) -> Vec<String> {
    let deadline = Instant::now() + KNOWN_TIME;
    let mut groups: HashMap<(PathBuf, String), Vec<usize>> = HashMap::new();
    let mut written: HashMap<PathBuf, HashSet<PathBuf>> = HashMap::new();
    for (index, change) in changes.iter().enumerate() {
        let extension = Path::new(&change.file)
            .extension()
            .and_then(|found| found.to_str())
            .map(str::to_ascii_lowercase)
            .filter(|found| !found.is_empty() && found.chars().all(|c| c.is_ascii_alphanumeric()));
        let (false, Some(extension), Ok(path)) = (change.partial, extension, std::path::absolute(resolve(base, &change.file))) else {
            continue;
        };
        let Some(root) = path.ancestors().skip(1).find(|folder| folder.is_dir()).and_then(repository_root) else {
            continue;
        };
        written.entry(root.clone()).or_default().insert(path);
        groups.entry((root, extension)).or_default().push(index);
    }
    let mut widened: Vec<String> = Vec::new();
    for ((root, extension), members) in groups {
        if Instant::now() >= deadline {
            break;
        }
        let files = listed(&root, &extension, deadline);
        let known = known_lines(&files, written.get(&root).unwrap_or(&HashSet::new()), deadline);
        if known.is_empty() {
            continue;
        }
        for index in members {
            if let Some(change) = changes.get_mut(index) {
                if merge_known(change, &known) {
                    widened.push(change.file.clone());
                }
            }
        }
    }
    widened
}

#[cfg(test)]
mod tests {
    use super::marked_paths;

    fn triples(items: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, attribute, value) in items {
            for part in [path, attribute, value] {
                out.extend_from_slice(part.as_bytes());
                out.push(0);
            }
        }
        out
    }

    #[test]
    fn only_the_listed_attribute_values_mark_a_file() {
        let none = [
            ("a.py", "comment-guard", "unspecified"),
            ("a.py", "linguist-vendored", "unspecified"),
            ("a.py", "linguist-generated", "unspecified"),
        ];
        assert!(marked_paths(&triples(&none)).is_empty());
        assert!(marked_paths(&triples(&[("a.py", "comment-guard", "skip")])).contains("a.py"));
        assert!(marked_paths(&triples(&[("a.py", "comment-guard", "set")])).contains("a.py"));
        assert!(marked_paths(&triples(&[("a.py", "linguist-vendored", "set")])).contains("a.py"));
        assert!(marked_paths(&triples(&[("a.py", "linguist-generated", "true")])).contains("a.py"));
        assert!(marked_paths(&triples(&[("a.py", "comment-guard", "unset")])).is_empty());
        assert!(marked_paths(&triples(&[("a.py", "linguist-vendored", "false")])).is_empty());
        assert!(marked_paths(&triples(&[("a.py", "comment-guard", "other")])).is_empty());
        assert!(marked_paths(b"").is_empty());
    }

    #[test]
    fn several_paths_in_one_answer_are_told_apart() {
        let answer = triples(&[
            ("up/a.py", "comment-guard", "skip"),
            ("up/a.py", "linguist-vendored", "unspecified"),
            ("own/b.py", "comment-guard", "unspecified"),
            ("own/b.py", "linguist-vendored", "unspecified"),
            ("gen/c.py", "linguist-generated", "set"),
        ]);
        let marked = marked_paths(&answer);
        assert!(marked.contains("up/a.py"));
        assert!(marked.contains("gen/c.py"));
        assert!(!marked.contains("own/b.py"));
    }
}
