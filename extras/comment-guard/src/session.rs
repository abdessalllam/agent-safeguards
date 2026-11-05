use std::cell::Cell;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

const RETENTION: Duration = Duration::from_secs(14 * 24 * 60 * 60);
const PRUNE_LIMIT: usize = 200;
const PRUNE_VISITS: usize = 2000;

pub struct Ledger {
    dir: PathBuf,
    session: u64,
    pruned: Cell<bool>,
}

fn hash(text: &str) -> u64 {
    let mut value: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        value ^= u64::from(byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value
}

fn absolute_dir(variable: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var(variable).ok()?);
    path.is_absolute().then_some(path)
}

pub fn state_dir() -> Option<PathBuf> {
    let root = match absolute_dir("XDG_STATE_HOME") {
        Some(path) => path,
        None => absolute_dir("HOME")?.join(".local").join("state"),
    };
    Some(root.join("agent-safeguards").join("comment-guard"))
}

fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn identity(path: &Path) -> String {
    let resolved = fs::canonicalize(path).unwrap_or_else(|_| {
        match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => fs::canonicalize(parent)
                .map(|dir| dir.join(name))
                .unwrap_or_else(|_| lexical(path)),
            _ => lexical(path),
        }
    });
    resolved.to_string_lossy().into_owned()
}

fn hex16(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn owned(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix(".tmp-") {
        return rest
            .split_once('-')
            .is_some_and(|(pid, nanos)| digits(pid) && digits(nanos));
    }
    let stem = name
        .strip_suffix(".json")
        .or_else(|| name.strip_suffix(".stamp"));
    stem.and_then(|stem| stem.split_once('-'))
        .is_some_and(|(session, entry)| hex16(session) && hex16(entry))
}

impl Ledger {
    pub fn open(dir: &Path, session: &str) -> Option<Ledger> {
        if session.is_empty() {
            return None;
        }
        fs::create_dir_all(dir).ok()?;
        Some(Ledger {
            dir: dir.to_path_buf(),
            session: hash(session),
            pruned: Cell::new(false),
        })
    }

    fn entry(&self, identity: &str) -> PathBuf {
        self.dir
            .join(format!("{:016x}-{:016x}.json", self.session, hash(identity)))
    }

    fn stamp(&self, key: &str) -> PathBuf {
        self.dir
            .join(format!("{:016x}-{:016x}.stamp", self.session, hash(key)))
    }

    fn temp(&self) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        self.dir
            .join(format!(".tmp-{}-{nanos}", std::process::id()))
    }

    pub fn read(&self, identity: &str) -> Option<Vec<String>> {
        let raw = fs::read_to_string(self.entry(identity)).ok()?;
        let value: Value = serde_json::from_str(&raw).ok()?;
        if value.get("path")?.as_str()? != identity {
            return None;
        }
        value
            .get("comments")?
            .as_array()?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect()
    }

    pub fn baseline(&self, identity: &str, current: impl FnOnce() -> Vec<String>) -> Vec<String> {
        if let Some(found) = self.read(identity) {
            return found;
        }
        let comments = current();
        let body = json!({ "path": identity, "comments": comments }).to_string();
        let temp = self.temp();
        let written = fs::File::create(&temp)
            .and_then(|mut file| file.write_all(body.as_bytes()))
            .is_ok();
        let outcome = if written {
            fs::hard_link(&temp, self.entry(identity))
        } else {
            Err(std::io::Error::from(ErrorKind::Other))
        };
        let _ = fs::remove_file(&temp);
        match outcome {
            Ok(()) => {
                self.prune();
                comments
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                self.read(identity).unwrap_or(comments)
            }
            Err(_) => comments,
        }
    }

    pub fn last_check(&self, key: &str) -> Option<SystemTime> {
        fs::metadata(self.stamp(key)).ok()?.modified().ok()
    }

    pub fn mark_check(&self, key: &str) {
        let temp = self.temp();
        if fs::write(&temp, b"").is_err() {
            return;
        }
        if fs::rename(&temp, self.stamp(key)).is_err() {
            let _ = fs::remove_file(&temp);
        }
    }

    fn prune(&self) {
        if self.pruned.replace(true) {
            return;
        }
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let now = SystemTime::now();
        let mut removed = 0usize;
        for (visited, entry) in entries.flatten().enumerate() {
            if removed >= PRUNE_LIMIT || visited >= PRUNE_VISITS {
                break;
            }
            if !owned(&entry.file_name().to_string_lossy()) {
                continue;
            }
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            let old = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age > RETENTION);
            if old && fs::remove_file(entry.path()).is_ok() {
                removed = removed.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{hash, identity, lexical, owned, Ledger, RETENTION};
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("comment-guard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn age(path: &Path, extra_days: u64) {
        let old = SystemTime::now() - RETENTION - Duration::from_secs(extra_days * 86400);
        let file = std::fs::OpenOptions::new().write(true).open(path).expect("open");
        file.set_modified(old).expect("set time");
    }

    #[test]
    fn the_first_baseline_wins() {
        let dir = scratch("first");
        let ledger = Ledger::open(&dir, "session-a").expect("ledger");
        let first = ledger.baseline("/x/a.py", || vec!["# one".to_owned()]);
        let second = ledger.baseline("/x/a.py", || vec!["# one".to_owned(), "# two".to_owned()]);
        assert_eq!(first, vec!["# one".to_owned()]);
        assert_eq!(second, first);
        assert!(ledger.read("/x/b.py").is_none());
        let other = Ledger::open(&dir, "session-b").expect("ledger");
        assert!(other.read("/x/a.py").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_session_has_no_ledger() {
        let dir = scratch("empty");
        assert!(Ledger::open(&dir, "").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_stamps_are_kept_per_folder() {
        let dir = scratch("stamp");
        let ledger = Ledger::open(&dir, "session-c").expect("ledger");
        assert!(ledger.last_check("/a").is_none());
        ledger.mark_check("/a");
        assert!(ledger.last_check("/a").is_some());
        assert!(ledger.last_check("/b").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_stamp_that_is_a_symlink_is_replaced_not_followed() {
        let dir = scratch("symlink");
        let outside_dir = scratch("symlink-outside");
        let outside = outside_dir.join("victim.txt");
        std::fs::write(&outside, "keep me").expect("write");
        let ledger = Ledger::open(&dir, "session-d").expect("ledger");
        std::os::unix::fs::symlink(&outside, ledger.stamp("/a")).expect("link");
        ledger.mark_check("/a");
        assert_eq!(std::fs::read_to_string(&outside).expect("read"), "keep me");
        let kind = std::fs::symlink_metadata(ledger.stamp("/a")).expect("meta").file_type();
        assert!(!kind.is_symlink());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside_dir);
    }

    #[test]
    fn paths_are_cleaned_and_hashes_differ() {
        assert_eq!(lexical(Path::new("/a/./b/../c.py")), Path::new("/a/c.py"));
        assert_ne!(hash("/a/a.py"), hash("/a/b.py"));
        let dir = scratch("identity");
        let file = dir.join("a.py");
        let _ = std::fs::write(&file, "x = 1\n");
        let plain = identity(&file);
        let dotted = identity(&dir.join(".").join("a.py"));
        assert_eq!(plain, dotted);
        let missing = identity(&dir.join("new.py"));
        assert!(missing.ends_with("new.py"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_files_in_the_tools_own_format_are_owned() {
        assert!(owned("0123456789abcdef-fedcba9876543210.json"));
        assert!(owned("0123456789abcdef-fedcba9876543210.stamp"));
        assert!(owned(".tmp-123-456789"));
        assert!(!owned("notes.json"));
        assert!(!owned("backup.stamp"));
        assert!(!owned("0123456789ABCDEF-fedcba9876543210.json"));
        assert!(!owned("0123456789abcdef-fedcba9876543210.txt"));
        assert!(!owned(".tmp-x-y"));
        assert!(!owned(".tmp-1"));
    }

    #[test]
    fn pruning_removes_old_owned_files_once_and_keeps_everything_else() {
        let dir = scratch("prune");
        let owned_old = dir.join("0123456789abcdef-fedcba9876543210.json");
        let owned_new = dir.join("1123456789abcdef-fedcba9876543210.json");
        let foreign_old = dir.join("notes.json");
        let stamp_like = dir.join("backup.stamp");
        let folder = dir.join("0123456789abcdef-0000000000000000.json");
        for file in [&owned_old, &owned_new, &foreign_old, &stamp_like] {
            std::fs::write(file, "{}").expect("write");
        }
        std::fs::create_dir(&folder).expect("dir");
        age(&owned_old, 1);
        age(&foreign_old, 30);
        age(&stamp_like, 30);
        let ledger = Ledger::open(&dir, "session-e").expect("ledger");
        ledger.baseline("/x/a.py", Vec::new);
        assert!(!owned_old.exists());
        assert!(owned_new.exists());
        assert!(foreign_old.exists());
        assert!(stamp_like.exists());
        assert!(folder.is_dir());
        let second_old = dir.join("2123456789abcdef-fedcba9876543210.json");
        std::fs::write(&second_old, "{}").expect("write");
        age(&second_old, 1);
        ledger.baseline("/x/b.py", Vec::new);
        assert!(second_old.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
