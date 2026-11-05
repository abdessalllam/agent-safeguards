use std::cell::Cell;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

const RETENTION: Duration = Duration::from_secs(14 * 24 * 60 * 60);
const PRUNE_LIMIT: usize = 200;
const PRUNE_VISITS: usize = 2000;
const LOCK_STALE: Duration = Duration::from_secs(5);
const LOCK_WAIT: Duration = Duration::from_secs(6);
const LOCK_SOON: Duration = Duration::from_millis(250);
const LOCK_AHEAD: Duration = Duration::from_secs(2);
const REMEMBERED_STATES: usize = 8;
const PENDING_SECONDS: u64 = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seen {
    pub hash: u64,
    pub sig: u64,
}

struct Pending {
    from: u64,
    to: u64,
    net: usize,
    at: u64,
    since: u64,
}

struct Stored {
    comments: Vec<String>,
    seen: Vec<Seen>,
    pending: Option<Pending>,
}

pub struct Ledger {
    dir: PathBuf,
    session: u64,
    pruned: Cell<bool>,
}

fn lock_is_stale(lock: &Path) -> bool {
    let Ok(modified) = fs::metadata(lock).and_then(|meta| meta.modified()) else {
        return false;
    };
    match SystemTime::now().duration_since(modified) {
        Ok(age) => age > LOCK_STALE,
        Err(ahead) => ahead.duration() > LOCK_AHEAD,
    }
}

fn hash(text: &str) -> u64 {
    let mut value: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        value ^= u64::from(byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value
}

static TOKENS: AtomicU64 = AtomicU64::new(0);

pub fn content_hash(text: &str) -> u64 {
    hash(text)
}

pub fn signature(comments: &[String]) -> u64 {
    let mut sorted: Vec<&str> = comments.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    hash(&sorted.join("\n"))
}

pub fn seen_of(text: &str, comments: &[String]) -> Seen {
    Seen {
        hash: hash(text),
        sig: signature(comments),
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
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
        .or_else(|| name.strip_suffix(".stamp"))
        .or_else(|| name.strip_suffix(".start"))
        .or_else(|| name.strip_suffix(".lock"));
    stem.and_then(|stem| stem.split_once('-'))
        .is_some_and(|(session, entry)| hex16(session) && hex16(entry))
}

fn parse_hex(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?, 16).ok()
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

    fn named(&self, key: &str, extension: &str) -> PathBuf {
        self.dir
            .join(format!("{:016x}-{:016x}.{extension}", self.session, hash(key)))
    }

    fn entry(&self, identity: &str) -> PathBuf {
        self.named(identity, "json")
    }

    fn stamp(&self, key: &str) -> PathBuf {
        self.named(key, "stamp")
    }

    fn start_file(&self, id: &str) -> PathBuf {
        self.named(id, "start")
    }

    fn temp(&self) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        self.dir
            .join(format!(".tmp-{}-{nanos}", std::process::id()))
    }

    fn lock_token(&self) -> String {
        let name = self.temp().file_name().map(|name| name.to_string_lossy().into_owned());
        format!("{}-{}", name.unwrap_or_default(), TOKENS.fetch_add(1, Ordering::Relaxed))
    }

    fn locked_within<T, F: FnOnce() -> T>(&self, identity: &str, wait: Duration, work: F) -> Result<T, F> {
        let lock = self.named(identity, "lock");
        let token = self.lock_token();
        let mut held = false;
        let started = Instant::now();
        while started.elapsed() < wait {
            match fs::OpenOptions::new().write(true).create_new(true).open(&lock) {
                Ok(mut file) => {
                    let _ = file.write_all(token.as_bytes());
                    held = true;
                    break;
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if lock_is_stale(&lock) {
                        let _ = fs::remove_file(&lock);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        if !held {
            return Err(work);
        }
        let result = work();
        if fs::read_to_string(&lock).is_ok_and(|content| content == token) {
            let _ = fs::remove_file(&lock);
        }
        Ok(result)
    }

    fn locked<T>(&self, identity: &str, work: impl FnOnce() -> T) -> T {
        match self.locked_within(identity, LOCK_WAIT, work) {
            Ok(result) => result,
            Err(work) => work(),
        }
    }

    fn load(&self, identity: &str) -> Option<Stored> {
        let raw = fs::read_to_string(self.entry(identity)).ok()?;
        let value: Value = serde_json::from_str(&raw).ok()?;
        if value.get("path")?.as_str()? != identity {
            return None;
        }
        let comments = value
            .get("comments")?
            .as_array()?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()?;
        let seen = value
            .get("seen")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some(Seen {
                            hash: parse_hex(item.get("h")?)?,
                            sig: parse_hex(item.get("s")?)?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let pending = value.get("pending").and_then(|item| {
            let at = item.get("at")?.as_u64()?;
            Some(Pending {
                from: parse_hex(item.get("from")?)?,
                to: parse_hex(item.get("to")?)?,
                net: usize::try_from(item.get("net")?.as_u64()?).ok()?,
                at,
                since: item.get("since").and_then(Value::as_u64).unwrap_or(at),
            })
        });
        Some(Stored { comments, seen, pending })
    }

    fn store(&self, identity: &str, stored: &Stored) {
        let seen: Vec<Value> = stored
            .seen
            .iter()
            .map(|state| json!({ "h": format!("{:016x}", state.hash), "s": format!("{:016x}", state.sig) }))
            .collect();
        let pending = stored.pending.as_ref().map(|item| {
            json!({ "from": format!("{:016x}", item.from), "to": format!("{:016x}", item.to), "net": item.net, "at": item.at, "since": item.since })
        });
        let body = json!({ "path": identity, "comments": stored.comments, "seen": seen, "pending": pending })
            .to_string();
        let temp = self.temp();
        if fs::write(&temp, body).is_err() {
            return;
        }
        if fs::rename(&temp, self.entry(identity)).is_err() {
            let _ = fs::remove_file(&temp);
        }
    }

    pub fn read(&self, identity: &str) -> Option<Vec<String>> {
        self.load(identity).map(|stored| stored.comments)
    }

    pub fn knows(&self, identity: &str, state: Seen) -> bool {
        self.load(identity).is_some_and(|stored| {
            stored
                .seen
                .iter()
                .any(|known| known.hash == state.hash || known.sig == state.sig)
        })
    }

    pub fn baseline_for(&self, identity: &str, state: Seen, make: impl FnOnce() -> Vec<String>) -> Vec<String> {
        self.locked(identity, || {
            if let Some(stored) = self.load(identity) {
                let known = stored
                    .seen
                    .iter()
                    .any(|seen| seen.hash == state.hash || seen.sig == state.sig);
                if known {
                    return stored.comments;
                }
            }
            self.write_fresh(identity, make(), state)
        })
    }

    pub fn rebaseline(&self, identity: &str, comments: Vec<String>, state: Seen) -> Vec<String> {
        self.locked(identity, || self.write_fresh(identity, comments, state))
    }

    pub fn rebaseline_soon(&self, identity: &str, comments: Vec<String>, state: Seen) {
        let _ = self.locked_within(identity, LOCK_SOON, || self.write_fresh(identity, comments, state));
    }

    fn write_fresh(&self, identity: &str, comments: Vec<String>, state: Seen) -> Vec<String> {
        let first = !self.entry(identity).exists();
        self.store(
            identity,
            &Stored {
                comments: comments.clone(),
                seen: vec![state],
                pending: None,
            },
        );
        if first {
            self.prune();
        }
        comments
    }

    pub fn accept(&self, identity: &str, states: &[Seen]) {
        self.locked(identity, || {
            let Some(mut stored) = self.load(identity) else {
                return;
            };
            for state in states {
                if !stored.seen.contains(state) {
                    stored.seen.push(*state);
                }
            }
            while stored.seen.len() > REMEMBERED_STATES {
                stored.seen.remove(0);
            }
            self.store(identity, &stored);
        });
    }

    pub fn carry(&self, identity: &str, from: u64, to: u64) -> usize {
        self.carry_at(identity, from, to, now_seconds())
    }

    fn carry_at(&self, identity: &str, from: u64, to: u64, now: u64) -> usize {
        match self.load(identity).and_then(|stored| stored.pending) {
            Some(pending) => Self::carried(&pending, from, to, now),
            None => 0,
        }
    }

    fn carried(pending: &Pending, from: u64, to: u64, now: u64) -> usize {
        let recent = now.saturating_sub(pending.at) <= PENDING_SECONDS;
        if pending.from == from && pending.to != to && recent {
            pending.net
        } else {
            0
        }
    }

    pub fn commit_note(&self, identity: &str, from: u64, to: u64, net: usize, expected: usize) -> Result<Option<u64>, usize> {
        self.commit_note_at(identity, from, to, net, expected, now_seconds())
    }

    fn commit_note_at(
        &self,
        identity: &str,
        from: u64,
        to: u64,
        net: usize,
        expected: usize,
        now: u64,
    ) -> Result<Option<u64>, usize> {
        self.locked(identity, || {
            let Some(mut stored) = self.load(identity) else {
                return Ok(None);
            };
            let current = stored
                .pending
                .as_ref()
                .map_or(0, |pending| Self::carried(pending, from, to, now));
            if current != expected {
                return Err(current);
            }
            if net == 0 {
                return Ok(None);
            }
            let (total, since) = match stored.pending.as_ref() {
                Some(pending) if pending.from == from && now.saturating_sub(pending.at) <= PENDING_SECONDS => {
                    if pending.to == to {
                        return Ok(None);
                    }
                    (pending.net.saturating_add(net), pending.since)
                }
                _ => (net, now),
            };
            stored.pending = Some(Pending {
                from,
                to,
                net: total,
                at: now,
                since,
            });
            self.store(identity, &stored);
            Ok(Some(now))
        })
    }

    pub fn revoke_note(&self, identity: &str, from: u64, net: usize, noted: u64) {
        self.locked(identity, || {
            let Some(mut stored) = self.load(identity) else {
                return;
            };
            let Some(pending) = stored.pending.as_mut() else {
                return;
            };
            if pending.from != from || pending.since > noted {
                return;
            }
            pending.net = pending.net.saturating_sub(net);
            if pending.net == 0 {
                stored.pending = None;
            }
            self.store(identity, &stored);
        });
    }

    pub fn last_check(&self, key: &str) -> Option<SystemTime> {
        fs::metadata(self.stamp(key)).ok()?.modified().ok()
    }

    fn touch(&self, target: PathBuf) {
        let temp = self.temp();
        if fs::write(&temp, b"").is_err() {
            return;
        }
        if fs::rename(&temp, target).is_err() {
            let _ = fs::remove_file(&temp);
        }
    }

    pub fn mark_check(&self, key: &str) {
        self.touch(self.stamp(key));
    }

    pub fn mark_start(&self, id: &str) {
        self.touch(self.start_file(id));
    }

    pub fn take_start(&self, id: &str) -> Option<SystemTime> {
        let path = self.start_file(id);
        let started = fs::metadata(&path).ok()?.modified().ok();
        let _ = fs::remove_file(&path);
        started
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
    use super::{hash, identity, lexical, owned, seen_of, signature, Ledger, Seen, RETENTION};
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime};

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

    fn state(number: u64) -> Seen {
        Seen { hash: number, sig: number + 1_000 }
    }

    #[test]
    fn a_baseline_holds_while_the_file_is_in_a_known_state_and_resets_when_it_is_not() {
        let dir = scratch("first");
        let ledger = Ledger::open(&dir, "session-a").expect("ledger");
        let first = ledger.baseline_for("/x/a.py", state(1), || vec!["# one".to_owned()]);
        let again = ledger.baseline_for("/x/a.py", state(1), || vec!["# one".to_owned(), "# two".to_owned()]);
        assert_eq!(first, vec!["# one".to_owned()]);
        assert_eq!(again, first);
        ledger.accept("/x/a.py", &[state(2)]);
        assert_eq!(ledger.baseline_for("/x/a.py", state(2), || vec!["# other".to_owned()]), first);
        let changed = ledger.baseline_for("/x/a.py", state(3), || vec!["# fresh".to_owned()]);
        assert_eq!(changed, vec!["# fresh".to_owned()]);
        assert!(ledger.baseline_for("/x/a.py", state(1), Vec::new).is_empty());
        assert!(ledger.read("/x/b.py").is_none());
        ledger.accept("/x/missing.py", &[state(1)]);
        assert!(ledger.read("/x/missing.py").is_none());
        let other = Ledger::open(&dir, "session-b").expect("ledger");
        assert!(other.read("/x/a.py").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_with_the_same_comments_is_known_even_when_the_bytes_differ() {
        let dir = scratch("signature");
        let ledger = Ledger::open(&dir, "session-s").expect("ledger");
        let comments = vec!["# one".to_owned(), "# two".to_owned()];
        let written = seen_of("x\n# one\n# two\n", &comments);
        ledger.baseline_for("/x/a.py", written, || vec!["# base".to_owned()]);
        let reformatted = seen_of("x \r\n# one\r\n# two\r\n", &[comments[1].clone(), comments[0].clone()]);
        assert_ne!(written.hash, reformatted.hash);
        assert_eq!(written.sig, reformatted.sig);
        assert!(ledger.knows("/x/a.py", reformatted));
        assert_eq!(signature(&[]), signature(&[]));
        assert_ne!(signature(&["# a".to_owned()]), signature(&["# b".to_owned()]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_the_most_recent_states_are_remembered() {
        let dir = scratch("seen");
        let ledger = Ledger::open(&dir, "session-g").expect("ledger");
        ledger.baseline_for("/x/a.py", state(100), || vec!["# keep".to_owned()]);
        for value in 1..=20u64 {
            ledger.accept("/x/a.py", &[state(value)]);
        }
        assert_eq!(ledger.baseline_for("/x/a.py", state(20), Vec::new), vec!["# keep".to_owned()]);
        assert!(ledger.baseline_for("/x/a.py", state(100), Vec::new).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_edits_are_carried_only_for_the_same_pre_image_within_a_few_seconds() {
        let dir = scratch("pending");
        let ledger = Ledger::open(&dir, "session-q").expect("ledger");
        ledger.baseline_for("/x/a.py", state(1), Vec::new);
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 10, 2, 0, 100), Ok(Some(100)));
        assert_eq!(ledger.carry_at("/x/a.py", 1, 11, 101), 2);
        assert_eq!(ledger.carry_at("/x/a.py", 1, 10, 101), 0);
        assert_eq!(ledger.carry_at("/x/a.py", 9, 11, 101), 0);
        assert_eq!(ledger.carry_at("/x/a.py", 1, 11, 104), 0);
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 12, 1, 2, 101), Ok(Some(101)));
        assert_eq!(ledger.carry_at("/x/a.py", 1, 13, 102), 3);
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 14, 0, 3, 102), Ok(None));
        assert_eq!(ledger.carry_at("/x/a.py", 1, 13, 102), 3);
        assert_eq!(ledger.commit_note_at("/x/a.py", 5, 15, 1, 0, 103), Ok(Some(103)));
        assert_eq!(ledger.carry_at("/x/a.py", 1, 13, 103), 0);
        assert_eq!(ledger.carry_at("/x/a.py", 5, 16, 103), 1);
        assert_eq!(ledger.commit_note_at("/x/none.py", 1, 10, 2, 0, 100), Ok(None));
        assert_eq!(ledger.carry_at("/x/none.py", 1, 11, 100), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_note_is_refused_when_another_edit_was_noted_after_the_carry_was_read() {
        let dir = scratch("overlap");
        let ledger = Ledger::open(&dir, "session-o").expect("ledger");
        ledger.baseline_for("/x/a.py", state(1), Vec::new);
        let first_carry = ledger.carry_at("/x/a.py", 1, 10, 100);
        let second_carry = ledger.carry_at("/x/a.py", 1, 20, 100);
        assert_eq!((first_carry, second_carry), (0, 0));
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 10, 2, first_carry, 100), Ok(Some(100)));
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 20, 2, second_carry, 100), Err(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_same_edit_noted_twice_is_counted_once_and_a_note_can_be_revoked() {
        let dir = scratch("same-edit");
        let ledger = Ledger::open(&dir, "session-n").expect("ledger");
        ledger.baseline_for("/x/a.py", state(1), Vec::new);
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 10, 2, 0, 100), Ok(Some(100)));
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 10, 2, 0, 101), Ok(None));
        assert_eq!(ledger.carry_at("/x/a.py", 1, 11, 101), 2);
        ledger.revoke_note("/x/a.py", 9, 2, 100);
        assert_eq!(ledger.carry_at("/x/a.py", 1, 11, 101), 2);
        ledger.revoke_note("/x/a.py", 1, 2, 100);
        assert_eq!(ledger.carry_at("/x/a.py", 1, 11, 101), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_note_that_was_replaced_is_not_revoked_from_its_replacement() {
        let dir = scratch("revoke-replaced");
        let ledger = Ledger::open(&dir, "session-q").expect("ledger");
        ledger.baseline_for("/x/a.py", state(1), Vec::new);
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 10, 2, 0, 100), Ok(Some(100)));
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 20, 1, 0, 110), Ok(Some(110)));
        ledger.revoke_note("/x/a.py", 1, 2, 100);
        assert_eq!(ledger.carry_at("/x/a.py", 1, 30, 111), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_note_is_revoked_even_when_another_edit_was_noted_after_it() {
        let dir = scratch("revoke-later");
        let ledger = Ledger::open(&dir, "session-r").expect("ledger");
        ledger.baseline_for("/x/a.py", state(1), Vec::new);
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 10, 1, 0, 100), Ok(Some(100)));
        assert_eq!(ledger.commit_note_at("/x/a.py", 1, 20, 1, 1, 102), Ok(Some(102)));
        ledger.revoke_note("/x/a.py", 1, 1, 100);
        assert_eq!(ledger.carry_at("/x/a.py", 1, 30, 103), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_lock_dated_far_in_the_future_is_broken_and_a_quick_rebaseline_gives_up_on_a_held_lock() {
        let dir = scratch("future-lock");
        let ledger = Ledger::open(&dir, "session-f").expect("ledger");
        let lock = ledger.named("/x/a.py", "lock");
        let file = std::fs::File::create(&lock).expect("lock");
        file.set_modified(SystemTime::now() + Duration::from_secs(3600)).expect("date");
        let started = Instant::now();
        assert_eq!(ledger.locked("/x/a.py", || 7), 7);
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        std::fs::write(&lock, "holder").expect("write");
        let started = Instant::now();
        ledger.rebaseline_soon("/x/a.py", vec!["# a".to_owned()], state(1));
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(ledger.read("/x/a.py").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_tokens_never_repeat_even_within_one_clock_tick() {
        let dir = scratch("tokens");
        let ledger = Ledger::open(&dir, "session-t").expect("ledger");
        let tokens: std::collections::HashSet<String> = (0..2000).map(|_| ledger.lock_token()).collect();
        assert_eq!(tokens.len(), 2000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_waiter_stays_out_until_a_fresh_lock_is_released() {
        let dir = scratch("waiter");
        let ledger = Ledger::open(&dir, "session-v").expect("ledger");
        let lock = ledger.named("/x/a.py", "lock");
        std::fs::write(&lock, "holder").expect("write");
        let release = lock.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            let _ = std::fs::remove_file(&release);
        });
        let started = Instant::now();
        let ran_after = ledger.locked("/x/a.py", || started.elapsed());
        handle.join().expect("join");
        assert!(ran_after >= Duration::from_millis(500), "{ran_after:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_lock_is_only_released_by_its_owner() {
        let dir = scratch("owner");
        let ledger = Ledger::open(&dir, "session-w").expect("ledger");
        let lock = ledger.named("/x/a.py", "lock");
        ledger.locked("/x/a.py", || {
            std::fs::write(&lock, "someone-else").expect("write");
        });
        assert_eq!(std::fs::read_to_string(&lock).expect("read"), "someone-else");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parallel_hook_runs_never_corrupt_a_record_or_lose_an_update() {
        let dir = scratch("parallel");
        let seed = Ledger::open(&dir, "session-p").expect("ledger");
        seed.baseline_for("/x/a.py", state(0), || vec!["# base".to_owned()]);
        let mut workers = Vec::new();
        for worker in 1..=4u64 {
            let folder = dir.clone();
            workers.push(std::thread::spawn(move || {
                let ledger = Ledger::open(&folder, "session-p").expect("ledger");
                for round in 0..25u64 {
                    ledger.accept("/x/a.py", &[state(worker * 1000 + round)]);
                    let _ = ledger.read("/x/a.py");
                }
            }));
        }
        for worker in workers {
            worker.join().expect("worker panicked");
        }
        let ledger = Ledger::open(&dir, "session-p").expect("ledger");
        assert_eq!(ledger.read("/x/a.py").expect("record must still parse"), vec!["# base".to_owned()]);
        let leftovers = std::fs::read_dir(&dir)
            .expect("list")
            .flatten()
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.starts_with(".tmp-") || name.ends_with(".lock")
            })
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_accepts_do_not_drop_each_others_states() {
        let dir = scratch("accepts");
        let seed = Ledger::open(&dir, "session-r").expect("ledger");
        seed.baseline_for("/x/a.py", state(0), Vec::new);
        let mut workers = Vec::new();
        for worker in 1..=4u64 {
            let folder = dir.clone();
            workers.push(std::thread::spawn(move || {
                let ledger = Ledger::open(&folder, "session-r").expect("ledger");
                ledger.accept("/x/a.py", &[state(worker * 10)]);
            }));
        }
        for worker in workers {
            worker.join().expect("worker panicked");
        }
        let ledger = Ledger::open(&dir, "session-r").expect("ledger");
        for worker in 1..=4u64 {
            assert!(ledger.knows("/x/a.py", state(worker * 10)), "state {worker} was lost");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_lock_serialises_read_modify_write_updates() {
        let dir = scratch("lock");
        let counter = dir.join("counter.txt");
        std::fs::write(&counter, "0").expect("write");
        let mut workers = Vec::new();
        for _ in 0..8 {
            let folder = dir.clone();
            let file = counter.clone();
            workers.push(std::thread::spawn(move || {
                let ledger = Ledger::open(&folder, "session-l").expect("ledger");
                for _ in 0..40 {
                    ledger.locked("/x/a.py", || {
                        let now: u64 = std::fs::read_to_string(&file).expect("read").trim().parse().expect("number");
                        std::thread::sleep(Duration::from_micros(200));
                        std::fs::write(&file, (now + 1).to_string()).expect("write");
                    });
                }
            }));
        }
        for worker in workers {
            worker.join().expect("worker panicked");
        }
        assert_eq!(std::fs::read_to_string(&counter).expect("read").trim(), "320");
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

    #[test]
    fn a_start_time_is_read_once_per_command() {
        let dir = scratch("start");
        let ledger = Ledger::open(&dir, "session-f").expect("ledger");
        assert!(ledger.take_start("tool-1").is_none());
        ledger.mark_start("tool-1");
        assert!(ledger.take_start("tool-2").is_none());
        assert!(ledger.take_start("tool-1").is_some());
        assert!(ledger.take_start("tool-1").is_none());
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
        assert!(owned("0123456789abcdef-fedcba9876543210.start"));
        assert!(owned("0123456789abcdef-fedcba9876543210.lock"));
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
        ledger.baseline_for("/x/a.py", state(1), Vec::new);
        assert!(!owned_old.exists());
        assert!(owned_new.exists());
        assert!(foreign_old.exists());
        assert!(stamp_like.exists());
        assert!(folder.is_dir());
        let second_old = dir.join("2123456789abcdef-fedcba9876543210.json");
        std::fs::write(&second_old, "{}").expect("write");
        age(&second_old, 1);
        ledger.baseline_for("/x/b.py", state(1), Vec::new);
        assert!(second_old.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
