use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::changes::MAX_OLD_FILE;

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

pub fn run_git(dir: &Path, args: &[&str], deadline: Instant) -> Option<Ran> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
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

fn is_marked(raw: &[u8]) -> bool {
    let parts: Vec<&[u8]> = raw.split(|byte| *byte == 0).collect();
    parts.chunks(3).any(|chunk| match chunk {
        [_, attribute, value] => matches!(
            (*attribute, *value),
            (b"comment-guard", b"skip" | b"set")
                | (b"linguist-vendored" | b"linguist-generated", b"set" | b"true")
        ),
        _ => false,
    })
}

pub fn marked_upstream(path: &Path, deadline: Instant) -> bool {
    let Some(name) = path.to_str() else {
        return false;
    };
    let Some(dir) = path.ancestors().skip(1).find(|folder| folder.is_dir()) else {
        return false;
    };
    let args = [
        "check-attr",
        "-z",
        "comment-guard",
        "linguist-vendored",
        "linguist-generated",
        "--",
        name,
    ];
    match run_git(dir, &args, deadline) {
        Some(ran) if ran.success => is_marked(&ran.stdout),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_marked;

    fn triples(items: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (attribute, value) in items {
            for part in ["a.py", attribute, value] {
                out.extend_from_slice(part.as_bytes());
                out.push(0);
            }
        }
        out
    }

    #[test]
    fn only_the_listed_attribute_values_mark_a_file() {
        let none = [
            ("comment-guard", "unspecified"),
            ("linguist-vendored", "unspecified"),
            ("linguist-generated", "unspecified"),
        ];
        assert!(!is_marked(&triples(&none)));
        assert!(is_marked(&triples(&[("comment-guard", "skip")])));
        assert!(is_marked(&triples(&[("comment-guard", "set")])));
        assert!(is_marked(&triples(&[("linguist-vendored", "set")])));
        assert!(is_marked(&triples(&[("linguist-generated", "true")])));
        assert!(!is_marked(&triples(&[("comment-guard", "unset")])));
        assert!(!is_marked(&triples(&[("linguist-vendored", "false")])));
        assert!(!is_marked(&triples(&[("comment-guard", "other")])));
        assert!(!is_marked(b""));
    }
}
