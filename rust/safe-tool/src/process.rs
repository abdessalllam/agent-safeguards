use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::consts::{MAX_OUTPUT_BYTES, SAFE_ENV_KEYS};

pub struct ProcessResult {
    pub returncode: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn join_under(mut base: String, parts: &[&str]) -> String {
    for part in parts {
        if !base.ends_with('/') {
            base.push('/');
        }
        base.push_str(part);
    }
    base
}

pub fn environment() -> HashMap<String, String> {
    let mut scrubbed = HashMap::new();
    for key in SAFE_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            scrubbed.insert((*key).to_owned(), value);
        }
    }
    let home = guard_common::env::user_home().to_owned();
    scrubbed.insert("HOME".to_owned(), home.clone());
    scrubbed.insert("LC_ALL".to_owned(), "C".to_owned());
    scrubbed.insert("PATH".to_owned(), guard_common::env::trusted_path().to_owned());
    scrubbed.insert("TMPDIR".to_owned(), "/tmp".to_owned());
    scrubbed.insert("XDG_CONFIG_HOME".to_owned(), join_under(home.clone(), &[".config"]));
    scrubbed.insert(
        "XDG_DATA_HOME".to_owned(),
        join_under(home.clone(), &[".local", "share"]),
    );
    scrubbed.insert(
        "XDG_STATE_HOME".to_owned(),
        join_under(home, &[".local", "state"]),
    );
    scrubbed.insert("GIT_PAGER".to_owned(), "cat".to_owned());
    scrubbed.insert("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned());
    scrubbed.insert("NO_COLOR".to_owned(), "1".to_owned());
    scrubbed
}

fn read_pipe(mut pipe: impl Read) -> Vec<u8> {
    let cap = MAX_OUTPUT_BYTES.saturating_add(1);
    let mut stored = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                if stored.len() < cap {
                    let room = cap.saturating_sub(stored.len());
                    let take = count.min(room);
                    if let Some(bytes) = chunk.get(..take) {
                        stored.extend_from_slice(bytes);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    stored
}

fn status_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return -signal;
    }
    1
}

pub fn run(command: &[String], cwd: &str, timeout: u64) -> Option<ProcessResult> {
    let program = command.first()?;
    let arguments = command.get(1..).unwrap_or(&[]);
    let mut child = Command::new(program);
    child
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    guard_common::sys::new_session(&mut child);
    let mut child = child.spawn().ok()?;
    let stdout = child.stdout.take()?;
    let stderr = child.stderr.take()?;
    // A reader per pipe, otherwise a full stderr buffer stalls the child before stdout is drained.
    let (sender, receiver) = std::sync::mpsc::channel::<(bool, Vec<u8>)>();
    let out_sender = sender.clone();
    thread::spawn(move || {
        let _ = out_sender.send((true, read_pipe(stdout)));
    });
    thread::spawn(move || {
        let _ = sender.send((false, read_pipe(stderr)));
    });
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let (mut stdout_bytes, mut stderr_bytes, mut status) = (None, None, None);
    loop {
        while let Ok((is_stdout, bytes)) = receiver.try_recv() {
            if is_stdout {
                stdout_bytes = Some(bytes);
            } else {
                stderr_bytes = Some(bytes);
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(found)) => status = Some(found),
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
        if let (Some(stdout_bytes), Some(stderr_bytes), Some(status)) = (&stdout_bytes, &stderr_bytes, status) {
            if stdout_bytes.len() > MAX_OUTPUT_BYTES || stderr_bytes.len() > MAX_OUTPUT_BYTES {
                return None;
            }
            return Some(ProcessResult {
                returncode: status_code(status),
                stdout: stdout_bytes.clone(),
                stderr: stderr_bytes.clone(),
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::{environment, run};
    use crate::consts::MAX_OUTPUT_BYTES;
    use std::time::Instant;

    #[cfg(unix)]
    #[test]
    fn echo_returns_bytes() {
        let result = run(
            &["/bin/echo".to_owned(), "hi".to_owned()],
            "/tmp",
            5,
        );
        let result = result.expect("echo");
        assert_eq!(result.returncode, 0);
        assert_eq!(result.stdout, b"hi\n");
        assert!(result.stderr.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn false_returns_one() {
        let result = run(&["/usr/bin/false".to_owned()], "/tmp", 5).expect("false");
        assert_eq!(result.returncode, 1);
    }

    #[test]
    fn missing_cwd_is_none() {
        let result = run(
            &["/bin/echo".to_owned(), "x".to_owned()],
            "/tmp/s0-missing-cwd",
            5,
        );
        assert!(result.is_none());
    }

    #[test]
    fn missing_program_is_none() {
        let result = run(&["/tmp/s0-missing-program".to_owned()], "/tmp", 5);
        assert!(result.is_none());
    }

    #[test]
    fn timeout_kills_the_child() {
        let started = Instant::now();
        let result = run(&["/bin/sleep".to_owned(), "30".to_owned()], "/tmp", 1);
        assert!(result.is_none());
        assert!(started.elapsed().as_secs() < 15);
    }

    #[test]
    fn oversized_output_is_none() {
        let count = (MAX_OUTPUT_BYTES / 1024).saturating_add(2).to_string();
        let result = run(
            &[
                "/bin/dd".to_owned(),
                "if=/dev/zero".to_owned(),
                "bs=1024".to_owned(),
                format!("count={count}"),
            ],
            "/tmp",
            20,
        );
        assert!(result.is_none());
    }

    #[test]
    fn environment_keeps_only_the_scrubbed_keys() {
        let values = environment();
        assert_eq!(
            values.get("PATH").map(String::as_str),
            Some(guard_common::env::trusted_path())
        );
        assert_eq!(values.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(values.get("GIT_PAGER").map(String::as_str), Some("cat"));
        assert_eq!(values.get("NO_COLOR").map(String::as_str), Some("1"));
        assert_eq!(values.get("TMPDIR").map(String::as_str), Some("/tmp"));
        assert_eq!(
            values.get("HOME").map(String::as_str),
            Some(guard_common::env::user_home())
        );
        assert!(!values.contains_key("USER"));
        assert!(!values.contains_key("PYTHONPATH"));
        if std::env::var("SSH_AUTH_SOCK").is_ok() {
            assert!(values.contains_key("SSH_AUTH_SOCK"));
        } else {
            assert!(!values.contains_key("SSH_AUTH_SOCK"));
        }
    }

    #[test]
    fn a_descendant_holding_the_pipe_ends_at_the_deadline() {
        let started = Instant::now();
        let result = run(
            &["/bin/sh".to_owned(), "-c".to_owned(), "/bin/sleep 3 & exit 0".to_owned()],
            "/",
            1,
        );
        assert!(result.is_none());
        assert!(started.elapsed().as_millis() < 2500);
    }
}
