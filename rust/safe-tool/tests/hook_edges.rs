use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str) -> Home {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = PathBuf::from(guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("hook-edges-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).expect("fixture home");
    Home(root)
}

struct Run {
    code: Option<i32>,
    stdout: String,
    seconds: f64,
}

fn hook(home: &Home, event: &str, input: &[u8], budget: Option<f64>) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_safe-tool"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home.0)
        .current_dir(&home.0)
        .args(["hook", "claude", event]);
    if let Some(seconds) = budget {
        command.env(
            "AGENT_SAFEGUARDS_TEST_OVERRIDES",
            json!({ "HOOK_BUDGET_SECONDS": seconds }).to_string(),
        );
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hook");
    let mut stdin = child.stdin.take().expect("stdin");
    let started = Instant::now();
    let bytes = input.to_vec();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
    let deadline = started + Duration::from_secs(90);
    let output = loop {
        if child.try_wait().expect("poll").is_some() || Instant::now() > deadline {
            break child;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut child = output;
    let ended = child.try_wait().expect("status");
    if ended.is_none() {
        let _ = child.kill();
    }
    let seconds = started.elapsed().as_secs_f64();
    let _ = feeder.join();
    let finished = child.wait_with_output().expect("collect");
    Run {
        code: finished.status.code(),
        stdout: String::from_utf8_lossy(&finished.stdout).into_owned(),
        seconds,
    }
}

fn message(key: &str) -> String {
    guard_common::locale::message(key, &[])
}

fn denied_with(run: &Run, key: &str) -> bool {
    let text = message(key);
    let parsed: Value = serde_json::from_str(run.stdout.trim()).expect("one JSON answer");
    parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
        && parsed["hookSpecificOutput"]["permissionDecisionReason"] == text.as_str()
}

fn pre(tool: &str, input: Value) -> Vec<u8> {
    json!({ "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input })
        .to_string()
        .into_bytes()
}

#[test]
fn a_command_nested_past_the_recursion_limit_is_an_internal_denial() {
    let home = home("recursion");
    let command = format!("{}true", "eval ".repeat(331));
    let run = hook(&home, "PreToolUse", &pre("Bash", json!({ "command": command })), Some(120.0));
    assert_eq!(run.code, Some(0));
    assert!(denied_with(&run, "safe_tool.deny.internal"), "{}", run.stdout);
}

#[test]
fn a_read_blocked_on_a_pipe_ends_with_the_timeout_denial() {
    let home = home("fifo");
    let pipe = home.0.join("blocked.fifo");
    let made = Command::new("mkfifo").arg(&pipe).status().expect("mkfifo");
    assert!(made.success());
    let input = pre("Read", json!({ "file_path": pipe.to_string_lossy() }));
    let run = hook(&home, "PreToolUse", &input, Some(0.5));
    assert_eq!(run.code, Some(0), "{}", run.stdout);
    assert!(denied_with(&run, "safe_tool.deny.too_slow"), "{}", run.stdout);
    assert!(run.seconds < 30.0, "{}", run.seconds);
}

#[test]
fn control_separators_around_a_line_number_are_an_internal_denial() {
    let home = home("separators");
    let file = home.0.join("plain.txt");
    std::fs::write(&file, "ordinary text\n").expect("fixture");
    for offset in ["\u{1c}1", "1\u{1d}", "\u{1f}12\u{1f}"] {
        let input = pre("Read", json!({ "file_path": file.to_string_lossy(), "offset": offset }));
        let run = hook(&home, "PreToolUse", &input, None);
        assert_eq!(run.code, Some(0));
        assert!(denied_with(&run, "safe_tool.deny.internal"), "{offset:?} {}", run.stdout);
    }
    let spaced = pre("Read", json!({ "file_path": file.to_string_lossy(), "offset": " \u{a0}1\t" }));
    assert!(hook(&home, "PreToolUse", &spaced, None).stdout.is_empty());
}

#[test]
fn an_integer_beyond_u64_is_a_positive_offset() {
    let home = home("bigint");
    let file = home.0.join("token.txt");
    let secret = format!("ghp_{}\n", "A".repeat(32));
    std::fs::write(&file, &secret).expect("fixture");
    let path = file.to_string_lossy().into_owned();
    let raw = format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":{},\"offset\":18446744073709551616,\"limit\":1}}}}",
        json!(path)
    );
    let beyond = hook(&home, "PreToolUse", raw.as_bytes(), None);
    assert_eq!(beyond.code, Some(0));
    assert!(beyond.stdout.is_empty(), "{}", beyond.stdout);
    let first = pre("Read", json!({ "file_path": path, "offset": 1, "limit": 1 }));
    assert!(hook(&home, "PreToolUse", &first, None).stdout.contains("deny"));
}

#[test]
fn numbers_in_a_scrubbed_response_keep_their_python_text() {
    let home = home("numbers");
    let token = format!("ghp_{}", "A".repeat(32));
    let raw = format!(
        "{{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Grep\",\"tool_response\":{{\"content\":\"{token}\",\"ratio\":0.10743469891394097,\"big\":18446744073709551617,\"neg\":-0,\"exp\":1E3,\"tiny\":1e-7}}}}"
    );
    let run = hook(&home, "PostToolUse", raw.as_bytes(), None);
    assert_eq!(run.code, Some(0));
    let text = run.stdout.trim();
    for expected in [
        "\"ratio\":0.10743469891394097",
        "\"big\":18446744073709551617",
        "\"neg\":0",
        "\"exp\":1000.0",
        "\"tiny\":1e-07",
    ] {
        assert!(text.contains(expected), "{expected} in {text}");
    }
}

#[test]
fn nesting_is_read_as_deep_as_python_reads_it() {
    let home = home("nesting");
    let nested = |count: usize| {
        format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"true\"}},\"metadata\":{}1{}}}",
            "[".repeat(count),
            "]".repeat(count)
        )
        .into_bytes()
    };
    let deep = hook(&home, "PreToolUse", &nested(500), None);
    assert_eq!(deep.code, Some(0));
    assert!(deep.stdout.is_empty(), "{}", deep.stdout);
    let limit = hook(&home, "PreToolUse", &nested(9996), None);
    assert!(limit.stdout.is_empty(), "{}", limit.stdout);
    let past = hook(&home, "PreToolUse", &nested(9997), None);
    assert!(past.stdout.contains("deny"), "{}", past.stdout);
}
