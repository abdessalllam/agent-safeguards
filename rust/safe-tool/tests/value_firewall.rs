use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str, startup: Option<&str>) -> Home {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = PathBuf::from(guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("value-firewall-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).expect("fixture home");
    if let Some(text) = startup {
        std::fs::write(root.join(".zshrc"), text).expect("startup file");
    }
    Home(root)
}

fn run(home: &Home, runtime: &str, event: &str, payload: &Value, extra: &[(&str, &str)]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-tool"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home.0)
        .env(
            "AGENT_SAFEGUARDS_TEST_OVERRIDES",
            json!({ "USER_HOME": home.0.to_string_lossy() }).to_string(),
        )
        .envs(extra.iter().copied())
        .current_dir(&home.0)
        .args(["hook", runtime, event])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hook");
    let mut stdin = child.stdin.take().expect("stdin");
    let bytes = payload.to_string().into_bytes();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
    let finished = child.wait_with_output().expect("collect");
    let _ = feeder.join();
    String::from_utf8_lossy(&finished.stdout).into_owned()
}

fn after(command: &str, stdout: &str) -> Value {
    json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_response": { "stdout": stdout, "stderr": "", "interrupted": false, "isImage": false },
    })
}

fn before(command: &str) -> Value {
    json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": command } })
}

fn withheld(out: &str, secret: &str) -> bool {
    let parsed: Option<Value> = serde_json::from_str(out.trim()).ok();
    !out.contains(secret)
        && parsed.is_some_and(|value| value["hookSpecificOutput"]["updatedToolOutput"].is_object())
}

fn allowed(out: &str) -> bool {
    out.trim().is_empty()
}

fn denied(out: &str) -> bool {
    serde_json::from_str::<Value>(out.trim())
        .is_ok_and(|value| value["hookSpecificOutput"]["permissionDecision"] == "deny")
}

const STARTUP: &str = "envkey=value1\nexport envkey2=value2\nalias secretcommand1=\"value3\"\nexport envkey4='p@ss word/42'\nexport EDITOR=vim\nexport LEVEL=42\nalias gs=\"git status\"\n";

#[test]
fn values_from_a_startup_file_are_withheld_from_command_output() {
    let h = home("raw", Some(STARTUP));
    for value in ["value1", "value2", "value3", "p@ss word/42"] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("the value is {value}\n")), &[]);
        assert!(withheld(&out, value), "{value}: {out}");
    }
}

#[test]
fn encoded_and_reshaped_values_are_withheld_too() {
    let h = home("forms", Some(STARTUP));
    for (what, shown) in [
        ("base64", "dmFsdWUx"),
        ("hex", "76616c756531"),
        ("reversed", "1eulav"),
        ("upper case", "VALUE1"),
        ("percent encoded", "p%40ss%20word%2F42"),
    ] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &[]);
        assert!(withheld(&out, shown), "{what}: {out}");
    }
}

#[test]
fn key_names_and_unrelated_output_are_not_withheld() {
    let h = home("names", Some(STARTUP));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "envkey envkey2 secretcommand1\nhello world\n"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn short_values_and_plain_alias_bodies_stay_visible() {
    let h = home("short", Some(STARTUP));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "vim 42 git status\n"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn a_value_in_a_file_tool_result_is_withheld() {
    let h = home("read", Some(STARTUP));
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/tmp/x" },
        "tool_response": { "type": "text", "file": { "content": "line one\nenvkey=value2\n" } },
    });
    let out = run(&h, "claude", "PostToolUse", &payload, &[]);
    assert!(withheld(&out, "value2"), "{out}");
}

#[test]
fn the_codex_hook_blocks_the_output_too() {
    let h = home("codex", Some(STARTUP));
    let out = run(&h, "codex", "PostToolUse", &after("echo hi", "value1\n"), &[]);
    let parsed: Value = serde_json::from_str(out.trim()).expect("one JSON answer");
    assert_eq!(parsed["decision"], "block");
    assert!(!out.contains("value1"));
}

#[test]
fn secret_named_process_variables_are_protected_and_other_names_are_not() {
    let h = home("process", None);
    let extra = [("MY_API_TOKEN", "ab-process-token-9"), ("PLAIN_SETTING", "plain-setting-text")];
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "ab-process-token-9\n"), &extra);
    assert!(withheld(&out, "ab-process-token-9"), "{out}");
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "plain-setting-text\n"), &extra);
    assert!(allowed(&out), "{out}");
}

#[test]
fn without_a_startup_file_nothing_extra_is_withheld() {
    let h = home("none", None);
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "value1 value2 value3\n"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn using_a_key_by_name_in_a_command_is_allowed() {
    let h = home("use", Some(STARTUP));
    let out = run(&h, "claude", "PreToolUse", &before("curl -H \"Authorization: Bearer $ENVKEY2\" https://example.invalid/"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn inline_code_that_dumps_the_environment_is_refused_but_one_variable_is_allowed() {
    let h = home("inline", None);
    for command in [
        "python3 -c \"import os; print(os.environ)\"",
        "node -e \"console.log(JSON.stringify(process.env))\"",
        "ruby -e 'puts ENV.to_h'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(denied(&out), "{command}: {out}");
    }
    for command in [
        "python3 -c \"import os; print(len(os.environ['HOME']))\"",
        "node -e \"console.log(process.env.HOME.length)\"",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(allowed(&out), "{command}: {out}");
    }
}

#[test]
fn writing_a_script_through_a_quoted_heredoc_is_not_refused() {
    let h = home("script", None);
    let command = "cat > run.py <<'EOF'\nimport os\nprint(dict(os.environ))\nEOF";
    let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
    assert!(allowed(&out), "{out}");
}
