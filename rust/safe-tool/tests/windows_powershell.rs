#![cfg(windows)]
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn decision(command: &str) -> String {
    let cwd = std::env::current_dir().expect("cwd").to_string_lossy().into_owned();
    let payload = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": cwd, "tool_input": { "command": command } });
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-tool"))
        .args(["hook", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start");
    child.stdin.take().expect("stdin").write_all(payload.to_string().as_bytes()).expect("write");
    let output = child.wait_with_output().expect("wait");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() {
        return "allow".to_owned();
    }
    let value: Value = serde_json::from_str(text.trim()).expect("json");
    value["hookSpecificOutput"]["permissionDecision"].as_str().unwrap_or("").to_owned()
}

fn profile() -> String {
    std::env::var("USERPROFILE").expect("USERPROFILE")
}

#[test]
fn powershell_and_cmd_reads_of_keys_and_environment_are_refused() {
    let home = profile();
    for command in [
        format!("Get-Content '{home}\\.ssh\\id_rsa'"),
        "gc $env:USERPROFILE\\.aws\\credentials".to_owned(),
        format!("type '{home}\\.env'"),
        "Get-ChildItem Env:".to_owned(),
        "cmd /c type %USERPROFILE%\\.ssh\\id_rsa".to_owned(),
        format!("[IO.File]::ReadAllText('{home}\\.ssh\\id_rsa')"),
        format!("Select-String -Path '{home}\\.env' -Pattern TOKEN"),
        format!("Set-Content -Path $env:TEMP\\out.txt -Value (Get-Content '{home}\\.ssh\\id_rsa')"),
        "Invoke-Expression -Command 'Get-Content ~\\.ssh\\id_rsa'".to_owned(),
        "Get-Item -Path Env:EXAMPLE_TOKEN".to_owned(),
        "powershell -EncodedCommand !!!".to_owned(),
    ] {
        assert_eq!(decision(&command), "deny", "{command}");
    }
}

#[test]
fn ordinary_reads_and_git_are_allowed() {
    for command in ["Get-Content .\\Cargo.toml", "git status"] {
        assert_eq!(decision(command), "allow", "{command}");
    }
}
