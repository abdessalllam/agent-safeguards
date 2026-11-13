#![cfg(windows)]
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn verdict(command: &str) -> (String, String) {
    let cwd = std::env::current_dir().expect("cwd").to_string_lossy().into_owned();
    let payload = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": cwd, "tool_input": { "command": command } });
    let mut child = Command::new(env!("CARGO_BIN_EXE_delete-guard"))
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
        return ("allow".to_owned(), String::new());
    }
    let value: Value = serde_json::from_str(text.trim()).expect("json");
    let inner = &value["hookSpecificOutput"];
    (
        inner["permissionDecision"].as_str().unwrap_or("").to_owned(),
        inner["permissionDecisionReason"].as_str().unwrap_or("").to_owned(),
    )
}

fn profile() -> String {
    std::env::var("USERPROFILE").expect("USERPROFILE")
}

fn temp() -> String {
    let plain = std::fs::canonicalize(std::env::temp_dir()).expect("temp").to_string_lossy().into_owned();
    plain.trim_start_matches(r"\\?\").to_owned()
}

#[test]
fn powershell_and_cmd_deletes_of_real_data_are_refused_with_the_windows_path() {
    let home = profile();
    for command in [
        format!("Remove-Item -Recurse -Force '{home}\\Documents\\old'"),
        format!("rm -rf '{home}\\Documents\\old'"),
        format!("Get-ChildItem '{home}\\x' | Remove-Item"),
        format!("[System.IO.Directory]::Delete('{home}\\Documents\\old', $true)"),
        format!("powershell -Command \"Remove-Item '{home}\\old' -Recurse\""),
        "Remove-Item $env:USERPROFILE\\Documents\\old -Recurse".to_owned(),
        "Remove-Item .\\build -Recurse".to_owned(),
        "cmd /c rd /s /q C:\\Users".to_owned(),
    ] {
        let (decision, reason) = verdict(&command);
        assert_eq!(decision, "deny", "{command}");
        assert!(reason.contains("Delete guard") && reason.contains("Recycle Bin"), "{reason}");
        assert!(!reason.contains("trash <path>") && !reason.contains("trash-put"), "{reason}");
    }
}

#[test]
fn protected_folders_and_the_profile_itself_are_refused() {
    let home = profile();
    for command in ["Remove-Item C:\\Windows -Recurse".to_owned(), "Remove-Item C:\\ -Recurse -Force".to_owned(), format!("Remove-Item '{home}' -Recurse")] {
        let (decision, reason) = verdict(&command);
        assert_eq!(decision, "deny", "{command}");
        assert!(reason.contains("protected folder") || reason.contains("holds a Trash"), "{reason}");
    }
}

#[test]
fn a_temp_folder_a_preview_and_a_read_are_allowed() {
    let temp = temp();
    let home = profile();
    for command in [
        format!("Remove-Item -Recurse -Force '{temp}\\guard-test-x'"),
        format!("Remove-Item '{home}\\Documents\\old' -Recurse -WhatIf"),
        format!("Get-Content '{home}\\notes.txt'"),
    ] {
        let (decision, reason) = verdict(&command);
        assert_eq!(decision, "allow", "{command}: {reason}");
    }
}
