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

fn home(name: &str) -> Home {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = PathBuf::from(guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("dg-edges-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).expect("fixture home");
    Home(root)
}

fn run(home: &Home, payload: &Value, budget: f64, dir: &std::path::Path) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_delete-guard"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home.0)
        .env("AGENT_SAFEGUARDS_TEST_OVERRIDES", json!({ "HOOK_BUDGET_SECONDS": budget }).to_string())
        .current_dir(dir)
        .args(["hook", "codex"]);
    let mut child = command
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
    let output = child.wait_with_output().expect("collect");
    let _ = feeder.join();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn payload(home: &Home, command: &str) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": home.0.to_string_lossy(),
    })
}

fn internal(home: &Home, command: &str) -> bool {
    run(home, &payload(home, command), 300.0, &home.0).contains("internal error")
}

#[test]
fn the_recursion_budget_matches_python_for_eval_remote_and_substitution_chains() {
    let home = home("recursion");
    let eval = |count: usize| format!("{}echo rm", "eval ".repeat(count));
    let remote = |count: usize| format!("{}echo rm", "ssh host ".repeat(count));
    let substitution = |count: usize| format!("echo {}echo rm{}", "$(".repeat(count), ")".repeat(count));
    assert!(!internal(&home, &eval(246)));
    assert!(internal(&home, &eval(247)));
    assert!(!internal(&home, &remote(197)));
    assert!(internal(&home, &remote(198)));
    assert!(!internal(&home, &substitution(1006)));
    assert!(internal(&home, &substitution(1007)));
}

#[test]
fn an_empty_cwd_is_an_unknown_folder_and_a_relative_workdir_joins_it_as_python_does() {
    let home = home("cwd");
    let unknown = json!({ "cwd": "", "tool_input": { "command": "rm -r build" } });
    let answer = run(&home, &unknown, 3.0, &home.0);
    assert!(answer.contains("deny") && answer.contains("current folder is unknown"), "{answer}");
    let joined = json!({ "cwd": "", "tool_input": { "command": "rm -r ghost", "workdir": "tmp" } });
    let answer = run(&home, &joined, 3.0, std::path::Path::new("/usr"));
    assert!(answer.contains("deny") && answer.contains("/usr/tmp/ghost"), "{answer}");
}
