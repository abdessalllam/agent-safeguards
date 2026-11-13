#![cfg(unix)]
use serde_json::{json, Value};

#[test]
fn fuzz_command_records_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/fuzz_command.json");
    let text = std::fs::read_to_string(path).expect("run python3 tests/gen_fuzz_command.py first");
    let records: Vec<Value> = serde_json::from_str(&text).expect("json");
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let root = std::path::Path::new(&guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("fz-s4-rust-{}-{stamp}", std::process::id()));
    let home = root.join("home");
    let work = home.join("project");
    std::fs::create_dir_all(&work).expect("fixture directories");
    for name in [".zshrc", ".bashrc", ".profile", ".zsh_history", "ordinary.txt"] {
        std::fs::File::create(home.join(name)).expect("fixture file");
    }
    std::fs::File::create(work.join("ordinary.txt")).expect("work file");
    let original = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&work).expect("fixture cwd");
    guard_common::overrides::set_local("USER_HOME", json!(home.to_string_lossy()));
    let mut bad = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let function = record["fn"].as_str().expect("fn");
        let args = record["args"].as_array().expect("args");
        let command = args[0].as_str().expect("command");
        let result: Result<bool, String> = match function {
            "sensitive_command" => {
                safe_tool::consts::set_ps_target(args[2].as_str().expect("target"));
                safe_tool::command::sensitive_command(command, args[1].as_bool().expect("flag")).map_err(|_| "ValueError".to_owned())
            }
            "blocked_only_by_startup_file" => safe_tool::command::blocked_only_by_startup_file(command).map_err(|_| "ValueError".to_owned()),
            "blocked_by_git_format" => safe_tool::command::blocked_by_git_format(command).map_err(|_| "UnresolvableCommand".to_owned()),
            "blocked_only_by_proxy" => safe_tool::command::blocked_only_by_proxy(command).map_err(|_| "ValueError".to_owned()),
            other => panic!("unknown function {other}"),
        };
        let matches = match (&result, record["exc"].as_str()) {
            (Ok(actual), None) => record["ret"].as_bool() == Some(*actual),
            (Err(kind), Some(expected)) => kind == expected,
            _ => false,
        };
        if !matches {
            bad.push(format!("#{index} {function} {command:?}: got {result:?}, want {} {}", record["exc"], record["ret"]));
        }
    }
    std::env::set_current_dir(original).expect("restore cwd");
    guard_common::overrides::clear_local();
    let _ = std::fs::remove_dir_all(&root);
    assert!(bad.is_empty(), "{} records differ, first: {:#?}", bad.len(), &bad[..bad.len().min(10)]);
}
