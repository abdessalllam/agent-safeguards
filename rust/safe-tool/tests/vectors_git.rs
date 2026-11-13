#![cfg(unix)]
use serde_json::{json, Value};
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::sync::Mutex;

use safe_tool::{commit, git, local_only, process::ProcessResult};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("string array")
        .iter()
        .map(|item| item.as_str().expect("string").to_owned())
        .collect()
}

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex bytes");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex pair");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}

fn result(value: &Value) -> Option<ProcessResult> {
    let fields = value.as_array()?;
    Some(ProcessResult {
        returncode: fields.first().and_then(Value::as_i64).expect("returncode") as i32,
        stdout: bytes(fields.get(1).expect("stdout")),
        stderr: fields.get(2).map(bytes).unwrap_or_default(),
    })
}

fn sorted<I: IntoIterator<Item = String>>(items: I) -> Value {
    let mut values: Vec<String> = items.into_iter().collect();
    values.sort();
    json!(values)
}

#[test]
fn vectors_match_python() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/git.json");
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_git.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("git vectors");
    let parent = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let fixture = std::path::PathBuf::from(guard_common::sys::realpath(&parent.to_string_lossy()))
        .join(format!("s7-vectors-open-{}", std::process::id()));
    let plain = fixture.join("plain");
    std::fs::create_dir_all(&plain).expect("fixture directory");
    symlink(&plain, fixture.join("linked-parent")).expect("parent link");
    symlink(plain.join("exclude"), plain.join("linked-file")).expect("file link");
    let previous = std::env::var("AGENT_SAFEGUARDS_LOCAL_ONLY").ok();
    for (index, record) in records.iter().enumerate() {
        let name = record.get("fn").and_then(Value::as_str).expect("function");
        if name == "git_commit_scripted" {
            continue;
        }
        let args = record
            .get("args")
            .and_then(Value::as_array)
            .expect("arguments");
        let expected = record.get("ret").expect("ret");
        let exception = record.get("exc").expect("exc");
        let (actual, actual_exception) = match name {
            "authentication_state" => (
                json!(git::authentication_state(
                    &git::AuthNode::parse(args.first().and_then(Value::as_str).expect("payload"))
                        .expect("json payload")
                )),
                Value::Null,
            ),
            "local_only_entries" | "local_only_paths" | "local_only_exclude_patterns" => {
                if let Some(setting) = args.first().and_then(Value::as_str) {
                    std::env::set_var("AGENT_SAFEGUARDS_LOCAL_ONLY", setting);
                } else {
                    std::env::remove_var("AGENT_SAFEGUARDS_LOCAL_ONLY");
                }
                let items = match name {
                    "local_only_entries" => local_only::local_only_entries(),
                    "local_only_paths" => local_only::local_only_paths(),
                    _ => local_only::local_only_exclude_patterns(),
                };
                (json!(items), Value::Null)
            }
            "is_force_git_add" | "is_safe_tool_commit" => {
                let words = strings(args.first().expect("words"));
                let found = if name == "is_force_git_add" {
                    local_only::is_force_git_add(&words)
                } else {
                    local_only::is_safe_tool_commit(&words)
                };
                match found {
                    Ok(value) => (json!(value), Value::Null),
                    Err(local_only::LocalOnlyError::UnresolvableCommand) => {
                        (Value::Null, json!("UnresolvableCommand"))
                    }
                    Err(local_only::LocalOnlyError::EmbeddedNul) => {
                        (Value::Null, json!("ValueError"))
                    }
                }
            }
            "commit_messages" => (
                json!(commit::commit_messages(&strings(
                    args.first().expect("arguments")
                ))),
                Value::Null,
            ),
            "object_id" => (
                json!(commit::object_id(&bytes(args.first().expect("output")))),
                Value::Null,
            ),
            "commit_detail" => (
                json!(commit::commit_detail(&bytes(args.first().expect("output")))),
                Value::Null,
            ),
            "decoded_paths" => {
                let input = result(args.first().expect("result"));
                (
                    sorted(local_only::decoded_paths(input.as_ref())),
                    Value::Null,
                )
            }
            "open_without_symlinks" => {
                let label = args.first().and_then(Value::as_str).expect("path label");
                let path = if label.is_empty() || label == "/" {
                    label.to_owned()
                } else {
                    fixture.join(label).to_string_lossy().into_owned()
                };
                match local_only::open_without_symlinks(&path) {
                    Ok(file) => {
                        drop(file);
                        (json!("opened"), Value::Null)
                    }
                    Err(local_only::OpenError::IndexError) => (Value::Null, json!("IndexError")),
                    Err(local_only::OpenError::ValueError) => (Value::Null, json!("ValueError")),
                    Err(local_only::OpenError::Io(error)) => {
                        let class = match error.kind() {
                            ErrorKind::NotFound => "FileNotFoundError",
                            ErrorKind::NotADirectory => "NotADirectoryError",
                            _ => "OSError",
                        };
                        (Value::Null, json!(class))
                    }
                }
            }
            "commit_operation_failed" => {
                let results: Vec<ProcessResult> = args
                    .first()
                    .and_then(Value::as_array)
                    .expect("results")
                    .iter()
                    .filter_map(result)
                    .collect();
                let refs: Vec<Option<&ProcessResult>> = results.iter().map(Some).collect();
                let (code, payload) = commit::commit_operation_failed(&refs);
                (json!([code, payload]), Value::Null)
            }
            "repository_root" => (
                json!(git::repository_root(
                    args.first().and_then(Value::as_str).expect("cwd")
                )),
                Value::Null,
            ),
            "git_exclude_path" => (
                json!(local_only::git_exclude_path(
                    args.first().and_then(Value::as_str).expect("cwd")
                )),
                Value::Null,
            ),
            "untracked_local_only_paths" => (
                sorted(local_only::untracked_local_only_paths(
                    args.first().and_then(Value::as_str).expect("cwd"),
                )),
                Value::Null,
            ),
            "new_staged_local_only_paths" => (
                sorted(local_only::new_staged_local_only_paths(
                    args.first().and_then(Value::as_str).expect("cwd"),
                )),
                Value::Null,
            ),
            "git_identity_ready" => (
                json!(git::git_identity_ready(
                    args.first().and_then(Value::as_str).expect("cwd")
                )),
                Value::Null,
            ),
            "commit_hook_exists" => (
                json!(commit::commit_hook_exists(
                    args.first().and_then(Value::as_str).expect("cwd")
                )),
                Value::Null,
            ),
            "ensure_local_excludes" => match local_only::ensure_local_excludes(
                args.first().and_then(Value::as_str).expect("cwd"),
            ) {
                Ok(value) => (json!(value), Value::Null),
                Err(local_only::EnsureError::UnicodeDecodeError) => {
                    (Value::Null, json!("UnicodeDecodeError"))
                }
                Err(local_only::EnsureError::ValueError) => (Value::Null, json!("ValueError")),
            },
            "requires_local_artifact_approval" => {
                let command = args.first().and_then(Value::as_str).expect("command");
                let cwd = args.get(1).and_then(Value::as_str);
                match local_only::requires_local_artifact_approval(command, cwd) {
                    Ok(value) => (json!(value), Value::Null),
                    Err(local_only::LocalOnlyError::UnresolvableCommand) => {
                        (Value::Null, json!("UnresolvableCommand"))
                    }
                    Err(local_only::LocalOnlyError::EmbeddedNul) => {
                        (Value::Null, json!("ValueError"))
                    }
                }
            }
            "git_commit" => {
                let messages = strings(args.first().expect("messages"));
                let (code, payload) =
                    commit::git_commit_result(&messages, "/nonexistent/s7-git-fixture");
                (json!([code, payload]), Value::Null)
            }
            other => panic!("unknown vector function {other}"),
        };
        assert_eq!(
            &actual_exception, exception,
            "exception at {index} in {name}"
        );
        assert_eq!(&actual, expected, "result at {index} in {name}");
    }
    if let Some(value) = previous {
        std::env::set_var("AGENT_SAFEGUARDS_LOCAL_ONLY", value);
    } else {
        std::env::remove_var("AGENT_SAFEGUARDS_LOCAL_ONLY");
    }
    std::fs::remove_file(plain.join("exclude")).expect("remove opened file");
    std::fs::remove_file(plain.join("linked-file")).expect("remove file link");
    std::fs::remove_file(fixture.join("linked-parent")).expect("remove parent link");
    std::fs::remove_dir(&plain).expect("remove plain");
    std::fs::remove_dir(&fixture).expect("remove fixture");
}

#[test]
fn exhaustive_small_predicates_match_python() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_git.txt"
    );
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_git.py first");
    let previous = std::env::var("AGENT_SAFEGUARDS_LOCAL_ONLY").ok();
    for (index, line) in source.lines().enumerate() {
        let mut parts = line.split('\t');
        let kind = parts.next().expect("kind");
        let hex = parts.next().expect("text");
        let expected = parts.next().expect("expected") == "1";
        let encoded = Value::String(hex.to_owned());
        let text = String::from_utf8(bytes(&encoded)).expect("utf8 subject");
        let actual = match kind {
            "F" => local_only::is_force_git_add(&["git".into(), "add".into(), text])
                .expect("force add"),
            "L" => {
                std::env::set_var("AGENT_SAFEGUARDS_LOCAL_ONLY", &text);
                !local_only::local_only_entries().is_empty()
            }
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(actual, expected, "exhaustive row {index} kind {kind}");
    }
    if let Some(value) = previous {
        std::env::set_var("AGENT_SAFEGUARDS_LOCAL_ONLY", value);
    } else {
        std::env::remove_var("AGENT_SAFEGUARDS_LOCAL_ONLY");
    }
}
