use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use delete_guard::{check, cli, decision, errors::Stop, find, targets, tokens};
use guard_common::overrides;
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy());
    let root = Path::new(&temp).join(format!("d5-check-rust-{}-{stamp}", std::process::id()));
    for name in [
        "u",
        "u/Documents",
        "plain",
        "plain/inner",
        "pool",
        "pool/one",
        "holder",
        "holder/.Trash",
        "holder/.Trash/old",
    ] {
        fs::create_dir_all(root.join(name)).expect("directory");
    }
    for name in ["plain/a", "pool/one/a", "script.sh"] {
        fs::write(root.join(name), "echo okay\n").expect("file");
    }
    root
}

fn normalize(value: Value, root: &str) -> Value {
    match value {
        Value::String(text) => json!(text.replace(root, "@ROOT@")),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| normalize(item, root))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| (key, normalize(item, root)))
                .collect(),
        ),
        other => other,
    }
}

fn decode(value: &Value, root: &str) -> String {
    value.as_str().unwrap_or("").replace("@ROOT@", root)
}

fn strings(value: &Value, root: &str) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().map(|item| decode(item, root)).collect())
        .unwrap_or_default()
}

fn stop<T>(
    result: Result<T, Stop>,
    encode: impl FnOnce(T) -> Value,
) -> (Value, Option<&'static str>) {
    match result {
        Ok(value) => (encode(value), None),
        Err(Stop::Denied(reason)) => (
            json!(reason.to_string()),
            Some(if reason.is_remote() {
                "RemoteDenied"
            } else {
                "Denied"
            }),
        ),
        Err(Stop::TooSlow) => (Value::Null, Some("CheckTooSlow")),
        Err(Stop::Internal) => (json!("embedded null byte"), Some("ValueError")),
    }
}

fn setup(record: &Value, root: &str) {
    std::env::set_var(
        "AGENT_SAFEGUARDS_REMOTE_COMMANDS",
        record
            .get("configured_env")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    overrides::clear_local();
    overrides::set_local("USER_HOME", json!(format!("{root}/u")));
    overrides::set_local("TEMP_ROOTS", json!([root]));
    targets::set_remote(
        record
            .get("remote")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(|item| decode(item, root)).collect()),
    );
    targets::clear_remote_targets();
    targets::set_quoted_words(HashSet::new());
    decision::set_pending_ask(None);
    tokens::set_variables_changed(HashSet::new());
    let stdin = record
        .get("stdin")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let pair = item.as_array()?;
                    Some((
                        decode(pair.first()?, root),
                        pair.get(1)
                            .and_then(Value::as_str)
                            .map(|value| value.replace("@ROOT@", root)),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    find::set_stdin_files(stdin);
}

fn whole_run(args: &[Value], root: &str) -> Value {
    let args: Vec<String> = args.iter().map(|value| decode(value, root)).collect();
    let hook = args.first().is_some_and(|arg| arg == "hook");
    let count = if hook { 2 } else { args.len() };
    let mut command = Command::new(env!("CARGO_BIN_EXE_delete-guard"));
    command
        .args(args.iter().take(count))
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if hook {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().expect("binary");
    if hook {
        if let Some(mut input) = child.stdin.take() {
            input
                .write_all(args.get(2).map(String::as_bytes).unwrap_or(&[]))
                .expect("stdin");
        }
    }
    let output = child.wait_with_output().expect("output");
    json!({"code": output.status.code().unwrap_or(-1), "stdout": String::from_utf8_lossy(&output.stdout), "stderr": String::from_utf8_lossy(&output.stderr)})
}

#[test]
fn check_vectors_match_python() {
    let root = fixture();
    let root_text = root.to_string_lossy().into_owned();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/check.json");
    let records: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(source)
            .expect("vectors; run python3 rust/delete-guard/tests/gen_check.py"),
    )
    .expect("JSON");
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        setup(record, &root_text);
        let name = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let arg = |at: usize| decode(args.get(at).unwrap_or(&Value::Null), &root_text);
        let cwd = args.get(1).and_then(Value::as_str).map(|_| arg(1));
        let (ret, exc) = match name {
            "writes_a_file" => (json!(check::writes_a_file(&arg(0), &arg(1))), None),
            "pattern_word" => (json!(check::pattern_word(&arg(0))), None),
            "redirection_names" => stop(
                check::redirection_names(
                    &arg(0),
                    &arg(1),
                    args.get(2)
                        .and_then(Value::as_str)
                        .map(|_| arg(2))
                        .as_deref(),
                ),
                |value| json!(value),
            ),
            "check_device_writes" => {
                let redirects: Vec<(String, String, String)> = args
                    .first()
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| {
                                let tuple = item.as_array()?;
                                Some((
                                    arg_in(tuple, 0, &root_text),
                                    arg_in(tuple, 1, &root_text),
                                    arg_in(tuple, 2, &root_text),
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                stop(
                    check::check_device_writes(&redirects, cwd.as_deref()),
                    |_| Value::Null,
                )
            }
            "line_input_files" => (json!(check::line_input_files(&arg(0))), None),
            "check_shell" => stop(
                check::check_shell(
                    &strings(args.first().unwrap_or(&Value::Null), &root_text),
                    cwd.as_deref(),
                ),
                |_| Value::Null,
            ),
            "git_clean" => stop(
                check::git_clean(&strings(args.first().unwrap_or(&Value::Null), &root_text)),
                |_| Value::Null,
            ),
            "configured_remote_names" => {
                let mut names: Vec<String> = check::configured_remote_names().into_iter().collect();
                names.sort();
                (json!(names), None)
            }
            "check_command" => stop(check::check_command(&arg(0), cwd.as_deref()), |_| {
                Value::Null
            }),
            "check_chunks" => stop(check::check_chunks(&arg(0), cwd.as_deref()), |_| {
                Value::Null
            }),
            "check_one_chunk" => stop(
                check::check_one_chunk(
                    &strings(args.first().unwrap_or(&Value::Null), &root_text),
                    cwd.as_deref(),
                    &arg(2),
                    args.get(3).and_then(Value::as_bool).unwrap_or(true),
                ),
                |(folder, trusted)| json!([folder, trusted]),
            ),
            "script_path" => (json!(cli::script_path(&arg(0))), None),
            "preflight_trash_patterns" => (json!(cli::preflight_trash_patterns()), None),
            "remote_preflight_script" => (json!(cli::remote_preflight_script()), None),
            "whole_run" => (whole_run(args, &root_text), None),
            _ => panic!("unexpected function {name}"),
        };
        let actual = normalize(ret, &root_text);
        if actual != record.get("ret").cloned().unwrap_or(Value::Null)
            || exc != record.get("exc").and_then(Value::as_str)
            || (name != "whole_run"
                && normalize(json!(decision::pending_ask()), &root_text)
                    != record.get("ask").cloned().unwrap_or(Value::Null))
        {
            failures.push(format!(
                "row {index} {name}: actual={actual:?}/{exc:?} expected={:?}/{:?}",
                record.get("ret"),
                record.get("exc")
            ));
            if failures.len() >= 25 {
                break;
            }
        }
    }
    fs::remove_dir_all(&root).expect("remove fixture");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn arg_in(tuple: &[Value], at: usize, root: &str) -> String {
    decode(tuple.get(at).unwrap_or(&Value::Null), root)
}

fn decode_hex(value: &str) -> String {
    let bytes: Vec<u8> = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("byte"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8")
}

#[test]
fn exhaustive_check_predicates_match_python() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/exhaustive_check.txt");
    let records = fs::read_to_string(source).expect("exhaustive vectors; run gen_check.py");
    for (index, line) in records.lines().enumerate() {
        let fields: Vec<&str> = line.split('\t').collect();
        let name = fields.first().copied().unwrap_or("");
        let first = decode_hex(fields.get(1).copied().unwrap_or(""));
        match name {
            "pattern_word" => assert_eq!(
                check::pattern_word(&first),
                decode_hex(fields.get(2).copied().unwrap_or("")),
                "row {index}"
            ),
            "device_redirect_hint" => assert_eq!(
                check::device_redirect_hint(&first),
                fields.get(2).copied() == Some("1"),
                "row {index}: {first:?}"
            ),
            "writes_a_file" => assert_eq!(
                check::writes_a_file(&first, &decode_hex(fields.get(2).copied().unwrap_or(""))),
                fields.get(3).copied() == Some("1"),
                "row {index}"
            ),
            _ => panic!("unknown predicate {name}"),
        }
    }
}
