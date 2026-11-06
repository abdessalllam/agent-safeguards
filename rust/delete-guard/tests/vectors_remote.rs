use std::fs;
use std::path::{Path, PathBuf};

use delete_guard::{decision, errors::Stop, find, remote, targets};
use guard_common::overrides;
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy());
    let root = Path::new(&temp).join(format!("d4-remote-rust-{}-{stamp}", std::process::id()));
    for name in ["u", "safe", "safe/sub", "holder", "holder/.Trash", "bin"] {
        fs::create_dir_all(root.join(name)).expect("directory");
    }
    fs::write(root.join("safe/file"), "x").expect("file");
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

fn stopped<T>(
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

fn setup(root: &str, record: &Value) {
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
    decision::set_pending_ask(None);
    find::set_stdin_files(
        record
            .get("stdin")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let pair = item.as_array()?;
                        let name = decode(pair.first()?, root);
                        let folder = pair
                            .get(1)
                            .and_then(Value::as_str)
                            .map(|value| value.replace("@ROOT@", root));
                        Some((name, folder))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    );
}

#[test]
fn remote_vectors_match_python() {
    let root = fixture();
    let root_text = root.to_string_lossy().into_owned();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/remote.json");
    let records: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(source)
            .expect("vectors; run python3 rust/delete-guard/tests/gen_remote.py"),
    )
    .expect("JSON");
    for (index, record) in records.iter().enumerate() {
        setup(&root_text, record);
        let name = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let arg = |index| decode(args.get(index).unwrap_or(&Value::Null), &root_text);
        let cwd = args.get(1).and_then(Value::as_str).map(|_| arg(1));
        let (actual, exception) = match name {
            "remote_command_words" => stopped(
                remote::remote_command_words(
                    &arg(0),
                    &strings(args.get(1).unwrap_or(&Value::Null), &root_text),
                ),
                |words| json!(words),
            ),
            "check_remote_command" => {
                stopped(remote::check_remote_command(&arg(0)), |_| Value::Null)
            }
            "check_rsync_operand" => stopped(
                remote::check_rsync_operand(&arg(0), cwd.as_deref(), &arg(2)),
                |_| Value::Null,
            ),
            "rsync" => stopped(
                remote::rsync(
                    &strings(args.first().unwrap_or(&Value::Null), &root_text),
                    cwd.as_deref(),
                ),
                |_| Value::Null,
            ),
            "wrapper_directory" => stopped(
                remote::wrapper_directory(&arg(0), cwd.as_deref()),
                |value| json!(value),
            ),
            "wrapper_directories" => stopped(
                remote::wrapper_directories(
                    &strings(args.first().unwrap_or(&Value::Null), &root_text),
                    cwd.as_deref(),
                ),
                |value| json!(value),
            ),
            "check_chunk" => {
                let command_cwd = args.get(1).and_then(Value::as_str).map(|_| arg(1));
                stopped(
                    remote::check_chunk(
                        &strings(args.first().unwrap_or(&Value::Null), &root_text),
                        command_cwd.as_deref(),
                        &arg(2),
                        record
                            .get("trusted")
                            .and_then(Value::as_bool)
                            .unwrap_or(true),
                    ),
                    |(folder, changed)| json!([folder, changed]),
                )
            }
            other => panic!("unknown function {other}"),
        };
        let expected = record.get("ret").expect("ret").clone();
        let expected_exception = record.get("exc").and_then(Value::as_str);
        assert_eq!(
            (normalize(actual, &root_text), exception),
            (expected, expected_exception),
            "row {index} function {name}"
        );
        let targets = json!(targets::remote_targets());
        assert_eq!(
            normalize(targets, &root_text),
            *record.get("targets").expect("targets"),
            "target state row {index}"
        );
        let stdin = json!(find::stdin_files());
        assert_eq!(
            normalize(stdin, &root_text),
            *record.get("stdin_after").expect("stdin state"),
            "stdin state row {index}"
        );
        let ask = json!(decision::pending_ask());
        assert_eq!(
            normalize(ask, &root_text),
            *record.get("ask").expect("ask state"),
            "ask state row {index}"
        );
    }
    fs::remove_dir_all(root).expect("fixture cleanup");
}

fn from_hex(hex: &str) -> String {
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("byte"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8")
}

#[test]
fn exhaustive_remote_option_words_match_python() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/exhaustive_remote.txt");
    let content = fs::read_to_string(source)
        .expect("exhaustive vectors; run python3 rust/delete-guard/tests/gen_remote.py");
    for (index, line) in content.lines().enumerate() {
        let mut parts = line.splitn(3, '\t');
        let name = parts.next().expect("name");
        let word = from_hex(parts.next().expect("word"));
        let expected: Value = serde_json::from_str(parts.next().expect("result")).expect("JSON");
        let words = vec![
            name.to_owned(),
            word,
            "host".to_owned(),
            "rm".to_owned(),
            "x".to_owned(),
        ];
        let actual = stopped(remote::remote_command_words(name, &words), |value| {
            json!(value)
        });
        assert_eq!(json!([actual.0, actual.1]), expected, "row {index}");
    }
}
