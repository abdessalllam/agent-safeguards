#![cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};

use delete_guard::{decision, errors::Stop, find, targets};
use guard_common::overrides;
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy());
    let root = Path::new(&temp).join(format!("d3-find-rust-{}-{stamp}", std::process::id()));
    for name in [
        "u",
        "safe",
        "safe/nested",
        "holder",
        "holder/.Trash",
        "plain",
    ] {
        fs::create_dir_all(root.join(name)).expect("directory");
    }
    fs::write(root.join("safe/nested/a"), "x").expect("file");
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

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).expect("vector field")
}

fn stop(result: Result<(), Stop>) -> (Value, Option<&'static str>) {
    match result {
        Ok(()) => (Value::Null, None),
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

fn decode_hex(hex: &str) -> String {
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("byte"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8")
}

#[test]
fn exhaustive_find_predicates_match_python() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/exhaustive_find.txt");
    let text = fs::read_to_string(source).expect("exhaustive vectors");
    for (index, line) in text.lines().enumerate() {
        let (hex, expected) = line.split_once('\t').expect("record");
        let command: Vec<String> = decode_hex(hex).split('\0').map(str::to_owned).collect();
        let parts = find::find_parts(&command);
        let actual = json!([
            [
                parts.starts,
                parts.executions,
                parts.deletes,
                parts.follows,
                parts.global_follow,
                parts.input_roots
            ],
            find::find_deleting(&command),
            find::deletes_from_names(&command)
        ]);
        let expected: Value = serde_json::from_str(expected).expect("result");
        assert_eq!(actual, expected, "row {index}");
    }
}

#[test]
fn find_vectors_match_python() {
    let root = fixture();
    let root_text = root.to_string_lossy().into_owned();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/find.json");
    let records: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(source).expect("vectors")).expect("JSON");
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        overrides::clear_local();
        overrides::set_local("TEMP_ROOTS", json!([root_text]));
        overrides::set_local("USER_HOME", json!(format!("{root_text}/u")));
        targets::set_remote(
            record
                .get("remote")
                .and_then(Value::as_array)
                .map(|items| items.iter().map(|item| decode(item, &root_text)).collect()),
        );
        decision::set_pending_ask(None);
        find::set_stdin_files(Vec::new());
        let args = field(record, "args").as_array().expect("args");
        let words = strings(args.first().unwrap_or(&Value::Null), &root_text);
        let cwd = args
            .get(1)
            .and_then(Value::as_str)
            .map(|text| text.replace("@ROOT@", &root_text));
        let name = field(record, "fn").as_str().expect("fn");
        let (ret, exc) = match name {
            "find_parts" => {
                let parts = find::find_parts(&words);
                (
                    json!([
                        parts.starts,
                        parts.executions,
                        parts.deletes,
                        parts.follows,
                        parts.global_follow,
                        parts.input_roots
                    ]),
                    None,
                )
            }
            "find_deleting" => (json!(find::find_deleting(&words)), None),
            "deletes_from_names" => (json!(find::deletes_from_names(&words)), None),
            "find" => stop(find::find(&words, cwd.as_deref())),
            "xargs" => stop(find::xargs(&words, cwd.as_deref())),
            _ => panic!("unknown function {name}"),
        };
        let actual = normalize(ret, &root_text);
        let expected = field(record, "ret");
        let actual_ask = normalize(json!(decision::pending_ask()), &root_text);
        if (&actual != expected
            || exc != field(record, "exc").as_str()
            || actual_ask != *field(record, "ask"))
            && failures.len() < 20
        {
            failures.push(format!("{index} {name}: ret={actual:?} expected={expected:?} exc={exc:?} expected_exc={:?} ask={actual_ask:?} expected_ask={:?}", field(record, "exc"), field(record, "ask")));
        }
    }
    overrides::clear_local();
    targets::set_remote(None);
    let _ = fs::remove_dir_all(&root);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
