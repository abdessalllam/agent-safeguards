use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use delete_guard::{errors::Stop, globs::GlobError, targets};
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("d2-targets-rust-{}-{stamp}", std::process::id()));
    for name in [
        "plain",
        "plain/inner",
        "holder",
        "holder/.Trash",
        "pool",
        "pool/ordinary",
        "pool/files_trashbin",
        "repo/.git",
    ] {
        fs::create_dir_all(root.join(name)).expect("fixture directory");
    }
    for name in [
        "file",
        "pool/ordinary/item",
        "pool/files_trashbin/item",
        "repo/.git/HEAD",
    ] {
        fs::write(root.join(name), "x").expect("fixture file");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("plain"), root.join("link")).expect("fixture link");
    root
}

fn normalized(value: Value, root: &str) -> Value {
    match value {
        Value::String(text) => json!(text.replace(root, "{FIXTURE}")),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| normalized(value, root))
                .collect(),
        ),
        other => other,
    }
}

fn decode_hex(hex: &str) -> String {
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex digits");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect();
    String::from_utf8(bytes).expect("UTF-8 value")
}

fn stop_result(result: Result<(), Stop>) -> (Value, Option<&'static str>) {
    match result {
        Ok(()) => (Value::Null, None),
        Err(Stop::Denied(denied)) => (
            json!(denied.to_string()),
            Some(if denied.is_remote() {
                "RemoteDenied"
            } else {
                "Denied"
            }),
        ),
        Err(Stop::TooSlow) => (Value::Null, Some("CheckTooSlow")),
    }
}

fn glob_result(result: Result<(), GlobError>) -> (Value, Option<&'static str>) {
    match result {
        Ok(()) => (Value::Null, None),
        Err(GlobError::Stop(stop)) => stop_result(Err(stop)),
        Err(GlobError::Regex) => (Value::Null, Some("error")),
        Err(GlobError::Attribute) => (Value::Null, Some("AttributeError")),
        Err(GlobError::Value(reason)) => (json!(reason), Some("ValueError")),
    }
}

#[test]
fn vectors_match_python() {
    let root = fixture();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/targets.json");
    let text =
        fs::read_to_string(path).expect("read target vectors; run python3 tests/gen_targets.py");
    let records: Vec<Value> = serde_json::from_str(&text).expect("parse target vectors");
    let root_text = root.to_string_lossy().into_owned();
    for (index, record) in records.iter().enumerate() {
        let name = record.get("fn").and_then(Value::as_str).expect("function");
        let args = record
            .get("args")
            .and_then(Value::as_array)
            .expect("arguments");
        let arg = |at: usize| {
            args.get(at)
                .and_then(Value::as_str)
                .unwrap_or("")
                .replace("{FIXTURE}", &root_text)
        };
        let remote = record.get("remote").and_then(Value::as_array).map(|roots| {
            roots
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        });
        targets::set_remote(remote);
        targets::clear_remote_targets();
        let quoted: HashSet<String> = record
            .get("quoted")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        targets::set_quoted_words(quoted);
        let (actual, exception) = match name {
            "remote_literal" => (json!(targets::remote_literal(&arg(0))), None),
            "remote_trash_protected" => (json!(targets::remote_trash_protected(&arg(0))), None),
            "quoted_literal_words" => {
                let mut words: Vec<String> =
                    targets::quoted_literal_words(&arg(0)).into_iter().collect();
                words.sort();
                (json!(words), None)
            }
            "location_path" => match targets::location_path(
                &arg(0),
                &arg(1),
                args.get(2).and_then(Value::as_bool).unwrap_or(true),
            ) {
                Ok(path) => (json!(path), None),
                Err(found) => glob_result(Err(found)),
            },
            "in_trash" => (json!(targets::in_trash(&arg(0))), None),
            "repository_root" => (
                json!(targets::repository_root(
                    args.first()
                        .and_then(Value::as_str)
                        .map(|_| arg(0))
                        .as_deref()
                )),
                None,
            ),
            "is_folder_path" => match targets::is_folder_path(&arg(0), &arg(1), &arg(2)) {
                Ok(value) => (json!(value), None),
                Err(stop) => stop_result(Err(stop)),
            },
            "is_plain_folder" => {
                let entry = fs::read_dir(&root)
                    .expect("fixture entries")
                    .filter_map(Result::ok)
                    .find(|entry| entry.file_name().to_string_lossy() == arg(0))
                    .expect("named entry");
                match targets::is_plain_folder(&entry, &arg(1), &arg(2)) {
                    Ok(value) => (json!(value), None),
                    Err(stop) => stop_result(Err(stop)),
                }
            }
            "check_match_mark" => stop_result(targets::check_match_mark(&arg(0), &arg(1))),
            "check_sendable" => stop_result(targets::check_sendable(&arg(0))),
            "check_resolved" => {
                let cwd = args.get(1).and_then(Value::as_str).map(|_| arg(1));
                stop_result(targets::check_resolved(
                    &arg(0),
                    cwd.as_deref(),
                    args.get(2).and_then(Value::as_bool).unwrap_or(false),
                    &arg(3),
                ))
            }
            "check_remote_trash_target" => stop_result(targets::check_remote_trash_target(&arg(0))),
            "check_remote_target" => {
                let (result, error) = stop_result(targets::check_remote_target(&arg(0), &arg(1)));
                if error.is_none() {
                    (json!([result, targets::remote_targets()]), error)
                } else {
                    (result, error)
                }
            }
            "check_target" => {
                let cwd = args.get(1).and_then(Value::as_str).map(|_| arg(1));
                let literal = args.get(4).and_then(Value::as_bool);
                let (result, error) = glob_result(targets::check_target(
                    &arg(0),
                    cwd.as_deref(),
                    args.get(2).and_then(Value::as_bool).unwrap_or(false),
                    &arg(3),
                    literal,
                ));
                if error.is_none() {
                    (json!([result, targets::remote_targets()]), error)
                } else {
                    (result, error)
                }
            }
            _ => panic!("unknown function {name}"),
        };
        assert_eq!(
            exception,
            record.get("exc").and_then(Value::as_str),
            "exception at vector {index} {name}"
        );
        if exception == Some("ValueError") {
            continue;
        }
        assert_eq!(
            normalized(actual, &root_text),
            *record.get("ret").expect("return"),
            "value at vector {index} {name}"
        );
    }
    targets::set_remote(None);
    targets::set_quoted_words(HashSet::new());
    fs::remove_dir_all(root).expect("remove owned fixture");
}

#[test]
fn exhaustive_remote_predicates_match_python() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/exhaustive_targets.txt");
    let text = fs::read_to_string(path)
        .expect("read exhaustive targets; run python3 tests/gen_targets.py");
    for (index, line) in text.lines().enumerate() {
        let (hex, expected) = line.split_once('\t').expect("hex and expected");
        let value = decode_hex(hex);
        targets::set_quoted_words(HashSet::new());
        let plain = targets::remote_literal(&value);
        targets::set_quoted_words(HashSet::from([value.clone()]));
        let quoted = targets::remote_literal(&value);
        let mut words: Vec<String> = targets::quoted_literal_words(&value).into_iter().collect();
        words.sort();
        let actual = json!([
            plain,
            quoted,
            words,
            targets::remote_trash_protected(&value)
        ]);
        let expected: Value = serde_json::from_str(expected).expect("expected JSON");
        assert_eq!(
            actual, expected,
            "exhaustive target row {index} value {hex}"
        );
    }
    targets::set_quoted_words(HashSet::new());
}
