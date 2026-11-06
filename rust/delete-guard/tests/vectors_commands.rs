use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use delete_guard::{commands, decision, errors::Stop, targets};
use guard_common::overrides;
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy());
    let root = Path::new(&temp).join(format!("d3-commands-rust-{}-{stamp}", std::process::id()));
    for name in [
        "u",
        "u/Documents",
        "plain",
        "plain/inner",
        "pool",
        "pool/one",
        "pool/two",
        "holder",
        "holder/.Trash",
        "holder/.Trash/old",
        "other",
    ] {
        fs::create_dir_all(root.join(name)).expect("directory");
    }
    for name in ["plain/a", "pool/one/a", "pool/two/b", "other/f"] {
        fs::write(root.join(name), "x").expect("file");
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
fn exhaustive_option_helpers_match_python() {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/exhaustive_commands.txt");
    let text = fs::read_to_string(source).expect("exhaustive vectors");
    for (index, line) in text.lines().enumerate() {
        let (hex, expected) = line.split_once('\t').expect("record");
        let option = decode_hex(hex);
        let command = |fish| match commands::is_command_option(&option, fish) {
            Ok(value) => json!(value),
            Err(_) => json!("IndexError"),
        };
        let actual = json!([
            commands::is_short(&option),
            commands::bundle_letters(&option, false),
            commands::bundle_letters(&option, true),
            command(false),
            command(true),
            commands::value_is_next(&option, false),
            commands::value_is_next(&option, true)
        ]);
        let expected: Value = serde_json::from_str(expected).expect("result");
        assert_eq!(actual, expected, "row {index}");
    }
}

#[test]
fn command_vectors_match_python() {
    let root = fixture();
    let root_text = root.to_string_lossy().into_owned();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/commands.json");
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
        targets::set_quoted_words(
            strings(field(record, "quoted"), &root_text)
                .into_iter()
                .collect::<HashSet<_>>(),
        );
        decision::set_pending_ask(None);
        let args = field(record, "args").as_array().expect("args");
        let arg = |at: usize| args.get(at).unwrap_or(&Value::Null);
        let name = field(record, "fn").as_str().expect("fn");
        let words = strings(arg(0), &root_text);
        let cwd = args
            .get(1)
            .and_then(Value::as_str)
            .map(|text| text.replace("@ROOT@", &root_text));
        let (ret, exc) = match name {
            "rm" => stop(commands::rm(&words, cwd.as_deref())),
            "trash" => stop(commands::trash(&words, cwd.as_deref())),
            "mv" => stop(commands::mv(&words, cwd.as_deref())),
            "gio" => stop(commands::gio(&words, cwd.as_deref())),
            "trash_one" => stop(commands::trash_one(
                &decode(arg(0), &root_text),
                args.get(1)
                    .and_then(Value::as_str)
                    .map(|_| root_text.as_str()),
                arg(2).as_bool().unwrap_or(false),
            )),
            "kio_command" => (json!(commands::kio_command(&words)), None),
            "deletes_files" => (json!(commands::deletes_files(&words)), None),
            "moves_and_deletes" => (json!(commands::moves_and_deletes(&words)), None),
            "is_short" => (json!(commands::is_short(&decode(arg(0), &root_text))), None),
            "value_letters" => (
                json!(commands::value_letters(arg(0).as_bool().unwrap_or(false))),
                None,
            ),
            "bundle_letters" => (
                json!(commands::bundle_letters(
                    &decode(arg(0), &root_text),
                    arg(1).as_bool().unwrap_or(false)
                )),
                None,
            ),
            "is_command_option" => match commands::is_command_option(
                &decode(arg(0), &root_text),
                arg(1).as_bool().unwrap_or(false),
            ) {
                Ok(value) => (json!(value), None),
                Err(_) => (json!("string index out of range"), Some("IndexError")),
            },
            "value_is_next" => (
                json!(commands::value_is_next(
                    &decode(arg(0), &root_text),
                    arg(1).as_bool().unwrap_or(false)
                )),
                None,
            ),
            "shell_words" => {
                let (options, operands) =
                    commands::shell_words(&words, arg(1).as_bool().unwrap_or(false));
                (json!([options, operands]), None)
            }
            "shell_gets_a_name" => (
                json!(commands::shell_gets_a_name(
                    &words,
                    &decode(arg(1), &root_text),
                    arg(2).as_bool().unwrap_or(false)
                )),
                None,
            ),
            _ => panic!("unknown function {name}"),
        };
        let actual = normalize(ret, &root_text);
        let expected = field(record, "ret");
        let actual_ask = normalize(json!(decision::pending_ask()), &root_text);
        if (&actual != expected
            || exc != field(record, "exc").as_str()
            || actual_ask != *field(record, "ask"))
            && failures.len() < 15
        {
            failures.push(format!("{index} {name}: ret={actual:?} expected={expected:?} exc={exc:?} expected_exc={:?} ask={actual_ask:?} expected_ask={:?}", field(record, "exc"), field(record, "ask")));
        }
    }
    overrides::clear_local();
    targets::set_remote(None);
    targets::set_quoted_words(HashSet::new());
    let _ = fs::remove_dir_all(&root);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
