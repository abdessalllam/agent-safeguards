#![cfg(unix)]
use serde_json::{json, Value};

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|word| word.as_str().expect("word").to_owned())
        .collect()
}

#[test]
fn vectors_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/chunk.json");
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_chunk.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vector json");
    let old_cwd = std::env::current_dir().expect("cwd");
    let source_root = std::env::var("S3_SOURCE_REPO").unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .and_then(std::path::Path::parent)
            .expect("repository root")
            .to_string_lossy()
            .into_owned()
    });
    std::env::set_current_dir(source_root).expect("oracle cwd");
    for (index, record) in records.iter().enumerate() {
        let function = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let expected = record.get("ret").expect("ret");
        let exception = record.get("exc").expect("exc");
        let (actual, actual_exception) = match function {
            "sensitive_chunk" => {
                match safe_tool::chunk::sensitive_chunk(&strings(args.first().expect("words"))) {
                    Ok(value) => (json!(value), Value::Null),
                    Err(_) => (Value::Null, json!("ValueError")),
                }
            }
            "docker_inspect_shows_environment" => (
                json!(safe_tool::chunk::docker_inspect_shows_environment(
                    &strings(args.first().expect("arguments"))
                )),
                Value::Null,
            ),
            "ps_shows_environment" => {
                safe_tool::consts::set_ps_target(
                    args.get(1).and_then(Value::as_str).expect("target"),
                );
                (
                    json!(safe_tool::chunk::ps_shows_environment(&strings(
                        args.first().expect("arguments")
                    ))),
                    Value::Null,
                )
            }
            "ps_format_shows_environment" => (
                json!(safe_tool::chunk::ps_format_shows_environment(
                    args.first().and_then(Value::as_str).expect("format")
                )),
                Value::Null,
            ),
            "ps_walk" => {
                safe_tool::consts::set_ps_target(
                    args.get(3).and_then(Value::as_str).expect("target"),
                );
                let unix: Vec<char> = strings(args.get(1).expect("unix"))
                    .iter()
                    .filter_map(|letter| letter.chars().next())
                    .collect();
                let bsd: Vec<char> = strings(args.get(2).expect("bsd"))
                    .iter()
                    .filter_map(|letter| letter.chars().next())
                    .collect();
                (
                    json!(safe_tool::chunk::ps_walk(
                        &strings(args.first().expect("arguments")),
                        &unix,
                        &bsd
                    )),
                    Value::Null,
                )
            }
            "prints_secret_variable" => (
                json!(safe_tool::chunk::prints_secret_variable(
                    args.first().and_then(Value::as_str).expect("command")
                )),
                Value::Null,
            ),
            other => panic!("unknown vector function {other}"),
        };
        assert_eq!(
            &actual_exception, exception,
            "exception mismatch at {index} in {function}"
        );
        assert_eq!(&actual, expected, "value mismatch at {index} in {function}");
    }
    std::env::set_current_dir(old_cwd).expect("restore cwd");
}

#[test]
fn exhaustive_predicates_match_python() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_chunk.txt"
    );
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_chunk.py first");
    for (index, line) in source.lines().enumerate() {
        let mut parts = line.split('\t');
        let encoded = parts.next().expect("hex");
        let bytes: Vec<u8> = encoded
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("pair"), 16).expect("hex byte")
            })
            .collect();
        let value = String::from_utf8(bytes).expect("utf8");
        let expected = parts.next() == Some("1");
        let format_expected = parts.next() == Some("1");
        let docker_expected = parts.next() == Some("1");
        assert_eq!(
            safe_tool::chunk::prints_secret_variable(&value),
            expected,
            "at {index}"
        );
        assert_eq!(
            safe_tool::chunk::ps_format_shows_environment(&value),
            format_expected,
            "ps format at {index}"
        );
        assert_eq!(
            safe_tool::chunk::docker_inspect_shows_environment(&[
                "inspect".into(),
                format!("--format={value}")
            ]),
            docker_expected,
            "docker format at {index}"
        );
    }
}
