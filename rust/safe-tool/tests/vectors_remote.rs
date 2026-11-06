use serde_json::{json, Value};

fn string(value: &Value) -> &str {
    value.as_str().expect("string")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| string(item).to_owned())
        .collect()
}

fn flags(value: &Value) -> Vec<String> {
    strings(value)
}

#[test]
fn vectors_match_python() {
    let previous = std::env::current_dir().expect("cwd");
    let default_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .expect("repository root");
    let root = std::env::var("S8_SOURCE_REPO")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| default_root.to_path_buf());
    std::env::set_current_dir(root).expect("oracle cwd");
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/remote.json");
    let source = std::fs::read_to_string(path).expect("generate remote vectors");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vectors JSON");
    for (index, record) in records.iter().enumerate() {
        let name = string(record.get("fn").expect("fn"));
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let argument = |at: usize| args.get(at).expect("argument");
        let (actual, exception) = match name {
            "remote_stages" => (
                json!(safe_tool::remote::remote_stages(string(argument(0)))),
                Value::Null,
            ),
            "shown" => (
                json!(safe_tool::remote::shown(string(argument(0)))),
                Value::Null,
            ),
            "may_take_next" => {
                let flags = flags(argument(2));
                let refs: Vec<&str> = flags.iter().map(String::as_str).collect();
                (
                    json!(safe_tool::remote::may_take_next(
                        string(argument(0)),
                        string(argument(1)),
                        &refs,
                        string(argument(3))
                    )),
                    Value::Null,
                )
            }
            "resolve_long_options" => {
                let values = strings(argument(1));
                let flags = flags(argument(2));
                let value_refs: Vec<&str> = values.iter().map(String::as_str).collect();
                let flag_refs: Vec<&str> = flags.iter().map(String::as_str).collect();
                (
                    json!(safe_tool::remote::resolve_long_options(
                        &strings(argument(0)),
                        &value_refs,
                        &flag_refs
                    )),
                    Value::Null,
                )
            }
            "remote_option_problem" => (
                json!(safe_tool::remote::remote_option_problem(
                    string(argument(0)),
                    &strings(argument(1))
                )),
                Value::Null,
            ),
            "pm2_read" => (
                json!(safe_tool::remote::pm2_read(&strings(argument(0)))),
                Value::Null,
            ),
            "flag_is_set" => {
                let options = flags(argument(2));
                let refs: Vec<&str> = options.iter().map(String::as_str).collect();
                (
                    json!(safe_tool::remote::flag_is_set(
                        &strings(argument(0)),
                        string(argument(1)),
                        &refs
                    )),
                    Value::Null,
                )
            }
            "docker_follows" => (
                json!(safe_tool::remote::docker_follows(&strings(argument(0)))),
                Value::Null,
            ),
            "remote_docker_problem" => (
                json!(safe_tool::remote::remote_docker_problem(&strings(
                    argument(0)
                ))),
                Value::Null,
            ),
            "remote_check" => match safe_tool::remote::remote_check(string(argument(0))) {
                Ok(value) => (json!(value), Value::Null),
                Err(_) => (Value::Null, json!("ValueError")),
            },
            "remote_readonly" => match safe_tool::remote::remote_readonly(string(argument(0))) {
                Ok(value) => (json!(value), Value::Null),
                Err(_) => (Value::Null, json!("ValueError")),
            },
            other => panic!("unknown vector function {other}"),
        };
        assert_eq!(
            &exception,
            record.get("exc").expect("exc"),
            "exception at {index} in {name}"
        );
        assert_eq!(
            &actual,
            record.get("ret").expect("ret"),
            "value at {index} in {name}"
        );
    }
    std::env::set_current_dir(previous).expect("restore cwd");
}

fn from_hex(encoded: &str) -> String {
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hex = std::str::from_utf8(pair).expect("hex pair");
            u8::from_str_radix(hex, 16).expect("hex digit")
        })
        .collect();
    String::from_utf8(bytes).expect("UTF-8")
}

#[test]
fn exhaustive_predicates_match_python() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_remote.txt"
    );
    let source = std::fs::read_to_string(path).expect("generate exhaustive remote vectors");
    for (index, line) in source.lines().enumerate() {
        let mut parts = line.split('\t');
        let name = parts.next().expect("name");
        let value = from_hex(parts.next().expect("hex"));
        let expected: Value =
            serde_json::from_str(parts.next().expect("expected")).expect("result JSON");
        let actual = match name {
            "shown" => json!(safe_tool::remote::shown(&value)),
            "may_take_next" => json!(safe_tool::remote::may_take_next(
                &value,
                "nfH",
                &["--follow", "--no-stream"],
                "H"
            )),
            "docker_follows" => json!(safe_tool::remote::docker_follows(&[value])),
            "flag_is_set" => json!(safe_tool::remote::flag_is_set(
                &[value],
                "--no-stream",
                &["--format"]
            )),
            other => panic!("unknown exhaustive function {other}"),
        };
        assert_eq!(actual, expected, "exhaustive row {index} in {name}");
    }
}
