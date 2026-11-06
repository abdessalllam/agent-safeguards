use serde_json::{json, Value};

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("word array")
        .iter()
        .map(|word| word.as_str().expect("word").to_owned())
        .collect()
}

#[test]
fn vectors_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/git_rules.json");
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_git_rules.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vector json");
    for (index, record) in records.iter().enumerate() {
        let function = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let kwargs = record
            .get("kwargs")
            .and_then(Value::as_object)
            .expect("kwargs");
        let expected = record.get("ret").expect("ret");
        let actual = match function {
            "git_subcommand" => json!(safe_tool::git_rules::git_subcommand(&strings(
                args.first().expect("words")
            ))),
            "log_format_is_safe" => json!(safe_tool::git_rules::log_format_is_safe(
                args.first().and_then(Value::as_str).expect("format")
            )),
            "ref_format_is_safe" => json!(safe_tool::git_rules::ref_format_is_safe(
                args.first().and_then(Value::as_str).expect("format")
            )),
            "safe_history_arguments" => json!(safe_tool::git_rules::safe_history_arguments(
                &strings(args.first().expect("arguments")),
                kwargs.get("show").and_then(Value::as_bool).expect("show")
            )),
            "shows_only_blobs" => json!(safe_tool::git_rules::shows_only_blobs(&strings(
                args.first().expect("arguments")
            ))),
            "formats_are_unsafe" => {
                let headers = args
                    .iter()
                    .skip(1)
                    .map(|value| value.as_str().expect("header"))
                    .collect::<Vec<_>>();
                json!(safe_tool::git_rules::formats_are_unsafe(
                    &strings(args.first().expect("arguments")),
                    &headers,
                    kwargs.get("refs").and_then(Value::as_bool).unwrap_or(false)
                ))
            }
            "safe_git_config" => json!(safe_tool::git_rules::safe_git_config(&strings(
                args.first().expect("words")
            ))),
            "runs_git_config" => json!(safe_tool::git_rules::runs_git_config(&strings(
                args.first().expect("words")
            ))),
            "sensitive_git_command" => json!(safe_tool::git_rules::sensitive_git_command(
                &strings(args.first().expect("words"))
            )),
            "prints_definitions" => json!(safe_tool::git_rules::prints_definitions(
                args.first().and_then(Value::as_str).expect("command"),
                &strings(args.get(1).expect("arguments"))
            )),
            other => panic!("unknown vector function {other}"),
        };
        assert_eq!(
            record.get("exc"),
            Some(&Value::Null),
            "unexpected oracle exception at {index} in {function}"
        );
        assert_eq!(
            &actual, expected,
            "result mismatch at {index} in {function}"
        );
    }
}
