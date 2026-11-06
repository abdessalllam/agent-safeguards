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
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/words.json");
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_words.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vector json");
    let fixture = std::env::temp_dir().join(format!("safe-tool-s1-self-{}", std::process::id()));
    std::fs::create_dir_all(&fixture).expect("self fixture directory");
    let self_link = fixture.join("safe-tool");
    std::os::unix::fs::symlink(&*safe_tool::consts::SELF_PATH, &self_link)
        .expect("self fixture link");
    for (index, record) in records.iter().enumerate() {
        let function = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let expected = record.get("ret").expect("ret");
        let exception = record.get("exc").expect("exc");
        let (actual, actual_exception) = match function {
            "normalized" => (
                json!(safe_tool::words::normalized(
                    args.first().and_then(Value::as_str).expect("word")
                )),
                Value::Null,
            ),
            "is_self" => {
                let word = args.first().and_then(Value::as_str).expect("word");
                let substituted = if expected == &json!(true) && word != "safe-tool" {
                    self_link.to_str().expect("self fixture path")
                } else {
                    word
                };
                match safe_tool::words::is_self(substituted) {
                    Ok(found) => (json!(found), Value::Null),
                    Err(_) => (Value::Null, json!("ValueError")),
                }
            }
            "tokenize" => (
                json!(safe_tool::words::tokenize(
                    args.first().and_then(Value::as_str).expect("command")
                )),
                Value::Null,
            ),
            "unwrap" => match safe_tool::words::unwrap(&strings(args.first().expect("words"))) {
                Ok(result) => (json!(result), Value::Null),
                Err(_) => (Value::Null, json!("UnresolvableCommand")),
            },
            "without_global_options" => (
                json!(safe_tool::words::without_global_options(
                    args.first().and_then(Value::as_str).expect("executable"),
                    &strings(args.get(1).expect("arguments"))
                )),
                Value::Null,
            ),
            other => panic!("unknown vector function {other}"),
        };
        assert_eq!(
            &actual_exception, exception,
            "exception mismatch at {index} in {function}"
        );
        assert_eq!(
            &actual, expected,
            "result mismatch at {index} in {function}"
        );
    }
    std::fs::remove_file(&self_link).expect("remove self fixture link");
    std::fs::remove_dir(&fixture).expect("remove self fixture directory");
}
