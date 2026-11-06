use serde_json::{json, Value};

fn arg(args: &[Value], index: usize) -> &Value {
    args.get(index).expect("vector argument")
}

fn string(args: &[Value], index: usize) -> &str {
    arg(args, index).as_str().expect("string argument")
}

fn index(args: &[Value], position: usize) -> usize {
    usize::try_from(arg(args, position).as_u64().expect("index argument"))
        .expect("index fits usize")
}

fn complex(value: Result<String, safe_tool::output::ResponseTooComplex>) -> (Value, Value) {
    match value {
        Ok(value) => (json!(value), Value::Null),
        Err(_) => (Value::Null, json!("_ResponseTooComplex")),
    }
}

fn complex_optional(
    value: Result<Option<String>, safe_tool::output::ResponseTooComplex>,
) -> (Value, Value) {
    match value {
        Ok(value) => (json!(value), Value::Null),
        Err(_) => (Value::Null, json!("_ResponseTooComplex")),
    }
}

#[test]
fn vectors_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/output.json"
    ))
    .expect("run python3 rust/safe-tool/tests/gen_output.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("output vectors JSON");
    for (number, record) in records.iter().enumerate() {
        if record.get("flag").and_then(Value::as_bool) == Some(true) {
            std::env::set_var("AGENT_SAFEGUARDS_SHOW_ADDRESSES", "1");
        } else {
            std::env::remove_var("AGENT_SAFEGUARDS_SHOW_ADDRESSES");
        }
        let name = record.get("fn").and_then(Value::as_str).expect("function");
        let args = record
            .get("args")
            .and_then(Value::as_array)
            .expect("arguments");
        let (actual, exception) = match name {
            "response_text" => complex(safe_tool::output::response_text(
                arg(args, 0),
                index(args, 1),
            )),
            "response_values" => complex(safe_tool::output::response_values(
                arg(args, 0),
                index(args, 1),
            )),
            "response_labels" => complex(safe_tool::output::response_labels(
                arg(args, 0),
                index(args, 1),
            )),
            "shows_private_address" => (
                json!(safe_tool::output::shows_private_address(string(args, 0))),
                Value::Null,
            ),
            "reportable_address" => (
                json!(safe_tool::output::reportable_address(string(args, 0))),
                Value::Null,
            ),
            "shows_host_details" => (
                json!(safe_tool::output::shows_host_details(
                    string(args, 0),
                    string(args, 1)
                )),
                Value::Null,
            ),
            "plain_chunk" => {
                let words: Vec<String> = arg(args, 0)
                    .as_array()
                    .expect("chunk")
                    .iter()
                    .map(|item| item.as_str().expect("word").to_owned())
                    .collect();
                (json!(safe_tool::output::plain_chunk(&words)), Value::Null)
            }
            "sensitive_output" => {
                match safe_tool::output::sensitive_output(string(args, 0), arg(args, 1)) {
                    Ok(value) => (json!(value), Value::Null),
                    Err(_) => (Value::Null, json!("_ResponseTooComplex")),
                }
            }
            "withheld_because" => complex_optional(safe_tool::output::withheld_because(
                string(args, 0),
                arg(args, 1),
            )),
            "shape_key" => (
                json!(safe_tool::output::shape_key(
                    string(args, 0),
                    index(args, 1)
                )),
                Value::Null,
            ),
            "withheld_shape" => {
                let root = args.get(1).and_then(Value::as_bool).unwrap_or(true);
                let depth = args.get(2).and_then(Value::as_u64).unwrap_or(0) as usize;
                (
                    safe_tool::output::withheld_shape(arg(args, 0), root, depth),
                    Value::Null,
                )
            }
            "withhold_post_hook" => {
                let why = args.get(2).and_then(Value::as_str);
                let replacement = args.get(3).filter(|value| !value.is_null());
                match safe_tool::output::withhold_post_hook(
                    string(args, 0),
                    arg(args, 1),
                    why,
                    replacement,
                ) {
                    Ok(value) => (value, Value::Null),
                    Err(_) => (Value::Null, json!("KeyError")),
                }
            }
            _ => panic!("unexpected function at vector {number}"),
        };
        assert!(
            exception == record.get("exc").cloned().unwrap_or(Value::Null),
            "exception mismatch at vector {number} ({name})"
        );
        assert!(
            actual == record.get("ret").cloned().unwrap_or(Value::Null),
            "result mismatch at vector {number} ({name})"
        );
    }
    std::env::remove_var("AGENT_SAFEGUARDS_SHOW_ADDRESSES");
}

#[test]
fn exhaustive_predicates_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_output.txt"
    ))
    .expect("run python3 rust/safe-tool/tests/gen_output.py first");
    for (number, line) in source.lines().enumerate() {
        let mut fields = line.split('\t');
        let name = fields.next().expect("function");
        let encoded = fields.next().expect("hex input");
        let expected = fields.next().expect("expected result");
        let bytes: Vec<u8> = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let digits = std::str::from_utf8(chunk).expect("hex digits");
                u8::from_str_radix(digits, 16).expect("valid hex")
            })
            .collect();
        let candidate = String::from_utf8(bytes).expect("UTF-8 input");
        let actual = match name {
            "shape_key" => safe_tool::output::shape_key(&candidate, 3),
            "reportable_address" => {
                (safe_tool::output::reportable_address(&candidate) as u8).to_string()
            }
            "plain_chunk" => (safe_tool::output::plain_chunk(&[candidate.clone(), "ls".to_owned()])
                as u8)
                .to_string(),
            _ => panic!("unknown exhaustive function at line {number}"),
        };
        assert!(
            actual == expected,
            "exhaustive mismatch at line {number} ({name})"
        );
    }
}

#[test]
fn named_output_behaviors() {
    use safe_tool::output;
    assert_eq!(
        output::response_text(&json!(["a", "b"]), 0),
        Ok("a\nb".to_owned())
    );
    assert_eq!(
        output::response_values(&json!({"a": "x"}), 0),
        Ok("a\nx".to_owned())
    );
    assert_eq!(
        output::response_labels(&json!({"a": "x"}), 0),
        Ok("a=x".to_owned())
    );
    assert!(output::response_text(&json!("x"), 65).is_err());
    assert!(output::reportable_address("8.8.8.8"));
    assert!(!output::reportable_address("127.0.0.1"));
    assert_eq!(output::shape_key("bad-key", 2), "field2");
    assert_eq!(output::withheld_shape(&json!(["x"]), true, 0), json!([]));
}
