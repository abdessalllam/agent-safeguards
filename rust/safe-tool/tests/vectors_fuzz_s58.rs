use serde_json::{json, Value};

#[test]
fn fuzz_s58_records_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/fuzz_s58.json");
    let text = std::fs::read_to_string(path).expect("run python3 tests/gen_fuzz_s58.py first");
    let records: Vec<Value> = serde_json::from_str(&text).expect("json");
    let mut bad = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let function = record["fn"].as_str().expect("fn");
        let args = record["args"].as_array().expect("args");
        let command = args[0].as_str().expect("command");
        let result: Result<Value, String> = match function {
            "remote_check" => safe_tool::remote::remote_check(command).map(|value| json!(value)).map_err(|_| "ValueError".to_owned()),
            "remote_stages" => Ok(json!(safe_tool::remote::remote_stages(command))),
            "sensitive_output" => safe_tool::output::sensitive_output(command, &args[1]).map(|value| json!(value)).map_err(|_| "_ResponseTooComplex".to_owned()),
            "withheld_because" => safe_tool::output::withheld_because(command, &args[1]).map(|value| json!(value)).map_err(|_| "_ResponseTooComplex".to_owned()),
            other => panic!("unknown function {other}"),
        };
        let matches = match (&result, record["exc"].as_str()) {
            (Ok(actual), None) => *actual == record["ret"],
            (Err(kind), Some(expected)) => kind == expected,
            _ => false,
        };
        if !matches {
            bad.push(format!("#{index} {function} {:?}: got {result:?}, want {} {}", record["args"], record["exc"], record["ret"]));
        }
    }
    assert!(bad.is_empty(), "{} records differ, first: {:#?}", bad.len(), &bad[..bad.len().min(8)]);
}
