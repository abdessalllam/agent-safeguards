use serde_json::Value;

#[test]
fn vectors_match_python() {
    let records: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/consts.json")).expect("vector file missing: run rust/gen-vectors.sh")).expect("vector json");
    for record in &records {
        let function = record
            .get("fn")
            .and_then(Value::as_str)
            .expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let expected = record.get("ret").expect("ret");
        let actual = safe_tool::consts::replay(function, args);
        if &actual != expected {
            let arg = args.first().and_then(Value::as_str).unwrap_or("");
            let shown: String = arg.chars().take(120).collect();
            panic!("mismatch {function} arg={shown:?}\nactual={actual}\nexpected={expected}");
        }
    }
}
