use guard_common::emit::dumps;
use serde_json::Value;

#[test]
fn vectors_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/emit.json");
    let text = std::fs::read_to_string(path).expect("vector file");
    let rows: Vec<Value> = serde_json::from_str(&text).expect("vector json");
    for (index, row) in rows.iter().enumerate() {
        let args = row.get("args").and_then(Value::as_array).expect("args");
        let value = args.first().unwrap_or(&Value::Null);
        let got = dumps(value);
        let expected = row.get("ret").and_then(Value::as_str).unwrap_or("");
        if got != expected {
            panic!("index={index} len {} vs {}", got.len(), expected.len());
        }
    }
}
