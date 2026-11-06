use delete_guard::consts::{constant_value, replay_regex};
use serde_json::Value;

#[test]
fn vectors_match_python() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/consts.json");
    let text = std::fs::read_to_string(&path).expect("read vectors");
    let records: Vec<Value> = serde_json::from_str(&text).expect("parse vectors");
    for record in &records {
        let name = record.get("fn").and_then(Value::as_str).unwrap_or("");
        let args = record.get("args").and_then(Value::as_array);
        let expected = record.get("ret");
        let exc = record.get("exc");
        assert!(exc.is_none() || exc == Some(&Value::Null), "{name} raised");
        if let Some((constant, method)) = name.rsplit_once('.') {
            if matches!(method, "search" | "match" | "fullmatch") {
                let text = args.and_then(|items| items.first()).and_then(Value::as_str).unwrap_or("");
                let found = replay_regex(constant, method, text).unwrap_or_else(|| panic!("unknown regex {name}"));
                let actual = match found {
                    Some((start, end)) => Value::Array(vec![Value::from(start), Value::from(end)]),
                    None => Value::Null,
                };
                assert_eq!(&actual, expected.unwrap_or(&Value::Null), "{name} on {text:?}");
                continue;
            }
        }
        let actual = constant_value(name).unwrap_or_else(|| panic!("unknown constant {name}"));
        assert_eq!(&actual, expected.unwrap_or(&Value::Null), "{name}");
    }
}
