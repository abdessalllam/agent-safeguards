#![cfg(unix)]
use guard_common::locale::{message, FormatValue};
use serde_json::Value;

#[test]
fn vectors_match_python() {
    unsafe {
        std::env::remove_var("AGENT_SAFEGUARDS_LOCALE");
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/locale.json");
    let text = std::fs::read_to_string(path).expect("vector file");
    let rows: Vec<Value> = serde_json::from_str(&text).expect("vector json");
    for (index, row) in rows.iter().enumerate() {
        let args = row.get("args").and_then(Value::as_array).expect("args");
        let key = args.first().and_then(Value::as_str).unwrap_or("");
        let values = decode_values(args.get(1));
        let borrowed: Vec<(&str, FormatValue)> = values
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect();
        let got = message(key, &borrowed);
        let ret = row.get("ret").and_then(Value::as_str).unwrap_or("");
        let exc = row.get("exc").and_then(Value::as_str);
        if exc.is_some() {
            panic!("index={index} unexpected python exception");
        }
        if got != ret {
            panic!("index={index} len {} vs {}", got.len(), ret.len());
        }
    }
}

fn decode_values(value: Option<&Value>) -> Vec<(String, FormatValue)> {
    let Some(Value::Object(map)) = value else {
        return Vec::new();
    };
    let mut names: Vec<&String> = map.keys().collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|name| {
            let encoded = map.get(name)?;
            Some((name.clone(), decode_one(encoded)?))
        })
        .collect()
}

fn decode_one(value: &Value) -> Option<FormatValue> {
    let pair = value.as_array()?;
    let kind = pair.first()?.as_str()?;
    let payload = pair.get(1)?;
    match kind {
        "s" => Some(FormatValue::Text(payload.as_str()?.to_owned())),
        "i" => Some(FormatValue::Int(payload.as_i64()?)),
        "f" => Some(FormatValue::Float(payload.as_f64()?)),
        _ => None,
    }
}
