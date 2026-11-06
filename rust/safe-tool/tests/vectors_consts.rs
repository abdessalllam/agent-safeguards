use std::collections::BTreeMap;

use serde_json::Value;

#[test]
fn vectors_match_python() {
    let records: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/consts.json")).expect("vector file missing: run rust/gen-vectors.sh")).expect("vector json");
    let mut failures: BTreeMap<String, (usize, String)> = BTreeMap::new();
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
            let entry = failures.entry(function.to_owned()).or_insert((0, String::new()));
            entry.0 += 1;
            if entry.1.is_empty() {
                entry.1 = format!("arg={shown:?}\nactual={actual}\nexpected={expected}");
            }
        }
    }
    if !failures.is_empty() {
        let mut report = String::new();
        for (function, (count, first)) in &failures {
            report.push_str(&format!("{function}: {count} mismatches, first {first}\n"));
        }
        panic!("{report}");
    }
}
