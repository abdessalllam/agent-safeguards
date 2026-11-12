#[cfg(unix)]
use guard_common::pyglob::expanduser;
#[cfg(unix)]
use serde_json::Value;

#[cfg(unix)]
#[test]
fn expanduser_records_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/expanduser.json");
    let text = std::fs::read_to_string(path).expect("run python3 tests/gen_pyglob.py first");
    let records: Vec<Value> = serde_json::from_str(&text).expect("json");
    let original = std::env::var("HOME").ok();
    let mut bad = Vec::new();
    for record in &records {
        match record["home"].as_str() {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
        let path = record["path"].as_str().expect("path");
        let actual = expanduser(path);
        if record["exc"].is_null() {
            let want = record["ret"].as_str().expect("ret");
            if actual.as_deref() != Ok(want) {
                bad.push(format!("{:?} home {:?}: got {actual:?} want {want:?}", path, record["home"]));
            }
        } else if actual.is_ok() {
            bad.push(format!("{path:?}: expected an error"));
        }
    }
    match original {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    assert!(bad.is_empty(), "{bad:?}");
}
