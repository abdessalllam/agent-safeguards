use guard_common::pyengine::{PyMatch, PyRegex};
use serde_json::Value;

type Shape = Option<(usize, usize, Vec<Option<(usize, usize)>>)>;

fn expected(value: &Value) -> Shape {
    if value.is_null() {
        return None;
    }
    let groups = value[2]
        .as_array()
        .expect("groups")
        .iter()
        .map(|group| if group.is_null() { None } else { Some((group[0].as_u64().expect("from") as usize, group[1].as_u64().expect("to") as usize)) })
        .collect();
    Some((value[0].as_u64().expect("start") as usize, value[1].as_u64().expect("end") as usize, groups))
}

fn shaped(found: Option<PyMatch>) -> Shape {
    found.map(|item| (item.start, item.end, item.groups))
}

#[test]
fn engine_matches_python_re() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/pyengine.json");
    let text = std::fs::read_to_string(path).expect("run python3 tests/gen_pyengine.py first");
    let records: Vec<Value> = serde_json::from_str(&text).expect("json");
    let mut bad: Vec<String> = Vec::new();
    let mut total = 0usize;
    for record in &records {
        let pattern = record["pattern"].as_str().expect("pattern");
        let regex = match PyRegex::new(pattern) {
            Ok(regex) => regex,
            Err(error) => {
                bad.push(format!("{pattern:?}: parse error {error}"));
                continue;
            }
        };
        for case in record["cases"].as_array().expect("cases") {
            total += 1;
            let subject: Vec<char> = case["text"].as_str().expect("text").chars().collect();
            let mut problems = Vec::new();
            if shaped(regex.search_chars(&subject, 0, false)) != expected(&case["search"]) {
                problems.push("search");
            }
            if shaped(regex.match_chars(&subject)) != expected(&case["match"]) {
                problems.push("match");
            }
            if shaped(regex.fullmatch_chars(&subject)) != expected(&case["fullmatch"]) {
                problems.push("fullmatch");
            }
            let all: Vec<_> = regex.find_iter_chars(&subject).into_iter().map(|item| shaped(Some(item))).collect();
            let want: Vec<_> = case["finditer"].as_array().expect("finditer").iter().map(expected).collect();
            if all != want {
                problems.push("finditer");
            }
            if !problems.is_empty() {
                bad.push(format!("{pattern:?} on {:?}: {problems:?}", case["text"]));
            }
        }
    }
    assert!(total > 10_000, "cases {total}");
    assert!(bad.is_empty(), "{} problems of {total} cases, first: {:#?}", bad.len(), &bad[..bad.len().min(40)]);
}
