#[cfg(unix)]
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::path::Path;

use guard_common::pyglob::fnmatchcase;
#[cfg(unix)]
use guard_common::pyglob::iglob;
#[cfg(unix)]
use serde_json::Value;

fn unhex(text: &str) -> String {
    let bytes: Vec<u8> = (0..text.len() / 2)
        .map(|index| u8::from_str_radix(text.get(index * 2..index * 2 + 2).unwrap_or("00"), 16).unwrap_or(0))
        .collect();
    String::from_utf8(bytes).unwrap_or_default()
}

#[test]
fn fnmatch_rows_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/fnmatch.txt");
    let text = fs::read_to_string(path).expect("run python3 tests/gen_pyglob.py first");
    let mut bad = Vec::new();
    let mut total = 0usize;
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let pattern = unhex(fields.get(1).copied().unwrap_or(""));
        let name = unhex(fields.get(2).copied().unwrap_or(""));
        let want = fields.get(3).copied().unwrap_or("") == "1";
        total += 1;
        let got = fnmatchcase(&name, &pattern);
        if got != want && bad.len() < 30 {
            bad.push(format!("{pattern:?} vs {name:?}: got {got} want {want}"));
        }
    }
    assert!(total > 100_000, "rows {total}");
    assert!(bad.is_empty(), "{} rows differ, first: {bad:?}", bad.len());
}

#[cfg(unix)]
fn build_tree(root: &Path) {
    for folder in ["a/sub/.dothidden", "b", "ab", ".hidden", "sp ace", "link-target"] {
        fs::create_dir_all(root.join(folder)).expect("folder");
    }
    for name in [
        "a/x.txt", "a/.hid", "a/y.py", "a/sub/z.txt", "a/sub/.dothidden/q", "b/x.txt", ".hidden/f", "file1", "file2",
        ".dot", "a[1]", "we*ird", "sp ace/in", "link-target/x.txt",
    ] {
        fs::write(root.join(name), "x").expect("file");
    }
    std::os::unix::fs::symlink("a", root.join("link_a")).expect("link");
    std::os::unix::fs::symlink("file1", root.join("link_file")).expect("link");
    std::os::unix::fs::symlink("missing", root.join("dangling")).expect("link");
}

#[cfg(unix)]
#[test]
fn iglob_records_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/pyglob.json");
    let text = fs::read_to_string(path).expect("run python3 tests/gen_pyglob.py first");
    let records: Vec<Value> = serde_json::from_str(&text).expect("json");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = Path::new(&guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("pyglob-rust-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&root).expect("root");
    build_tree(&root);
    let root_text = root.to_string_lossy().into_owned();
    let mut full: HashMap<String, Vec<String>> = HashMap::new();
    for record in &records {
        if record["limit"].as_u64() == Some(100_000) && record["exc"].is_null() {
            let mut list: Vec<String> = record["ret"].as_array().expect("ret").iter().map(|item| item.as_str().expect("s").to_owned()).collect();
            list.sort();
            full.insert(record["pattern"].as_str().expect("pattern").to_owned(), list);
        }
    }
    let mut bad = Vec::new();
    for record in &records {
        let pattern = record["pattern"].as_str().expect("pattern");
        let limit = record["limit"].as_u64().expect("limit") as usize;
        let actual = iglob(&pattern.replace("@ROOT@", &root_text), limit);
        if !record["exc"].is_null() {
            if actual.is_ok() {
                bad.push(format!("{pattern:?} limit {limit}: expected an error"));
            }
            continue;
        }
        let Ok(found) = actual else {
            bad.push(format!("{pattern:?} limit {limit}: unexpected error"));
            continue;
        };
        let mut got: Vec<String> = found.iter().map(|item| item.replace(&root_text, "@ROOT@")).collect();
        let expected: Vec<String> = record["ret"].as_array().expect("ret").iter().map(|item| item.as_str().expect("s").to_owned()).collect();
        if limit == 100_000 {
            got.sort();
            let mut sorted = expected.clone();
            sorted.sort();
            if got != sorted {
                bad.push(format!("{pattern:?}: got {got:?} want {sorted:?}"));
            }
        } else {
            let everything = full.get(pattern).cloned().unwrap_or_default();
            if got.len() != expected.len() || got.iter().any(|item| !everything.contains(item)) {
                bad.push(format!("{pattern:?} limit {limit}: got {got:?} want {expected:?}"));
            }
        }
    }
    let _ = fs::remove_dir_all(&root);
    assert!(bad.is_empty(), "{} records differ, first: {:?}", bad.len(), &bad[..bad.len().min(12)]);
}
