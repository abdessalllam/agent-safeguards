#![cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};

use delete_guard::globs::{self, GlobError, GlobToken};
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("d2-globs-rust-{}-{stamp}", std::process::id()));
    for name in [
        "pool",
        "pool/one",
        "pool/one/two",
        "pool/.hidden",
        "pool/files_trashbin",
        "pool/UPPER",
        "pool/123",
        "empty",
        "holder",
        "holder/.local/share/Trash",
    ] {
        fs::create_dir_all(root.join(name)).expect("fixture directory");
    }
    for name in [
        "pool/one/record",
        "pool/one/two/record",
        "pool/files_trashbin/record",
        "pool/UPPER/record",
        "pool/123/record",
        "pool/.hidden/record",
        "file",
        "holder/.local/share/Trash/record",
    ] {
        fs::write(root.join(name), "x").expect("fixture file");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("pool"), root.join("link")).expect("fixture link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("missing"), root.join("dangling"))
        .expect("fixture dangling link");
    root
}

fn normalized(value: Value, root: &str) -> Value {
    match value {
        Value::String(text) => json!(text.replace(root, "{FIXTURE}")),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| normalized(value, root))
                .collect(),
        ),
        other => other,
    }
}

fn decode_hex(hex: &str) -> String {
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex digits");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect();
    String::from_utf8(bytes).expect("UTF-8 pattern")
}

fn glob_error(error: &GlobError) -> &'static str {
    match error {
        GlobError::Stop(stop) if stop.as_denied().is_some() => "Denied",
        GlobError::Stop(_) => "CheckTooSlow",
        GlobError::Regex => "error",
        GlobError::Attribute => "AttributeError",
        GlobError::Value(_) => "ValueError",
    }
}

#[test]
fn vectors_match_python() {
    let root = fixture();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/globs.json");
    let text = fs::read_to_string(path).expect("read glob vectors; run python3 tests/gen_globs.py");
    let records: Vec<Value> = serde_json::from_str(&text).expect("parse glob vectors");
    let root_text = root.to_string_lossy().into_owned();
    let probes = ['a', '0', '-', '[', ']', ' ', '\n', '\u{1c}', 'é', 'α', '*'];
    for (index, record) in records.iter().enumerate() {
        let name = record.get("fn").and_then(Value::as_str).expect("function");
        let args = record
            .get("args")
            .and_then(Value::as_array)
            .expect("arguments");
        let arg = |at: usize| {
            args.get(at)
                .and_then(Value::as_str)
                .unwrap_or("")
                .replace("{FIXTURE}", &root_text)
        };
        let mut error = None;
        let actual = match name {
            "glob_tokens" => {
                if let Ok(tokens) = globs::glob_tokens(&arg(0)) {
                    json!(tokens
                        .iter()
                        .map(|token| match token {
                            GlobToken::Star => json!(["*", ""]),
                            GlobToken::Question => json!(["?", ""]),
                            GlobToken::Literal(ch) => json!(["lit", ch.to_string()]),
                            GlobToken::Set(_) => json!([
                                "set",
                                probes
                                    .iter()
                                    .map(|ch| globs::glob_token_matches(token, *ch)
                                        .expect("set token"))
                                    .collect::<Vec<_>>()
                            ]),
                        })
                        .collect::<Vec<_>>())
                } else {
                    error = Some("error");
                    json!(null)
                }
            }
            "glob_match" => {
                match globs::glob_tokens(&arg(0))
                    .and_then(|tokens| globs::glob_match(&tokens, &arg(1)))
                {
                    Ok(value) => json!(value),
                    Err(found) => {
                        error = Some(glob_error(&found));
                        json!(null)
                    }
                }
            }
            "glob_token_matches" => match globs::glob_tokens(&arg(0)) {
                Ok(tokens) => {
                    let token = args
                        .get(1)
                        .and_then(Value::as_u64)
                        .and_then(|at| tokens.get(at as usize));
                    match token {
                        Some(token) => match globs::glob_token_matches(
                            token,
                            arg(2).chars().next().unwrap_or(' '),
                        ) {
                            Ok(value) => json!(value),
                            Err(found) => {
                                error = Some(glob_error(&found));
                                json!(null)
                            }
                        },
                        None => {
                            error = Some("IndexError");
                            json!(null)
                        }
                    }
                }
                Err(found) => {
                    error = Some(glob_error(&found));
                    json!(null)
                }
            },
            "holds_trash" => json!(globs::holds_trash(&arg(0))),
            "is_folder" => {
                let entry = fs::read_dir(&root)
                    .expect("fixture entries")
                    .filter_map(Result::ok)
                    .find(|entry| entry.file_name().to_string_lossy() == arg(0))
                    .expect("named entry");
                json!(globs::is_folder(&entry))
            }
            "glob_entries" => {
                let mut visits = args.get(1).and_then(Value::as_u64).unwrap_or(0) as usize;
                match globs::glob_entries(
                    &arg(0),
                    &mut visits,
                    &arg(2),
                    &arg(3),
                    &delete_guard::budget::Budget::new(3.0),
                ) {
                    Ok(entries) => json!([
                        entries
                            .iter()
                            .map(|entry| entry.file_name().to_string_lossy().into_owned())
                            .collect::<Vec<_>>(),
                        visits
                    ]),
                    Err(stop) => {
                        error = stop.as_denied().map(|_| "Denied").or(Some("CheckTooSlow"));
                        json!(null)
                    }
                }
            }
            "glob_walk" => {
                let mut matches = Vec::new();
                let mut visits = args.get(2).and_then(Value::as_u64).unwrap_or(0) as usize;
                let parts: Vec<String> = args
                    .get(1)
                    .and_then(Value::as_array)
                    .expect("parts")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                match globs::glob_walk(
                    &arg(0),
                    &parts,
                    &mut matches,
                    &mut visits,
                    &arg(3),
                    &arg(4),
                    args.get(5).and_then(Value::as_bool).unwrap_or(false),
                ) {
                    Ok(()) => json!([matches, visits]),
                    Err(found) => {
                        error = Some(glob_error(&found));
                        json!(null)
                    }
                }
            }
            "glob_matches" => {
                let cwd = args.get(1).and_then(Value::as_str).map(|_| arg(1));
                match globs::glob_matches(&arg(0), cwd.as_deref(), &arg(2)) {
                    Ok(matches) => json!(matches),
                    Err(found) => {
                        error = Some(glob_error(&found));
                        json!(null)
                    }
                }
            }
            _ => panic!("unknown function {name}"),
        };
        let expected = record.get("ret").expect("return");
        let actual = normalized(actual, &root_text);
        assert_eq!(
            error,
            record.get("exc").and_then(Value::as_str),
            "exception at vector {index} {name}"
        );
        assert_eq!(&actual, expected, "value at vector {index} {name}");
    }
    fs::remove_dir_all(root).expect("remove owned fixture");
}

#[test]
fn exhaustive_patterns_match_python() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/exhaustive_globs.txt");
    let text =
        fs::read_to_string(path).expect("read exhaustive globs; run python3 tests/gen_globs.py");
    let mut mismatches = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let (hex, expected) = line.split_once('\t').expect("hex and expected");
        let pattern = decode_hex(hex);
        let actual = match globs::glob_tokens(&pattern) {
            Ok(tokens) => {
                let results = ["", "a", "0", "]", "é"]
                    .iter()
                    .map(|name| globs::glob_match(&tokens, name).expect("match"))
                    .collect::<Vec<_>>();
                json!([results, null])
            }
            Err(error) => json!([null, glob_error(&error)]),
        };
        let expected: Value = serde_json::from_str(expected).expect("expected JSON");
        if actual != expected && mismatches.len() < 50 {
            mismatches.push((index, hex.to_owned(), actual, expected));
        }
    }
    assert!(
        mismatches.is_empty(),
        "first exhaustive mismatches: {mismatches:?}"
    );
}
