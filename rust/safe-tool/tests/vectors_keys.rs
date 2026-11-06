use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn string(value: &Value) -> &str {
    value.as_str().expect("string")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| string(item).to_owned())
        .collect()
}

fn fixture() -> Fixture {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = PathBuf::from(guard_common::sys::realpath(
        &std::env::temp_dir().to_string_lossy(),
    ))
    .join(format!("s8-keys-{}-{nonce}", std::process::id()));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("sub")).expect("fixture home");
    std::fs::write(home.join("dotfiles-zshrc"), "A=1\n").expect("valid link target");
    std::fs::write(home.join("other-file"), "A=1\n").expect("invalid link target");
    for (name, content) in [
        ("empty", "".to_owned()),
        ("basic", "A=1\nB=\nexport C=3\n".to_owned()),
        (
            "continuation",
            "A=1 \\\nB=2\nC=$(cmd with args)\nexport D=$(other thing)\n".to_owned(),
        ),
        (
            "quotes",
            "export A='hello there'\nA=\nreadonly -g B=2 # comment\n".to_owned(),
        ),
        (
            "too_many_lines",
            "A=1\n".repeat(safe_tool::consts::MAX_STARTUP_FILE_LINES + 1),
        ),
        (
            "long_pending",
            format!(
                "A={}\\\nB=2\n",
                "x".repeat(safe_tool::consts::MAX_STARTUP_LINE_CHARS + 1)
            ),
        ),
    ] {
        std::fs::write(root.join(name), content).expect("fixture file");
    }
    std::fs::write(root.join("invalid_utf8"), b"A=\xff\nB=2\n").expect("UTF-8 fixture");
    Fixture(root)
}

fn set_startup_variant(home: &Path, root: &Path, variant: &str) {
    let path = home.join(".zshrc");
    if path.symlink_metadata().is_ok() {
        std::fs::remove_file(&path).expect("old startup fixture");
    }
    match variant {
        "plain" => std::fs::write(path, "A=1\n").expect("plain startup file"),
        "missing" => {}
        "linked_valid" => {
            std::os::unix::fs::symlink(home.join("dotfiles-zshrc"), path).expect("valid link")
        }
        "linked_bad" => {
            std::os::unix::fs::symlink(home.join("other-file"), path).expect("invalid link")
        }
        "linked_outside" => {
            std::os::unix::fs::symlink(root.join("outside-zshrc"), path).expect("outside link")
        }
        other => panic!("unknown variant {other}"),
    }
}

#[test]
fn vectors_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/keys.json"
    ))
    .expect("generate keys vectors");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vectors JSON");
    let fixture = fixture();
    let home = fixture.0.join("home");
    guard_common::overrides::set_local("USER_HOME", json!(home.to_string_lossy().to_string()));
    for (index, record) in records.iter().enumerate() {
        let name = string(record.get("fn").expect("fn"));
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let argument = |at: usize| args.get(at).expect("argument");
        let (actual, exception) = match name {
            "startup_key_file" => {
                set_startup_variant(&home, &fixture.0, string(argument(1)));
                let requested = argument(0).as_str();
                match safe_tool::keys::startup_key_file(requested) {
                    Ok(result) => (
                        json!(result.map(
                            |path| path.replace(&home.to_string_lossy().to_string(), "<HOME>")
                        )),
                        Value::Null,
                    ),
                    Err(_) => (Value::Null, json!("ValueError")),
                }
            }
            "keys_set_in" => {
                let kind = string(argument(0));
                let path = match kind {
                    "directory" => home.to_string_lossy().to_string(),
                    "nul" => format!("{}\0", home.to_string_lossy()),
                    _ => fixture.0.join(kind).to_string_lossy().to_string(),
                };
                match safe_tool::keys::keys_set_in(&path) {
                    Ok((found, complete)) => {
                        let mut found: Vec<_> = found.into_iter().collect();
                        found.sort();
                        (json!([found, complete]), Value::Null)
                    }
                    Err(_) => (Value::Null, json!("ValueError")),
                }
            }
            "apply_line" | "apply_command" => {
                let mut found: HashSet<String> = strings(argument(1)).into_iter().collect();
                if name == "apply_line" {
                    safe_tool::keys::apply_line(string(argument(0)), &mut found);
                } else {
                    safe_tool::keys::apply_command(&strings(argument(0)), &mut found);
                }
                let mut found: Vec<_> = found.into_iter().collect();
                found.sort();
                (json!(found), Value::Null)
            }
            other => panic!("unknown vector function {other}"),
        };
        assert_eq!(
            &exception,
            record.get("exc").expect("exc"),
            "exception at {index} in {name}"
        );
        assert_eq!(
            &actual,
            record.get("ret").expect("ret"),
            "value at {index} in {name}"
        );
    }
    guard_common::overrides::clear_local();
}

fn from_hex(encoded: &str) -> String {
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hex = std::str::from_utf8(pair).expect("hex pair");
            u8::from_str_radix(hex, 16).expect("hex digit")
        })
        .collect();
    String::from_utf8(bytes).expect("UTF-8")
}

#[test]
fn exhaustive_lines_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_keys.txt"
    ))
    .expect("generate exhaustive keys lines");
    for (index, line) in source.lines().enumerate() {
        let (encoded, expected) = line.split_once('\t').expect("tab");
        let expected: Value = serde_json::from_str(expected).expect("result JSON");
        let mut found = HashSet::new();
        safe_tool::keys::apply_line(&from_hex(encoded), &mut found);
        let mut found: Vec<_> = found.into_iter().collect();
        found.sort();
        assert_eq!(json!(found), expected, "exhaustive line {index}");
    }
}
