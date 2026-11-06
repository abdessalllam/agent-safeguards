use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let first = chunk.first().copied().expect("first hex digit");
            let second = chunk.get(1).copied().expect("second hex digit");
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            digit(first) * 16 + digit(second)
        })
        .collect()
}

fn string(value: &Value) -> &str {
    value.as_str().expect("string vector field")
}

fn fixture() -> Fixture {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = PathBuf::from(guard_common::sys::realpath(
        &std::env::temp_dir().to_string_lossy(),
    ))
    .join(format!("s9-redact-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).expect("fixture home");
    std::fs::write(
        root.join(".zshrc"),
        "export PRESENT=1\nEMPTY=\nexport LATER=2\nunset LATER\n",
    )
    .expect("startup fixture");
    std::fs::write(root.join(".bashrc"), "BASH_ONLY=1\n").expect("second startup fixture");
    Fixture(root)
}

#[test]
fn vectors_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/redact.json"
    ))
    .expect("run python3 rust/safe-tool/tests/gen_redact.py");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vectors JSON");
    let home = fixture();
    guard_common::overrides::set_local("USER_HOME", json!(home.0.to_string_lossy().to_string()));
    guard_common::overrides::set_local("SCAN_BUDGET_SECONDS", json!(300.0));
    for (index, record) in records.iter().enumerate() {
        let name = string(record.get("fn").expect("fn"));
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let expected = record.get("ret").expect("ret");
        let exception = record.get("exc").expect("exc");
        match name {
            "all_octets" => {
                let actual =
                    safe_tool::redact::all_octets(string(args.first().expect("candidate")));
                if exception == "ValueError" {
                    assert_eq!(actual, Err("ValueError"), "vector {index}");
                } else {
                    assert_eq!(actual.ok(), expected.as_bool(), "vector {index}");
                }
            }
            "is_ipv6" => {
                let actual = safe_tool::redact::is_ipv6(string(args.first().expect("candidate")));
                assert_eq!(
                    actual,
                    expected.as_bool().expect("boolean"),
                    "vector {index}"
                );
            }
            "redact" => {
                let raw = hex_bytes(string(args.first().expect("raw")));
                let actual = safe_tool::redact::redact_bytes(&raw);
                let expected = expected.as_array().expect("result");
                assert_eq!(
                    expected.first().and_then(Value::as_i64),
                    Some(0),
                    "vector {index}"
                );
                assert_eq!(
                    actual,
                    string(expected.get(1).expect("stdout")),
                    "vector {index}"
                );
            }
            "has_key" => {
                let input = args
                    .first()
                    .and_then(Value::as_array)
                    .expect("key arguments");
                let arguments: Vec<String> = input
                    .iter()
                    .map(|item| string(item).replace("<HOME>", &home.0.to_string_lossy()))
                    .collect();
                let actual = safe_tool::cli::has_key_result(&arguments);
                if exception == "ValueError" {
                    assert!(actual.is_err(), "vector {index}");
                } else {
                    let (code, stdout, stderr) = actual.expect("key result");
                    let result = expected.as_array().expect("key expected");
                    assert_eq!(
                        i64::from(code),
                        result.first().and_then(Value::as_i64).expect("code"),
                        "vector {index}"
                    );
                    assert_eq!(
                        stdout,
                        string(result.get(1).expect("stdout")),
                        "vector {index}"
                    );
                    assert_eq!(
                        stderr,
                        string(result.get(2).expect("stderr")),
                        "vector {index}"
                    );
                }
            }
            "cli" => {
                let arguments = args.first().and_then(Value::as_array).expect("arguments");
                let raw = hex_bytes(string(args.get(1).expect("stdin")));
                let mut command = Command::new(env!("CARGO_BIN_EXE_safe-tool"));
                command
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &home.0)
                    .current_dir(&home.0);
                for item in arguments {
                    command.arg(string(item));
                }
                let mut child = command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn CLI");
                child
                    .stdin
                    .take()
                    .expect("CLI stdin")
                    .write_all(&raw)
                    .expect("write CLI stdin");
                let actual = child.wait_with_output().expect("CLI output");
                let result = expected.as_array().expect("CLI expected");
                assert_eq!(
                    actual.status.code().map(i64::from),
                    result.first().and_then(Value::as_i64),
                    "vector {index}"
                );
                assert_eq!(
                    actual.stdout,
                    hex_bytes(string(result.get(1).expect("stdout"))),
                    "vector {index}"
                );
                assert_eq!(
                    actual.stderr,
                    hex_bytes(string(result.get(2).expect("stderr"))),
                    "vector {index}"
                );
            }
            other => panic!("unknown function {other}"),
        }
    }
    guard_common::overrides::clear_local();
}

#[test]
fn exhaustive_predicates_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_redact.txt"
    ))
    .expect("run python3 rust/safe-tool/tests/gen_redact.py");
    for (index, line) in source.lines().enumerate() {
        let mut pieces = line.split('|');
        let raw = hex_bytes(pieces.next().expect("hex"));
        let candidate = String::from_utf8(raw).expect("UTF-8");
        let octets = match safe_tool::redact::all_octets(&candidate) {
            Ok(true) => "1",
            Ok(false) => "0",
            Err(_) => "E",
        };
        let ipv6 = if safe_tool::redact::is_ipv6(&candidate) {
            "1"
        } else {
            "0"
        };
        assert_eq!(octets, pieces.next().expect("octets"), "row {index}");
        assert_eq!(ipv6, pieces.next().expect("ipv6"), "row {index}");
    }
}
