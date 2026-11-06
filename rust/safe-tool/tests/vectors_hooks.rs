use std::io::{Read, Write};
use std::ops::Deref;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

fn hex_decode(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair.first().copied().unwrap_or(b'0') as char)
                .to_digit(16)
                .expect("hex digit");
            let low = (pair.get(1).copied().unwrap_or(b'0') as char)
                .to_digit(16)
                .expect("hex digit");
            u8::try_from(high * 16 + low).expect("byte")
        })
        .collect()
}

fn decoded_value(text: &str) -> Value {
    serde_json::from_slice(&hex_decode(text)).expect("encoded vector value")
}

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(std::path::PathBuf);

impl Deref for Fixture {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in [
            "plain.txt",
            "unicode.txt",
            "nul.txt",
            "empty.txt",
            "key.txt",
            "skip.pdf",
        ] {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn fixture() -> Fixture {
    let number = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("s6-hooks-{}-{number}", std::process::id()));
    std::fs::create_dir_all(&root).expect("fixture directory");
    std::fs::write(root.join("plain.txt"), "alpha\nbeta\ngamma\n").expect("plain file");
    std::fs::write(root.join("unicode.txt"), "πρώτο\r\n第二行\nthird\n").expect("unicode file");
    std::fs::write(root.join("nul.txt"), b"before\0after\n").expect("nul file");
    std::fs::write(root.join("empty.txt"), b"").expect("empty file");
    std::fs::write(
        root.join("key.txt"),
        format!("{}{}{}\n", "token=", "ghp_", "A".repeat(32)),
    )
    .expect("synthetic key file");
    std::fs::write(root.join("skip.pdf"), "placeholder").expect("skip file");
    Fixture(root)
}

fn substitute_fixture(raw: &[u8], fixture: &std::path::Path) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    text.replace("$FIXTURE", &fixture.to_string_lossy())
        .into_bytes()
}

fn vector_rows() -> Vec<Value> {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/hooks.json"
    ))
    .expect("run python3 rust/safe-tool/tests/gen_hooks.py");
    serde_json::from_str(&source).expect("hook vectors JSON")
}

fn check_content_tool_name_exhaustive(row: &Value) {
    let alphabet: Vec<char> = get(row, "alphabet").chars().collect();
    let maximum = row.get("max").and_then(Value::as_u64).expect("max") as usize;
    let bits = get(row, "bits").as_bytes();
    let mut words = vec![String::new()];
    let mut index = 0usize;
    for length in 0..=maximum {
        for word in &words {
            let expected = bits.get(index).copied().expect("expected bit") == b'1';
            assert_eq!(
                safe_tool::hooks::content_tool_name(&Value::String(word.clone())),
                expected,
                "content name exhaustive length {length} index {index}"
            );
            index += 1;
        }
        words = words
            .into_iter()
            .flat_map(|prefix| {
                alphabet.iter().map(move |character| {
                    let mut next = prefix.clone();
                    next.push(*character);
                    next
                })
            })
            .collect();
    }
    assert_eq!(index, bits.len(), "all exhaustive cases");
}

fn get<'a>(row: &'a Value, name: &str) -> &'a str {
    row.get(name).and_then(Value::as_str).expect("vector field")
}

fn replay_direct(row: &Value, fixture: &std::path::Path) -> (Value, Option<&'static str>) {
    let args = decoded_value(get(row, "args_hex"));
    let args = args.as_array().expect("args");
    let first = args.first().expect("first arg");
    let result = match get(row, "fn") {
        "command_of" => json!(safe_tool::hooks::command_of(first)),
        "content_tool" => json!(safe_tool::hooks::content_tool(first)),
        "content_tool_name" => json!(safe_tool::hooks::content_tool_name(first)),
        "line_number" => {
            let default = args.get(1).and_then(Value::as_u64).expect("default");
            return match safe_tool::hooks::line_number(first, default as usize) {
                Ok(value) => (json!(value), None),
                Err(_) => (Value::Null, Some("ValueError")),
            };
        }
        "read_lines" => {
            let cwd = args.get(1).expect("cwd");
            let cwd = if cwd.as_str() == Some("$FIXTURE") {
                Value::String(fixture.to_string_lossy().into_owned())
            } else {
                cwd.clone()
            };
            return match safe_tool::hooks::read_lines(first, &cwd) {
                Ok(value) => (json!(value), None),
                Err(_) => (Value::Null, Some("ValueError")),
            };
        }
        "redact_keys" => {
            let depth = args.get(1).and_then(Value::as_u64).expect("depth") as usize;
            return match safe_tool::hooks::redact_keys(first, depth) {
                Ok(value) => (json!(value), None),
                Err(_) => (Value::Null, Some("_ResponseTooComplex")),
            };
        }
        "json_payloads" => {
            let raw = hex_decode(first.as_str().expect("hex string"));
            json!(safe_tool::hooks::json_payloads(&raw))
        }
        other => panic!("unexpected function {other}"),
    };
    (result, None)
}

#[test]
fn vectors_match_python() {
    let fixture = fixture();
    let rows = vector_rows();
    for (number, row) in rows.iter().enumerate() {
        if get(row, "fn") == "run_hook" {
            continue;
        }
        if get(row, "fn") == "content_tool_name_exhaustive" {
            check_content_tool_name_exhaustive(row);
            continue;
        }
        let (actual, exception) = replay_direct(row, &fixture);
        let expected_exception = row.get("exc").and_then(Value::as_str);
        assert_eq!(exception, expected_exception, "direct vector {number}");
        if exception.is_none() {
            let expected = decoded_value(get(row, "ret_hex"));
            assert_eq!(actual, expected, "direct vector {number}");
        }
    }
}

#[test]
fn hook_vector_child() {
    if std::env::var_os("S6_HOOK_CHILD").is_none() {
        return;
    }
    let fixture = std::env::var("S6_FIXTURE").expect("fixture path");
    let fixture = std::path::Path::new(&fixture);
    let mut raw = Vec::new();
    std::io::stdin()
        .read_to_end(&mut raw)
        .expect("vectors input");
    let rows: Vec<Value> = serde_json::from_slice(&raw).expect("vectors");
    for (number, row) in rows.iter().enumerate() {
        let input = substitute_fixture(&hex_decode(get(row, "input_hex")), fixture);
        let expected = row.get("expected_event").and_then(Value::as_str);
        let code = safe_tool::hooks::run_hook_bytes(get(row, "runtime"), expected, &input);
        println!("S6CASE:{number}:{code}");
    }
}

fn json_lines(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

#[test]
fn whole_hook_runs_match_python() {
    let fixture = fixture();
    let rows: Vec<Value> = vector_rows()
        .into_iter()
        .filter(|row| row.get("fn").and_then(Value::as_str) == Some("run_hook"))
        .collect();
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("hook_vector_child")
        .arg("--nocapture")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &fixture.0)
        .env("S6_HOOK_CHILD", "1")
        .env("S6_FIXTURE", &fixture.0)
        .env("AGENT_SAFEGUARDS_REQUIRE_RTK", "0")
        .env("AGENT_SAFEGUARDS_AUTO_EXCLUDE", "0")
        .env("AGENT_SAFEGUARDS_FAIL_OPEN", "0")
        .current_dir(&fixture.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook child");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(serde_json::to_string(&rows).expect("rows").as_bytes())
        .expect("write vectors");
    let completed = child.wait_with_output().expect("child output");
    assert!(completed.status.success(), "hook child failed");
    assert!(completed.stderr.is_empty(), "hook child stderr");
    let stdout = String::from_utf8(completed.stdout).expect("stdout UTF-8");
    let mut current = String::new();
    let mut seen = 0;
    for line in stdout.lines() {
        if let Some(marker) = line.strip_prefix("S6CASE:") {
            let (number, code) = marker.split_once(':').expect("case marker");
            let number: usize = number.parse().expect("case number");
            let code: i64 = code.parse().expect("case code");
            assert_eq!(number, seen, "case ordering");
            let row = rows.get(number).expect("row");
            let expected_stdout =
                String::from_utf8(hex_decode(get(row, "stdout_hex"))).expect("Python stdout UTF-8");
            assert_eq!(
                json_lines(&current),
                json_lines(&expected_stdout),
                "hook vector {number}"
            );
            assert_eq!(
                code,
                row.get("exit").and_then(Value::as_i64).expect("exit"),
                "hook vector {number}"
            );
            assert_eq!(
                get(row, "stderr_hex"),
                "",
                "Python hook stderr vector {number}"
            );
            current.clear();
            seen += 1;
        } else if line.starts_with('{') {
            current.push_str(line);
            current.push('\n');
        }
    }
    assert_eq!(seen, rows.len(), "all hook cases replayed");
}
