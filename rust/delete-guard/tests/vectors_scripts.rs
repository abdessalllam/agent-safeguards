use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use delete_guard::{errors::Stop, scripts};
use guard_common::overrides;
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy());
    let root = Path::new(&temp).join(format!("d4-scripts-rust-{}-{stamp}", std::process::id()));
    for name in ["u", "bin", "safe", "unsafe", "plain"] {
        fs::create_dir_all(root.join(name)).expect("directory");
    }
    for (name, body) in [
        ("safe.sh", "#!/bin/sh\necho okay\n"),
        ("danger.sh", "#!/bin/sh\nrm -rf \"$1\"\n"),
        ("plain.txt", "rm -rf \"$1\"\n"),
        (
            "vetted.sh",
            "#!/bin/sh\ndelete-guard check-remote \"$1\" || exit 3\n",
        ),
        ("echo.sh", "#!/bin/sh\necho \"delete-guard check-remote\"\n"),
        (
            "heredoc.sh",
            "#!/bin/sh\ncat <<'EOF'\nrm -rf /\nEOF\necho done\n",
        ),
        ("nested.sh", "#!/bin/sh\nsh danger.sh\n"),
    ] {
        fs::write(root.join(name), body).expect("file");
    }
    let tool = root.join("bin/tool.sh");
    fs::write(&tool, "#!/bin/sh\necho okay\n").expect("tool");
    let mut permissions = fs::metadata(&tool).expect("metadata").permissions();
    permissions.set_mode(permissions.mode() | 0o100);
    fs::set_permissions(&tool, permissions).expect("executable");
    fs::write(root.join("binary.sh"), b"#!/bin/sh\n\x00rm -rf /\n").expect("binary");
    let mut big = b"#!/bin/sh\n".to_vec();
    for _ in 0..40000 {
        big.extend_from_slice(b"# padding\n");
    }
    big.extend_from_slice(b"rm -rf /\n");
    fs::write(root.join("big.sh"), big).expect("large script");
    root
}

fn normalize(value: Value, root: &str, repo: &str) -> Value {
    match value {
        Value::String(text) => json!(text.replace(root, "@ROOT@").replace(repo, "@REPO@")),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| normalize(item, root, repo))
                .collect(),
        ),
        other => other,
    }
}

fn decode(value: &Value, root: &str, repo: &str) -> String {
    value
        .as_str()
        .unwrap_or("")
        .replace("@ROOT@", root)
        .replace("@REPO@", repo)
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("byte"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn stopped<T>(
    result: Result<T, Stop>,
    encode: impl FnOnce(T) -> Value,
) -> (Value, Option<&'static str>) {
    match result {
        Ok(value) => (encode(value), None),
        Err(Stop::Denied(reason)) => (
            json!(reason.to_string()),
            Some(if reason.is_remote() {
                "RemoteDenied"
            } else {
                "Denied"
            }),
        ),
        Err(Stop::TooSlow) => (Value::Null, Some("CheckTooSlow")),
        Err(Stop::Internal) => (json!("embedded null byte"), Some("ValueError")),
    }
}

#[test]
fn script_vectors_match_python() {
    let root = fixture();
    let root_text = root.to_string_lossy().into_owned();
    let original_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{root_text}/bin:{original_path}"));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo")
        .to_string_lossy()
        .into_owned();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/scripts.json");
    let records: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(source)
            .expect("vectors; run python3 rust/delete-guard/tests/gen_scripts.py"),
    )
    .expect("JSON");
    let mut phase = 0;
    for (index, record) in records.iter().enumerate() {
        let next_phase = record.get("phase").and_then(Value::as_i64).unwrap_or(0);
        if next_phase != phase {
            fs::write(root.join("safe.sh"), "#!/bin/sh\nrm -rf \"$1\"\n").expect("changed file");
            phase = next_phase;
        }
        overrides::clear_local();
        overrides::set_local("USER_HOME", json!(format!("{root_text}/u")));
        overrides::set_local("TEMP_ROOTS", json!([root_text]));
        let name = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let arg = |index| decode(args.get(index).unwrap_or(&Value::Null), &root_text, &repo);
        let shell = record
            .get("shell")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let cwd = args.get(1).and_then(Value::as_str).map(|_| arg(1));
        let (actual, exception) = match name {
            "script_excluded" => (json!(scripts::script_excluded(&arg(0))), None),
            "read_regular_file" => stopped(
                scripts::read_regular_file(
                    &arg(0),
                    args.get(1).and_then(Value::as_u64).unwrap_or(0) as usize,
                ),
                |value| value.map_or(Value::Null, |bytes| json!(hex(&bytes))),
            ),
            "is_reviewed_script" => stopped(
                scripts::is_reviewed_script(&arg(0), &bytes(&arg(1))),
                |value| json!(value),
            ),
            "without_text_heredocs" => (json!(scripts::without_text_heredocs(&arg(0))), None),
            "check_script" => stopped(
                scripts::check_script(&arg(0), cwd.as_deref(), shell),
                |_| Value::Null,
            ),
            "check_script_file" => stopped(
                scripts::check_script_file(&arg(0), cwd.as_deref(), shell),
                |_| Value::Null,
            ),
            "search_path" => (json!(scripts::search_path(&arg(0))), None),
            "without_heredoc_bodies" => (json!(scripts::without_heredoc_bodies(&arg(0))), None),
            "runs_checker" => (
                json!(scripts::runs_checker(
                    &arg(0),
                    args.get(1).and_then(Value::as_u64).unwrap_or(0) as usize
                )),
                None,
            ),
            "vets_deletes" => stopped(
                scripts::vets_deletes(
                    args.first()
                        .and_then(Value::as_str)
                        .map(|_| arg(0))
                        .as_deref(),
                ),
                |value| json!(value),
            ),
            other => panic!("unknown function {other}"),
        };
        let expected = record.get("ret").expect("ret").clone();
        let expected_exception = record.get("exc").and_then(Value::as_str);
        assert_eq!(
            (normalize(actual, &root_text, &repo), exception),
            (expected, expected_exception),
            "row {index} function {name}"
        );
    }
    std::env::set_var("PATH", original_path);
    fs::remove_dir_all(root).expect("fixture cleanup");
}
