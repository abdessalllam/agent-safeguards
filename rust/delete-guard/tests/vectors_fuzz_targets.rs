use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use delete_guard::errors::Stop;
use delete_guard::globs::GlobError;
use delete_guard::targets;
use guard_common::overrides;
use serde_json::{json, Value};

fn build(root: &Path, spec: &Value) {
    let names = |key: &str| -> Vec<String> {
        spec[key].as_array().expect("list").iter().map(|item| item.as_str().expect("name").to_owned()).collect()
    };
    for name in names("directories") {
        fs::create_dir_all(root.join(name)).expect("directory");
    }
    for name in names("files") {
        let path = root.join(&name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
        fs::write(path, "x").expect("file");
    }
    for link in spec["links"].as_array().expect("links") {
        let (name, target) = (link[0].as_str().expect("name"), link[1].as_str().expect("target"));
        std::os::unix::fs::symlink(target, root.join(name)).expect("link");
    }
    for (name, text) in spec["worktree_files"].as_object().expect("worktree files") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
        fs::write(path, text.as_str().expect("text")).expect("worktree file");
    }
    for name in names("git_repositories") {
        let mut init = Command::new("git");
        init.args(["init", "-q"]).arg(root.join(name));
        for (key, value) in [("GIT_CONFIG_GLOBAL", "/dev/null"), ("GIT_CONFIG_SYSTEM", "/dev/null"), ("GIT_TERMINAL_PROMPT", "0")] {
            init.env(key, value);
        }
        let status = init.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().expect("git init");
        assert!(status.success());
    }
}

fn substituted(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => json!(text.replace("@ROOT@", root)),
        Value::Array(items) => Value::Array(items.iter().map(|item| substituted(item, root)).collect()),
        other => other.clone(),
    }
}

#[test]
fn fuzz_target_records_match_python() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/fuzz_targets.json");
    let text = fs::read_to_string(path).expect("run python3 tests/gen_fuzz_targets.py first");
    let document: Value = serde_json::from_str(&text).expect("json");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root: PathBuf = Path::new(&guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("fz-d2-rust-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&root).expect("root");
    build(&root, &document["fixture"]);
    let root_text = root.to_string_lossy().into_owned();
    let mut bad = Vec::new();
    for (index, record) in document["records"].as_array().expect("records").iter().enumerate() {
        overrides::clear_local();
        for (name, value) in record["overrides"].as_object().expect("overrides") {
            overrides::set_local(name, substituted(value, &root_text));
        }
        targets::set_remote(None);
        targets::clear_remote_targets();
        targets::set_quoted_words(Default::default());
        let raw = record["raw"].as_str().expect("raw").replace("@ROOT@", &root_text);
        let cwd = record["cwd"].as_str().map(|item| item.replace("@ROOT@", &root_text));
        let result = targets::check_target(
            &raw,
            cwd.as_deref(),
            record["recursive"].as_bool().expect("recursive"),
            "rm",
            record["literal"].as_bool(),
        );
        let (actual, exception) = match result {
            Ok(()) => (Value::Null, None),
            Err(GlobError::Stop(Stop::Denied(denied))) => (
                json!(denied.to_string().replace(&root_text, "@ROOT@")),
                Some(if denied.is_remote() { "RemoteDenied" } else { "Denied" }),
            ),
            Err(GlobError::Stop(Stop::TooSlow)) => (Value::Null, Some("CheckTooSlow")),
            Err(GlobError::Stop(Stop::Internal)) => (Value::Null, Some("ValueError")),
            Err(GlobError::Regex) => (Value::Null, Some("error")),
            Err(GlobError::Attribute) => (Value::Null, Some("AttributeError")),
            Err(GlobError::Value(_)) => (Value::Null, Some("ValueError")),
        };
        let want_exception = record["exc"].as_str();
        let comparable = want_exception == Some("ValueError") || actual == record["ret"];
        if exception != want_exception || !comparable {
            bad.push(format!(
                "#{index} raw {:?} cwd {:?} recursive {} literal {:?} overrides {}: got {exception:?} {actual}, want {want_exception:?} {}",
                record["raw"], record["cwd"], record["recursive"], record["literal"], record["overrides"], record["ret"]
            ));
        }
    }
    overrides::clear_local();
    let _ = fs::remove_dir_all(&root);
    assert!(bad.is_empty(), "{} records differ, first: {:#?}", bad.len(), &bad[..bad.len().min(6)]);
}
