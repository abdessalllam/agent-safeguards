#![cfg(unix)]
use safe_tool::{consts, paths};
use serde_json::{json, Value};

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("string array")
        .iter()
        .map(|item| item.as_str().expect("string").to_owned())
        .collect()
}

#[test]
fn runtime_home_wrappers_use_shared_home() {
    assert_eq!(paths::covers_home("~"), Ok(true));
    assert_eq!(
        paths::searches_home("grep", &["-r", "K", "~"].map(String::from)),
        Ok(true)
    );
}

fn fixture() -> (std::path::PathBuf, String, String) {
    let temporary = guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy());
    let root = std::path::Path::new(&temporary).join(format!("paths-fixture-{}", std::process::id()));
    let home = root.join("home");
    let cwd = root.join("work");
    for path in [
        home.join(".config/fish"),
        home.join(".local/share/zsh"),
        home.join("project"),
        cwd.join("src"),
        cwd.join("nested"),
    ] {
        std::fs::create_dir_all(path).expect("create fixture path");
    }
    std::os::unix::fs::symlink(&home, cwd.join("home-link")).expect("create fixture symlink");
    std::os::unix::fs::symlink(&home, cwd.join("glob-home")).expect("create fixture symlink");
    std::fs::create_dir(cwd.join("glob-other")).expect("create fixture directory");
    (
        root,
        home.to_string_lossy().into_owned(),
        cwd.to_string_lossy().into_owned(),
    )
}

fn remove_fixture(root: &std::path::Path) {
    for path in ["work/home-link", "work/glob-home"] {
        std::fs::remove_file(root.join(path)).expect("remove fixture link");
    }
    for path in [
        "work/glob-other",
        "work/nested",
        "work/src",
        "work",
        "home/.config/fish",
        "home/.config",
        "home/.local/share/zsh",
        "home/.local/share",
        "home/.local",
        "home/project",
        "home",
    ] {
        std::fs::remove_dir(root.join(path)).expect("remove fixture directory");
    }
    std::fs::remove_dir(root).expect("remove fixture root");
}

#[test]
fn vectors_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/paths.json"
    ))
    .expect("run python3 tests/gen_paths.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vector json");
    let (root, home, cwd) = fixture();
    let original = std::env::current_dir().expect("initial working directory");
    for (index, record) in records.iter().enumerate() {
        let name = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let expected = record.get("ret").expect("ret");
        let actual = match name {
            "working_folder" => {
                let mode = args.first().and_then(Value::as_str).expect("mode");
                if mode == "deleted" {
                    let gone = root.join("gone");
                    std::fs::create_dir(&gone).expect("create deleted cwd");
                    std::env::set_current_dir(&gone).expect("enter deleted cwd");
                    std::fs::remove_dir(&gone).expect("delete cwd");
                    let result = paths::working_folder();
                    std::env::set_current_dir(&original).expect("restore cwd");
                    assert_eq!(result, guard_common::env::user_home());
                    json!("@HOME@")
                } else {
                    std::env::set_current_dir(&cwd).expect("enter fixture cwd");
                    let result = paths::working_folder();
                    std::env::set_current_dir(&original).expect("restore cwd");
                    assert_eq!(result, cwd);
                    json!("@CWD@")
                }
            }
            "covers_home" => {
                let operand = args.first().and_then(Value::as_str).expect("operand");
                match paths::covers_home_at(
                    &operand.replace("@ROOT@", &root.to_string_lossy()),
                    &home,
                    &cwd,
                ) {
                    Ok(found) => json!(found),
                    Err(_) => json!("ValueError"),
                }
            }
            "searches_home" => {
                consts::set_startup_rules(
                    !record
                        .get("disabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                );
                let result = paths::searches_home_at(
                    args.first().and_then(Value::as_str).expect("executable"),
                    &strings(args.get(1).expect("arguments"))
                        .iter()
                        .map(|item| item.replace("@ROOT@", &root.to_string_lossy()))
                        .collect::<Vec<_>>(),
                    &home,
                    &cwd,
                );
                consts::set_startup_rules(true);
                match result {
                    Ok(found) => json!(found),
                    Err(_) => json!("ValueError"),
                }
            }
            "search_targets" => json!(paths::search_targets(
                args.first().and_then(Value::as_str).expect("executable"),
                &strings(args.get(1).expect("arguments")),
            )),
            "traces_commands" => json!(paths::traces_commands(
                args.first().and_then(Value::as_str).expect("executable"),
                &strings(args.get(1).expect("arguments")),
            )),
            "chunks_with_separators" => json!(paths::chunks_with_separators(
                args.first().and_then(Value::as_str).expect("command"),
            )),
            "grep_prints_nothing_private" => json!(paths::grep_prints_nothing_private(&strings(
                args.first().expect("arguments")
            ))),
            "prints_nothing_private" => json!(paths::prints_nothing_private(&strings(
                args.first().expect("words")
            ))),
            "names_sensitive_path" => json!(paths::names_sensitive_path(
                args.first().and_then(Value::as_str).expect("lowered"),
                args.get(1).and_then(Value::as_str).expect("code"),
            )),
            other => panic!("unknown vector function {other}"),
        };
        if record.get("exc") == Some(&json!("ValueError")) {
            assert_eq!(actual, json!("ValueError"), "expected an error at {index} in {name}");
            continue;
        }
        assert_eq!(
            record.get("exc"),
            Some(&Value::Null),
            "unexpected oracle exception at {index} in {name}"
        );
        assert_eq!(&actual, expected, "result mismatch at {index} in {name}");
    }
    remove_fixture(&root);
}

fn decode_hex(hex: &str) -> String {
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit");
            let low = (pair[1] as char).to_digit(16).expect("hex digit");
            (high * 16 + low) as u8
        })
        .collect::<Vec<_>>();
    String::from_utf8(bytes).expect("utf8")
}

#[test]
fn exhaustive_small_predicates_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_paths.txt"
    ))
    .expect("run python3 tests/gen_paths.py first");
    for (index, row) in source.lines().enumerate() {
        let fields: Vec<&str> = row.split('\t').collect();
        let input = decode_hex(fields.get(1).expect("hex input"));
        let expected = *fields.last().expect("expected");
        let actual = match *fields.first().expect("kind") {
            "T" => {
                if paths::traces_commands("bash", &[input]) {
                    "1".to_owned()
                } else {
                    "0".to_owned()
                }
            }
            "G" => paths::grep_prints_nothing_private(&[input]).unwrap_or_else(|| "-".to_owned()),
            "F" => {
                let name = decode_hex(fields.get(2).expect("name"));
                if guard_common::pyglob::fnmatchcase(&name, &input) {
                    "1".to_owned()
                } else {
                    "0".to_owned()
                }
            }
            other => panic!("unknown exhaustive kind {other}"),
        };
        assert_eq!(actual, expected, "exhaustive mismatch at row {index}");
    }
}
