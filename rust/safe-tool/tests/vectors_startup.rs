#![cfg(unix)]
use serde_json::{json, Value};

#[test]
fn vectors_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/startup.json");
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_startup.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vector json");
    let temp = guard_common::sys::realpath(std::env::temp_dir().to_string_lossy().as_ref());
    let fixture =
        std::path::Path::new(&temp).join(format!("safe-tool-s3-startup-{}", std::process::id()));
    let home = fixture.join("home");
    let work = home.join("project");
    std::fs::create_dir_all(&work).expect("fixture directories");
    for name in [
        ".zshrc",
        ".bashrc",
        ".profile",
        ".zsh_history",
        "ordinary.txt",
    ] {
        std::fs::File::create(home.join(name)).expect("fixture file");
    }
    std::fs::File::create(work.join("ordinary.txt")).expect("work fixture file");
    let old_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&work).expect("fixture cwd");
    let home_string = home.to_string_lossy().into_owned();
    let work_string = work.to_string_lossy().into_owned();
    for (index, record) in records.iter().enumerate() {
        let function = record.get("fn").and_then(Value::as_str).expect("fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let text = args
            .first()
            .and_then(Value::as_str)
            .expect("text")
            .replace("{HOME}", &home_string);
        let expected = record.get("ret").expect("ret");
        let expected = expected.as_str().map_or_else(
            || expected.clone(),
            |value| json!(value.replace("{HOME}", &home_string)),
        );
        let exception = record.get("exc").expect("exc");
        let (actual, actual_exception) = match function {
            "could_name_startup_file" => (
                json!(safe_tool::startup::could_name_startup_file(
                    &text,
                    args.get(1).and_then(Value::as_bool).expect("dotted")
                )),
                Value::Null,
            ),
            "glob_names_startup_file" => match safe_tool::startup::glob_names_startup_file_at(
                &text,
                &home_string,
                &work_string,
            ) {
                Ok(value) => (json!(value), Value::Null),
                Err(_) => (Value::Null, json!("ValueError")),
            },
            "find_names_startup_file" => match safe_tool::startup::find_names_startup_file_at(
                &text,
                &home_string,
                &work_string,
            ) {
                Ok(value) => (json!(value), Value::Null),
                Err(_) => (Value::Null, json!("ValueError")),
            },
            "mentions_startup_file" => (
                json!(safe_tool::startup::mentions_startup_file(&text)),
                Value::Null,
            ),
            "pipeline_context" => (
                json!(safe_tool::startup::pipeline_context(&text)),
                Value::Null,
            ),
            "safe_source" => (json!(safe_tool::startup::safe_source(&text)), Value::Null),
            "without_safe_sources" => (
                json!(safe_tool::startup::without_safe_sources(&text)),
                Value::Null,
            ),
            "reads_startup_file" => {
                safe_tool::consts::set_startup_rules(
                    args.get(1).and_then(Value::as_bool).expect("enabled"),
                );
                match safe_tool::startup::reads_startup_file_at(&text, &home_string, &work_string) {
                    Ok(value) => (json!(value), Value::Null),
                    Err(_) => (Value::Null, json!("ValueError")),
                }
            }
            other => panic!("unknown vector function {other}"),
        };
        assert_eq!(
            &actual_exception, exception,
            "exception mismatch at {index} in {function}"
        );
        assert_eq!(actual, expected, "value mismatch at {index} in {function}");
    }
    safe_tool::consts::set_startup_rules(true);
    std::env::set_current_dir(old_cwd).expect("restore cwd");
    std::fs::remove_file(work.join("ordinary.txt")).expect("remove work file");
    for name in [
        ".zshrc",
        ".bashrc",
        ".profile",
        ".zsh_history",
        "ordinary.txt",
    ] {
        std::fs::remove_file(home.join(name)).expect("remove fixture file");
    }
    std::fs::remove_dir(&work).expect("remove work directory");
    std::fs::remove_dir(&home).expect("remove home directory");
    std::fs::remove_dir(&fixture).expect("remove fixture directory");
}

#[test]
fn exhaustive_predicates_match_python() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_startup.txt"
    );
    let source = std::fs::read_to_string(path).expect("run python3 tests/gen_startup.py first");
    for (index, line) in source.lines().enumerate() {
        let mut parts = line.split('\t');
        let encoded = parts.next().expect("hex");
        let bytes: Vec<u8> = encoded
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("pair"), 16).expect("hex byte")
            })
            .collect();
        let value = String::from_utf8(bytes).expect("utf8");
        let safe = parts.next() == Some("1");
        let could = parts.next() == Some("1");
        let mentions = parts.next() == Some("1");
        let pipeline = parts.next() == Some("1");
        assert_eq!(
            safe_tool::startup::safe_source(&value),
            safe,
            "safe_source at {index}"
        );
        assert_eq!(
            safe_tool::startup::could_name_startup_file(&value, true),
            could,
            "could_name at {index}"
        );
        assert_eq!(
            safe_tool::startup::mentions_startup_file(&value),
            mentions,
            "mentions at {index}"
        );
        assert_eq!(
            safe_tool::startup::pipeline_context(&value),
            pipeline,
            "pipeline at {index}"
        );
    }
}
