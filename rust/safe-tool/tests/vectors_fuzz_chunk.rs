use serde_json::{json, Value};

fn strings(value: &Value) -> Vec<String> {
    value.as_array().expect("array").iter().map(|item| item.as_str().expect("word").to_owned()).collect()
}

#[test]
fn fuzz_chunk_records_match_python() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/fuzz_chunk.json");
    let text = std::fs::read_to_string(path).expect("run python3 tests/gen_fuzz_chunk.py first");
    let records: Vec<Value> = serde_json::from_str(&text).expect("json");
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let root = std::path::Path::new(&guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("fz-s3-rust-{}-{stamp}", std::process::id()));
    let home = root.join("home");
    let work = home.join("project");
    std::fs::create_dir_all(&work).expect("fixture directories");
    for name in [".zshrc", ".bashrc", ".profile", ".zsh_history", "ordinary.txt"] {
        std::fs::File::create(home.join(name)).expect("fixture file");
    }
    std::fs::File::create(work.join("ordinary.txt")).expect("work file");
    let original = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&work).expect("fixture cwd");
    guard_common::overrides::set_local("USER_HOME", json!(home.to_string_lossy()));
    let home_text = home.to_string_lossy().into_owned();
    let work_text = work.to_string_lossy().into_owned();
    let mut bad = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let function = record["fn"].as_str().expect("fn");
        let args = record["args"].as_array().expect("args");
        let text_arg = || args[0].as_str().expect("text").to_owned();
        let result: Result<Value, ()> = match function {
            "sensitive_chunk" => {
                safe_tool::consts::set_ps_target(args[1].as_str().expect("target"));
                safe_tool::consts::set_startup_rules(args[2].as_bool().expect("rules"));
                safe_tool::chunk::sensitive_chunk(&strings(&args[0])).map(|value| json!(value)).map_err(|_| ())
            }
            "glob_names_startup_file" => safe_tool::startup::glob_names_startup_file_at(&text_arg(), &home_text, &work_text).map(|value| json!(value)).map_err(|_| ()),
            "find_names_startup_file" => safe_tool::startup::find_names_startup_file_at(&text_arg(), &home_text, &work_text).map(|value| json!(value)).map_err(|_| ()),
            "mentions_startup_file" => Ok(json!(safe_tool::startup::mentions_startup_file(&text_arg()))),
            "pipeline_context" => Ok(json!(safe_tool::startup::pipeline_context(&text_arg()))),
            "without_safe_sources" => Ok(json!(safe_tool::startup::without_safe_sources(&text_arg()))),
            "safe_source" => Ok(json!(safe_tool::startup::safe_source(&text_arg()))),
            "could_name_startup_file" => Ok(json!(safe_tool::startup::could_name_startup_file(&text_arg(), args[1].as_bool().expect("dotted")))),
            "reads_startup_file" => {
                safe_tool::consts::set_startup_rules(args[1].as_bool().expect("rules"));
                safe_tool::startup::reads_startup_file_at(&text_arg(), &home_text, &work_text).map(|value| json!(value)).map_err(|_| ())
            }
            "prints_secret_variable" => Ok(json!(safe_tool::chunk::prints_secret_variable(&text_arg()))),
            "ps_format_shows_environment" => Ok(json!(safe_tool::chunk::ps_format_shows_environment(&text_arg()))),
            "docker_inspect_shows_environment" => Ok(json!(safe_tool::chunk::docker_inspect_shows_environment(&strings(&args[0])))),
            other => panic!("unknown function {other}"),
        };
        safe_tool::consts::set_startup_rules(true);
        let expected_error = !record["exc"].is_null();
        let matches = match (&result, expected_error) {
            (Err(()), true) => true,
            (Ok(actual), false) => *actual == record["ret"],
            _ => false,
        };
        if !matches {
            bad.push(format!("#{index} {function} {:?}: got {result:?}, want {} {}", record["args"], record["exc"], record["ret"]));
        }
    }
    std::env::set_current_dir(original).expect("restore cwd");
    guard_common::overrides::clear_local();
    let _ = std::fs::remove_dir_all(&root);
    assert!(bad.is_empty(), "{} records differ, first: {:#?}", bad.len(), &bad[..bad.len().min(8)]);
}
