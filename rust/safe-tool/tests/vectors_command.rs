#![cfg(unix)]
use guard_common::shell::HereDocument;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

struct Fixture(std::path::PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        for tag in ["rewrite", "same", "code3", "code4"] {
            let _ = std::fs::remove_file(self.0.join(tag));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    value.as_str().unwrap_or_else(|| panic!("missing {name}"))
}

fn argument<'a>(args: &'a [Value], index: usize, name: &str) -> &'a Value {
    args.get(index).unwrap_or_else(|| panic!("missing {name}"))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("string array")
        .iter()
        .map(|item| string(item, "array item").to_owned())
        .collect()
}

fn index(value: &Value, name: &str) -> usize {
    value.as_u64().unwrap_or_else(|| panic!("missing {name}")) as usize
}

fn document(value: &Value) -> HereDocument {
    let field = |name| value.get(name).unwrap_or_else(|| panic!("missing {name}"));
    let outer = field("outer").as_array().map(|items| {
        (
            argument(items, 0, "outer line")
                .as_i64()
                .expect("outer line"),
            argument(items, 1, "outer opening")
                .as_i64()
                .expect("outer opening"),
            string(argument(items, 2, "outer quote"), "outer quote").to_owned(),
        )
    });
    HereDocument {
        line_start: index(field("line_start"), "line_start"),
        marker_start: index(field("marker_start"), "marker_start"),
        delimiter_end: index(field("delimiter_end"), "delimiter_end"),
        line_end: index(field("line_end"), "line_end"),
        body_start: index(field("body_start"), "body_start"),
        body_end: index(field("body_end"), "body_end"),
        end: index(field("end"), "end"),
        quoted: field("quoted").as_bool().expect("quoted"),
        outer,
    }
}

#[test]
fn vectors_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/command.json"
    ))
    .expect("run python3 rust/safe-tool/tests/gen_command.py first");
    let records: Vec<Value> = serde_json::from_str(&source).expect("vector JSON");
    let source_root = std::env::var("S4_SOURCE_REPO").unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .and_then(std::path::Path::parent)
            .expect("root")
            .to_string_lossy()
            .into_owned()
    });
    let previous = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(source_root).expect("oracle cwd");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let fixture = std::env::temp_dir().join(format!("s4-rtk-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&fixture).expect("fixture folder");
    let _cleanup = Fixture(fixture.clone());
    for (tag, script) in [
        ("rewrite", "#!/bin/sh\nprintf 'rtk %s\\n' \"$2\"\n"),
        ("same", "#!/bin/sh\nprintf '%s\\n' \"$2\"\n"),
        ("code3", "#!/bin/sh\nprintf 'rtk %s\\n' \"$2\"\nexit 3\n"),
        ("code4", "#!/bin/sh\nprintf 'rtk %s\\n' \"$2\"\nexit 4\n"),
    ] {
        let path = fixture.join(tag);
        std::fs::write(&path, script).expect("fixture script");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
    for (number, record) in records.iter().enumerate() {
        let name = string(record.get("fn").expect("fn"), "fn");
        let args = record.get("args").and_then(Value::as_array).expect("args");
        let (actual, exception) = match name {
            "unused_marker" => (
                json!(safe_tool::command::unused_marker(string(
                    argument(args, 0, "command"),
                    "command"
                ))),
                Value::Null,
            ),
            "owner_words" => (
                json!(safe_tool::command::owner_words(
                    string(argument(args, 0, "line"), "line"),
                    string(argument(args, 1, "marker"), "marker")
                )),
                Value::Null,
            ),
            "is_data_owner" => {
                let words = argument(args, 0, "words");
                let words = if words.is_null() {
                    None
                } else {
                    Some(strings(words))
                };
                (
                    json!(safe_tool::command::is_data_owner(words.as_deref())),
                    Value::Null,
                )
            }
            "is_data_heredoc" => (
                json!(safe_tool::command::is_data_heredoc(
                    string(argument(args, 0, "command"), "command"),
                    &document(argument(args, 1, "document")),
                    string(argument(args, 2, "marker"), "marker")
                )),
                Value::Null,
            ),
            "plain_enough" => (
                json!(safe_tool::command::plain_enough(string(
                    argument(args, 0, "code"),
                    "code"
                ))),
                Value::Null,
            ),
            "heredoc_views" => (
                json!(safe_tool::command::heredoc_views(string(
                    argument(args, 0, "command"),
                    "command"
                ))),
                Value::Null,
            ),
            "tokenize_with_loose_bodies" => (
                json!(safe_tool::command::tokenize_with_loose_bodies(string(
                    argument(args, 0, "code"),
                    "code"
                ))),
                Value::Null,
            ),
            "sensitive_command" => match safe_tool::command::sensitive_command(
                string(argument(args, 0, "command"), "command"),
                argument(args, 1, "data_heredocs")
                    .as_bool()
                    .expect("data_heredocs"),
            ) {
                Ok(value) => (json!(value), Value::Null),
                Err(_) => (Value::Null, json!("ValueError")),
            },
            "blocked_only_by_startup_file" => {
                match safe_tool::command::blocked_only_by_startup_file(string(
                    argument(args, 0, "command"),
                    "command",
                )) {
                    Ok(value) => (json!(value), Value::Null),
                    Err(_) => (Value::Null, json!("ValueError")),
                }
            }
            "blocked_by_git_format" => match safe_tool::command::blocked_by_git_format(string(
                argument(args, 0, "command"),
                "command",
            )) {
                Ok(value) => (json!(value), Value::Null),
                Err(_) => (Value::Null, json!("UnresolvableCommand")),
            },
            "blocked_only_by_proxy" => match safe_tool::command::blocked_only_by_proxy(string(
                argument(args, 0, "command"),
                "command",
            )) {
                Ok(value) => (json!(value), Value::Null),
                Err(_) => (Value::Null, json!("ValueError")),
            },
            "require_rtk" => {
                std::env::set_var(
                    "AGENT_SAFEGUARDS_REQUIRE_RTK",
                    string(argument(args, 0, "required"), "required"),
                );
                std::env::set_var(
                    "CLAUDE_PLUGIN_OPTION_REQUIRE_RTK",
                    string(argument(args, 1, "plugin"), "plugin"),
                );
                (json!(safe_tool::command::require_rtk()), Value::Null)
            }
            "rtk_required" => {
                let path = argument(args, 1, "path");
                let path = if path.is_null() {
                    Value::Null
                } else if let Some(tag) = path.as_str().filter(|tag| !tag.starts_with('/')) {
                    json!(fixture.join(tag).to_string_lossy())
                } else {
                    path.clone()
                };
                guard_common::overrides::set_local("RTK_PATH", path);
                let result = safe_tool::command::rtk_required(string(
                    argument(args, 0, "command"),
                    "command",
                ));
                guard_common::overrides::clear_local();
                (json!(result), Value::Null)
            }
            "on_budget_alarm" => {
                safe_tool::command::set_decision_made(
                    argument(args, 0, "decided").as_bool().expect("decided"),
                );
                match safe_tool::command::on_budget_alarm() {
                    Ok(()) => (Value::Null, Value::Null),
                    Err(_) => (Value::Null, json!("_CheckTooSlow")),
                }
            }
            "set_budget" => {
                let seconds = argument(args, 0, "seconds").as_f64().expect("seconds");
                match safe_tool::command::set_budget(seconds) {
                    Ok(()) => (Value::Null, Value::Null),
                    Err(_) => (Value::Null, json!("itimer_error")),
                }
            }
            "deny_hook" => (
                safe_tool::command::deny_hook(
                    args.first()
                        .and_then(Value::as_str)
                        .unwrap_or("safe_tool.deny.sensitive"),
                ),
                Value::Null,
            ),
            "ask_local_artifact_hook" => {
                (safe_tool::command::ask_local_artifact_hook(), Value::Null)
            }
            other => panic!("unknown function {other}"),
        };
        assert_eq!(
            exception,
            *record.get("exc").expect("exc"),
            "exception at {number} in {name}"
        );
        assert_eq!(
            actual,
            *record.get("ret").expect("ret"),
            "value at {number} in {name}"
        );
    }
    std::env::set_current_dir(previous).expect("restore cwd");
}

#[test]
fn exhaustive_predicates_match_python() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/exhaustive_command.txt"
    ))
    .expect("run python3 rust/safe-tool/tests/gen_command.py first");
    for (number, line) in source.lines().enumerate() {
        let mut parts = line.split('\t');
        let function = parts.next().expect("function");
        let hex = parts.next().expect("hex");
        let expected = parts.next().expect("expected");
        let bytes = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("pair"), 16).expect("hex")
            })
            .collect::<Vec<_>>();
        let value = String::from_utf8(bytes).expect("utf8");
        if function == "proxy_prefix" {
            let expected_bytes = expected
                .as_bytes()
                .chunks(2)
                .map(|pair| {
                    u8::from_str_radix(std::str::from_utf8(pair).expect("pair"), 16).expect("hex")
                })
                .collect::<Vec<_>>();
            let expected_text = String::from_utf8(expected_bytes).expect("utf8");
            assert_eq!(
                safe_tool::command::without_proxy_prefix(&value),
                expected_text,
                "proxy prefix at {number}"
            );
            continue;
        }
        let actual = match function {
            "data_env" => safe_tool::command::names_non_template_data_env(&value),
            "plain_enough" => safe_tool::command::plain_enough(&value),
            "is_data_owner" => {
                let words: Vec<String> = serde_json::from_str(&value).expect("words");
                safe_tool::command::is_data_owner(Some(&words))
            }
            other => panic!("unknown predicate {other}"),
        };
        assert_eq!(actual, expected == "1", "{function} at {number}");
    }
}
