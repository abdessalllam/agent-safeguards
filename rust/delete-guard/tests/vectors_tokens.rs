#![cfg(unix)]
use std::collections::HashSet;

use delete_guard::tokens;
use serde_json::{json, Value};

fn words(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("words array")
        .iter()
        .map(|word| word.as_str().expect("word").to_owned())
        .collect()
}

fn optional(value: &Value) -> Option<&str> {
    value.as_str()
}

fn sorted(values: HashSet<String>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().collect();
    values.sort();
    values
}

fn chunk_value(part: &tokens::Chunk) -> Value {
    json!([
        part.words,
        part.before,
        part.after,
        part.opened,
        part.redirected,
        part.redirections
    ])
}

#[test]
fn vectors_match_python() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/tokens.json");
    let text = std::fs::read_to_string(path)
        .expect("read tokens vectors; run python3 tests/gen_tokens.py");
    let records: Vec<Value> = serde_json::from_str(&text).expect("parse tokens vectors");
    for (index, record) in records.iter().enumerate() {
        let name = record.get("fn").and_then(Value::as_str).expect("function");
        let args = record
            .get("args")
            .and_then(Value::as_array)
            .expect("arguments");
        let arg = |number: usize| args.get(number).expect("argument");
        let mut exception = None;
        let actual = match name {
            "function_header_length" => json!(tokens::function_header_length(&words(arg(0)))),
            "open_parentheses" => json!(tokens::open_parentheses(words(arg(0)))),
            "without_syntax_prefix" => json!(tokens::without_syntax_prefix(&words(arg(0)))),
            "chunk" => {
                let redirections: Vec<(String, String, String)> = arg(4)
                    .as_array()
                    .expect("redirections")
                    .iter()
                    .map(|item| {
                        let item = item.as_array().expect("redirection");
                        (
                            item.first()
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned(),
                            item.get(1).and_then(Value::as_str).unwrap_or("").to_owned(),
                            item.get(2).and_then(Value::as_str).unwrap_or("").to_owned(),
                        )
                    })
                    .collect();
                chunk_value(&tokens::chunk(
                    &words(arg(0)),
                    optional(arg(1)),
                    optional(arg(2)),
                    arg(3).as_bool().expect("redirected"),
                    &redirections,
                ))
            }
            "protect_escaped_separators" => json!(tokens::protect_escaped_separators(
                arg(0).as_str().expect("text")
            )),
            "tokenize" => match tokens::tokenize(arg(0).as_str().expect("command")) {
                Some(parts) => Value::Array(parts.iter().map(chunk_value).collect()),
                None => Value::Null,
            },
            "base" => json!(tokens::base(arg(0).as_str().expect("word"))),
            "is_computed" => json!(tokens::is_computed(arg(0).as_str().expect("path"))),
            "home_expanded" => json!(tokens::home_expanded(arg(0).as_str().expect("path"))),
            "variables_changed_by" => json!(sorted(tokens::variables_changed_by(&words(arg(0))))),
            "variables_changed" => json!(sorted(tokens::variables_changed(
                arg(0).as_str().expect("command")
            ))),
            "expand" => {
                let changed: HashSet<String> = words(arg(2)).into_iter().collect();
                tokens::set_variables_changed(changed);
                match tokens::expand(arg(0).as_str().expect("path"), optional(arg(1))) {
                    Ok(value) => json!(value),
                    Err(tokens::ExpandError::ValueError) => {
                        exception = Some("ValueError");
                        Value::Null
                    }
                }
            }
            _ => panic!("unknown vector function {name}"),
        };
        assert!(
            record.get("exc") == Some(&json!(exception)),
            "exception at vector {index} {name}"
        );
        let mut expected = record.get("ret").expect("expected return").clone();
        if name == "expand" {
            if let Some(value) = expected.as_str() {
                let cwd = std::env::current_dir().expect("current directory");
                expected = if let Some(relative) = value.strip_prefix("{CWD_REL}:") {
                    json!(guard_common::sys::realpath(
                        &cwd.join(relative).to_string_lossy()
                    ))
                } else {
                    json!(value.replace("{CWD}", &cwd.to_string_lossy()))
                };
            }
        }
        assert!(actual == expected, "vector {index} {name} differed");
    }
    tokens::set_variables_changed(HashSet::new());
}
