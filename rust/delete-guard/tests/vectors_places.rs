#![cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};

use delete_guard::places;
use guard_common::overrides;
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("d1-oracle-rust-{}-{stamp}", std::process::id()));
    for path in [
        "clean",
        "repo/.git",
        "nested/one/two/three/.git",
        "too_deep/one/two/three/four/.git",
        "skipped/node_modules/pkg/.git",
        "outer/.git",
        "outer/plain",
        "outer/cache/a/b/.git",
        "outer/vendor/lib/.git",
        "outer/.worktrees/w",
    ] {
        fs::create_dir_all(root.join(path)).expect("fixture folder");
    }
    fs::write(root.join("file"), "x").expect("fixture file");
    fs::write(root.join("outer/.worktrees/w/.git"), "gitdir: x").expect("worktree file");
    for folder in ["limit", "outer/limit"] {
        fs::create_dir(root.join(folder)).expect("limit folder");
        for index in 0..=places::MAX_REPOSITORY_SCAN {
            fs::write(root.join(folder).join(index.to_string()), "").expect("limit file");
        }
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("repo"), root.join("symlink")).expect("fixture symlink");
    root
}

#[test]
fn vectors_match_python() {
    let root = fixture();
    let vector_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/places.json");
    let text = fs::read_to_string(vector_path)
        .expect("read places vectors; run python3 tests/gen_places.py");
    let records: Vec<Value> = serde_json::from_str(&text).expect("parse places vectors");
    let fixture_text = root.to_string_lossy();
    for (index, record) in records.iter().enumerate() {
        let name = record.get("fn").and_then(Value::as_str).expect("function");
        let args = record
            .get("args")
            .and_then(Value::as_array)
            .expect("arguments");
        let arg = |number: usize| {
            args.get(number)
                .and_then(Value::as_str)
                .unwrap_or("")
                .replace("{FIXTURE}", &fixture_text)
        };
        if name == "check_repository" {
            overrides::set_local("TEMP_ROOTS", json!([]));
            let denied = places::check_repository(&arg(0), &arg(1)).is_err();
            overrides::clear_local();
            let expected = record.get("exc").and_then(Value::as_str) == Some("Denied");
            assert!(denied == expected, "vector {index} {name} {} differed", arg(0));
            continue;
        }
        let actual = match name {
            "glob_base" => json!(places::glob_base(&arg(0))),
            "inside" => json!(places::inside(&arg(0), &arg(1))),
            "protected" => json!(places::protected(&arg(0))),
            "names_trash" => json!(places::names_trash(&arg(0))),
            "trash_roots" => {
                if args.first().is_some_and(Value::is_null) {
                    std::env::remove_var("XDG_DATA_HOME");
                } else {
                    std::env::set_var("XDG_DATA_HOME", arg(0));
                }
                json!(places::trash_roots())
            }
            "holds_repository" => json!(places::holds_repository(
                &arg(0),
                args.get(1)
                    .and_then(Value::as_u64)
                    .map_or(places::MAX_REPOSITORY_DEPTH, |levels| levels as usize)
            )),
            "inside_repository" => json!(places::inside_repository(&arg(0))),
            _ => panic!("unknown vector function {name}"),
        };
        let expected = record.get("ret").expect("expected return").clone();
        assert!(
            record.get("exc").is_some_and(Value::is_null),
            "Python exception at vector {index} {name}"
        );
        assert!(actual == expected, "vector {index} {name} differed");
    }
    fs::remove_dir_all(root).expect("remove owned fixture");
}
