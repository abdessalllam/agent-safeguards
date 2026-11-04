use std::path::PathBuf;
use std::process::Command;

use serde_json::json;

use comment_guard::{judge, Provider, Verdict};

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "comment-guard-test-{}-{}",
        std::process::id(),
        name
    ));
    let _ = std::fs::remove_dir_all(&path);
    let _ = std::fs::create_dir_all(&path);
    path
}

fn run(payload: &str) -> Verdict {
    judge(payload, Provider::Claude)
}

fn edit(path: &str, old: &str, new: &str) -> Verdict {
    run(&json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": { "file_path": path, "old_string": old, "new_string": new },
    })
    .to_string())
}

fn write(path: &str, content: &str) -> Verdict {
    run(&json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": path, "content": content },
    })
    .to_string())
}

fn patch(command: &str) -> Verdict {
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": { "command": command },
    });
    judge(&payload.to_string(), Provider::Codex)
}

fn denied(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Deny(_))
}

fn reason(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Deny(text) => text.clone(),
        _ => String::new(),
    }
}

fn comment_block(prefix: &str, count: usize) -> String {
    let mut out = String::new();
    for i in 0..count {
        out.push_str(&format!("{prefix} line {i}\n"));
    }
    out
}

#[test]
fn nine_line_python_block_is_denied() {
    let verdict = edit("a.py", "", &comment_block("#", 9));
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("9 comment lines"));
}

#[test]
fn single_comment_line_is_allowed() {
    assert!(!denied(&edit("a.py", "", "# one line\n")));
}

#[test]
fn two_blocks_of_one_line_are_denied() {
    let verdict = edit("a.py", "", "# one\nx = 1\n# two\n");
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("2 block(s)"));
}

#[test]
fn a_comment_kept_from_old_does_not_count() {
    let old = "# k1\n# k2\nx = 1\n";
    let new = "y = 2\n# k1\n# k2\n# added\nx = 1\n";
    assert!(!denied(&edit("a.py", old, new)));
    assert!(denied(&edit("a.py", "x = 1\n", new)));
}

#[test]
fn date_marker_is_denied() {
    let verdict = edit("a.py", "", "# fixed 2024-01-02 for good\n");
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("2024-01-02"));
}

#[test]
fn decision_marker_is_denied() {
    let verdict = edit("a.py", "", "# from D556\n");
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("D556"));
}

#[test]
fn history_phrases_are_denied() {
    let phrases = [
        "previously",
        "used to",
        "no longer",
        "was already",
        "originally",
        "formerly",
        "this change",
        "as requested",
    ];
    for phrase in phrases {
        let line = format!("# {phrase} like so\n");
        let verdict = edit("a.py", "", &line);
        assert!(denied(&verdict), "phrase {phrase} was allowed");
        assert!(reason(&verdict).to_ascii_lowercase().contains(phrase));
    }
}

#[test]
fn short_decision_lookalikes_are_not_markers() {
    assert!(!denied(&edit("a.py", "", "# tag ISD5 here\n")));
    assert!(!denied(&edit("a.py", "", "# D5 only\n")));
}

#[test]
fn a_line_of_101_characters_is_denied_and_100_is_allowed() {
    let long = format!("# {}\n", "a".repeat(99));
    assert!(denied(&edit("a.py", "", &long)));
    let fits = format!("# {}\n", "a".repeat(98));
    assert!(!denied(&edit("a.py", "", &fits)));
}

#[test]
fn every_exemption_is_ignored() {
    let prefixes = [
        "noqa",
        "type:",
        "pragma",
        "pylint:",
        "mypy:",
        "ruff:",
        "fmt:",
        "isort:",
        "pyright:",
        "eslint-",
        "prettier-ignore",
        "@ts-",
        "istanbul ",
        "c8 ",
        "go:",
        "nolint",
        "swiftlint:",
        "mark:",
        "region",
        "endregion",
        "spdx-license-identifier",
        "copyright",
        "license",
        "shellcheck",
        "vim:",
        "nosec",
        "cspell:",
        "-*-",
        "eslint-disable",
        "lint:",
        "clippy::",
        "rustfmt::",
        "+build",
        "@flow",
        "@jsx",
    ];
    for prefix in prefixes {
        let line = format!("# {prefix} one\n# {prefix} two\n# {prefix} three\n");
        assert!(!denied(&edit("a.py", "", &line)), "exemption {prefix} counted");
    }
}

#[test]
fn a_shebang_is_not_a_comment() {
    assert!(!denied(&edit("a.py", "", "#!/a\n#!/b\n#!/c\n# only comment\n")));
}

#[test]
fn a_php_attribute_is_not_a_comment() {
    assert!(!denied(&edit("a.php", "", "#[A]\n#[B]\n#[C]\n# only comment\n")));
}

#[test]
fn write_into_an_existing_file_compares_with_its_content() {
    let dir = temp_dir("write-existing");
    let path = dir.join("a.py");
    std::fs::write(&path, "# a\n# b\n# c\n").ok();
    let text = "# a\n# b\n# c\n";
    assert!(!denied(&write(&path.to_string_lossy(), text)));
    assert!(denied(&write(&path.to_string_lossy(), "# x\n# y\n# z\n")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_to_a_new_file_has_empty_old() {
    let dir = temp_dir("write-new");
    let path = dir.join("fresh.py");
    assert!(!denied(&write(&path.to_string_lossy(), "# only one\n")));
    assert!(denied(&write(&path.to_string_lossy(), "# a\n# b\n# c\n")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn multi_edit_edits_add_up() {
    let payload = json!({
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": "a.py",
            "edits": [
                { "old_string": "a", "new_string": "# one" },
                { "old_string": "b", "new_string": "# two" },
                { "old_string": "c", "new_string": "# three" },
            ],
        },
    })
    .to_string();
    let verdict = run(&payload);
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("3 comment lines"));
}

#[test]
fn a_block_comment_of_four_lines_is_denied() {
    assert!(denied(&edit("a.rs", "", "/*\n * one\n * two\n */\n")));
}

#[test]
fn a_doc_comment_counts() {
    assert!(denied(&edit("a.rs", "", "/// one\n/// two\n/// three\n")));
}

#[test]
fn each_language_family_is_recognised() {
    assert!(denied(&edit("a.py", "", &comment_block("#", 3))));
    assert!(denied(&edit("a.rs", "", &comment_block("//", 3))));
    assert!(denied(&edit("a.lua", "", &comment_block("--", 3))));
    assert!(denied(&edit("a.php", "", &comment_block("//", 3))));
    assert!(denied(&edit("a.php", "", &comment_block("#", 3))));
}

#[test]
fn markdown_comment_looking_lines_are_allowed() {
    assert!(!denied(&edit("a.md", "", &comment_block("#", 20))));
}

#[test]
fn patch_adding_a_file_is_judged() {
    assert!(!denied(&patch(
        "*** Begin Patch\n*** Add File: new.py\n+# one\n+print(1)\n*** End Patch\n"
    )));
    assert!(denied(&patch(
        "*** Begin Patch\n*** Add File: new.py\n+# a\n+# b\n+# c\n*** End Patch\n"
    )));
}

#[test]
fn patch_with_two_hunks_counts_two_blocks() {
    let verdict = patch(
        "*** Begin Patch\n*** Update File: a.py\n@@\n-x = 1\n+# a\n@@\n-y = 1\n+# b\n*** End Patch\n",
    );
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("2 block(s)"));
}

#[test]
fn patch_move_reports_the_new_path() {
    let verdict = patch(
        "*** Begin Patch\n*** Update File: old.py\n*** Move to: new.py\n@@\n-x = 1\n+# a\n+# b\n+# c\n*** End Patch\n",
    );
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("new.py"));
}

#[test]
fn patch_delete_produces_no_change() {
    assert!(!denied(&patch(
        "*** Begin Patch\n*** Delete File: gone.py\n+# a\n+# b\n+# c\n*** End Patch\n"
    )));
}

#[test]
fn relative_path_uses_the_payload_cwd() {
    let dir = temp_dir("cwd");
    let path = dir.join("rel.py");
    std::fs::write(&path, "# a\n# b\n# c\n").ok();
    let payload = json!({
        "tool_name": "Write",
        "cwd": dir.to_string_lossy(),
        "tool_input": { "file_path": "rel.py", "content": "# a\n# b\n# c\n" },
    })
    .to_string();
    assert!(!denied(&run(&payload)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_input_and_wrong_types_allow() {
    assert!(matches!(run("{not json"), Verdict::BadInput));
    assert!(matches!(run("[1, 2]"), Verdict::BadInput));
    let payload = json!({
        "tool_name": "Edit",
        "tool_input": { "file_path": 5, "old_string": "a", "new_string": "# a" },
    })
    .to_string();
    assert!(matches!(run(&payload), Verdict::Allow));
}

#[test]
fn another_hook_event_allows() {
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Edit",
        "tool_input": { "file_path": "a.py", "old_string": "", "new_string": "# a\n# b\n# c\n" },
    })
    .to_string();
    assert!(matches!(run(&payload), Verdict::Allow));
}

#[test]
fn hostile_single_long_line_is_denied() {
    let text = "#".repeat(4 * 1024 * 1024);
    let verdict = edit("a.py", "", &text);
    assert!(denied(&verdict));
}

#[test]
fn hostile_many_block_openings_are_denied() {
    let unit = format!("/*{}\n", " ".repeat(18));
    let text = unit.repeat(100_000);
    let verdict = edit("a.rs", "", &text);
    assert!(denied(&verdict));
}

#[test]
fn hostile_patch_with_many_files_is_allowed() {
    let mut command = String::from("*** Begin Patch\n");
    for i in 0..50_000 {
        command.push_str(&format!("*** Add File: f{i}.py\n+# a\n"));
    }
    command.push_str("*** End Patch\n");
    let verdict = patch(&command);
    assert!(!denied(&verdict));
}

#[test]
fn a_blank_context_line_keeps_two_blocks_apart() {
    let verdict = patch(
        "*** Begin Patch\n*** Update File: a.py\n@@\n+# first\n\n+# second\n*** End Patch\n",
    );
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("2 block(s)"));
    let added = patch("*** Begin Patch\n*** Add File: a.py\n+# first\n\n+# second\n*** End Patch\n");
    assert!(denied(&added));
}

#[test]
fn a_byte_order_mark_does_not_hide_the_first_comment() {
    assert!(denied(&edit("a.py", "", "\u{feff}# one\n# two\n# three\n")));
}

#[test]
fn updating_one_file_twice_counts_two_blocks() {
    let verdict = patch(
        "*** Begin Patch\n*** Update File: a.py\n@@\n+# first\n*** Update File: a.py\n@@\n+# second\n*** End Patch\n",
    );
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("2 block(s)"));
}

#[test]
fn a_move_after_a_hunk_still_judges_one_file() {
    let verdict = patch(
        "*** Begin Patch\n*** Update File: old.py\n@@\n+# first\n*** Move to: new.py\n@@\n+# second\n*** End Patch\n",
    );
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("new.py"));
    assert!(reason(&verdict).contains("2 block(s)"));
}

#[test]
fn a_letter_next_to_a_marker_is_not_a_boundary() {
    assert!(!denied(&edit("a.py", "", "# \u{e9}used to work\n")));
    assert!(!denied(&edit("a.py", "", "# this change\u{e9}\n")));
    assert!(!denied(&edit("a.py", "", "# \u{e9}D556 here\n")));
    assert!(!denied(&edit("a.py", "", "# D556\u{e9} here\n")));
    assert!(denied(&edit("a.py", "", "# (used to) work\n")));
}

#[test]
fn the_first_violating_path_is_reported_with_its_own_rule() {
    let verdict = patch(
        "*** Begin Patch\n*** Add File: a.py\n+# a\n+# b\n+# c\n*** Add File: b.py\n+# fixed 2024-01-02\n*** End Patch\n",
    );
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("a.py"));
    assert!(reason(&verdict).contains("3 comment lines"));
}

#[test]
fn the_length_limit_counts_characters_not_bytes() {
    let fits = format!("#{}\n", "\u{e9}".repeat(99));
    assert!(!denied(&edit("a.py", "", &fits)));
    let long = format!("#{}\n", "\u{e9}".repeat(100));
    assert!(denied(&edit("a.py", "", &long)));
}

#[test]
fn windows_line_endings_are_counted() {
    assert!(denied(&edit("a.py", "", "# one\r\n# two\r\n# three\r\n")));
}

#[test]
fn write_skips_a_big_file_and_a_non_utf8_file() {
    let dir = temp_dir("write-skips");
    let big = dir.join("big.py");
    std::fs::write(&big, "# a\n".repeat(600_000)).ok();
    assert!(!denied(&write(&big.to_string_lossy(), "# a\n# b\n# c\n")));
    let bad = dir.join("bad.py");
    std::fs::write(&bad, b"\xff\xfe# a\n").ok();
    assert!(!denied(&write(&bad.to_string_lossy(), "# a\n# b\n# c\n")));
    let _ = std::fs::remove_dir_all(&dir);
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_comment-guard")
}

fn feed(arguments: &[&str], input: &[u8]) -> std::process::Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(binary())
        .args(arguments)
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not start the binary");
    let mut stdin = child.stdin.take().expect("no stdin");
    let _ = stdin.write_all(input);
    drop(stdin);
    child.wait_with_output().expect("could not wait for the binary")
}

#[test]
fn a_deny_prints_exactly_one_json_line_and_exits_zero() {
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": { "file_path": "a.py", "old_string": "", "new_string": comment_block("#", 9) },
    })
    .to_string();
    let output = feed(&["hook", "claude", "PreToolUse"], payload.as_bytes());
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).expect("stdout is not UTF-8");
    assert_eq!(text.matches('\n').count(), 1);
    let value: serde_json::Value = serde_json::from_str(text.trim()).expect("stdout is not JSON");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
}

#[test]
fn an_allow_prints_nothing() {
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": { "file_path": "a.py", "old_string": "", "new_string": "# one\n" },
    })
    .to_string();
    let output = feed(&["hook", "claude", "PreToolUse"], payload.as_bytes());
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn input_above_eight_mebibytes_is_allowed_with_a_note() {
    let violating = |padding: usize| {
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": { "file_path": "a.py", "old_string": "", "new_string": comment_block("#", 9) },
            "padding": "x".repeat(padding),
        })
        .to_string()
    };
    let small = feed(&["hook", "claude", "PreToolUse"], violating(10).as_bytes());
    assert!(!small.stdout.is_empty());
    let big = feed(&["hook", "claude", "PreToolUse"], violating(9 * 1024 * 1024).as_bytes());
    assert_eq!(big.status.code(), Some(0));
    assert!(big.stdout.is_empty());
    assert!(!big.stderr.is_empty());
}

#[test]
fn a_repeated_add_file_counts_two_blocks() {
    let verdict = patch(
        "*** Begin Patch\n*** Add File: a.py\n+# one\n*** Add File: a.py\n+# two\n*** End Patch\n",
    );
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("2 block(s)"));
}

#[test]
fn a_move_before_any_hunk_still_joins_the_files() {
    let joined = patch(
        "*** Begin Patch\n*** Update File: b.py\n@@\n+# one\n*** Update File: a.py\n*** Move to: b.py\n@@\n+# two\n*** End Patch\n",
    );
    assert!(denied(&joined));
    assert!(reason(&joined).contains("b.py"));
    assert!(reason(&joined).contains("2 block(s)"));
    let split = patch(
        "*** Begin Patch\n*** Update File: a.py\n@@\n+# one\n+# two\n*** Update File: a.py\n*** Move to: c.py\n@@\n+# three\n+# four\n*** End Patch\n",
    );
    assert!(denied(&split));
    assert!(reason(&split).contains("c.py"));
    assert!(reason(&split).contains("4 comment lines"));
}

#[test]
fn a_bang_after_the_slashes_is_not_part_of_the_marker() {
    assert!(denied(&edit("a.rs", "", "// ! noqa\n// a\n// b\n")));
}

#[test]
fn the_hook_is_silent_when_the_guard_is_off() {
    let dir = temp_dir("silent-off");
    let output = Command::new(binary())
        .args(["hook", "claude"])
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD")
        .env("XDG_CONFIG_HOME", &dir)
        .env("HOME", &dir)
        .output()
        .expect("could not start the binary");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn bad_arguments_print_the_usage_text() {
    let output = Command::new(binary())
        .arg("nonsense")
        .output()
        .expect("could not start the binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("usage: comment-guard"));
}

#[test]
fn version_prints_the_package_version() {
    let output = Command::new(binary())
        .arg("--version")
        .output()
        .expect("could not start the binary");
    assert_eq!(output.status.code(), Some(0));
    let expected = format!("comment-guard {}", env!("CARGO_PKG_VERSION"));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), expected);
}

#[cfg(unix)]
#[test]
fn a_non_utf8_argument_prints_the_usage_and_exits_two() {
    use std::os::unix::ffi::OsStrExt;
    let output = Command::new(binary())
        .arg(std::ffi::OsStr::from_bytes(&[0xff, 0xfe]))
        .output()
        .expect("could not start the binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("usage: comment-guard"));
}

#[test]
fn switch_defaults_to_off() {
    let dir = temp_dir("switch-off");
    let output = Command::new(binary())
        .arg("check")
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD")
        .env("XDG_CONFIG_HOME", &dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let output = match output {
        Ok(value) => value,
        Err(error) => panic!("could not start the binary: {error}"),
    };
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("off"));
}

#[test]
fn switch_env_var_turns_the_guard_on() {
    let dir = temp_dir("switch-env");
    let output = Command::new(binary())
        .arg("check")
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD", "YeS")
        .env("XDG_CONFIG_HOME", &dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let output = match output {
        Ok(value) => value,
        Err(error) => panic!("could not start the binary: {error}"),
    };
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("on"));
}

#[test]
fn switch_file_turns_the_guard_on() {
    let dir = temp_dir("switch-file");
    let folder = dir.join("agent-safeguards");
    std::fs::create_dir_all(&folder).ok();
    std::fs::write(folder.join("comment-guard"), b"").ok();
    let output = Command::new(binary())
        .arg("check")
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD")
        .env("XDG_CONFIG_HOME", &dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let output = match output {
        Ok(value) => value,
        Err(error) => panic!("could not start the binary: {error}"),
    };
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("on"));
}

#[test]
fn hook_prints_nothing_when_off() {
    let dir = temp_dir("hook-off");
    let output = Command::new(binary())
        .args(["hook", "claude"])
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD")
        .env("XDG_CONFIG_HOME", &dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let output = match output {
        Ok(value) => value,
        Err(error) => panic!("could not start the binary: {error}"),
    };
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn usage_exits_two() {
    let output = Command::new(binary()).arg("nonsense").output();
    let output = match output {
        Ok(value) => value,
        Err(error) => panic!("could not start the binary: {error}"),
    };
    assert_eq!(output.status.code(), Some(2));
}

fn git(repo: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("could not start git");
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn repository(name: &str) -> PathBuf {
    let repo = temp_dir(name);
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "user.name", "Test User"]);
    git(&repo, &["config", "user.email", "test@example.com"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    repo
}

fn put(repo: &std::path::Path, name: &str, content: &str) {
    let path = repo.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("could not create a folder");
    }
    std::fs::write(path, content).expect("could not write a file");
}

fn commit_all(repo: &std::path::Path) {
    git(repo, &["add", "-A"]);
    git(repo, &["-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "base"]);
}

fn staged_tree(repo: &std::path::Path) -> String {
    git(repo, &["add", "-A"]);
    git(repo, &["write-tree"])
}

fn tree_check(repo: &std::path::Path, id: &str, enabled: bool) -> std::process::Output {
    let off_dir = temp_dir("tree-off");
    let mut command = Command::new(binary());
    command
        .args(["tree", id])
        .current_dir(repo)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
    if enabled {
        command.env("AGENT_SAFEGUARDS_COMMENT_GUARD", "1");
    } else {
        command
            .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD")
            .env("XDG_CONFIG_HOME", &off_dir);
    }
    let output = command.output().expect("could not start the binary");
    let _ = std::fs::remove_dir_all(&off_dir);
    output
}

fn verdict_of(repo: &std::path::Path) -> (Option<i32>, String, String) {
    let id = staged_tree(repo);
    let output = tree_check(repo, &id, true);
    let _ = std::fs::remove_dir_all(repo);
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn tree_is_silent_when_the_guard_is_off() {
    let repo = repository("tree-guard-off");
    put(&repo, "a.py", &comment_block("#", 9));
    let id = staged_tree(&repo);
    let output = tree_check(&repo, &id, false);
    let _ = std::fs::remove_dir_all(&repo);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn tree_denies_a_commit_that_adds_a_long_comment_block() {
    let repo = repository("tree-long-block");
    put(&repo, "a.py", "x = 1\n");
    commit_all(&repo);
    put(&repo, "a.py", &format!("x = 1\n{}y = 2\n", comment_block("#", 9)));
    let (code, out, err) = verdict_of(&repo);
    assert_eq!(code, Some(1));
    assert!(out.contains("9 comment lines in 1 block(s) to a.py"), "{out}");
    assert!(err.is_empty());
}

#[test]
fn tree_allows_two_new_comment_lines() {
    let repo = repository("tree-two-lines");
    put(&repo, "a.py", "x = 1\n");
    commit_all(&repo);
    put(&repo, "a.py", &format!("x = 1\n{}y = 2\n", comment_block("#", 2)));
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0));
    assert!(out.is_empty());
}

#[test]
fn tree_denies_one_line_comments_scattered_through_a_file() {
    let repo = repository("tree-scattered");
    put(&repo, "a.py", "x = 1\n");
    commit_all(&repo);
    put(&repo, "a.py", "# a\nx = 1\n# b\ny = 2\n# c\nz = 3\n");
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(1));
    assert!(out.contains("3 comment lines in 3 block(s) to a.py"), "{out}");
}

#[test]
fn tree_does_not_count_comments_that_were_already_in_the_file() {
    let repo = repository("tree-kept");
    put(&repo, "a.py", &format!("{}x = 1\n", comment_block("#", 5)));
    commit_all(&repo);
    put(&repo, "a.py", &format!("{}x = 2\ny = 3\n", comment_block("#", 5)));
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0));
    assert!(out.is_empty());
}

#[test]
fn tree_ignores_files_without_a_known_language() {
    let repo = repository("tree-other-language");
    put(&repo, "notes.md", &comment_block("#", 9));
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0));
    assert!(out.is_empty());
}

#[test]
fn tree_follows_a_rename_so_moved_comments_are_not_new() {
    let repo = repository("tree-rename");
    put(&repo, "a.py", &format!("{}x = 1\n", comment_block("#", 5)));
    commit_all(&repo);
    git(&repo, &["mv", "a.py", "b.py"]);
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn tree_checks_the_first_commit_of_a_repository() {
    let repo = repository("tree-first-commit");
    put(&repo, "a.py", &format!("{}x = 1\n", comment_block("#", 3)));
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(1));
    assert!(out.contains("3 comment lines in 1 block(s) to a.py"), "{out}");
}

#[test]
fn tree_names_the_history_marker_it_found() {
    let repo = repository("tree-history");
    put(&repo, "a.py", "x = 1\n");
    commit_all(&repo);
    put(&repo, "a.py", "x = 1\n# fixed on 2026-11-03\n");
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(1));
    assert!(out.contains("2026-11-03"), "{out}");
}

#[test]
fn tree_is_skipped_while_a_merge_is_in_progress() {
    let repo = repository("tree-merge");
    put(&repo, "a.py", "x = 1\n");
    commit_all(&repo);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    put(&repo, ".git/MERGE_HEAD", &format!("{head}\n"));
    put(&repo, "a.py", &format!("x = 1\n{}", comment_block("#", 9)));
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0));
    assert!(out.is_empty());
}

#[test]
fn tree_is_skipped_after_a_squash_merge() {
    let repo = repository("tree-squash");
    put(&repo, "a.py", "x = 1\n");
    commit_all(&repo);
    git(&repo, &["checkout", "-q", "-b", "topic"]);
    put(&repo, "a.py", &format!("x = 1\n{}", comment_block("#", 9)));
    commit_all(&repo);
    git(&repo, &["checkout", "-q", "-"]);
    git(&repo, &["merge", "--squash", "topic"]);
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn tree_is_skipped_while_a_rebase_is_in_progress() {
    for marker in ["rebase-merge", "rebase-apply"] {
        let repo = repository("tree-rebase");
        put(&repo, "a.py", "x = 1\n");
        commit_all(&repo);
        put(&repo, &format!(".git/{marker}/state"), "");
        put(&repo, "a.py", &format!("x = 1\n{}", comment_block("#", 9)));
        let (code, out, _) = verdict_of(&repo);
        assert_eq!(code, Some(0), "{marker}: {out}");
    }
}

#[test]
fn tree_skips_files_above_two_mebibytes() {
    let repo = repository("tree-large");
    let big = format!("{}{}", "x = 1\n".repeat(400_000), comment_block("#", 9));
    put(&repo, "a.py", &big);
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0));
    assert!(out.is_empty());
}

#[test]
fn tree_allows_a_deleted_file() {
    let repo = repository("tree-delete");
    put(&repo, "a.py", &comment_block("#", 9));
    commit_all(&repo);
    git(&repo, &["rm", "-q", "a.py"]);
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(0));
    assert!(out.is_empty());
}

#[test]
fn tree_reads_paths_with_spaces_and_non_ascii_letters() {
    let repo = repository("tree-odd-path");
    put(&repo, "dir/my file \u{e9}.py", &comment_block("#", 9));
    let (code, out, _) = verdict_of(&repo);
    assert_eq!(code, Some(1));
    assert!(out.contains("dir/my file \u{e9}.py"), "{out}");
}

#[test]
fn tree_with_an_unknown_id_is_allowed_with_a_note() {
    let repo = repository("tree-bad-id");
    let output = tree_check(&repo, "not-an-id", true);
    let _ = std::fs::remove_dir_all(&repo);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn tree_needs_exactly_one_argument() {
    for arguments in [vec!["tree"], vec!["tree", "a", "b"]] {
        let output = Command::new(binary()).args(&arguments).output();
        let output = match output {
            Ok(value) => value,
            Err(error) => panic!("could not start the binary: {error}"),
        };
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
    }
}
