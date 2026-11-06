use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

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
fn a_line_of_76_characters_is_denied_and_75_is_allowed() {
    let long = format!("# {}\n", "a".repeat(74));
    assert!(denied(&edit("a.py", "", &long)));
    let fits = format!("# {}\n", "a".repeat(73));
    assert!(!denied(&edit("a.py", "", &fits)));
}

#[test]
fn every_tool_directive_is_ignored() {
    let directives = [
        "noqa",
        "noqa: E501",
        "noqa: E501,W291",
        "type: ignore",
        "type: ignore[attr-defined]",
        "type: List[int]",
        "pragma: no cover",
        "pragma: no branch",
        "pragma once",
        "pylint: disable=missing-docstring,invalid-name",
        "mypy: ignore-errors",
        "ruff: noqa: E501",
        "fmt: off",
        "fmt: skip",
        "isort: skip",
        "pyright: basic",
        "pyright: ignore[reportMissingImports]",
        "eslint-disable-next-line no-console",
        "eslint-disable",
        "eslint-env node",
        "prettier-ignore",
        "@ts-ignore",
        "@ts-expect-error",
        "istanbul ignore next",
        "c8 ignore next 2",
        "go:generate stringer -type=Color",
        "go:build linux && amd64",
        "nolint:errcheck",
        "nolint:gosec,errcheck",
        "swiftlint:disable force_cast",
        "swiftlint:disable:next identifier_name",
        "spdx-license-identifier: MIT",
        "SPDX-License-Identifier: Apache-2.0",
        "SPDX-License-Identifier: MIT OR Apache-2.0",
        "shellcheck disable=SC2086",
        "shellcheck source=/dev/null",
        "nosec",
        "nosec B101",
        "cspell:disable-next-line",
        "-*- coding: utf-8 -*-",
        "clippy::needless_return",
        "rustfmt::skip",
        "+build linux,amd64",
        "@flow strict",
        "@jsx h",
        "eslint-disable-next-line eqeqeq",
        "eslint-disable-next-line radix, yoda",
        "go:embed templates",
        "go:linkname bytesHash runtime.memhash",
        "go:build integration",
        "go:cgo_import_dynamic puts puts \"libc.so\"",
        "+build linux darwin windows",
        "SPDX-License-Identifier: GPL-2.0-only WITH Classpath-exception-2.0",
        "noqa: PLR0913, ANN101",
        "nolint:gosec,errcheck,staticcheck",
        "SPDX-License-Identifier: Unlicense",
        "SPDX-License-Identifier: OpenSSL",
        "SPDX-License-Identifier: Zlib",
        "SPDX-License-Identifier: curl",
        "SPDX-License-Identifier: PostgreSQL",
        "SPDX-License-Identifier: LicenseRef-Company-Proprietary",
        "SPDX-License-Identifier: BSD-3-Clause",
        "SPDX-License-Identifier: CC-BY-4.0",
        "SPDX-License-Identifier: (MIT OR Apache-2.0) AND BSD-2-Clause",
        "SPDX-License-Identifier: 0BSD",
        "SPDX-License-Identifier: X11",
        "SPDX-License-Identifier: MS-PL",
        "SPDX-License-Identifier: MS-RL",
        "SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note",
        "SPDX-License-Identifier: LGPL-2.1+",
        "SPDX-License-Identifier: BSD-3-Clause-Clear",
        "SPDX-License-Identifier: CC-BY-SA-4.0",
        "SPDX-License-Identifier: CC0-1.0",
        "SPDX-License-Identifier: GPL-3.0-or-later",
        "go:build linux || darwin || windows || freebsd",
        "go:build (linux && amd64) || (darwin && arm64)",
    ];
    for directive in directives {
        let line = format!("# {directive}\n# {directive}\n# {directive}\n");
        assert!(!denied(&edit("a.py", "", &line)), "directive {directive} counted");
    }
}

#[test]
fn a_directive_cannot_carry_a_sentence_in_its_arguments() {
    let sentences = [
        "noqa: note-one",
        "noqa: ignore next line if no cover",
        "noqa: E501 note",
        "SPDX-License-Identifier: THIS IS THE HIDDEN NOTE",
        "SPDX-License-Identifier: MIT AND",
        "nolint:note-one",
        "nolint:one,two,three,four,five",
        "go:cgo_note_one_explain_the_cache",
        "go:embed one two three four five six seven",
        "eslint-disable-next-line note one",
        "type: ignore note two",
        "pragma: no cover because it is hard",
        "fmt: off until the end of the table",
        "fmt: off on skip next line",
        "noqa: E501explainthecachehere",
        "SPDX-License-Identifier: HIDE AND THIS AND NOTE",
        "SPDX-License-Identifier: note-one-explain-the-cache",
        "SPDX-License-Identifier: note-1-explain-the-cache",
        "SPDX-License-Identifier: MIT AND MIT AND MIT AND MIT AND MIT",
        "SPDX-License-Identifier: GPL-note-one-explain-the-cache-1",
        "SPDX-License-Identifier: MIT-note-three-explain-retry-3",
        "SPDX-License-Identifier: CC-note-four-explain-fall-4",
        "istanbul ignore next for now",
    ];
    for sentence in sentences {
        let line = format!("# {sentence}\n# {sentence}\n# {sentence}\n");
        assert!(denied(&edit("a.py", "", &line)), "{sentence} carried a message");
    }
}

#[test]
fn a_directive_followed_by_prose_is_a_comment() {
    let starts = [
        "noqa", "type:", "pragma", "pylint:", "mypy:", "ruff:", "fmt:", "isort:", "pyright:", "eslint-", "prettier-ignore",
        "@ts-", "istanbul ", "c8 ", "go:", "nolint", "swiftlint:", "spdx-license-identifier", "shellcheck", "nosec",
        "cspell:", "-*-", "lint:", "clippy::", "rustfmt::", "+build", "@flow", "@jsx", "nolintnextline", "nolintbegin",
        "nolintend", "clang-format", "deno-lint-ignore", "deno-fmt-ignore", "stylelint-", "@generated", "sbatch",
        "pbs", "oar", "msub",
    ];
    for prefix in starts {
        let line = format!("# {prefix} note one\n# {prefix} note two\n# {prefix} note three\n");
        assert!(denied(&edit("a.py", "", &line)), "prose after {prefix} went through");
    }
    let removed = ["mark:", "region", "endregion", "copyright", "license", "vim:"];
    for prefix in removed {
        let line = format!("# {prefix} note one\n# {prefix} note two\n# {prefix} note three\n");
        assert!(denied(&edit("a.py", "", &line)), "{prefix} is no directive");
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
    assert!(!denied(&write(&path.to_string_lossy(), "# x\n# y\n# z\n")));
    assert!(denied(&write(&path.to_string_lossy(), "# x\n# y\n# z\n# w\n# v\n# u\n")));
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
    let fits = format!("#{}\n", "\u{e9}".repeat(74));
    assert!(!denied(&edit("a.py", "", &fits)));
    let long = format!("#{}\n", "\u{e9}".repeat(75));
    assert!(denied(&edit("a.py", "", &long)));
}

#[test]
fn windows_line_endings_are_counted() {
    assert!(denied(&edit("a.py", "", "# one\r\n# two\r\n# three\r\n")));
}

#[test]
fn big_and_non_utf8_files_are_judged_and_only_files_over_the_limit_are_skipped() {
    let dir = temp_dir("write-skips");
    let big = dir.join("big.py");
    let body = "x = 1\n".repeat(400_000);
    std::fs::write(&big, format!("{body}# a\n")).ok();
    assert!(!denied(&write(&big.to_string_lossy(), &format!("{body}# a\n# b\n# c\n"))));
    assert!(denied(&write(&big.to_string_lossy(), &format!("{body}# a\n# b\n# c\n# d\n"))));
    let huge = dir.join("huge.py");
    std::fs::write(&huge, "x = 1\n".repeat(1_500_000)).ok();
    assert!(!denied(&write(&huge.to_string_lossy(), "# a\n# b\n# c\n# d\n")));
    let bad = dir.join("bad.py");
    std::fs::write(&bad, b"\xff\xfe\nx = 1\n").ok();
    assert!(!denied(&write(&bad.to_string_lossy(), "x = 1\n# a\n# b\n")));
    assert!(denied(&write(&bad.to_string_lossy(), "# a\n# b\n# c\n# d\n")));
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
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM", "0")
        .env("XDG_CONFIG_HOME", "/nonexistent-comment-guard-config")
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES")
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS")
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

fn hook_with(envs: &[(&str, &str)], config: Option<&str>, content: &str) -> String {
    use std::io::Write;
    use std::process::Stdio;
    let dir = temp_dir("tuning");
    if let Some(text) = config {
        let folder = dir.join("agent-safeguards");
        std::fs::create_dir_all(&folder).expect("folder");
        std::fs::write(folder.join("comment-guard"), text).expect("config");
    }
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": dir.join("a.py").to_string_lossy(), "content": content },
    });
    let mut command = Command::new(binary());
    command
        .args(["hook", "claude", "PreToolUse"])
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES")
        .env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS")
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD", "1")
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM", "0")
        .env("XDG_CONFIG_HOME", &dir);
    for (name, value) in envs {
        command.env(name, value);
    }
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("start");
    let _ = child.stdin.take().expect("stdin").write_all(payload.to_string().as_bytes());
    let out = String::from_utf8_lossy(&child.wait_with_output().expect("wait").stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn the_comment_line_limit_can_be_tuned_by_environment_and_file() {
    let five = "# c1\n# c2\n# c3\n# c4\n# c5\nx = 1\n";
    let three = "# c1\n# c2\n# c3\nx = 1\n";
    assert!(hook_with(&[], None, five).contains("deny"));
    assert!(hook_with(&[], None, three).contains("deny"));
    assert!(hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES", "3")], None, three).is_empty());
    assert!(hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES", "5")], None, five).is_empty());
    let four = hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES", "4")], None, five);
    assert!(four.contains("deny") && four.contains("4 line(s)"), "{four}");
    assert!(hook_with(&[], Some("lines = 5\n"), five).is_empty());
    assert!(hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES", "2")], Some("lines = 5\n"), five).contains("deny"));
    assert!(hook_with(&[], Some("lines = 99\n"), three).contains("deny"));
    assert!(hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES", "0")], None, three).contains("deny"));
}

#[test]
fn the_comment_line_length_can_be_tuned_by_environment_and_file() {
    let sixty = format!("# {}\nx = 1\n", "a".repeat(58));
    let ninety = format!("# {}\nx = 1\n", "a".repeat(88));
    assert!(hook_with(&[], None, &sixty).is_empty());
    let short = hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS", "40")], None, &sixty);
    assert!(short.contains("deny") && short.contains("40 characters"), "{short}");
    assert!(hook_with(&[], Some("line_chars = 40\n"), &sixty).contains("deny"));
    assert!(hook_with(&[], None, &ninety).contains("deny"));
    assert!(hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS", "100")], None, &ninety).is_empty());
    assert!(hook_with(&[], Some("line_chars = 100\n"), &ninety).is_empty());
    assert!(hook_with(&[("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS", "10")], None, &sixty).is_empty());
}

#[test]
fn trimming_keeps_as_many_lines_and_characters_as_the_limits_allow() {
    let trim = ("AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM", "1");
    let six = "# c1\n# c2\n# c3\n# c4\n# c5\n# c6\nx = 1\n";
    let out: Value = serde_json::from_str(hook_with(&[trim, ("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES", "3")], None, six).trim()).expect("json");
    assert_eq!(out["hookSpecificOutput"]["updatedInput"]["content"], "# c1\n# c2\n# c3\nx = 1\n");
    assert!(out["hookSpecificOutput"]["additionalContext"].as_str().is_some_and(|text| text.contains("3 line(s)")));
    let wide = format!("# ok\n# {}\nx = 1\n", "a".repeat(80));
    let out: Value = serde_json::from_str(hook_with(&[trim], None, &wide).trim()).expect("json");
    assert_eq!(out["hookSpecificOutput"]["updatedInput"]["content"], "# ok\nx = 1\n");
    assert!(hook_with(&[trim, ("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS", "100")], None, &wide).is_empty());
    let mid = format!("# {}\n# ok\nx = 1\n", "a".repeat(58));
    let out: Value = serde_json::from_str(hook_with(&[trim, ("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS", "40")], None, &mid).trim()).expect("json");
    assert_eq!(out["hookSpecificOutput"]["updatedInput"]["content"], "# ok\nx = 1\n");
}

#[test]
fn check_prints_the_limits_in_force() {
    let dir = temp_dir("check-limits");
    let folder = dir.join("agent-safeguards");
    std::fs::create_dir_all(&folder).expect("folder");
    std::fs::write(folder.join("comment-guard"), "lines = 3\nline_chars = 50\n").expect("config");
    let run = |lines: Option<&str>| {
        let mut command = Command::new(binary());
        command.arg("check").env("XDG_CONFIG_HOME", &dir).env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES").env_remove("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS");
        if let Some(value) = lines {
            command.env("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES", value);
        }
        String::from_utf8_lossy(&command.output().expect("start").stdout).into_owned()
    };
    assert!(run(None).contains("Limits: 3 comment line(s) per file, 50 characters per line."));
    assert!(run(Some("7")).contains("Limits: 7 comment line(s) per file, 50 characters per line."));
    let _ = std::fs::remove_dir_all(&dir);
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
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM", "0")
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
