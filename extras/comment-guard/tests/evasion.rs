use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use comment_guard::{judge_in, Provider, Verdict};

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "comment-guard-evasion-{}-{}",
        std::process::id(),
        name
    ));
    let _ = std::fs::remove_dir_all(&path);
    let _ = std::fs::create_dir_all(&path);
    path
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

fn lines(prefix: &str, suffix: &str, count: usize) -> String {
    (0..count)
        .map(|n| format!("{prefix} line {n} {suffix}\n"))
        .collect()
}

fn pre(state: Option<&Path>, session: Option<&str>, tool: &str, input: Value, provider: Provider) -> Verdict {
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    });
    if let (Some(id), Some(map)) = (session, payload.as_object_mut()) {
        map.insert("session_id".to_owned(), json!(id));
    }
    judge_in(&payload.to_string(), provider, state)
}

fn write_file(state: Option<&Path>, session: Option<&str>, path: &Path, content: &str) -> Verdict {
    pre(
        state,
        session,
        "Write",
        json!({ "file_path": path.to_string_lossy(), "content": content }),
        Provider::Claude,
    )
}

fn edit_file(state: Option<&Path>, session: Option<&str>, path: &Path, old: &str, new: &str) -> Verdict {
    pre(
        state,
        session,
        "Edit",
        json!({ "file_path": path.to_string_lossy(), "old_string": old, "new_string": new }),
        Provider::Claude,
    )
}

fn apply_edit(path: &Path, old: &str, new: &str) {
    let text = std::fs::read_to_string(path).expect("read");
    std::fs::write(path, text.replacen(old, new, 1)).expect("write");
}

#[test]
fn stacked_two_line_edits_are_judged_against_the_first_state_of_the_file() {
    let dir = temp_dir("stacked");
    let state = temp_dir("stacked-state");
    let path = dir.join("g_base.py");
    std::fs::write(&path, "def g() -> int:\n    return 1\n").expect("write");
    let first = edit_file(
        Some(&state),
        Some("s1"),
        &path,
        "def g() -> int:",
        "# stacked one\n# stacked two\ndef g() -> int:",
    );
    assert!(!denied(&first));
    apply_edit(&path, "def g() -> int:", "# stacked one\n# stacked two\ndef g() -> int:");
    let second = edit_file(
        Some(&state),
        Some("s1"),
        &path,
        "    return 1",
        "    # stacked three\n    # stacked four\n    return 1",
    );
    assert!(denied(&second));
    assert!(reason(&second).contains("4 comment lines"));
    let other_session = edit_file(
        Some(&state),
        Some("s2"),
        &path,
        "    return 1",
        "    # stacked three\n    # stacked four\n    return 1",
    );
    assert!(!denied(&other_session));
    let without_session = edit_file(
        Some(&state),
        None,
        &path,
        "    return 1",
        "    # stacked three\n    # stacked four\n    return 1",
    );
    assert!(!denied(&without_session));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn stacked_writes_and_a_swapped_comment_follow_the_same_baseline() {
    let dir = temp_dir("writes");
    let state = temp_dir("writes-state");
    let path = dir.join("m.py");
    assert!(!denied(&write_file(Some(&state), Some("w"), &path, "# one\n# two\nx = 1\n")));
    std::fs::write(&path, "# one\n# two\nx = 1\n").expect("write");
    assert!(denied(&write_file(Some(&state), Some("w"), &path, "# one\n# two\n# three\nx = 1\n")));
    let kept = write_file(Some(&state), Some("w"), &path, "# one\n# two\nx = 1\ny = 2\n");
    assert!(!denied(&kept));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_new_file_written_in_pieces_is_counted_as_a_whole() {
    let dir = temp_dir("pieces");
    let state = temp_dir("pieces-state");
    let path = dir.join("fresh.ts");
    assert!(!denied(&write_file(Some(&state), Some("p"), &path, "// a\n// b\nconst x = 1;\n")));
    std::fs::write(&path, "// a\n// b\nconst x = 1;\n").expect("write");
    let more = edit_file(Some(&state), Some("p"), &path, "const x = 1;", "const x = 1;\n// c\n// d");
    assert!(denied(&more));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn an_edit_is_judged_on_the_whole_file_so_a_docstring_end_is_not_a_start() {
    let dir = temp_dir("whole");
    let path = dir.join("doc.py");
    let text = "def f():\n    \"\"\"\n    Explains f.\n    \"\"\"\n    a = 1\n    b = 2\n    c = 3\n";
    std::fs::write(&path, text).expect("write");
    let verdict = edit_file(
        None,
        None,
        &path,
        "    \"\"\"\n    a = 1\n    b = 2\n    c = 3\n",
        "    \"\"\"\n    a = 10\n    b = 20\n    c = 30\n",
    );
    assert!(!denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn python_docstrings_cannot_carry_extra_comments() {
    let four = "def f():\n    \"\"\"\n    one\n    two\n    three\n    four\n    \"\"\"\n    return 1\n";
    assert!(denied(&write_file(None, None, Path::new("c_doc.py"), four)));
    let short = "def f():\n    \"\"\"One line.\"\"\"\n    return 1\n";
    assert!(!denied(&write_file(None, None, Path::new("c_doc.py"), short)));
}

#[test]
fn trailing_comments_on_code_lines_count() {
    let typescript = "const a = 1; // inline one\nconst b = 2; // inline two\nconst c = 3; // inline three\nconst d = 4; // inline four\n";
    let verdict = write_file(None, None, Path::new("d_inline.ts"), typescript);
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("4 comment lines"));
    let python = "a = 1  # one\nb = 2  # two\nc = 3  # three\n";
    assert!(denied(&write_file(None, None, Path::new("t.py"), python)));
    let strings = "url = \"http://example.com\"\nname = 'a # b'\n";
    assert!(!denied(&write_file(None, None, Path::new("t.py"), strings)));
}

#[test]
fn jsx_comments_count() {
    let jsx = "export const V = () => (\n  <div>\n    {/* jsx comment one */}\n    {/* jsx comment two */}\n    {/* jsx comment three */}\n    {/* jsx comment four */}\n  </div>\n);\n";
    assert!(denied(&write_file(None, None, Path::new("q_view.tsx"), jsx)));
}

#[test]
fn html_and_css_are_checked_with_the_same_limit() {
    let html = "<!-- html comment line one -->\n<!-- html comment line two -->\n<!-- html comment line three -->\n<!-- html comment line four -->\n<p>ok</p>\n";
    assert!(denied(&write_file(None, None, Path::new("f_page.html"), html)));
    let css = "/* css comment line one */\n/* css comment line two */\n/* css comment line three */\n/* css comment line four */\nbody { margin: 0; }\n";
    assert!(denied(&write_file(None, None, Path::new("k_style.css"), css)));
    assert!(denied(&write_file(None, None, Path::new("k_style.scss"), &lines("//", "", 4))));
    assert!(!denied(&write_file(None, None, Path::new("ok.html"), "<!-- one -->\n<p>ok</p>\n")));
}

#[test]
fn data_and_documentation_files_are_not_checked() {
    for name in ["i_conf.yaml", "i_conf.yml", "c.toml", "d.json", "n.md", "x.ini", "p.xml"] {
        assert!(!denied(&write_file(None, None, Path::new(name), &lines("#", "", 9))), "{name}");
        assert!(!denied(&write_file(None, None, Path::new(name), "<!-- a -->\n<!-- b -->\n<!-- c -->\n")), "{name}");
    }
}

#[test]
fn block_comment_styles_of_other_languages_count_every_line() {
    assert!(denied(&write_file(None, None, Path::new("a.lua"), "--[[\na\nb\nc\n]]\nx = 1\n")));
    assert!(denied(&write_file(None, None, Path::new("a.hs"), "{-\na\nb\nc\n-}\nx = 1\n")));
    assert!(denied(&write_file(None, None, Path::new("a.sql"), "/*\na\nb\nc\n*/\nselect 1;\n")));
    assert!(denied(&write_file(None, None, Path::new("a.rb"), "=begin\na\nb\nc\n=end\nx = 1\n")));
}

#[test]
fn a_patch_is_judged_on_the_resulting_file_and_on_the_session_baseline() {
    let dir = temp_dir("patch");
    let state = temp_dir("patch-state");
    let path = dir.join("p.py");
    std::fs::write(&path, "def f():\n    return 1\n").expect("write");
    let first = format!(
        "*** Begin Patch\n*** Update File: {}\n@@\n def f():\n+    # one\n+    # two\n     return 1\n*** End Patch\n",
        path.display()
    );
    let verdict = pre(Some(&state), Some("c1"), "apply_patch", json!({ "command": first }), Provider::Codex);
    assert!(!denied(&verdict));
    std::fs::write(&path, "def f():\n    # one\n    # two\n    return 1\n").expect("write");
    let second = format!(
        "*** Begin Patch\n*** Update File: {}\n@@\n     # two\n+    # three\n+    # four\n     return 1\n*** End Patch\n",
        path.display()
    );
    let verdict = pre(Some(&state), Some("c1"), "apply_patch", json!({ "command": second }), Provider::Codex);
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("4 comment lines"));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_patch_that_cannot_be_placed_falls_back_to_its_own_lines() {
    let dir = temp_dir("patch-fallback");
    let path = dir.join("p.py");
    std::fs::write(&path, "x = 1\n").expect("write");
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n@@\n missing context\n+# a\n+# b\n+# c\n*** End Patch\n",
        path.display()
    );
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_comment-guard")
}

struct Rig {
    cwd: PathBuf,
    state: PathBuf,
    home: PathBuf,
}

impl Rig {
    fn new(name: &str) -> Rig {
        let cwd = temp_dir(&format!("{name}-cwd"));
        let state = temp_dir(&format!("{name}-state"));
        let home = temp_dir(&format!("{name}-home"));
        Rig { cwd, state, home }
    }

    fn feed(&self, event: &str, payload: &Value) -> std::process::Output {
        self.feed_with("claude", event, payload, None)
    }

    fn feed_with(&self, host: &str, event: &str, payload: &Value, path: Option<&Path>) -> std::process::Output {
        let mut command = Command::new(binary());
        command
            .args(["hook", host, event])
            .env("AGENT_SAFEGUARDS_COMMENT_GUARD", "1")
            .env("XDG_STATE_HOME", &self.state)
            .env("HOME", &self.home);
        if let Some(folder) = path {
            command.env("PATH", folder);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("could not start the binary");
        let mut stdin = child.stdin.take().expect("no stdin");
        let _ = stdin.write_all(payload.to_string().as_bytes());
        drop(stdin);
        child.wait_with_output().expect("could not wait for the binary")
    }

    fn bash(&self, session: Option<&str>, command: &str) -> String {
        self.bash_at(&self.cwd, session, command, "claude", None)
    }

    fn bash_at(&self, cwd: &Path, session: Option<&str>, command: &str, host: &str, path: Option<&Path>) -> String {
        let mut payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "cwd": cwd.to_string_lossy(),
            "tool_input": { "command": command },
            "tool_response": {},
        });
        if let (Some(id), Some(map)) = (session, payload.as_object_mut()) {
            map.insert("session_id".to_owned(), json!(id));
        }
        let output = self.feed_with(host, "PostToolUse", &payload, path);
        assert_eq!(output.status.code(), Some(0));
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn pre_edit(&self, session: &str, path: &Path, old: &str, new: &str) -> String {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "session_id": session,
            "cwd": self.cwd.to_string_lossy(),
            "tool_name": "Edit",
            "tool_input": { "file_path": path.to_string_lossy(), "old_string": old, "new_string": new },
        });
        String::from_utf8_lossy(&self.feed("PreToolUse", &payload).stdout).into_owned()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.cwd);
        let _ = std::fs::remove_dir_all(&self.state);
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q"]);
    git(dir, &["config", "user.name", "Test User"]);
    git(dir, &["config", "user.email", "test@example.com"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
}

fn commit_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let file = dir.join(name);
    std::fs::write(&file, content).expect("write");
    git(dir, &["add", name]);
    git(dir, &["-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "base"]);
    file
}

fn blocked(output: &str) -> bool {
    output.contains("\"decision\":\"block\"")
}

#[test]
fn reading_a_file_does_not_blame_the_command_for_the_users_own_changes() {
    let rig = Rig::new("read-only");
    init_repo(&rig.cwd);
    let file = commit_file(&rig.cwd, "a.py", "x = 1\n");
    std::fs::write(&file, "x = 1\n# u1\n# u2\n# u3\n").expect("write");
    let _first_window = rig.bash(Some("r1"), "true");
    let second = rig.bash(Some("r1"), &format!("cat {}", file.display()));
    assert!(second.is_empty(), "{second}");
}

#[test]
fn a_command_edit_is_not_absorbed_into_the_baseline_of_the_next_edit() {
    let rig = Rig::new("absorb");
    init_repo(&rig.cwd);
    let file = commit_file(&rig.cwd, "a.py", "x = 1\n");
    std::fs::write(&file, "# one\n# two\nx = 1\n").expect("write");
    let after = rig.bash(Some("s7"), &format!("sed -i '' '1i x' {}", file.display()));
    assert!(after.is_empty(), "{after}");
    let verdict = rig.pre_edit("s7", &file, "x = 1", "# three\n# four\nx = 1");
    assert!(verdict.contains("\"permissionDecision\":\"deny\""), "{verdict}");
}

#[test]
fn a_moved_file_keeps_the_allowance_it_had_used() {
    let dir = temp_dir("moved");
    let state = temp_dir("moved-state");
    let from = dir.join("a.py");
    let to = dir.join("b.py");
    std::fs::write(&from, "def f():\n    return 1\n").expect("write");
    let first = edit_file(Some(&state), Some("m1"), &from, "def f():", "# one\n# two\ndef f():");
    assert!(!denied(&first));
    apply_edit(&from, "def f():", "# one\n# two\ndef f():");
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n*** Move to: {}\n@@\n # two\n+# three\n+# four\n def f():\n*** End Patch\n",
        from.display(),
        to.display()
    );
    let verdict = pre(Some(&state), Some("m1"), "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_patch_anchor_picks_the_place_the_patch_tool_would_edit() {
    let dir = temp_dir("anchor");
    let path = dir.join("a.py");
    std::fs::write(&path, "DATA = \"\"\"\n    return 1\n\"\"\"\ndef f():\n    return 1\n").expect("write");
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n@@ def f():\n-    return 1\n+    # one\n+    # two\n+    # three\n+    return 1\n*** End Patch\n",
        path.display()
    );
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unreachable_git_is_not_taken_for_a_missing_file() {
    let rig = Rig::new("no-git");
    let file = rig.cwd.join("a.py");
    std::fs::write(&file, lines("#", "", 10)).expect("write");
    if !creation_time_is_known(&file) {
        return;
    }
    let out = rig.bash_at(&rig.cwd, Some("g1"), &format!("cat {}", file.display()), "claude", Some(&rig.home));
    assert!(out.is_empty(), "{out}");
}

#[test]
fn a_committed_file_too_large_to_compare_is_left_alone() {
    let rig = Rig::new("big-blob");
    init_repo(&rig.cwd);
    let file = commit_file(&rig.cwd, "big.py", &"x = 1\n".repeat(600_000));
    std::fs::write(&file, lines("#", "", 5)).expect("write");
    let out = rig.bash(Some("g2"), &format!("cat {}", file.display()));
    assert!(out.is_empty(), "{out}");
}

#[test]
fn each_working_folder_keeps_its_own_check_time() {
    let rig = Rig::new("folders");
    let other = temp_dir("folders-b");
    let file = rig.cwd.join("p.py");
    std::fs::write(&file, lines("#", "", 4)).expect("write");
    if !creation_time_is_known(&file) {
        return;
    }
    let _ = rig.bash_at(&other, Some("f1"), "true", "claude", None);
    let out = rig.bash_at(&rig.cwd, Some("f1"), "true", "claude", None);
    assert!(blocked(&out), "{out}");
    let _ = std::fs::remove_dir_all(&other);
}

#[test]
fn the_codex_form_of_the_post_command_hook_blocks_too() {
    let rig = Rig::new("codex-post");
    let file = rig.cwd.join("c.py");
    std::fs::write(&file, lines("#", "", 4)).expect("write");
    if !creation_time_is_known(&file) {
        return;
    }
    let out = rig.bash_at(&rig.cwd, Some("c9"), &format!("echo > {}", file.display()), "codex", None);
    assert!(blocked(&out), "{out}");
    assert!(out.contains("4 comment lines"), "{out}");
}

#[test]
fn trailing_markers_without_a_space_still_count() {
    let typescript = "const a=1;// one\nconst b=2;// two\nconst c=3;// three\n";
    assert!(denied(&write_file(None, None, Path::new("t.ts"), typescript)));
    let rust = "fn f() {\n    let a = '\"'; // one\n    let b = '\"'; // two\n    let c = '\"'; // three\n}\n";
    assert!(denied(&write_file(None, None, Path::new("t.rs"), rust)));
}

#[test]
fn editing_the_code_next_to_an_inline_comment_leaves_the_comment_unchanged() {
    let dir = temp_dir("inline");
    let path = dir.join("a.c");
    std::fs::write(
        &path,
        "int a = /* stable a */ 1;\nint b = /* stable b */ 2;\nint c = /* stable c */ 3;\n",
    )
    .expect("write");
    let rewritten = "int a = /* stable a */ 10;\nint b = /* stable b */ 20;\nint c = /* stable c */ 30;\n";
    assert!(!denied(&write_file(None, None, &path, rewritten)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nested_block_comments_are_counted_to_their_real_end() {
    let haskell = "{- {- inner -}\none\ntwo\n-}\nx = 1\n";
    assert!(denied(&write_file(None, None, Path::new("a.hs"), haskell)));
}

fn creation_time_is_known(path: &Path) -> bool {
    std::fs::metadata(path).and_then(|meta| meta.created()).is_ok()
}

#[test]
fn a_file_written_by_a_command_with_too_many_comments_is_reported() {
    let rig = Rig::new("bash-new");
    let file = rig.cwd.join("l_bash.py");
    std::fs::write(&file, "x = 1\n# a\n# b\n# c\n# d\n").expect("write");
    if !creation_time_is_known(&file) {
        return;
    }
    let out = rig.bash(Some("b1"), &format!("printf '# a\\n# b\\n# c\\n# d\\n' > {}", file.display()));
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    assert!(out.contains("l_bash.py"), "{out}");
    assert!(out.contains("4 comment lines"), "{out}");
}

#[test]
fn a_command_that_adds_two_comments_is_silent_and_a_second_one_is_caught() {
    let rig = Rig::new("bash-append");
    let file = rig.cwd.join("o_thing.rb");
    std::fs::write(&file, "x = 1\n# a\n# b\n").expect("write");
    if !creation_time_is_known(&file) {
        return;
    }
    let first = rig.bash(Some("b2"), &format!("printf '# a\\n# b\\n' >> {}", file.display()));
    assert!(first.is_empty(), "{first}");
    std::fs::write(&file, "x = 1\n# a\n# b\ny = 2\n# c\n# d\n").expect("write");
    let second = rig.bash(Some("b2"), &format!("printf '# c\\n# d\\n' >> {}", file.display()));
    assert!(second.contains("\"decision\":\"block\""), "{second}");
}

#[test]
fn sed_on_a_file_the_session_edited_is_judged_against_its_baseline() {
    let rig = Rig::new("bash-sed");
    let file = rig.cwd.join("g_base.py");
    std::fs::write(&file, "def g() -> int:\n    return 1\n").expect("write");
    assert!(rig
        .pre_edit("b3", &file, "def g() -> int:", "# one\n# two\ndef g() -> int:")
        .is_empty());
    std::fs::write(&file, "# s1\n# s2\n# one\n# two\ndef g() -> int:\n    return 1\n").expect("write");
    let out = rig.bash(Some("b3"), &format!("sed -i '' '1i # s1' {}", file.display()));
    assert!(out.contains("\"decision\":\"block\""), "{out}");
}

#[test]
fn a_generated_file_is_not_reported() {
    let rig = Rig::new("bash-generated");
    let file = rig.cwd.join("gen.go");
    std::fs::write(&file, format!("// Code generated by tool. DO NOT EDIT.\n{}", lines("//", "", 9))).expect("write");
    if !creation_time_is_known(&file) {
        return;
    }
    let out = rig.bash(Some("b4"), &format!("tool > {}", file.display()));
    assert!(out.is_empty(), "{out}");
}

#[test]
fn other_tools_and_sessionless_calls_are_ignored_after_the_command() {
    let rig = Rig::new("bash-ignored");
    let file = rig.cwd.join("a.py");
    std::fs::write(&file, lines("#", "", 9)).expect("write");
    assert!(rig.bash(None, &format!("echo > {}", file.display())).is_empty());
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "session_id": "b5",
        "tool_name": "Read",
        "cwd": rig.cwd.to_string_lossy(),
        "tool_input": { "file_path": file.to_string_lossy() },
    });
    assert!(rig.feed("PostToolUse", &payload).stdout.is_empty());
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("could not run git");
    assert!(status.success(), "git {args:?} failed");
}

#[test]
fn a_tracked_file_is_judged_against_head() {
    let rig = Rig::new("bash-git");
    git(&rig.cwd, &["init", "-q"]);
    git(&rig.cwd, &["config", "user.name", "Test User"]);
    git(&rig.cwd, &["config", "user.email", "test@example.com"]);
    git(&rig.cwd, &["config", "commit.gpgsign", "false"]);
    let file = rig.cwd.join("lib.rs");
    std::fs::write(&file, "// old note\nfn a() {}\n").expect("write");
    git(&rig.cwd, &["add", "lib.rs"]);
    git(&rig.cwd, &["-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "first"]);
    std::fs::write(&file, "// old note\n// n1\n// n2\n// n3\nfn a() {}\n").expect("write");
    let out = rig.bash(Some("b6"), &format!("printf x >> {}", file.display()));
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    assert!(out.contains("3 comment lines"), "{out}");
    std::fs::write(&file, "// old note\n// n1\nfn a() {}\n").expect("write");
    let calm = rig.bash(Some("b6"), &format!("printf x >> {}", file.display()));
    assert!(calm.is_empty(), "{calm}");
}

#[test]
fn the_post_command_hook_accepts_the_codex_form_too() {
    let rig = Rig::new("bash-codex");
    let output = Command::new(binary())
        .args(["hook", "codex", "PostToolUse"])
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD", "1")
        .env("XDG_STATE_HOME", &rig.state)
        .env("HOME", &rig.home)
        .stdin(Stdio::null())
        .output()
        .expect("could not start the binary");
    assert_eq!(output.status.code(), Some(0));
    let bad = Command::new(binary())
        .args(["hook", "codex", "Stop"])
        .output()
        .expect("could not start the binary");
    assert_eq!(bad.status.code(), Some(2));
}
