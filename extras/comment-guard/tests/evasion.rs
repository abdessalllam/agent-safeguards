use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use comment_guard::{judge_in, judge_trimming_in, Provider, Verdict};

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
            .env("AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM", "0")
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

    fn pre_bash(&self, session: &str, tool_use_id: &str) {
        self.pre_bash_with(session, tool_use_id, "true");
    }

    fn pre_bash_with(&self, session: &str, tool_use_id: &str, command: &str) {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "session_id": session,
            "tool_use_id": tool_use_id,
            "cwd": self.cwd.to_string_lossy(),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        });
        let output = self.feed("PreToolUse", &payload);
        assert!(output.stdout.is_empty());
    }

    fn bash_with_id(&self, session: &str, tool_use_id: &str, command: &str) -> String {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "session_id": session,
            "tool_use_id": tool_use_id,
            "cwd": self.cwd.to_string_lossy(),
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "tool_response": {},
        });
        String::from_utf8_lossy(&self.feed("PostToolUse", &payload).stdout).into_owned()
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
    std::fs::create_dir(rig.cwd.join(".git")).expect("marker");
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
    let file = commit_file(&rig.cwd, "big.py", &"x = 1\n".repeat(1_600_000));
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

#[cfg(unix)]
fn fake_git(dir: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("git");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[cfg(unix)]
#[test]
fn a_git_that_never_answers_is_cut_off() {
    let rig = Rig::new("slow-git");
    std::fs::create_dir(rig.cwd.join(".git")).expect("marker");
    let bin = temp_dir("slow-git-bin");
    fake_git(&bin, "/bin/sleep 8");
    let file = rig.cwd.join("a.py");
    std::fs::write(&file, lines("#", "", 6)).expect("write");
    let started = std::time::Instant::now();
    let out = rig.bash_at(&rig.cwd, Some("g3"), &format!("cat {}", file.display()), "claude", Some(&bin));
    assert!(out.is_empty(), "{out}");
    assert!(started.elapsed() < std::time::Duration::from_secs(4), "{:?}", started.elapsed());
    let _ = std::fs::remove_dir_all(&bin);
}

#[cfg(unix)]
#[test]
fn a_git_helper_that_keeps_the_pipe_open_does_not_hold_the_hook() {
    let rig = Rig::new("pipe-git");
    std::fs::create_dir(rig.cwd.join(".git")).expect("marker");
    let bin = temp_dir("pipe-git-bin");
    fake_git(&bin, "/bin/sleep 8 &\nexit 0");
    let file = rig.cwd.join("a.py");
    std::fs::write(&file, lines("#", "", 6)).expect("write");
    let started = std::time::Instant::now();
    let out = rig.bash_at(&rig.cwd, Some("g4"), &format!("cat {}", file.display()), "claude", Some(&bin));
    assert!(out.is_empty(), "{out}");
    assert!(started.elapsed() < std::time::Duration::from_secs(4), "{:?}", started.elapsed());
    let _ = std::fs::remove_dir_all(&bin);
}

#[cfg(unix)]
#[test]
fn a_git_error_is_not_taken_for_a_missing_file() {
    let rig = Rig::new("git-error");
    std::fs::create_dir(rig.cwd.join(".git")).expect("marker");
    let bin = temp_dir("git-error-bin");
    fake_git(&bin, "echo 'fatal: detected dubious ownership in repository' >&2\nexit 128");
    let file = rig.cwd.join("a.py");
    std::fs::write(&file, lines("#", "", 10)).expect("write");
    if !creation_time_is_known(&file) {
        return;
    }
    let out = rig.bash_at(&rig.cwd, Some("g5"), &format!("cat {}", file.display()), "claude", Some(&bin));
    assert!(out.is_empty(), "{out}");
    let _ = std::fs::remove_dir_all(&bin);
}

#[test]
fn a_new_file_in_a_repository_is_judged_against_nothing() {
    let rig = Rig::new("untracked");
    init_repo(&rig.cwd);
    commit_file(&rig.cwd, "a.py", "x = 1\n");
    let fresh = rig.cwd.join("b.py");
    std::fs::write(&fresh, lines("#", "", 4)).expect("write");
    if !creation_time_is_known(&fresh) {
        return;
    }
    let out = rig.bash(Some("g6"), &format!("cat {}", fresh.display()));
    assert!(blocked(&out), "{out}");
}

#[test]
fn a_command_is_judged_from_the_moment_it_started() {
    let rig = Rig::new("started");
    init_repo(&rig.cwd);
    let file = commit_file(&rig.cwd, "a.py", "x = 1\n");
    std::fs::write(&file, "x = 1\n# u1\n# u2\n# u3\n").expect("write");
    rig.pre_bash("st1", "tool-1");
    let read = rig.bash_with_id("st1", "tool-1", &format!("cat {}", file.display()));
    assert!(read.is_empty(), "{read}");
    rig.pre_bash("st1", "tool-2");
    std::fs::write(&file, "x = 1\n# u1\n# u2\n# u3\n# a\n# b\n# c\n").expect("write");
    let wrote = rig.bash_with_id("st1", "tool-2", &format!("printf x >> {}", file.display()));
    assert!(blocked(&wrote), "{wrote}");
}

#[test]
fn a_whitespace_difference_after_an_anchor_does_not_rewind_the_search() {
    let dir = temp_dir("rewind");
    let path = dir.join("a.py");
    std::fs::write(&path, "DATA = \"\"\"\n    return 1\n\"\"\"\ndef f():\n    return 1 \n").expect("write");
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n@@ def f():\n-    return 1\n+    # one\n+    # two\n+    # three\n+    return 1\n*** End Patch\n",
        path.display()
    );
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_indented_anchor_keeps_its_indentation() {
    let dir = temp_dir("indent-anchor");
    let path = dir.join("a.py");
    let text = "class C:\n    def f(self):\n        return 1\nDATA = \"\"\"\ndef f(self):\n        return 1\n\"\"\"\n";
    std::fs::write(&path, text).expect("write");
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n@@     def f(self):\n-        return 1\n+        # one\n+        # two\n+        # three\n+        return 1\n*** End Patch\n",
        path.display()
    );
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_later_comment_on_a_line_with_a_block_comment_is_still_judged() {
    let verdict = write_file(None, None, Path::new("a.c"), "int x = /* stable */ 1; // previously broken\n");
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("previously"));
}

#[test]
fn a_move_to_another_language_does_not_inherit_the_old_scanners_record() {
    let dir = temp_dir("cross-move");
    let state = temp_dir("cross-move-state");
    let from = dir.join("a.pl");
    let to = dir.join("b.py");
    let text = "print(1);# one\nprint(2);# two\nprint(3);# three\n";
    std::fs::write(&from, text).expect("write");
    let first = edit_file(Some(&state), Some("x1"), &from, "print(1)", "print(4)");
    assert!(!denied(&first));
    apply_edit(&from, "print(1)", "print(4)");
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n*** Move to: {}\n@@\n print(4);# one\n print(2);# two\n print(3);# three\n*** End Patch\n",
        from.display(),
        to.display()
    );
    let verdict = pre(Some(&state), Some("x1"), "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(!denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_multi_edit_that_exhausts_the_work_budget_is_allowed_not_judged_by_fragments() {
    let dir = temp_dir("budget");
    let path = dir.join("big.py");
    let padding = "x".repeat(1024 * 1024);
    std::fs::write(&path, format!("flag = 0\nDATA = \"\"\"\nold\n{padding}\n\"\"\"\n")).expect("write");
    let mut edits: Vec<Value> = (0..70)
        .map(|n| {
            let (from, to) = if n % 2 == 0 { ("flag = 0", "flag = 1") } else { ("flag = 1", "flag = 0") };
            json!({ "old_string": from, "new_string": to })
        })
        .collect();
    edits.push(json!({ "old_string": "\nold\n", "new_string": "\n# one\n# two\n# three\n" }));
    let verdict = pre(
        None,
        None,
        "MultiEdit",
        json!({ "file_path": path.to_string_lossy(), "edits": edits }),
        Provider::Claude,
    );
    assert!(!denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn comments_on_one_physical_line_count_as_one_line_but_are_each_checked() {
    let three = "int f(void) { return /* a */ 1 + /* b */ 2 + /* c */ 3; }\n";
    assert!(!denied(&write_file(None, None, Path::new("a.c"), three)));
    let two_lines = "int a = /* a */ 1; /* b */\nint b = /* c */ 2; /* d */\n";
    assert!(!denied(&write_file(None, None, Path::new("a.c"), two_lines)));
    let three_lines = "int a = /* a */ 1;\nint b = /* b */ 2;\nint c = /* c */ 3;\n";
    assert!(denied(&write_file(None, None, Path::new("a.c"), three_lines)));
    let verdict = write_file(None, None, Path::new("a.c"), "int a = /* fine */ 1; /* used to differ */\n");
    assert!(denied(&verdict));
    assert!(reason(&verdict).contains("used to"));
}

#[test]
fn a_move_to_a_similar_language_keeps_the_allowance_that_was_used() {
    let dir = temp_dir("similar-move");
    let state = temp_dir("similar-move-state");
    let from = dir.join("a.py");
    let to = dir.join("b.rb");
    std::fs::write(&from, "x = 1\n").expect("write");
    let first = edit_file(Some(&state), Some("h1"), &from, "x = 1", "# one\n# two\nx = 1");
    assert!(!denied(&first));
    apply_edit(&from, "x = 1", "# one\n# two\nx = 1");
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n*** Move to: {}\n@@\n # one\n # two\n+# three\n+# four\n x = 1\n*** End Patch\n",
        from.display(),
        to.display()
    );
    let verdict = pre(Some(&state), Some("h1"), "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_patch_that_runs_out_of_budget_does_not_judge_its_earlier_intermediate_file() {
    let dir = temp_dir("patch-budget");
    let path = dir.join("a.py");
    let padding = "x".repeat(1024 * 1024);
    std::fs::write(&path, format!("flag = 0\nDATA = \"\"\"\n{padding}\n\"\"\"\n")).expect("write");
    let target = path.display();
    let mut patch = String::from("*** Begin Patch\n");
    patch.push_str(&format!("*** Update File: {target}\n@@\n+# one\n+# two\n+# three\n"));
    for n in 0..70 {
        let (from, to) = if n % 2 == 0 { ("flag = 0", "flag = 1") } else { ("flag = 1", "flag = 0") };
        patch.push_str(&format!("*** Update File: {target}\n@@\n-{from}\n+{to}\n"));
    }
    patch.push_str(&format!("*** Update File: {target}\n@@\n-# one\n-# two\n-# three\n"));
    patch.push_str("*** End Patch\n");
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(!denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn once_the_patch_budget_is_spent_later_sections_do_not_restart_from_the_original() {
    let dir = temp_dir("patch-sticky");
    let path = dir.join("a.py");
    std::fs::write(&path, "flag = 0\n").expect("write");
    let target = path.display();
    let padding = "x".repeat(1024 * 1024);
    let mut patch = String::from("*** Begin Patch\n");
    patch.push_str(&format!("*** Update File: {target}\n@@\n+DATA = \"\"\"\n+{padding}\n"));
    for n in 0..64 {
        let (from, to) = if n % 2 == 0 { ("flag = 0", "flag = 1") } else { ("flag = 1", "flag = 0") };
        patch.push_str(&format!("*** Update File: {target}\n@@\n-{from}\n+{to}\n"));
    }
    patch.push_str(&format!("*** Update File: {target}\n@@\n+# one\n+# two\n+# three\n+\"\"\"\n"));
    patch.push_str("*** End Patch\n");
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(!denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nothing_further_in_a_patch_is_judged_once_its_budget_is_spent() {
    let dir = temp_dir("patch-spent");
    let path = dir.join("a.py");
    std::fs::write(&path, "flag = 0\n").expect("write");
    let target = path.display();
    let padding = "x".repeat(1024 * 1024);
    let mut patch = String::from("*** Begin Patch\n");
    patch.push_str(&format!("*** Update File: {target}\n@@\n+DATA = \"\"\"\n+{padding}\n"));
    for n in 0..64 {
        let (from, to) = if n % 2 == 0 { ("flag = 0", "flag = 1") } else { ("flag = 1", "flag = 0") };
        patch.push_str(&format!("*** Update File: {target}\n@@\n-{from}\n+{to}\n"));
    }
    let fresh = dir.join("fresh.py");
    patch.push_str(&format!("*** Add File: {}\n+# one\n+# two\n+# three\n", fresh.display()));
    patch.push_str("*** End Patch\n");
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(!denied(&verdict));
    let short = format!("*** Begin Patch\n*** Add File: {}\n+# one\n+# two\n+# three\n*** End Patch\n", fresh.display());
    let alone = pre(None, None, "apply_patch", json!({ "command": short }), Provider::Codex);
    assert!(denied(&alone));
    let _ = std::fs::remove_dir_all(&dir);
}

fn mark_paths(dir: &Path) {
    let rules = "up/** comment-guard=skip\nvendor/** linguist-vendored\ngen/** linguist-generated\nown/** -comment-guard\n";
    std::fs::write(dir.join(".gitattributes"), rules).expect("write");
}

#[test]
fn edits_to_marked_upstream_paths_are_not_checked() {
    let rig = Rig::new("marked-edit");
    init_repo(&rig.cwd);
    mark_paths(&rig.cwd);
    let nine = lines("#", "", 9);
    for name in ["up/a.py", "up/deep/new/b.py", "vendor/c.py", "gen/d.py"] {
        let verdict = write_file(None, None, &rig.cwd.join(name), &nine);
        assert!(!denied(&verdict), "{name}");
    }
    for name in ["own/e.py", "plain.py"] {
        let verdict = write_file(None, None, &rig.cwd.join(name), &nine);
        assert!(denied(&verdict), "{name}");
    }
}

#[test]
fn a_folder_that_is_not_a_repository_has_no_exemptions() {
    let dir = temp_dir("marked-plain");
    mark_paths(&dir);
    let verdict = write_file(None, None, &dir.join("up/a.py"), &lines("#", "", 9));
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn files_a_command_wrote_under_a_marked_path_are_not_reported() {
    let rig = Rig::new("marked-bash");
    init_repo(&rig.cwd);
    mark_paths(&rig.cwd);
    std::fs::create_dir_all(rig.cwd.join("up")).expect("dir");
    let upstream = rig.cwd.join("up").join("x.py");
    let own = rig.cwd.join("own.py");
    std::fs::write(&upstream, lines("#", "", 6)).expect("write");
    if !creation_time_is_known(&upstream) {
        return;
    }
    let quiet = rig.bash(Some("m1"), &format!("rsync x {}", upstream.display()));
    assert!(quiet.is_empty(), "{quiet}");
    std::fs::write(&own, lines("#", "", 6)).expect("write");
    let loud = rig.bash(Some("m1"), &format!("printf x > {}", own.display()));
    assert!(blocked(&loud), "{loud}");
    assert!(loud.contains("own.py"), "{loud}");
}

#[test]
fn rewording_existing_comments_is_not_adding_comments() {
    let dir = temp_dir("reword");
    let path = dir.join("a.ts");
    let old = lines("//", "t3code namespace", 10);
    std::fs::write(&path, &old).expect("write");
    let renamed = old.replace("t3code", "melara");
    assert!(!denied(&write_file(None, None, &path, &renamed)));
    let with_more = format!("{renamed}{}", lines("//", "extra", 9));
    assert!(denied(&write_file(None, None, &path, &with_more)));
    let edit = edit_file(None, None, &path, "// line 3 t3code namespace", "// line 3 melara namespace");
    assert!(!denied(&edit));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_existing_long_comment_may_be_reworded_but_a_short_one_may_not_grow_long() {
    let dir = temp_dir("reword-long");
    let path = dir.join("a.ts");
    let long = format!("// {}\n", "word ".repeat(30));
    std::fs::write(&path, format!("{long}const a = 1;\n")).expect("write");
    let reworded = long.replacen("word", "term", 1);
    assert!(!denied(&write_file(None, None, &path, &format!("{reworded}const a = 1;\n"))));
    std::fs::write(&path, "// short\nconst a = 1;\n").expect("write");
    let grown = write_file(None, None, &path, &format!("{long}const a = 1;\n"));
    assert!(denied(&grown));
    assert!(reason(&grown).contains("75"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_date_that_was_already_in_a_comment_is_not_new() {
    let dir = temp_dir("reword-date");
    let path = dir.join("a.ts");
    std::fs::write(&path, "// fixed on 2024-01-02 by hand\nconst a = 1;\n").expect("write");
    let reworded = write_file(None, None, &path, "// fixed on 2024-01-02 by tool\nconst a = 1;\n");
    assert!(!denied(&reworded));
    let other_date = write_file(None, None, &path, "// fixed on 2025-02-03 by hand\nconst a = 1;\n");
    assert!(denied(&other_date));
    std::fs::write(&path, "// plain\nconst a = 1;\n").expect("write");
    assert!(denied(&write_file(None, None, &path, "// plain 2024-01-02\nconst a = 1;\n")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn one_comment_becoming_several_lines_counts_the_extra_lines() {
    let dir = temp_dir("grow");
    let path = dir.join("a.py");
    std::fs::write(&path, "# one\nx = 1\n").expect("write");
    assert!(denied(&write_file(None, None, &path, "# a\n# b\n# c\n# d\n# e\nx = 1\n")));
    assert!(!denied(&write_file(None, None, &path, "# a\n# b\nx = 1\n")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rewording_what_the_session_added_stays_within_its_allowance() {
    let dir = temp_dir("reword-session");
    let state = temp_dir("reword-session-state");
    let path = dir.join("a.py");
    std::fs::write(&path, "x = 1\n").expect("write");
    let first = edit_file(Some(&state), Some("rw"), &path, "x = 1", "# one\n# two\nx = 1");
    assert!(!denied(&first));
    apply_edit(&path, "x = 1", "# one\n# two\nx = 1");
    let reworded = edit_file(Some(&state), Some("rw"), &path, "# one\n# two", "# uno\n# dos");
    assert!(!denied(&reworded));
    apply_edit(&path, "# one\n# two", "# uno\n# dos");
    let more = edit_file(Some(&state), Some("rw"), &path, "x = 1", "# three\n# four\nx = 1");
    assert!(denied(&more));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn comments_added_by_someone_else_between_edits_are_not_counted_against_the_agent() {
    let dir = temp_dir("outside-edit");
    let state = temp_dir("outside-edit-state");
    let path = dir.join("a.py");
    std::fs::write(&path, "x = 1\ny = 2\n").expect("write");
    let first = edit_file(Some(&state), Some("oe"), &path, "x = 1", "# one\n# two\nx = 1");
    assert!(!denied(&first));
    apply_edit(&path, "x = 1", "# one\n# two\nx = 1");
    let outside = format!("{}# one\n# two\nx = 1\ny = 2\n", lines("#", "by hand", 5));
    std::fs::write(&path, outside).expect("write");
    let second = edit_file(Some(&state), Some("oe"), &path, "y = 2", "# three\n# four\ny = 2");
    assert!(!denied(&second));
    apply_edit(&path, "y = 2", "# three\n# four\ny = 2");
    let third = edit_file(Some(&state), Some("oe"), &path, "y = 2", "# five\n# six\ny = 2");
    assert!(denied(&third));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn an_edit_that_never_landed_does_not_forget_what_the_session_added() {
    let dir = temp_dir("not-landed");
    let state = temp_dir("not-landed-state");
    let path = dir.join("a.py");
    std::fs::write(&path, "x = 1\ny = 2\n").expect("write");
    assert!(!denied(&edit_file(Some(&state), Some("nl"), &path, "x = 1", "# one\n# two\nx = 1")));
    apply_edit(&path, "x = 1", "# one\n# two\nx = 1");
    assert!(!denied(&edit_file(Some(&state), Some("nl"), &path, "y = 2", "y = 3")));
    let again = edit_file(Some(&state), Some("nl"), &path, "y = 2", "# three\n# four\ny = 2");
    assert!(denied(&again));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn commands_that_only_run_git_do_not_blame_the_agent_for_the_comments_they_bring_in() {
    let rig = Rig::new("git-only");
    init_repo(&rig.cwd);
    let file = commit_file(&rig.cwd, "a.py", "x = 1\n");
    rig.pre_bash("go1", "t1");
    std::fs::write(&file, format!("{}x = 1\n", lines("#", "upstream", 9))).expect("write");
    let merged = rig.bash_with_id("go1", "t1", "git checkout feature -- a.py");
    assert!(merged.is_empty(), "{merged}");
    rig.pre_bash("go1", "t2");
    std::fs::write(&file, format!("{}# mine\nx = 1\n", lines("#", "upstream", 9))).expect("write");
    let later = rig.bash_with_id("go1", "t2", &format!("sed -i x {}", file.display()));
    assert!(later.is_empty(), "{later}");
    rig.pre_bash("go2", "t3");
    std::fs::write(&file, format!("{}x = 1\n", lines("#", "agent", 9))).expect("write");
    let written = rig.bash_with_id("go2", "t3", &format!("printf x > {}", file.display()));
    assert!(blocked(&written), "{written}");
}

#[test]
fn edits_and_commands_in_turn_keep_counting_from_the_original_file() {
    let rig = Rig::new("turns");
    let file = rig.cwd.join("a.py");
    std::fs::write(&file, "x = 1\ny = 2\n").expect("write");
    let first = rig.pre_edit("tn", &file, "x = 1", "# one\n# two\nx = 1");
    assert!(first.is_empty(), "{first}");
    std::fs::write(&file, "# one\n# two\nx = 1\ny = 2\n").expect("write");
    rig.pre_bash("tn", "t1");
    std::fs::write(&file, "# one\n# two\nx = 1\n# three\n# four\ny = 2\n").expect("write");
    let ran = rig.bash_with_id("tn", "t1", &format!("sed -i x {}", file.display()));
    assert!(blocked(&ran), "{ran}");
    let again = rig.pre_edit("tn", &file, "y = 2", "# five\ny = 2");
    assert!(again.contains("\"permissionDecision\":\"deny\""), "{again}");
}

#[test]
fn a_bulk_rename_through_a_command_is_not_reported_but_added_comments_still_are() {
    let rig = Rig::new("bulk-rename");
    init_repo(&rig.cwd);
    for n in 0..12 {
        let text = format!("# t3code note a\n# t3code note b\n# t3code note c\nx = {n}\n");
        std::fs::write(rig.cwd.join(format!("f{n}.py")), text).expect("write");
    }
    git(&rig.cwd, &["add", "-A"]);
    git(&rig.cwd, &["-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "base"]);
    rig.pre_bash("br", "t1");
    for n in 0..12 {
        let text = format!("# melara note a\n# melara note b\n# melara note c\nx = {n}\n");
        std::fs::write(rig.cwd.join(format!("f{n}.py")), text).expect("write");
    }
    let renamed = rig.bash_with_id("br", "t1", "python3 rename.py");
    assert!(renamed.is_empty(), "{renamed}");
    rig.pre_bash("br", "t2");
    let more = "# melara note a\n# melara note b\n# melara note c\n# extra one\n# extra two\n# extra three\nx = 0\n";
    std::fs::write(rig.cwd.join("f0.py"), more).expect("write");
    let loud = rig.bash_with_id("br", "t2", "python3 rename.py");
    assert!(blocked(&loud), "{loud}");
    assert!(loud.contains("f0.py"), "{loud}");
}

#[test]
fn a_patch_that_rewords_comments_is_allowed_and_one_that_adds_them_is_not() {
    let dir = temp_dir("patch-reword");
    let path = dir.join("a.ts");
    let old: String = (0..10).map(|n| format!("// note {n} about t3code\n")).collect();
    std::fs::write(&path, format!("{old}const a = 1;\n")).expect("write");
    let removed: String = (0..10).map(|n| format!("-// note {n} about t3code\n")).collect();
    let added: String = (0..10).map(|n| format!("+// note {n} about melara\n")).collect();
    let patch = format!("*** Begin Patch\n*** Update File: {}\n@@\n{removed}{added}*** End Patch\n", path.display());
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(!denied(&verdict));
    let extra: String = (0..5).map(|n| format!("+// extra {n}\n")).collect();
    let growing = format!("*** Begin Patch\n*** Update File: {}\n@@\n{removed}{added}{extra}*** End Patch\n", path.display());
    let verdict = pre(None, None, "apply_patch", json!({ "command": growing }), Provider::Codex);
    assert!(denied(&verdict));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn files_with_windows_line_endings_are_judged_like_any_other() {
    let dir = temp_dir("crlf");
    let path = dir.join("a.py");
    let old = "# one\r\n# two\r\n# three\r\nx = 1\r\n";
    std::fs::write(&path, old).expect("write");
    assert!(!denied(&write_file(None, None, &path, old)));
    assert!(!denied(&write_file(None, None, &path, "# uno\r\n# dos\r\n# tres\r\nx = 1\r\n")));
    assert!(denied(&write_file(None, None, &path, &format!("{old}# four\r\n# five\r\n# six\r\n"))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_that_is_not_utf8_is_handled_without_a_panic() {
    let dir = temp_dir("binary");
    let path = dir.join("a.py");
    let mut bytes = b"x = 1\n# keep\n".to_vec();
    bytes.extend_from_slice(&[0xff, 0xfe, 0x00, b'\n']);
    std::fs::write(&path, &bytes).expect("write");
    assert!(!denied(&edit_file(None, None, &path, "x = 1", "x = 2")));
    assert!(denied(&edit_file(None, None, &path, "x = 1", "# a\n# b\n# c\nx = 1")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_git_command_that_rewrites_a_file_unchanged_does_not_reset_the_allowance() {
    let rig = Rig::new("stash-pop");
    init_repo(&rig.cwd);
    let file = commit_file(&rig.cwd, "a.py", "x = 1\ny = 2\n");
    let first = rig.pre_edit("sp", &file, "x = 1", "# one\n# two\nx = 1");
    assert!(first.is_empty(), "{first}");
    std::fs::write(&file, "# one\n# two\nx = 1\ny = 2\n").expect("write");
    rig.pre_bash("sp", "t1");
    std::fs::write(&file, "# one\n# two\nx = 1\ny = 2\n").expect("write");
    let popped = rig.bash_with_id("sp", "t1", "git stash && git stash pop");
    assert!(popped.is_empty(), "{popped}");
    let again = rig.pre_edit("sp", &file, "y = 2", "# three\n# four\ny = 2");
    assert!(again.contains("\"permissionDecision\":\"deny\""), "{again}");
}

#[test]
fn two_edits_judged_against_the_same_file_state_share_one_allowance() {
    let dir = temp_dir("parallel-edits");
    let state = temp_dir("parallel-edits-state");
    let path = dir.join("a.py");
    std::fs::write(&path, "x = 1\ny = 2\n").expect("write");
    let first = edit_file(Some(&state), Some("pe"), &path, "x = 1", "# one\n# two\nx = 1");
    assert!(!denied(&first));
    let second = edit_file(Some(&state), Some("pe"), &path, "y = 2", "# three\n# four\ny = 2");
    assert!(denied(&second));
    assert!(reason(&second).contains("4 comment lines"));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_file_the_user_edited_before_a_command_that_names_it_is_not_blamed_on_the_command() {
    let rig = Rig::new("named-refresh");
    let file = rig.cwd.join("a.py");
    std::fs::write(&file, "x = 1\n").expect("write");
    let first = rig.pre_edit("nr", &file, "x = 1", "x = 2");
    assert!(first.is_empty(), "{first}");
    std::fs::write(&file, "x = 2\n").expect("write");
    let command = format!("black {}", file.display());
    std::fs::write(&file, format!("{}x = 2\n", lines("#", "by hand", 4))).expect("write");
    rig.pre_bash_with("nr", "t1", &command);
    std::fs::write(&file, format!("{}x = 2\n", lines("#", "by hand", 4))).expect("write");
    let out = rig.bash_with_id("nr", "t1", &command);
    assert!(out.is_empty(), "{out}");
}

#[test]
fn copying_a_commented_file_is_not_adding_comments() {
    let rig = Rig::new("copy");
    std::fs::create_dir_all(rig.cwd.join("vendor")).expect("dir");
    std::fs::create_dir_all(rig.cwd.join("src")).expect("dir");
    let source = rig.cwd.join("vendor").join("widget.py");
    let content = format!("{}x = 1\n", lines("#", "widget", 10));
    std::fs::write(&source, &content).expect("write");
    let copy = rig.cwd.join("src").join("widget.py");
    let command = "cp vendor/widget.py src/widget.py";
    rig.pre_bash_with("cp", "t1", command);
    std::fs::write(&copy, &content).expect("write");
    if !creation_time_is_known(&copy) {
        return;
    }
    let out = rig.bash_with_id("cp", "t1", command);
    assert!(out.is_empty(), "{out}");
    let after = rig.pre_edit("cp", &copy, "x = 1", "x = 2");
    assert!(after.is_empty(), "{after}");
    rig.pre_bash_with("cp", "t2", command);
    let other = rig.cwd.join("src").join("other.py");
    std::fs::write(&other, format!("{}x = 1\n", lines("#", "new text", 10))).expect("write");
    let loud = rig.bash_with_id("cp", "t2", &format!("{command} && printf x > {}", other.display()));
    assert!(blocked(&loud), "{loud}");
    let tree = "cp -r vendor src2";
    rig.pre_bash_with("cp", "t3", tree);
    std::fs::create_dir_all(rig.cwd.join("src2")).expect("dir");
    std::fs::write(rig.cwd.join("src2").join("widget.py"), &content).expect("write");
    let copied = rig.bash_with_id("cp", "t3", tree);
    assert!(copied.is_empty(), "{copied}");
}

#[test]
fn a_symbol_with_a_history_word_inside_it_is_not_a_history_comment() {
    let dir = temp_dir("snake");
    let path = dir.join("a.ts");
    let plain = write_file(None, None, &path, "// clear previously_cached entries\nconst a = 1;\n");
    assert!(!denied(&plain));
    let real = write_file(None, None, &path, "// previously cached entries\nconst a = 1;\n");
    assert!(denied(&real));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rewrapping_a_comment_is_not_adding_lines() {
    let dir = temp_dir("rewrap");
    let path = dir.join("a.rs");
    std::fs::write(&path, "// one long comment about renaming things across the whole codebase quickly\nfn a() {}\n")
        .expect("write");
    let wrapped = "// one long comment about\n// renaming things across\n// the whole codebase\n// quickly\nfn a() {}\n";
    assert!(!denied(&write_file(None, None, &path, wrapped)));
    let grown = "// one long comment about\n// renaming things across\n// the whole codebase\n// quickly and also\n// a lot of new words\nfn a() {}\n";
    assert!(denied(&write_file(None, None, &path, grown)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn git_commands_that_could_run_hooks_or_other_code_are_judged_like_any_command() {
    let rig = Rig::new("hooks");
    init_repo(&rig.cwd);
    let file = commit_file(&rig.cwd, "a.py", "x = 1\n");
    for (n, command) in [
        "git -c core.hooksPath=/tmp/h checkout -- a.py",
        "git commit --allow-empty -m m",
        "git checkout-index -f -- a.py",
    ]
    .iter()
    .enumerate()
    {
        let id = format!("h{n}");
        rig.pre_bash_with("hk", &id, command);
        std::fs::write(&file, format!("{}x = 1\n", lines("#", &format!("planted {n}"), 6))).expect("write");
        let out = rig.bash_with_id("hk", &id, command);
        assert!(blocked(&out), "{command}: {out}");
        std::fs::write(&file, "x = 1\n").expect("write");
    }
}

#[test]
fn many_marked_upstream_files_in_one_patch_are_all_skipped() {
    let rig = Rig::new("many-marked");
    init_repo(&rig.cwd);
    mark_paths(&rig.cwd);
    let mut patch = String::from("*** Begin Patch\n");
    for n in 0..60 {
        let path = rig.cwd.join("up").join(format!("f{n}.py"));
        patch.push_str(&format!("*** Add File: {}\n+x = {n}\n+# a\n+# b\n+# c\n", path.display()));
    }
    patch.push_str("*** End Patch\n");
    let verdict = pre(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(!denied(&verdict));
    let own = rig.cwd.join("own").join("e.py");
    let loud = format!("*** Begin Patch\n*** Add File: {}\n+x = 1\n+# a\n+# b\n+# c\n*** End Patch\n", own.display());
    assert!(denied(&pre(None, None, "apply_patch", json!({ "command": loud }), Provider::Codex)));
}

#[test]
fn a_file_rewritten_with_other_line_endings_is_still_in_a_known_state() {
    let dir = temp_dir("endings");
    let state = temp_dir("endings-state");
    let path = dir.join("a.py");
    std::fs::write(&path, "x = 1\ny = 2\n").expect("write");
    let first = edit_file(Some(&state), Some("le"), &path, "x = 1", "# one\n# two\nx = 1");
    assert!(!denied(&first));
    std::fs::write(&path, "# one\r\n# two\r\nx = 1\r\ny = 2\r\n").expect("write");
    let second = edit_file(Some(&state), Some("le"), &path, "y = 2", "# three\n# four\ny = 2");
    assert!(denied(&second));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn copies_made_with_globs_dots_and_spaced_names_are_copies_too() {
    let rig = Rig::new("copy-forms");
    std::fs::create_dir_all(rig.cwd.join("vendor")).expect("dir");
    std::fs::create_dir_all(rig.cwd.join("src")).expect("dir");
    let content = format!("{}x = 1\n", lines("#", "widget", 10));
    std::fs::write(rig.cwd.join("vendor").join("a.py"), &content).expect("write");
    std::fs::write(rig.cwd.join("vendor").join("my widget.py"), &content).expect("write");
    let glob = "cp vendor/*.py src/";
    rig.pre_bash_with("cf", "t1", glob);
    std::fs::write(rig.cwd.join("src").join("a.py"), &content).expect("write");
    if !creation_time_is_known(&rig.cwd.join("src").join("a.py")) {
        return;
    }
    let first = rig.bash_with_id("cf", "t1", glob);
    assert!(first.is_empty(), "{first}");
    let spaced = "cp \"vendor/my widget.py\" \"src/my widget.py\"";
    rig.pre_bash_with("cf", "t2", spaced);
    std::fs::write(rig.cwd.join("src").join("my widget.py"), &content).expect("write");
    let second = rig.bash_with_id("cf", "t2", spaced);
    assert!(second.is_empty(), "{second}");
    let dot = "cp -r . dest";
    rig.pre_bash_with("cf", "t3", dot);
    std::fs::create_dir_all(rig.cwd.join("dest")).expect("dir");
    std::fs::write(rig.cwd.join("dest").join("copy.py"), &content).expect("write");
    let third = rig.bash_with_id("cf", "t3", dot);
    assert!(third.is_empty(), "{third}");
}

#[test]
fn blank_comment_lines_are_never_forgiven_as_a_rewrap() {
    let dir = temp_dir("blank-lines");
    let path = dir.join("a.rs");
    std::fs::write(&path, "// alpha beta gamma delta\nfn a() {}\n").expect("write");
    let blanks = format!("// alpha beta\n// gamma\n{}fn a() {{}}\n", "//\n".repeat(10));
    assert!(denied(&write_file(None, None, &path, &blanks)));
    let wrapped = "// alpha beta\n// gamma delta\nfn a() {}\n";
    assert!(!denied(&write_file(None, None, &path, wrapped)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_same_edit_judged_twice_is_not_counted_twice() {
    let dir = temp_dir("retry");
    let state = temp_dir("retry-state");
    let path = dir.join("a.py");
    std::fs::write(&path, "x = 1\n").expect("write");
    let first = edit_file(Some(&state), Some("rt"), &path, "x = 1", "# one\nx = 1");
    assert!(!denied(&first));
    let again = edit_file(Some(&state), Some("rt"), &path, "x = 1", "# one\nx = 1");
    assert!(!denied(&again));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_named_folder_or_a_spaced_file_is_refreshed_before_a_command_too() {
    let rig = Rig::new("named-folder");
    std::fs::create_dir_all(rig.cwd.join("src")).expect("dir");
    let file = rig.cwd.join("src").join("a.py");
    let spaced = rig.cwd.join("src").join("my file.py");
    for target in [&file, &spaced] {
        std::fs::write(target, "x = 1\n").expect("write");
        let first = rig.pre_edit("nf", target, "x = 1", "x = 2");
        assert!(first.is_empty(), "{first}");
    }
    let command = "black src && black \"src/my file.py\"";
    for target in [&file, &spaced] {
        std::fs::write(target, format!("{}x = 2\n", lines("#", "by hand", 4))).expect("write");
    }
    rig.pre_bash_with("nf", "t1", command);
    for target in [&file, &spaced] {
        std::fs::write(target, format!("{}x = 2\n", lines("#", "by hand", 4))).expect("write");
    }
    let out = rig.bash_with_id("nf", "t1", command);
    assert!(out.is_empty(), "{out}");
}

#[test]
fn two_hooks_running_at_the_same_time_cannot_both_use_the_whole_allowance() {
    for trial in 0..20 {
        let dir = temp_dir(&format!("overlap-{trial}"));
        let state = temp_dir(&format!("overlap-state-{trial}"));
        let path = dir.join("a.py");
        std::fs::write(&path, "x = 1\ny = 2\n").expect("write");
        let gate = std::sync::Barrier::new(2);
        let results: Vec<bool> = std::thread::scope(|scope| {
            let workers: Vec<_> = [("x = 1", "# one\n# two\nx = 1"), ("y = 2", "# three\n# four\ny = 2")]
                .into_iter()
                .map(|(old, new)| {
                    let (gate, path, state) = (&gate, &path, &state);
                    scope.spawn(move || {
                        gate.wait();
                        denied(&edit_file(Some(state), Some("ov"), path, old, new))
                    })
                })
                .collect();
            workers.into_iter().map(|worker| worker.join().expect("worker")).collect()
        });
        assert_eq!(results.iter().filter(|denied| **denied).count(), 1, "trial {trial}: {results:?}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&state);
    }
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
        .env("AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM", "0")
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

#[test]
fn a_small_copy_starts_from_its_own_comments_too() {
    let rig = Rig::new("small-copy");
    std::fs::create_dir_all(rig.cwd.join("vendor")).expect("dir");
    std::fs::create_dir_all(rig.cwd.join("src")).expect("dir");
    let content = format!("{}x = 1\n", lines("#", "widget", 2));
    std::fs::write(rig.cwd.join("vendor").join("a.py"), &content).expect("write");
    let command = "cp vendor/a.py src/a.py";
    rig.pre_bash_with("sc", "t1", command);
    let copy = rig.cwd.join("src").join("a.py");
    std::fs::write(&copy, &content).expect("write");
    if !creation_time_is_known(&copy) {
        return;
    }
    let out = rig.bash_with_id("sc", "t1", command);
    assert!(out.is_empty(), "{out}");
    let after = rig.pre_edit("sc", &copy, "x = 1", "# one more\nx = 1");
    assert!(after.is_empty(), "{after}");
}

#[test]
fn a_bare_star_and_a_redirect_do_not_hide_the_source_of_a_copy() {
    let rig = Rig::new("star-copy");
    std::fs::create_dir_all(rig.cwd.join("vendor")).expect("dir");
    std::fs::create_dir_all(rig.cwd.join("dest")).expect("dir");
    std::fs::create_dir_all(rig.cwd.join("src")).expect("dir");
    let content = format!("{}x = 1\n", lines("#", "widget", 10));
    std::fs::write(rig.cwd.join("one.py"), &content).expect("write");
    std::fs::write(rig.cwd.join("vendor").join("my widget.py"), &content).expect("write");
    let star = "cp * dest/";
    rig.pre_bash_with("st", "t1", star);
    let first = rig.cwd.join("dest").join("one.py");
    std::fs::write(&first, &content).expect("write");
    if !creation_time_is_known(&first) {
        return;
    }
    let out = rig.bash_with_id("st", "t1", star);
    assert!(out.is_empty(), "{out}");
    let quiet = "cp \"vendor/my widget.py\" \"src/my widget.py\" >/dev/null 2>&1";
    rig.pre_bash_with("st", "t2", quiet);
    std::fs::write(rig.cwd.join("src").join("my widget.py"), &content).expect("write");
    let second = rig.bash_with_id("st", "t2", quiet);
    assert!(second.is_empty(), "{second}");
}

#[test]
fn many_unchanged_files_named_by_a_command_do_not_crowd_out_the_one_it_wrote() {
    let rig = Rig::new("crowd");
    for n in 0..60 {
        std::fs::write(rig.cwd.join(format!("f{n}.py")), "x = 1\n").expect("write");
    }
    std::fs::write(rig.cwd.join("gen.py"), "x = 1\n").expect("write");
    let command = "python3 gen.py && cat f*.py";
    rig.pre_bash_with("cr", "t1", command);
    let out = rig.cwd.join("out.py");
    std::fs::write(&out, format!("{}x = 1\n", lines("#", "typed by hand", 10))).expect("write");
    if !creation_time_is_known(&out) {
        return;
    }
    let reply = rig.bash_with_id("cr", "t1", command);
    assert!(blocked(&reply), "{reply}");
}

#[test]
fn empty_comment_lines_replaced_one_for_one_are_not_new_commentary() {
    let dir = temp_dir("php-empty");
    let path = dir.join("a.php");
    std::fs::write(&path, "<?php\n#\n#\n#\n$a = 1;\n").expect("write");
    let reworded = write_file(None, None, &path, "<?php\n//\n//\n//\n$a = 1;\n");
    assert!(!denied(&reworded), "{}", reason(&reworded));
    std::fs::write(&path, "<?php\n// ----\n$a = 1;\n").expect("write");
    let ruler = write_file(None, None, &path, "<?php\n# ====\n$a = 1;\n");
    assert!(!denied(&ruler), "{}", reason(&ruler));
    std::fs::write(&path, "<?php\n// alpha beta gamma delta\n$a = 1;\n").expect("write");
    let hollow = write_file(None, None, &path, "<?php\n//\n//\n//\n$a = 1;\n");
    assert!(!denied(&hollow), "{}", reason(&hollow));
    let padded = write_file(None, None, &path, "<?php\n//\n//\n//\n//\n$a = 1;\n");
    assert!(denied(&padded));
    std::fs::write(&path, "<?php\n// release note\n$a = 1;\n").expect("write");
    let emptied = write_file(None, None, &path, "<?php\n//\n//\n//\n$a = 1;\n");
    assert!(!denied(&emptied), "{}", reason(&emptied));
    std::fs::write(&path, "<?php\n// 1.\n// 2.\n// 3.\n$a = 1;\n").expect("write");
    let dotted = write_file(None, None, &path, "<?php\n// ...\n// ...\n// ...\n$a = 1;\n");
    assert!(!denied(&dotted), "{}", reason(&dotted));
    std::fs::write(&path, "<?php\n// ----\n$a = 1;\n").expect("write");
    let titled = write_file(None, None, &path, "<?php\n// Parsing helpers\n$a = 1;\n");
    assert!(!denied(&titled), "{}", reason(&titled));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn html_delimiter_lines_are_not_letters_that_a_rewrap_could_hide() {
    let dir = temp_dir("html-delims");
    let path = dir.join("page.html");
    std::fs::write(&path, "<!-- ab -->\n<p>hi</p>\n").expect("write");
    let hollow = write_file(None, None, &path, "<!--\n-->\n<!--\n-->\n<p>hi</p>\n");
    assert!(denied(&hollow));
    let plain = write_file(None, None, &path, "<!-- ab -->\n<p>hi there</p>\n");
    assert!(!denied(&plain));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_comment_split_into_thin_lines_is_not_a_rewrap() {
    let dir = temp_dir("thin-lines");
    let path = dir.join("a.rs");
    std::fs::write(&path, "// hello\nfn a() {}\n").expect("write");
    let padded = "// h ----\n// e ----\n// l ----\n// l ----\n// o ----\nfn a() {}\n";
    assert!(denied(&write_file(None, None, &path, padded)));
    let letters = "// h\n// e\n// l\n// l\n// o\nfn a() {}\n";
    assert!(denied(&write_file(None, None, &path, letters)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_few_thin_lines_beside_a_full_line_are_not_a_rewrap_either() {
    let dir = temp_dir("thin-tail");
    let path = dir.join("a.py");
    std::fs::write(&path, "# The parser keeps the original token boundaries intact today\nx = 1\n").expect("write");
    let split = "# The parser keeps the original token boundaries intact to\n# d\n# a\n# y\nx = 1\n";
    assert!(denied(&write_file(None, None, &path, split)));
    let cjk = "# \u{8fd9}\u{4e2a}\u{6a21}\u{5757}\u{89e3}\u{6790}\u{8bf7}\u{6c42}\u{8def}\u{5f84}\u{5e76}\u{89c4}\u{8303}\u{5316}\u{67e5}\u{8be2}\u{53c2}\u{6570}\u{7136}\u{540e}\u{8def}\u{7531}\nx = 1\n";
    std::fs::write(&path, cjk).expect("write");
    let pieces = "# \u{8fd9}\u{4e2a}\u{6a21}\u{5757}\u{89e3}\u{6790}\u{8bf7}\u{6c42}\u{8def}\u{5f84}\u{5e76}\u{89c4}\u{8303}\u{5316}\u{67e5}\u{8be2}\n# \u{53c2}\n# \u{6570}\n# \u{7136}\n# \u{540e}\n# \u{8def}\u{7531}\nx = 1\n";
    assert!(denied(&write_file(None, None, &path, pieces)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replacing_long_comments_with_shorter_ones_and_reflowing_stay_free() {
    let dir = temp_dir("short-swap");
    let path = dir.join("a.py");
    let long = "# this function walks the whole tree and collects every matching entry\n# it stops early when the caller asks it to stop walking\n# the result is sorted before it is returned to the caller\nx = 1\n";
    std::fs::write(&path, long).expect("write");
    let short = "# walks the tree\n# stops early\n# sorted\nx = 1\n";
    assert!(!denied(&write_file(None, None, &path, short)));
    std::fs::write(&path, "# this function walks the whole tree and collects every matching entry it stops early\nx = 1\n").expect("write");
    let reflowed = "# this function walks the whole tree and\n# collects every matching entry it stops\n# early\nx = 1\n";
    assert!(!denied(&write_file(None, None, &path, reflowed)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn removed_thin_lines_never_pay_for_padding_lines() {
    let dir = temp_dir("thin-pay");
    let path = dir.join("a.py");
    let fat = ["restore the cached"; 9].join(" ");
    std::fs::write(&path, format!("# {fat}\n# a\n# b\n# c\nx = 1\n")).expect("write");
    let padded = format!("{}# d\n# e\n# f\nx = 1\n", "# restore the cached\n".repeat(9));
    assert!(denied(&write_file(None, None, &path, &padded)));
    let reused = format!("{}# a\n# b\n# c\nx = 1\n", "# restore the cached\n".repeat(9));
    assert!(denied(&write_file(None, None, &path, &reused)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn one_sentence_per_line_is_a_rewrap_of_the_same_words() {
    let dir = temp_dir("sentences");
    let path = dir.join("a.rs");
    std::fs::write(&path, "/// Returns the root. See also Item. On success, Ok. Never panics.\nfn a() {}\n").expect("write");
    let split = "/// Returns the root.\n/// See also Item.\n/// On success, Ok.\n/// Never panics.\nfn a() {}\n";
    assert!(!denied(&write_file(None, None, &path, split)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_long_comment_is_not_swapped_for_many_lines_of_other_words() {
    let dir = temp_dir("other-words");
    let path = dir.join("a.py");
    let nato = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu";
    std::fs::write(&path, format!("# {nato} {nato}\nx = 1\n")).expect("write");
    let other = format!("{}x = 1\n", "# zebra yak xerus wolf vole urchin tapir\n".repeat(6));
    assert!(denied(&write_file(None, None, &path, &other)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rewrap_may_not_repeat_a_word_more_often_than_the_comment_it_replaced() {
    let dir = temp_dir("word-count");
    let path = dir.join("a.py");
    std::fs::write(&path, "# internationalization internationalization\nx = 1\n").expect("write");
    let again = format!("{}x = 1\n", "# internationalization\n".repeat(4));
    assert!(denied(&write_file(None, None, &path, &again)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn identical_removed_lines_each_lend_their_words() {
    let dir = temp_dir("word-twice");
    let path = dir.join("a.py");
    std::fs::write(&path, "# reconsideration of everything\n# reconsideration of everything\nx = 1\n").expect("write");
    let split = "# reconsideration\n# of\n# everything\n# reconsideration\n# of everything\nx = 1\n";
    assert!(!denied(&write_file(None, None, &path, split)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn build_scripting_and_markup_files_are_checked() {
    let dir = temp_dir("kinds");
    let kinds = [
        ("s6.ps1", "# ", "", "$a = 1\n"),
        ("m.psm1", "# ", "", "$a = 1\n"),
        ("main.tf", "# ", "", "variable \"a\" {}\n"),
        ("x.hcl", "// ", "", "a = 1\n"),
        ("Makefile", "# ", "", "all:\n\techo hi\n"),
        ("sub.mk", "# ", "", "all:\n\techo hi\n"),
        ("Dockerfile", "# ", "", "FROM scratch\n"),
        ("Dockerfile.dev", "# ", "", "FROM scratch\n"),
        ("a.dockerfile", "# ", "", "FROM scratch\n"),
        ("s14.bat", "REM ", "", "echo hi\n"),
        ("s15.cmd", ":: ", "", "echo hi\n"),
        ("s16.vbs", "' ", "", "x = 1\n"),
        ("a.vb", "REM ", "", "x = 1\n"),
        ("a.clj", "; ", "", "(def a 1)\n"),
        ("a.el", ";; ", "", "(setq a 1)\n"),
        ("a.asm", "; ", "", "nop\n"),
        ("a.erl", "% ", "", "a() -> ok.\n"),
        ("a.ml", "(* ", " *)", "let a = 1\n"),
        ("a.fs", "// ", "", "let a = 1\n"),
        ("a.adb", "-- ", "", "null;\n"),
        ("a.f90", "! ", "", "end\n"),
        ("a.nix", "# ", "", "{ }\n"),
        ("a.jl", "# ", "", "a = 1\n"),
        ("a.cmake", "# ", "", "set(A 1)\n"),
        ("a.bzl", "# ", "", "A = 1\n"),
        ("BUILD", "# ", "", "A = 1\n"),
        ("Jenkinsfile", "// ", "", "pipeline {}\n"),
        ("Gemfile", "# ", "", "source 'x'\n"),
        ("a.rake", "# ", "", "task :a\n"),
        ("a.svg", "<!-- ", " -->", "<svg></svg>\n"),
        ("a.erb", "<%# ", " %>", "<p></p>\n"),
        ("a.j2", "{# ", " #}", "<p></p>\n"),
        ("a.hbs", "{{! ", " }}", "<p></p>\n"),
        ("a.cshtml", "@* ", " *@", "<p></p>\n"),
        ("a.pug", "// ", "", "p hi\n"),
        ("a.thrift", "# ", "", "struct A {}\n"),
        ("a.v", "// ", "", "module a; endmodule\n"),
        ("a.glsl", "// ", "", "void main() {}\n"),
        ("a.mts", "// ", "", "export const a = 1;\n"),
        (".zshrc", "# ", "", "alias a=b\n"),
    ];
    for (name, open, close, code) in kinds {
        let path = dir.join(name);
        let four: String = (1..=4).map(|n| format!("{open}note {n}{close}\n")).collect();
        let two: String = (1..=2).map(|n| format!("{open}note {n}{close}\n")).collect();
        assert!(denied(&write_file(None, None, &path, &format!("{four}{code}"))), "four lines in {name}");
        assert!(!denied(&write_file(None, None, &path, &format!("{two}{code}"))), "two lines in {name}");
        assert!(!denied(&write_file(None, None, &path, code)), "code only in {name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_formatter_run_over_a_folder_does_not_blame_comments_that_were_already_there() {
    let rig = Rig::new("shape-format");
    init_repo(&rig.cwd);
    std::fs::create_dir_all(rig.cwd.join("src")).expect("folder");
    let file = commit_file(&rig.cwd, "src/a.py", "x = 1\n");
    let text = "# mine 1\n# mine 2\n# mine 3\n# mine 4\nx = 1\n";
    std::fs::write(&file, text).expect("write");
    let out = wrote_four_after(&rig, "f1", "black src", &file, text);
    assert!(out.is_empty(), "{out}");
}

#[test]
fn a_command_that_only_looks_at_another_folder_does_not_report_a_file_saved_there() {
    let rig = Rig::new("shape-look");
    let other = temp_dir("shape-look-other");
    let file = other.join("a.py");
    let text = "x = 1\n# note 1\n# note 2\n# note 3\n# note 4\n";
    let out = wrote_four_after(&rig, "l1", &format!("ls {}", other.display()), &file, text);
    assert!(out.is_empty(), "{out}");
    let written = other.join("b.py");
    let more = "y = 1\n# memo 1\n# memo 2\n# memo 3\n# memo 4\n";
    let out = wrote_four_after(&rig, "l2", &format!("printf x > {}/b.py; ls {}", other.display(), other.display()), &written, more);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let _ = std::fs::remove_dir_all(&other);
}

#[test]
fn a_script_without_an_extension_is_found_by_the_bash_check() {
    let rig = Rig::new("shape-shebang");
    let file = rig.cwd.join("tool");
    let text = "#!/bin/sh\n# note 1\n# note 2\n# note 3\n# note 4\necho hi\n";
    let out = wrote_four_after(&rig, "s1", &format!("printf x > {}", file.display()), &file, text);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let notes = rig.cwd.join("notes");
    let plain = "# note 1\n# note 2\n# note 3\n# note 4\nx\n";
    let quiet = wrote_four_after(&rig, "s2", &format!("printf x > {}", notes.display()), &notes, plain);
    assert!(quiet.is_empty(), "{quiet}");
}

#[test]
fn comment_forms_of_the_less_common_languages_are_all_seen() {
    let dir = temp_dir("exotic");
    let hidden = [
        ("a.cmake", "#[==[\nnote one\nnote two\nnote three\nnote four\n]==]\nset(A 1)\n"),
        ("b.cmake", "#[====[\nnote one\nnote two\nnote three\nnote four\n]====]\nset(A 1)\n"),
        ("a.pug", "//\n  note one\n  note two\n  note three\n  note four\np hi\n"),
        ("a.lean", "/-\nnote one\nnote two\nnote three\nnote four\n-/\ndef a := 1\n"),
        ("a.d", "/+\nnote one\nnote two\nnote three\nnote four\n+/\nvoid main() {}\n"),
        ("a.ml", "(*\n\"*)\nnote one\nnote two\nnote three\nnote four\n\"\n*)\nlet x = 1\n"),
        ("a.fs", "(*\n\"*)\nnote one\nnote two\nnote three\nnote four\n\"\n*)\nlet x = 1\n"),
        ("a.ps1", "$a++# note one\n$b++# note two\n$c++# note three\n$d++# note four\n"),
        ("Makefile", "A:=1# note one\nB:=2# note two\nC:=3# note three\nD:=4# note four\n"),
        ("a.bat", "echo 1 & rem note one\necho 2 & rem note two\necho 3 & :: note three\necho 4 & REM note four\n"),
        ("a.idr", "||| note one\n||| note two\n||| note three\n||| note four\n"),
        ("a.f90", "! note one\n! note two\n! note three\n! note four\nend\n"),
        ("a.pas", "{ note one }\n{ note two }\n{ note three }\n{ note four }\nbegin end.\n"),
        ("b.pas", "{$MESSAGE 'note one explain the cache'}\n{$MESSAGE 'note two explain the lock'}\n{$MESSAGE 'note three explain the retry'}\n{$MESSAGE 'note four explain the fallback'}\n"),
        ("c.cmake", "#[=====[\nnote one\nnote two\nnote three\nnote four\n]=====]\nset(A 1)\n"),
        ("d.cmake", "#[============[\nnote one\nnote two\nnote three\nnote four\n]============]\nset(A 1)\n"),
        ("e.cmake", "#[[\nnote one\nnote two\nnote three\nnote four\n]]\nset(A 1)\n"),
        ("f.cmake", "#[===[\nnote one\nnote two\nnote three\nnote four\n]===]\nset(A 1)\n"),
        ("a.lua", "--[==[\nnote one\nnote two\nnote three\nnote four\n]==]\nlocal a = 1\n"),
        ("b.lua", "--[=====[\nnote one\nnote two\nnote three\nnote four\n]=====]\nlocal a = 1\n"),
        ("b.bat", "@:: note one\n@:: note two\necho 3 & @:: note three\necho 4 & @:: note four\n"),
        ("b.f90", "!$ note one explain the cache\n!$ note two explain the lock\n!a$ note three explain the retry\n!x$ note four\nend\n"),
        ("d.f90", "!$ call note one explain the cache\n!$ if note two explain the lock\n!$ do note three explain the retry\n!$ end note four explain the fallback\nend\n"),
        ("c.pas", "{$R * note one explain the cache}\n{$R * note two explain the lock}\n{$R * note three explain the retry}\n{$R * note four explain the fallback}\nbegin end.\n"),
        ("b.ps1", "$a = 1 \\# note one\n$b = 2 \\# note two\n$c = 3 \\# note three\n$d = 4 \\# note four\n"),
    ];
    for (name, text) in hidden {
        let path = dir.join(name);
        assert!(denied(&write_file(None, None, &path, text)), "{name} hid its comments");
    }
    let plain = [
        ("a.f90", "!$OMP PARALLEL\n!$OMP DO\n!$OMP END DO\n!$OMP END PARALLEL\nend\n"),
        ("a.erl", "a() -> '100% one'.\nb() -> '100% two'.\nc() -> '100% three'.\nd() -> '100% four'.\n"),
        ("a.jsonnet", "local a = '# note one';\nlocal b = '# note two';\nlocal c = '# note three';\nlocal d = '# note four';\n"),
        ("a.pas", "{$MODE OBJFPC}\n{$H+}\n{$IFDEF UNIX}\n{$ENDIF}\nbegin end.\n"),
        ("a.pug", "p one\np two\n  span three\np four\n"),
        ("b.pas", "(*$MODE OBJFPC*)\n(*$H+*)\n(*$IFDEF UNIX*)\n(*$ENDIF*)\nbegin end.\n"),
        ("c.f90", "!dir$ IVDEP\n!DEC$ ATTRIBUTES DLLEXPORT :: a\n!$ call omp_set_num_threads(4)\n!$ use omp_lib\nend\n"),
        ("a.ps1", "Write-Host `# note one\nWrite-Host `# note two\n$a = \"say `\"# note three\"\n$b = \"say `\"# note four\"\n"),
        ("c.ps1", "Write-Host `# note one\nWrite-Host `# note two\nWrite-Host `# note three\nWrite-Host `# note four\n"),
        ("e.f90", "!$ subroutine note_one\n!$ function note_two()\n!$ module note_three\n!$ type note_four\nend\n"),
        ("a.lua", "local a = \"--[==[ one\"\nlocal b = \"--[==[ two\"\nlocal c = 3\n"),
        ("a.ml", "let a = \"(* one *)\"\nlet b = \"(* two *)\"\nlet c = \"(* three *)\"\n"),
    ];
    for (name, text) in plain {
        let path = dir.join(name);
        assert!(!denied(&write_file(None, None, &path, text)), "{name} was refused");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_script_without_an_extension_is_judged_by_its_first_line() {
    let dir = temp_dir("shebang");
    let four = "# note 1\n# note 2\n# note 3\n# note 4\n";
    for line in ["#!/usr/bin/env bash", "#!/bin/sh", "#!/usr/bin/env python3", "#!/usr/bin/perl"] {
        let path = dir.join("tool");
        assert!(denied(&write_file(None, None, &path, &format!("{line}\n{four}echo hi\n"))), "{line}");
        assert!(!denied(&write_file(None, None, &path, &format!("{line}\necho hi\n"))), "{line}");
    }
    let slashes = "// note 1\n// note 2\n// note 3\n// note 4\n";
    let node = dir.join("serve");
    assert!(denied(&write_file(None, None, &node, &format!("#!/usr/bin/env -S node\n{slashes}run();\n"))));
    let notes = dir.join("notes");
    assert!(!denied(&write_file(None, None, &notes, &format!("{four}x\n"))));
    let config = dir.join("settings.ini");
    assert!(!denied(&write_file(None, None, &config, &format!("{four}[a]\nb = 1\n"))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_powershell_block_comment_counts_every_line() {
    let dir = temp_dir("ps-block");
    let path = dir.join("a.ps1");
    let block = "<#\nnote one\nnote two\nnote three\n#>\n$a = 1\n";
    assert!(denied(&write_file(None, None, &path, block)));
    let _ = std::fs::remove_dir_all(&dir);
}

fn wrote_four_after(rig: &Rig, id: &str, command: &str, file: &Path, text: &str) -> String {
    rig.pre_bash_with("shape", id, command);
    std::fs::write(file, text).expect("write");
    rig.bash_with_id("shape", id, command)
}

#[test]
fn a_command_that_writes_outside_the_project_through_a_variable_is_reported() {
    let rig = Rig::new("shape-var");
    let scratch = temp_dir("shape-var-scratch");
    let four = "x = 1\n# note 1\n# note 2\n# note 3\n# note 4\n";
    let file = scratch.join("b.py");
    let command = format!("S={}; printf x > \"$S/b.py\"", scratch.display());
    let out = wrote_four_after(&rig, "v1", &command, &file, four);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let braces = scratch.join("c.py");
    let command = format!("D={}\nprintf x > ${{D}}/c.py", scratch.display());
    let other = "y = 1\n# memo 1\n# memo 2\n# memo 3\n# memo 4\n";
    let out = wrote_four_after(&rig, "v2", &command, &braces, other);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let hidden = scratch.join("q.py");
    let command = format!("D={}\nprintf x > \"$(dirname $D/z)/q.py\"", scratch.display());
    let third = "z = 1\n# memo 5\n# memo 6\n# memo 7\n# memo 8\n";
    let out = wrote_four_after(&rig, "v3", &command, &hidden, third);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn a_command_that_changes_folder_first_is_reported() {
    let rig = Rig::new("shape-cd");
    let scratch = temp_dir("shape-cd-scratch");
    let four = "x = 1\n# note 1\n# note 2\n# note 3\n# note 4\n";
    let file = scratch.join("e.py");
    let command = format!("cd {} && printf x > e.py", scratch.display());
    let out = wrote_four_after(&rig, "c1", &command, &file, four);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn an_existing_file_that_a_command_edits_is_judged_from_what_it_held_before() {
    let rig = Rig::new("shape-existing");
    let scratch = temp_dir("shape-existing-scratch");
    let file = scratch.join("g.py");
    std::fs::write(&file, "x = 1\n# old 1\n# old 2\n# old 3\ny = 2\n").expect("write");
    let command = format!("sed -i '' '1i x' {}", file.display());
    let four = "x = 1\n# old 1\n# old 2\n# old 3\n# note 1\n# note 2\n# note 3\ny = 2\n";
    let out = wrote_four_after(&rig, "e1", &command, &file, four);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let same = scratch.join("h.py");
    std::fs::write(&same, "x = 1\n# old 1\n# old 2\n# old 3\ny = 2\n").expect("write");
    let command = format!("sed -i '' 's/x = 1/x = 2/' {}", same.display());
    let swapped = "x = 2\n# old 1\n# old 2\n# old 3\ny = 2\n";
    let quiet = wrote_four_after(&rig, "e2", &command, &same, swapped);
    assert!(quiet.is_empty(), "{quiet}");
    let moved = scratch.join("m.py");
    std::fs::write(&moved, "x = 1\n# old 1\ny = 2\n").expect("write");
    let command = format!("cd {} && sed -i '' '1i x' m.py", scratch.display());
    let text = "x = 1\n# old 1\n# new 1\n# new 2\n# new 3\ny = 2\n";
    let out = wrote_four_after(&rig, "e3", &command, &moved, text);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let named = scratch.join("n.py");
    std::fs::write(&named, "x = 1\n# old 1\ny = 2\n").expect("write");
    let command = format!("S={}; sed -i '' '1i x' \"$S/n.py\"", scratch.display());
    let text = "x = 1\n# old 1\n# new 4\n# new 5\n# new 6\ny = 2\n";
    let out = wrote_four_after(&rig, "e4", &command, &named, text);
    assert!(out.contains("\"decision\":\"block\""), "{out}");
    let _ = std::fs::remove_dir_all(&scratch);
}

fn notebook_of(cells: &[(&str, &str)]) -> String {
    let items: Vec<Value> = cells
        .iter()
        .enumerate()
        .map(|(n, (kind, source))| json!({ "cell_type": kind, "metadata": {}, "source": source, "id": format!("c{n}") }))
        .collect();
    json!({ "cells": items, "metadata": {}, "nbformat": 4, "nbformat_minor": 5 }).to_string()
}

fn notebook_edit(state: Option<&Path>, session: Option<&str>, path: &Path, input: Value) -> Verdict {
    let mut input = input;
    if let Some(map) = input.as_object_mut() {
        map.insert("notebook_path".to_owned(), json!(path.to_string_lossy()));
    }
    pre(state, session, "NotebookEdit", input, Provider::Claude)
}

#[test]
fn a_notebook_edit_is_judged_by_the_code_it_leaves() {
    let dir = temp_dir("notebook");
    let path = dir.join("nb.ipynb");
    std::fs::write(&path, notebook_of(&[("code", "x = 1"), ("markdown", "# title")])).expect("write");
    let four = "# note 1\n# note 2\n# note 3\n# note 4\ny = 2";
    let inserted = json!({ "new_source": four, "cell_type": "code", "edit_mode": "insert", "cell_id": "c0" });
    assert!(denied(&notebook_edit(None, None, &path, inserted)));
    let two = json!({ "new_source": "# note 1\n# note 2\ny = 2", "cell_type": "code", "edit_mode": "insert" });
    assert!(!denied(&notebook_edit(None, None, &path, two)));
    let replaced = json!({ "new_source": four, "cell_id": "c0" });
    assert!(denied(&notebook_edit(None, None, &path, replaced)));
    let numbered = json!({ "new_source": four, "cell_id": "cell-0" });
    assert!(denied(&notebook_edit(None, None, &path, numbered)));
    let unknown = json!({ "new_source": four, "cell_id": "missing-0" });
    assert!(!denied(&notebook_edit(None, None, &path, unknown)));
    let prose = json!({ "new_source": "# a\n# b\n# c\n# d", "cell_type": "markdown", "edit_mode": "insert" });
    assert!(!denied(&notebook_edit(None, None, &path, prose)));
    let removed = json!({ "edit_mode": "delete", "cell_id": "c0" });
    assert!(!denied(&notebook_edit(None, None, &path, removed)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_notebook_written_or_edited_as_a_file_is_judged_by_its_code_cells() {
    let dir = temp_dir("notebook-file");
    let path = dir.join("nb.ipynb");
    let commented = notebook_of(&[("code", "# note 1\n# note 2\n# note 3\n# note 4\ny = 2")]);
    assert!(denied(&write_file(None, None, &path, &commented)));
    let markdown = notebook_of(&[("markdown", "# a\n# b\n# c\n# d"), ("code", "y = 2")]);
    assert!(!denied(&write_file(None, None, &path, &markdown)));
    std::fs::write(&path, notebook_of(&[("code", "y = 2")])).expect("write");
    let old = "\"source\":\"y = 2\"";
    let new = "\"source\":\"# note 1\\n# note 2\\n# note 3\\n# note 4\\ny = 2\"";
    assert!(denied(&edit_file(None, None, &path, old, new)));
    let _ = std::fs::remove_dir_all(&dir);
}

fn trimming(state: Option<&Path>, session: Option<&str>, tool: &str, input: Value, provider: Provider) -> Verdict {
    let mut payload = json!({ "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input });
    if let (Some(id), Some(map)) = (session, payload.as_object_mut()) {
        map.insert("session_id".to_owned(), json!(id));
    }
    judge_trimming_in(&payload.to_string(), provider, state)
}

fn cut(verdict: Verdict) -> (Value, String) {
    match verdict {
        Verdict::Trimmed { input, note } => (input, note),
        Verdict::Allow => panic!("allowed unchanged"),
        Verdict::Deny(reason) => panic!("denied: {reason}"),
        Verdict::BadInput => panic!("bad input"),
    }
}

fn written(path: &Path, content: &str) -> Value {
    json!({ "file_path": path.to_string_lossy(), "content": content })
}

#[test]
fn a_write_with_too_many_comments_is_written_without_the_extra_ones() {
    let dir = temp_dir("trim-write");
    let path = dir.join("a.py");
    let text = "# a1\n# a2\n# a3\n# a4\n# a5\nx = 1\ny = 2\n";
    let (input, note) = cut(trimming(None, None, "Write", written(&path, text), Provider::Claude));
    assert_eq!(input["content"], "# a1\n# a2\nx = 1\ny = 2\n");
    assert_eq!(input["file_path"], path.to_string_lossy().as_ref());
    assert!(note.contains("3 new comment line(s)") && note.contains("# a3") && note.contains("# a5"), "{note}");
    let apart = "# a1\nx = 1\n# a2\ny = 2\n# a3\nz = 3\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&path, apart), Provider::Claude));
    assert_eq!(input["content"], "# a1\nx = 1\ny = 2\nz = 3\n");
    let noisy = "# added on 2024-01-01 for the cache\n# ok one\n# ok two\n# ok three\nx = 1\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&path, noisy), Provider::Claude));
    assert_eq!(input["content"], "# ok one\n# ok two\nx = 1\n");
    let allowed = "# a1\n# a2\nx = 1\n";
    assert!(matches!(trimming(None, None, "Write", written(&path, allowed), Provider::Claude), Verdict::Allow));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_edit_with_too_many_comments_is_trimmed_inside_its_replacement() {
    let dir = temp_dir("trim-edit");
    let path = dir.join("a.py");
    std::fs::write(&path, "x = 1\ny = 2\nz = 3\n").expect("write");
    let at_end = json!({ "file_path": path.to_string_lossy(), "old_string": "y = 2", "new_string": "y = 2\n# n1\n# n2\n# n3\n# n4" });
    let (input, _) = cut(trimming(None, None, "Edit", at_end, Provider::Claude));
    assert_eq!(input["new_string"], "y = 2\n# n1\n# n2");
    let at_start = json!({ "file_path": path.to_string_lossy(), "old_string": "x = 1", "new_string": "# n1\n# n2\n# n3\n# n4\nx = 2" });
    let (input, _) = cut(trimming(None, None, "Edit", at_start, Provider::Claude));
    assert_eq!(input["new_string"], "# n1\n# n2\nx = 2");
    let middle = json!({ "file_path": path.to_string_lossy(), "old_string": "y = 2\n", "new_string": "# n1\ny = 3\n# n2\n# n3\n" });
    let (input, _) = cut(trimming(None, None, "Edit", middle, Provider::Claude));
    assert_eq!(input["new_string"], "# n1\ny = 3\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn comments_that_cannot_be_cut_safely_are_still_refused() {
    let dir = temp_dir("trim-refuse");
    let refuse = |name: &str, text: &str| {
        let verdict = trimming(None, None, "Write", written(&dir.join(name), text), Provider::Claude);
        assert!(matches!(verdict, Verdict::Deny(_)), "{name} was trimmed or allowed");
    };
    refuse("a.py", "def f():\n    \"\"\"\n    one\n    two\n    three\n    four\n    \"\"\"\n    return 1\n");
    refuse("b.py", "a = 1  # one\nb = 2  # two\nc = 3  # three\nd = 4  # four\n");
    refuse("c.c", "/*\none\ntwo\nthree\nfour\n*/\nint a;\n");
    refuse("d.html", "// one\n// two\n// three\n// four\n<p>hi</p>\n");
    refuse("e.sh", "cat <<EOF\n# one\n# two\n# three\n# four\nEOF\n");
    refuse("f.rs", "let s = r#\"\n// one\n// two\n// three\n// four\n\"#;\n");
    refuse("g.sh", "echo 'a\n# one\n# two\n# three\n# four\n'\n");
    refuse("h.c", "// one \\\n// two\n// three\n// four\nint a;\n");
    refuse("i.py", "x = 1  # a\ny = 2  # b\nz = 3  # c\n# one\n# two\n# three\n# four\n");
    refuse("j.go", "// #include <stdio.h>\n// one\n// two\n// three\nimport \"C\"\n");
    refuse("k.pug", "//\n  one\n  two\n  three\n  four\np hi\n");
    refuse("e1.js", "const s = `outer ${`inner\n// one\n// two\n// three\n// four\n`} tail`\nconst x = 1\n");
    refuse("e2.jsx", "export function F() {\n  return (\n    <pre>\n// one\n// two\n// three\n// four\n    </pre>\n  );\n}\n");
    refuse("e2.tsx", "export const F = () => (\n  <pre>\n// one\n// two\n// three\n// four\n  </pre>\n);\n");
    refuse("e3.cs", "var s = @$\"hello \\\"\"\n// one\n// two\n// three\n// four\n\\\"\";\nint x = 1;\n");
    refuse("e4.rs", "fn main() {\n    let s = cr##\" \"\n// one\n// two\n// three\n// four\n\"\"##;\n    let x = 1;\n}\n");
    refuse("e5.rb", "r = /\n# one\n# two\n# three\n# four\n/\nx = 1\n");
    refuse("e6.rb", "s = %q@\n# one\n# two\n# three\n# four\n@\nx = 1\n");
    refuse("e7.groovy", "def s = $/\n// one\n// two\n// three\n// four\n/$\ndef x = 1\n");
    refuse("e8.php", "<?php\necho 1;\n?>\n// one\n// two\n// three\n// four\n<?php\n$x = 1;\n");
    refuse("Dockerfile", "# syntax=docker/dockerfile:1\nFROM alpine # one\nRUN echo x # two\n");
    refuse("e10.rb", "# frozen_string_literal: true\nx = 1 # one\ny = 2 # two\n");
    refuse("e11.ps1", "#requires -Version 7\nGet-Date # one\nGet-Date # two\n");
    refuse("e12.scala", "val page = <pre>\n// one\n// two\n// three\n// four\n</pre>\nval x = 1\n");
    refuse("e13.rb", "__END__\n# one\n# two\n# three\n# four\n");
    refuse("first.py", "# mode: strict\nx = 1  # one\ny = 2  # two\n");
    refuse("x.nix", "s = ''\n# one\n# two\n# three\n# four\n'';\nx = 1\n");
    refuse("a.rb", "list = %w(\n# one\n# two\n# three\n# four\n)\nx = 1\n");
    refuse("b.rb", "text = %q{\n# one\n# two\n# three\n# four\n}\nx = 1\n");
    refuse("a.pl", "my $s = q{\n# one\n# two\n# three\n# four\n};\nmy $x = 1;\n");
    refuse("a.lua", "local s = [==[\n-- one\n-- two\n-- three\n-- four\n]==]\nlocal x = 1\n");
    refuse("b.lua", "local s = [[\n-- one\n-- two\n-- three\n-- four\n]]\nlocal x = 1\n");
    refuse("g.rs", "fn main() {\n    let s = r##\" \"\n// one\n// two\n// three\n// four\n\"##;\n    let x = 1;\n}\n");
    refuse("h.rs", "fn main() {\n    let s = r#\"x\" ;\n// one\n// two\n// three\n// four\na\"b\"#;\n    let x = 1;\n}\n");
    refuse("a.ex", "s = ~s(\n# one\n# two\n# three\n# four\n)\nx = 1\n");
    refuse("a.tcl", "set s {\n# one\n# two\n# three\n# four\n}\nset x 1\n");
    refuse("a.jsonnet", "local s = |||\n# one\n# two\n# three\n# four\n|||;\nlocal x = 1;\n");
    refuse("a.sql", "create function f() returns int as $$\n-- one\n-- two\n-- three\n-- four\nselect 1; $$ language sql;\n");
    refuse("Makefile", "define text\n# one\n# two\n# three\n# four\nendef\nall:\n\techo hi\n");
    refuse("a.ps1", "$s = @\"\n# one\n# two\n# three\n# four\n\"@\n$x = 1\n");
    refuse("l.sql", "/*+ one */\n/*+ two */\n/*+ three */\n/*+ four */\nselect 1;\n");
    refuse("m.html", "<!--[if IE]>\n<!--[if gt IE 8]>\n<!--[if lt IE 7]>\n<!--[if IE 9]>\n<p>hi</p>\n");
    refuse("r.cpp", "const char* s = R\"(\n// one\n// two\n// three\n// four\n)\";\nint x = 1;\n");
    refuse("r.h", "NSString *s = @\"x\";\n// one\n// two\n// three\n// four\nint x = 1;\n");
    refuse("Containerfile", "FROM alpine\n# one\n# two\n# three\n# four\nRUN echo x\n");
    refuse("justfile", "build:\n  echo hi\n# one\n# two\n# three\n# four\n");
    refuse("p.css", "/*! one */\n/*! two */\n/*! three */\n/*! four */\na { b: c }\n");
    refuse("q.css", "/*# one */\n/*# two */\n/*# three */\n/*# four */\na { b: c }\n");
    let css = "/* one */\n/* two */\n/* three */\n/* four */\na { b: c }\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("n.css"), css), Provider::Claude));
    assert_eq!(input["content"], "/* one */\n/* two */\na { b: c }\n");
    refuse("o.html", "<!-- one -->\n<!-- two -->\n<!-- three -->\n<p>hi</p>\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_languages_on_the_list_are_trimmed_and_their_directives_are_kept() {
    let dir = temp_dir("trim-list");
    let lines = |marker: &str| -> String { (1..=4).map(|n| format!("{marker} note {n}\n")).collect() };
    let cases = [
        ("a.kt", "//", "fun f() {}\n"),
        ("a.swift", "//", "func f() {}\n"),
        ("a.ts", "//", "export const x = 1;\n"),
        ("a.go", "//", "package a\n"),
        ("a.c", "//", "int a;\n"),
        ("a.java", "//", "class A {}\n"),
        ("a.sh", "#", "echo hi\n"),
        ("a.scss", "//", "a { b: c }\n"),
        ("a.rs", "//", "fn f() {}\n"),
    ];
    for (name, marker, code) in cases {
        let text = format!("{}{}", lines(marker), code);
        let (input, _) = cut(trimming(None, None, "Write", written(&dir.join(name), &text), Provider::Claude));
        let expected = format!("{marker} note 1\n{marker} note 2\n{code}");
        assert_eq!(input["content"], expected.as_str(), "{name}");
    }
    let python = "# coding: utf-8\nx = 1  # one\ny = 2  # two\nz = 3  # three\n";
    assert!(matches!(trimming(None, None, "Write", written(&dir.join("c.py"), python), Provider::Claude), Verdict::Deny(_)));
    let cookie = "# coding: utf-8\n# one\n# two\nx = 1\n";
    assert!(matches!(trimming(None, None, "Write", written(&dir.join("d.py"), cookie), Provider::Claude), Verdict::Allow));
    let source_map = "x = 1;\n//# sourceMappingURL=a.js.map\n// one\n// two\n";
    assert!(matches!(trimming(None, None, "Write", written(&dir.join("d.js"), source_map), Provider::Claude), Verdict::Allow));
    let reference = "/// <reference types=\"node\" />\n// a\n// b\n// c\n// d\nexport {};\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("r.ts"), reference), Provider::Claude));
    assert_eq!(input["content"], "/// <reference types=\"node\" />\n// a\n// b\nexport {};\n");
    let map = "a { b: c }\n/*# sourceMappingURL=a.css.map */\n/* one */\n/* two */\n/* three */\n/* four */\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("m.css"), map), Provider::Claude));
    assert_eq!(input["content"], "a { b: c }\n/*# sourceMappingURL=a.css.map */\n/* one */\n/* two */\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn what_the_eighteenth_review_found_is_refused_or_kept() {
    let dir = temp_dir("trim-eighteen");
    let refuse = |name: &str, text: &str| {
        let verdict = trimming(None, None, "Write", written(&dir.join(name), text), Provider::Claude);
        assert!(matches!(verdict, Verdict::Deny(_)), "{name} was trimmed or allowed");
    };
    let allow = |name: &str, text: &str| {
        let verdict = trimming(None, None, "Write", written(&dir.join(name), text), Provider::Claude);
        assert!(matches!(verdict, Verdict::Allow), "{name} was cut or refused");
    };
    refuse("f1.js", "const s = `A ${ \"}\" + `\n// one\n// two\n// three\n// four\n` } B`;\nconst x = 1;\n");
    refuse("f1c.js", "const s = `A ${ /}/.test(a) + `\n// one\n// two\n// three\n// four\n` } B`;\nconst x = 1;\n");
    refuse("f1d.js", "const s = `A ${ ' + `\n// one\n// two\n// three\n// four\n` } B`;\nlet y = '}';\nconst x = 1;\n");
    refuse("h1.js", "const t = `${foo / 2 + \"`\"} say \"hi\n// a\n// b\n// c\n// d\n`;\nconst z = 1;\n");
    refuse("h1b.ts", "const t = `${foo + '`'} it's '\n// a\n// b\n// c\n// d\n`;\nconst z = 1;\n");
    refuse("h2.py", "def ready():\n    return 1\n# Local Variables:\n# mode: python\n# End:\n");
    refuse("h2b.c", "int a;\n/* Local Variables: */\n/* tab-width: 4 */\n/* End: */\n");
    refuse("f1b.ts", "const s = `A ${ '}' + `\n// one\n// two\n// three\n// four\n` } B`;\nconst x = 1;\n");
    refuse("f2.js", "export function F() {\n  return (\n    <pre>\n// one\n// two\n// three\n// four\n    </pre>\n  );\n}\n");
    refuse("f2b.js", "const a = <Foo />;\n// one\n// two\n// three\n// four\nconst x = 1;\n");
    refuse("f3.sh", "# one\r\n# two\r\necho hello \\\r\n# three\r\nworld\r\n");
    refuse("f3.c", "// one\r\n// two\r\n#define X 1 \\\r\n// three\r\nint y;\r\n");
    refuse("f4.go", "package p\n\nimport (\n\t\"C\"\n)\n\n// note one\n// note two\n//export Hello\nfunc Hello() {}\n");
    refuse("f4b.go", "package q\n\n// #include <stdlib.h>\n// int kept;\n// int dropped_a;\n// int dropped_b;\nimport (\n\t\"C\"\n)\n");
    let line = "//line /Users/me/src/module/internal/services/payments/adapters/grpc/generated/v1/public/api.pb.go:10\n";
    refuse("f5.go", &format!("{line}package g\nfunc F() {{}}\n"));
    refuse("f5c.go", "//line C:\\Program Files\\go\\src\\module\\internal\\services\\payments\\adapters\\grpc\\generated\\v1\\api.pb.go:10\npackage g\n");
    allow("f5d.go", "//line My File.go:10\npackage g\n");
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("f5b.go"), "//line :10\n// one\n// two\npackage g\n"), Provider::Claude));
    assert_eq!(input["content"], "//line :10\n// one\npackage g\n");
    allow("g3.js", "// line http://example.com:8080\n// line cache:1\npackage g\n");
    refuse("g3b.js", "// line cache:1\n// line cache:2\n// line cache:3\n// line cache:4\nconst x = 1;\n");
    let embed = "//go:embed web/static/dist/application-7f3e9c1a8b7f3e9c1a8b7f3e9c1a8b7f3e9c1a8b7f3e9c1a8b7f3e9c1a8b.js\n";
    allow("f6.go", &format!("{embed}package e\n"));
    let job = "#!/bin/bash\n#SBATCH --job-name=train\n#SBATCH --time=01:00:00\n#SBATCH --mem=4G\n#SBATCH -N 4\n#PBS -N a\n#PBS -l select=1:ncpus=4\n#PBS -q fast\n#BSUB -J name\n#BSUB -n 4\n#BSUB -W 2:00\necho hello\n";
    allow("f7.sh", job);
    let unclean = "# one\n# two\n#SBATCH --mem=4G # limit\necho hi\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("f7b.sh"), unclean), Provider::Claude));
    assert_eq!(input["content"], "# one\n#SBATCH --mem=4G # limit\necho hi\n");
    refuse("f7c.sh", "# one\n#SBATCH --mem=4G # a\n#SBATCH --time=1 # b\n#SBATCH -N 2 # c\necho hi\n");
    allow("f8.cpp", "// note one\n// note two\n// NOLINTNEXTLINE(bugprone-use-after-move)\n// NOLINTBEGIN(build/include_order)\nint a;\n// NOLINTEND\n");
    allow("f8b.cpp", "// note one\n// note two\n// clang-format off\nint  a;\n// clang-format on\n");
    allow("f9.ts", "// note one\n// note two\n// deno-lint-ignore no-explicit-any\n// deno-lint-ignore-file no-explicit-any\n// deno-fmt-ignore\nexport {};\n");
    allow("f9b.css", "/* one */\n/* two */\n/* stylelint-disable selector-max-id */\na { b: c }\n/* stylelint-enable selector-max-id */\n");
    allow("f10b.go", "// note one\n// note two\n// @generated\npackage x\n");
    let many = "package x\n// note one\n// note two\n//go:embed a b c d e f g h\nvar x string\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("f6b.go"), many), Provider::Claude));
    assert_eq!(input["content"], "package x\n// note one\n//go:embed a b c d e f g h\nvar x string\n");
    for (name, text) in [
        ("g1.js", "const label = `progress ${done / total}`;\n// one\n// two\n// three\n// four\nconst x = 1;\n"),
        ("g1b.js", "const t = `${(a + b) / 2} ${a /= b} ${x[1] / 2}`;\n// one\n// two\n// three\n// four\nconst x = 1;\n"),
    ] {
        let (input, _) = cut(trimming(None, None, "Write", written(&dir.join(name), text), Provider::Claude));
        let expected = text.replace("// three\n// four\n", "");
        assert_eq!(input["content"], expected.as_str(), "{name}");
    }
    refuse("g1c.js", "const t = `${ a / /b}/.test(x) + `\n// one\n// two\n// three\n// four\n` };\nconst x = 1;\n");
    refuse("g1d.js", "const t = `${ a /* } */ + `\n// one\n// two\n// three\n// four\n` };\nconst x = 1;\n");
    allow("g4.sh", "#!/bin/bash\n#$ -S /bin/bash\n#$ -N train\n#$ -l h_rt=01:00:00\n#$ -cwd\necho hello\n");
    allow("g4b.sh", "#OAR -l nodes=1\n#OAR -n x\n#OAR -q y\necho hi\n");
    allow("g4c.sh", "#MSUB -l nodes=1\n#MSUB -N a\n#MSUB -q b\necho hi\n");
    let modeline = "// one\n// two\nint x;\n/* vim: set ts=4 sw=4: */\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("g5.c"), modeline), Provider::Claude));
    assert_eq!(input["content"], "int x;\n/* vim: set ts=4 sw=4: */\n");
    let biome = "// biome-ignore lint/suspicious/noExplicitAny: legacy JSON.parse result checked by the schema on the next line\nexport const x: any = 1;\n";
    refuse("f9c.ts", biome);
    let marker = "// Package api is the public client.\n// Callers should use the typed methods.\n// Code generated by protoc-gen-go. DO NOT EDIT.\npackage api\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("f10.go"), marker), Provider::Claude));
    assert_eq!(input["content"], "// Package api is the public client.\n// Code generated by protoc-gen-go. DO NOT EDIT.\npackage api\n");
    let plain = "const s = `n=${ a ? \"x}\" : 'y' } ok`;\n// one\n// two\n// three\n// four\nconst x = 1;\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("plain.js"), plain), Provider::Claude));
    assert_eq!(input["content"], "const s = `n=${ a ? \"x}\" : 'y' } ok`;\n// one\n// two\nconst x = 1;\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn what_the_twenty_first_review_found_is_refused_or_kept() {
    let dir = temp_dir("trim-twentyone");
    let state = temp_dir("trim-twentyone-state");
    let not_cut = |name: &str, text: &str| {
        let verdict = trimming(None, None, "Write", written(&dir.join(name), text), Provider::Claude);
        assert!(!matches!(verdict, Verdict::Trimmed { .. }), "{name} was trimmed");
    };
    let path = dir.join("a.py");
    let first = trimming(Some(&state), Some("t21"), "Write", written(&path, "# one\n# two\nx = 1\n"), Provider::Claude);
    assert!(matches!(first, Verdict::Allow));
    std::fs::write(&path, "# one\n# two\nx = 1\n").expect("write");
    let again = json!({ "file_path": path.to_string_lossy(), "old_string": "# one\n# two\nx = 1", "new_string": "# three\n# four\n# one\n# two\nx = 1" });
    let (input, _) = cut(trimming(Some(&state), Some("t21"), "Edit", again, Provider::Claude));
    assert_eq!(input["new_string"], "# one\n# two\nx = 1");
    not_cut("i2.swift", "let s = #\"\"\"\nquote \"\"\" in text\n// one\n// two\n// three\n// four\n\"\"\"#\nlet x = 1\n");
    not_cut("i3.swift", "let s = #\"\"\"\n\"\"\"\n\"\"\"#\n// one\n// two\n// three\n// four\nlet x = 1\n");
    not_cut("i4.kt", "val s = \"\"\"\n${\"\"\"\n// one\n// two\n// three\n// four\n\"\"\"}\n\"\"\"\nval x = 1\n");
    not_cut("i7.kt", "val a = \"\\${\"\n// one\n// two\n// three\n// four\nval x = 1\n");
    let slash = "val slash = \"\"\"\\\"\"\"\n// one\n// two\n// three\n// four\nval x = 1\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("i5.kt"), slash), Provider::Claude));
    assert_eq!(input["content"], "val slash = \"\"\"\\\"\"\"\n// one\n// two\nval x = 1\n");
    let region = "fun f() {\n// region setup\n// one\n// two\n// endregion\nval x = 1\n}\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("i6.kt"), region), Provider::Claude));
    assert_eq!(input["content"], "fun f() {\n// region setup\n// endregion\nval x = 1\n}\n");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn what_the_twenty_second_review_found_is_refused_or_kept() {
    let dir = temp_dir("trim-twentytwo");
    let state = temp_dir("trim-twentytwo-state");
    let path = dir.join("a.py");
    let text = "# one\n# two\nx = 1\n";
    assert!(matches!(trimming(Some(&state), Some("t22"), "Write", written(&path, text), Provider::Claude), Verdict::Allow));
    std::fs::write(&path, text).expect("write");
    assert!(matches!(trimming(Some(&state), Some("t22"), "Write", written(&path, text), Provider::Claude), Verdict::Allow));
    let code = json!({ "file_path": path.to_string_lossy(), "old_string": "x = 1", "new_string": "x = 2" });
    assert!(matches!(trimming(Some(&state), Some("t22"), "Edit", code, Provider::Claude), Verdict::Allow));
    let not_cut = |name: &str, text: &str| {
        let verdict = trimming(None, None, "Write", written(&dir.join(name), text), Provider::Claude);
        assert!(!matches!(verdict, Verdict::Trimmed { .. }), "{name} was trimmed");
    };
    not_cut("j2.py", "x = f\"\"\"\n{\"\"\"\n# one\n# two\n# three\n# four\n\"\"\"}\n\"\"\"\ny = 1\n");
    not_cut("j2b.py", "x = f'''\n{'''\n# one\n# two\n# three\n# four\n'''}\n'''\ny = 1\n");
    let plain = "x = \"\"\"see the stuff\"\"\"\n# one\n# two\n# three\n# four\ny = 1\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("j2c.py"), plain), Provider::Claude));
    assert_eq!(input["content"], "x = \"\"\"see the stuff\"\"\"\n# one\n# two\ny = 1\n");
    let buff = "x = \"\"\"a buff\"\"\"\n# one\n# two\n# three\n# four\ny = 1\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("j2e.py"), buff), Provider::Claude));
    assert_eq!(input["content"], "x = \"\"\"a buff\"\"\"\n# one\n# two\ny = 1\n");
    let property = "const t = x.return / 2 + `abc/def\n// one\n// two\n// three\n// four\n`;\nconst z = 1;\n";
    not_cut("j4b.js", property);
    not_cut("j2d.swift", "let a = \"\\(\"\n// one\n// two\n// three\n// four\nlet x = 1\n");
    not_cut("j2.swift", "let s = \"\"\"\n\\(\n\"\"\"\n// one\n// two\n// three\n// four\n\"\"\"\n)\n\"\"\"\nlet x = 1\n");
    let raw = "package p\nvar s = `\\`\n// one\n// two\n// three\n// four\nvar x = 1\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("j3.go"), raw), Provider::Claude));
    assert_eq!(input["content"], "package p\nvar s = `\\`\n// one\n// two\nvar x = 1\n");
    not_cut("j4.js", "function f() {\nreturn /`/\nconst s = `\n// one\n// two\n// three\n// four\n`\nreturn s\n}\n");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_write_the_guard_reads_in_another_form_is_never_rewritten() {
    let dir = temp_dir("trim-reform");
    let notebook = json!({ "cells": [{ "cell_type": "code", "metadata": {}, "source": "# n1\n# n2\n# n3\n# n4\ny = 2" }], "metadata": {}, "nbformat": 4, "nbformat_minor": 5 });
    let verdict = trimming(None, None, "Write", written(&dir.join("nb.ipynb"), &notebook.to_string()), Provider::Claude);
    assert!(matches!(verdict, Verdict::Deny(_)), "a notebook was rewritten as plain source");
    let crlf = "# a\r\n# b\r\n# c\r\n# d\r\nx = 1\r\n";
    match trimming(None, None, "Write", written(&dir.join("crlf.py"), crlf), Provider::Claude) {
        Verdict::Trimmed { input, .. } => assert_eq!(input["content"], "# a\r\n# b\r\nx = 1\r\n"),
        Verdict::Deny(_) => {}
        _ => panic!("a CRLF write was allowed or unreadable"),
    }
    let bom = "\u{feff}# a\n# b\n# c\n# d\nx = 1\n";
    match trimming(None, None, "Write", written(&dir.join("bom.py"), bom), Provider::Claude) {
        Verdict::Trimmed { input, .. } => assert_eq!(input["content"], "\u{feff}# a\n# b\nx = 1\n"),
        Verdict::Deny(_) => {}
        _ => panic!("a BOM write was allowed or unreadable"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn harmless_look_alikes_do_not_stop_a_trim_and_a_huge_file_is_trimmed_quickly() {
    let dir = temp_dir("trim-alike");
    let shift = "n = 1 << 4\n# one\n# two\n# three\n# four\nx = 1\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("a.py"), shift), Provider::Claude));
    assert_eq!(input["content"], "n = 1 << 4\n# one\n# two\nx = 1\n");
    let raw = "fn f() {\n    let s = r\"ok\";\n    let t = r#\"also \"fine\"\"#;\n    // one\n    // two\n    // three\n    // four\n    let x = 1;\n}\n";
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("a.rs"), raw), Provider::Claude));
    assert!(input["content"].as_str().is_some_and(|text| text.contains("// two") && !text.contains("// three")));
    let many: String = (0..60_000).map(|n| format!("# c{n}\n")).chain(std::iter::once("x = 1\n".to_owned())).collect();
    let started = std::time::Instant::now();
    let (input, _) = cut(trimming(None, None, "Write", written(&dir.join("b.py"), &many), Provider::Claude));
    assert_eq!(input["content"], "# c0\n# c1\nx = 1\n");
    assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_codex_patch_and_a_partial_edit_are_refused_not_trimmed() {
    let dir = temp_dir("trim-other");
    let patch = format!("*** Begin Patch\n*** Add File: {}\n+x = 1\n+# a\n+# b\n+# c\n+# d\n*** End Patch\n", dir.join("p.py").display());
    let verdict = trimming(None, None, "apply_patch", json!({ "command": patch }), Provider::Codex);
    assert!(matches!(verdict, Verdict::Deny(_)));
    let all = dir.join("a.py");
    std::fs::write(&all, "x = 1\nx = 1\n").expect("write");
    let every = json!({ "file_path": all.to_string_lossy(), "old_string": "x = 1", "new_string": "x = 1\n# a\n# b\n# c\n# d", "replace_all": true });
    assert!(matches!(trimming(None, None, "Edit", every, Provider::Claude), Verdict::Deny(_)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn what_a_trimmed_call_keeps_counts_against_the_session_allowance() {
    let dir = temp_dir("trim-session");
    let state = temp_dir("trim-session-state");
    let path = dir.join("a.py");
    let (input, _) = cut(trimming(Some(&state), Some("ts"), "Write", written(&path, "# a1\n# a2\n# a3\n# a4\nx = 1\ny = 2\n"), Provider::Claude));
    let content = input["content"].as_str().expect("content").to_owned();
    assert_eq!(content, "# a1\n# a2\nx = 1\ny = 2\n");
    std::fs::write(&path, &content).expect("write");
    let again = json!({ "file_path": path.to_string_lossy(), "old_string": "y = 2", "new_string": "y = 2\n# b1\n# b2" });
    let (input, _) = cut(trimming(Some(&state), Some("ts"), "Edit", again, Provider::Claude));
    assert_eq!(input["new_string"], "y = 2");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn the_installed_hook_answers_with_an_allow_that_carries_the_trimmed_input() {
    let rig = Rig::new("trim-hook");
    let file = rig.cwd.join("a.py");
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "session_id": "th",
        "cwd": rig.cwd.to_string_lossy(),
        "tool_name": "Write",
        "tool_input": { "file_path": file.to_string_lossy(), "content": "# a1\n# a2\n# a3\n# a4\nx = 1\n" },
    });
    let run = |trim: &str| {
        let mut command = Command::new(binary());
        command
            .args(["hook", "claude", "PreToolUse"])
            .env("AGENT_SAFEGUARDS_COMMENT_GUARD", "1")
            .env("AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM", trim)
            .env("XDG_STATE_HOME", &rig.state)
            .env("HOME", &rig.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command.spawn().expect("start");
        let _ = child.stdin.take().expect("stdin").write_all(payload.to_string().as_bytes());
        String::from_utf8_lossy(&child.wait_with_output().expect("wait").stdout).into_owned()
    };
    let out: Value = serde_json::from_str(run("1").trim()).expect("json");
    let inner = &out["hookSpecificOutput"];
    assert_eq!(inner["permissionDecision"], "allow");
    assert_eq!(inner["updatedInput"]["content"], "# a1\n# a2\nx = 1\n");
    assert!(inner["additionalContext"].as_str().is_some_and(|text| text.contains("# a3")));
    let refused: Value = serde_json::from_str(run("0").trim()).expect("json");
    assert_eq!(refused["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_rewrap_ignores_case_and_punctuation() {
    let dir = temp_dir("word-case");
    let path = dir.join("a.py");
    std::fs::write(&path, "# the loop ends early. when the cache is warm it returns\nx = 1\n").expect("write");
    let wrapped = "# The loop ends early.\n# When the cache\n# is warm it\n# returns.\nx = 1\n";
    assert!(!denied(&write_file(None, None, &path, wrapped)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rewrap_that_also_rewords_is_judged_as_a_plain_replacement() {
    let dir = temp_dir("reword-wrap");
    let path = dir.join("a.rs");
    std::fs::write(&path, "// one long comment about renaming things across the whole codebase quickly\nfn a() {}\n")
        .expect("write");
    let both = "// one long comment about\n// renaming stuff across\n// the whole codebase\n// very quickly\nfn a() {}\n";
    assert!(denied(&write_file(None, None, &path, both)));
    let wrapped = "// one long comment about\n// renaming things across\n// the whole codebase\n// quickly\nfn a() {}\n";
    let state = temp_dir("reword-wrap-state");
    assert!(!denied(&write_file(Some(&state), Some("rw"), &path, wrapped)));
    std::fs::write(&path, wrapped).expect("write");
    assert!(denied(&write_file(Some(&state), Some("rw"), &path, both)));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn blank_lines_are_still_charged_after_a_rewrap_is_forgiven() {
    let dir = temp_dir("wrap-blanks");
    let path = dir.join("a.rs");
    std::fs::write(&path, "// alpha beta gamma delta\nfn a() {}\n").expect("write");
    let hollow = "// alpha beta\n// gamma delta\n//\n//\nfn a() {}\n";
    assert!(denied(&write_file(None, None, &path, hollow)));
    let wrapped = "// alpha beta\n// gamma delta\nfn a() {}\n";
    assert!(!denied(&write_file(None, None, &path, wrapped)));
    let _ = std::fs::remove_dir_all(&dir);
}
