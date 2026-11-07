use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str, startup: Option<&str>) -> Home {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = PathBuf::from(guard_common::sys::realpath(&std::env::temp_dir().to_string_lossy()))
        .join(format!("value-firewall-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).expect("fixture home");
    if let Some(text) = startup {
        std::fs::write(root.join(".zshrc"), text).expect("startup file");
    }
    Home(root)
}

fn run(home: &Home, runtime: &str, event: &str, payload: &Value, extra: &[(&str, &str)]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-tool"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home.0)
        .env(
            "AGENT_SAFEGUARDS_TEST_OVERRIDES",
            json!({ "USER_HOME": home.0.to_string_lossy() }).to_string(),
        )
        .envs(extra.iter().copied())
        .current_dir(&home.0)
        .args(["hook", runtime, event])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hook");
    let mut stdin = child.stdin.take().expect("stdin");
    let bytes = payload.to_string().into_bytes();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
    let finished = child.wait_with_output().expect("collect");
    let _ = feeder.join();
    String::from_utf8_lossy(&finished.stdout).into_owned()
}

fn after(command: &str, stdout: &str) -> Value {
    json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_response": { "stdout": stdout, "stderr": "", "interrupted": false, "isImage": false },
    })
}

fn before(command: &str) -> Value {
    json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": command } })
}

fn withheld(out: &str, secret: &str) -> bool {
    let parsed: Option<Value> = serde_json::from_str(out.trim()).ok();
    !out.contains(secret)
        && parsed.is_some_and(|value| value["hookSpecificOutput"]["updatedToolOutput"].is_object())
}

fn allowed(out: &str) -> bool {
    out.trim().is_empty()
}

fn denied(out: &str) -> bool {
    serde_json::from_str::<Value>(out.trim())
        .is_ok_and(|value| value["hookSpecificOutput"]["permissionDecision"] == "deny")
}

const STARTUP: &str = "envkey=value1\nexport envkey2=value2\nalias secretcommand1=\"value3\"\nexport envkey4='p@ss word/42'\nexport EDITOR=vim\nexport LEVEL=42\nalias gs=\"git status\"\n";

#[test]
fn values_from_a_startup_file_are_withheld_from_command_output() {
    let h = home("raw", Some(STARTUP));
    for value in ["value1", "value2", "value3", "p@ss word/42"] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("the value is {value}\n")), &[]);
        assert!(withheld(&out, value), "{value}: {out}");
    }
}

#[test]
fn encoded_and_reshaped_values_are_withheld_too() {
    let h = home("forms", Some(STARTUP));
    for (what, shown) in [
        ("base64", "dmFsdWUx"),
        ("hex", "76616c756531"),
        ("reversed", "1eulav"),
        ("upper case", "VALUE1"),
        ("percent encoded", "p%40ss%20word%2F42"),
    ] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &[]);
        assert!(withheld(&out, shown), "{what}: {out}");
    }
}

#[test]
fn key_names_and_unrelated_output_are_not_withheld() {
    let h = home("names", Some(STARTUP));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "envkey envkey2 secretcommand1\nhello world\n"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn short_values_and_plain_alias_bodies_stay_visible() {
    let h = home("short", Some(STARTUP));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "vim 42 git status\n"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn a_value_in_a_file_tool_result_is_withheld() {
    let h = home("read", Some(STARTUP));
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/tmp/x" },
        "tool_response": { "type": "text", "file": { "content": "line one\nenvkey=value2\n" } },
    });
    let out = run(&h, "claude", "PostToolUse", &payload, &[]);
    assert!(withheld(&out, "value2"), "{out}");
}

#[test]
fn the_codex_hook_blocks_the_output_too() {
    let h = home("codex", Some(STARTUP));
    let out = run(&h, "codex", "PostToolUse", &after("echo hi", "value1\n"), &[]);
    let parsed: Value = serde_json::from_str(out.trim()).expect("one JSON answer");
    assert_eq!(parsed["decision"], "block");
    assert!(!out.contains("value1"));
}

#[test]
fn secret_named_process_variables_are_protected_and_other_names_are_not() {
    let h = home("process", None);
    let extra = [("MY_API_TOKEN", "ab-process-token-9"), ("PLAIN_SETTING", "plain-setting-text")];
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "ab-process-token-9\n"), &extra);
    assert!(withheld(&out, "ab-process-token-9"), "{out}");
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "plain-setting-text\n"), &extra);
    assert!(allowed(&out), "{out}");
}

#[test]
fn without_a_startup_file_nothing_extra_is_withheld() {
    let h = home("none", None);
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "value1 value2 value3\n"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn using_a_key_by_name_in_a_command_is_allowed() {
    let h = home("use", Some(STARTUP));
    let out = run(&h, "claude", "PreToolUse", &before("curl -H \"Authorization: Bearer $ENVKEY2\" https://example.invalid/"), &[]);
    assert!(allowed(&out), "{out}");
}

#[test]
fn inline_code_that_dumps_the_environment_is_refused_but_one_variable_is_allowed() {
    let h = home("inline", None);
    for command in [
        "python3 -c \"import os; print(os.environ)\"",
        "node -e \"console.log(JSON.stringify(process.env))\"",
        "ruby -e 'puts ENV.to_h'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(denied(&out), "{command}: {out}");
    }
    for command in [
        "python3 -c \"import os; print(len(os.environ['HOME']))\"",
        "node -e \"console.log(process.env.HOME.length)\"",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(allowed(&out), "{command}: {out}");
    }
}

#[test]
fn writing_a_script_through_a_quoted_heredoc_is_not_refused() {
    let h = home("script", None);
    let command = "cat > run.py <<'EOF'\nimport os\nprint(dict(os.environ))\nEOF";
    let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
    assert!(allowed(&out), "{out}");
}

fn put(home: &Home, relative: &str, text: &str) {
    let path = home.0.join(relative);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("folders");
    std::fs::write(path, text).expect("file");
}

fn why_coverage(out: &str) -> bool {
    let parsed: Value = serde_json::from_str(out.trim()).unwrap_or(Value::Null);
    let context = parsed["hookSpecificOutput"]["additionalContext"].as_str().unwrap_or("");
    context.contains(&guard_common::locale::message("safe_tool.withheld.why.coverage", &[]))
}

#[test]
fn ansi_c_and_locale_quoted_values_are_protected() {
    let h = home("ansi", Some("A=$'ansi-quoted-1'\nB=$'caf\\xc3\\xa9-escape'\nC=$\"locale-quoted-1\"\n"));
    for shown in ["ansi-quoted-1", "caf\u{e9}-escape", "locale-quoted-1"] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &[]);
        assert!(withheld(&out, shown), "{shown}: {out}");
    }
}

#[test]
fn a_startup_value_equal_to_a_field_name_does_not_withhold_every_result() {
    let h = home("field", Some("export LOG_DEST=stderr\n"));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "hello world\n"), &[]);
    assert!(allowed(&out), "{out}");
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "log goes to stderr\n"), &[]);
    assert!(withheld(&out, "log goes to"), "{out}");
}

#[test]
fn here_document_text_is_not_an_assignment_and_later_assignments_still_count() {
    let rc = "app_help() {\ncat <<'DOC'\nLOG_DEST=stderr\nDOC\n}\nexport REAL=value1\n";
    let h = home("heredoc", Some(rc));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "plain stderr text\n"), &[]);
    assert!(allowed(&out), "{out}");
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "value1\n"), &[]);
    assert!(withheld(&out, "value1"), "{out}");
}

#[test]
fn a_quoted_here_document_marker_that_never_ends_does_not_hide_later_assignments() {
    let h = home("unended", Some("echo \"<<EOF\"\nexport K2=value2\n"));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "value2\n"), &[]);
    assert!(withheld(&out, "value2"), "{out}");
}

#[test]
fn many_values_long_values_and_late_folder_files_are_all_covered() {
    let many: String = (0..600).map(|n| format!("A{n}=fixtureitem{n:04}\n")).collect();
    let h = home("many", Some(&many));
    let extra = [("MY_API_TOKEN", "ab-process-token-9")];
    for shown in ["fixtureitem0000", "fixtureitem0599", "ab-process-token-9"] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &extra);
        assert!(withheld(&out, shown), "{shown}: {out}");
    }
    let big = "x".repeat(1025);
    let h = home("big", Some(&format!("export BIG={big}\n")));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{big}\n")), &[]);
    assert!(withheld(&out, &big), "1025 characters");
    let h = home("folder", None);
    for n in 0..45 {
        put(&h, &format!(".zsh/f{n:02}.zsh"), &format!("export Z{n}=folderfile{n:02}x\n"));
    }
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "folderfile44x\n"), &[]);
    assert!(withheld(&out, "folderfile44x"), "{out}");
}

#[test]
fn startup_files_too_large_to_check_withhold_every_result_and_say_why() {
    let too_long = format!("export HUGE={}\n", "y".repeat(5000));
    let late = format!("{}export LATE=late-value-1\n", "# c\n".repeat(20001));
    for (name, rc) in [("long", too_long), ("late", late)] {
        let h = home(name, Some(&rc));
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", "hello world\n"), &[]);
        assert!(withheld(&out, "hello world"), "{name}: {out}");
        assert!(why_coverage(&out), "{name}: {out}");
    }
    let h = home("crowded", None);
    for n in 0..201 {
        put(&h, &format!(".zsh/f{n:03}.zsh"), "# nothing\n");
    }
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "hello world\n"), &[]);
    assert!(withheld(&out, "hello world") && why_coverage(&out), "crowded: {out}");
}

#[test]
fn unicode_json_and_mixed_case_percent_forms_are_withheld() {
    let h = home("forms2", Some("A='caf\u{e9}-fixture'\nB='Garden/piano'\n"));
    for shown in ["\"caf\\u00e9-fixture\"", "Garden%2fpiano", "Garden%2Fpiano"] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &[]);
        assert!(withheld(&out, shown), "{shown}: {out}");
    }
}

#[test]
fn a_here_document_marker_in_a_comment_a_string_or_arithmetic_hides_nothing() {
    let rcs = [
        "# example: cat <<EOF\nA=gardenpiano\ncat <<EOF\nhelp\nEOF\n",
        "printf \"%s\\n\" \"<<EOF\"\nA=gardenpiano\ncat <<EOF\nhelp\nEOF\n",
        "x=$((1<<4))\nA=gardenpiano\n",
    ];
    for (n, rc) in rcs.iter().enumerate() {
        let h = home(&format!("marker{n}"), Some(rc));
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", "gardenpiano\n"), &[]);
        assert!(withheld(&out, "gardenpiano"), "fixture {n}: {out}");
    }
}

#[test]
fn here_document_delimiters_of_every_shape_and_several_documents_are_data() {
    let rcs = [
        "cat <<EOF-HELP\nA=always\nEOF-HELP\n",
        "cat <<E\"OF\"\nA=always\nEOF\n",
        "cat <<123\nA=always\n123\n",
        "cat <<FIRST <<SECOND\nB=neverthere\nFIRST\nA=always\nSECOND\n",
        "cat <<-TABBED\n\tA=always\n\tTABBED\n",
    ];
    for (n, rc) in rcs.iter().enumerate() {
        let h = home(&format!("shape{n}"), Some(rc));
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", "this always succeeds\n"), &[]);
        assert!(allowed(&out), "fixture {n}: {out}");
    }
    let h = home("after-two", Some("cat <<FIRST <<SECOND\nB=neverthere\nFIRST\nA=always\nSECOND\nexport REAL=value1\n"));
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "value1\n"), &[]);
    assert!(withheld(&out, "value1"), "{out}");
}

#[test]
fn ansi_c_newline_nul_and_control_literals_are_protected() {
    let h = home("ansi2", Some("A=$'garden\\npiano'\nB=$'gardennul\\0tail'\nC=$'garden\\cApiano'\n"));
    for shown in ["garden\npiano", "gardennul\n", "garden\u{1}piano"] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &[]);
        assert!(!allowed(&out), "{shown:?}: {out}");
    }
}

#[test]
fn php_slash_escapes_and_combined_json_escapes_are_withheld() {
    let h = home("json3", Some("A='Garden/piano'\nB=$'caf\\xc3\\xa9\\bfixture'\n"));
    for shown in ["\"Garden\\/piano\"", "\"caf\\u00e9\\bfixture\""] {
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &[]);
        assert!(withheld(&out, shown), "{shown}: {out}");
    }
}

#[test]
fn twenty_thousand_comment_markers_are_scanned_in_linear_time() {
    let rc = format!("{}A=gardenpiano\n", "# <<EOF\n".repeat(19999));
    let h = home("linear", Some(&rc));
    let started = std::time::Instant::now();
    let out = run(&h, "claude", "PostToolUse", &after("echo hi", "gardenpiano\n"), &[]);
    assert!(withheld(&out, "gardenpiano"), "{out}");
    assert!(started.elapsed().as_secs_f64() < 2.5, "took {:?}", started.elapsed());
}

#[test]
fn more_inline_forms_are_judged_by_what_they_read() {
    let h = home("inline3", None);
    for command in [
        "php -r 'var_dump(GETENV());'",
        "php -r 'var_dump(getenv(name: null));'",
        "node -e 'console.log(process[\"env\"])'",
        "python3 -c 'from os import environb; print(dict(environb))'",
        "perl -e \"print %main'ENV\"",
        "python3 -c 'import os; print([os.environ[k] for\tk in os.environ])'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(denied(&out), "{command}: {out}");
    }
    for command in [
        "node -e 'console.log(process.env.constructor)'",
        "python3 -c 'from os import environ; print(environ[\"FIXTURE_NAME\"])'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(allowed(&out), "{command}: {out}");
    }
}

#[test]
fn multi_line_quotes_continuations_and_hashes_are_read_as_the_shell_reads_them() {
    let protected = [
        ("A='garden\npiano'\n", "garden\npiano"),
        ("HELP='\n<<EOF\n'\nA=gardenpiano\ncat <<EOF\nhelp\nEOF\n", "gardenpiano"),
        ("# sample command \\\nA=gardenpiano\n", "gardenpiano"),
        ("A=gardenpiano\\\n", "gardenpiano"),
        ("A='garden\\\npiano'\n", "garden\\\npiano"),
        ("A=river#harp\n", "river#harp"),
        ("A=$'garden\\cApiano'\n", "gardencApiano"),
    ];
    for (n, (rc, shown)) in protected.iter().enumerate() {
        let h = home(&format!("shell{n}"), Some(rc));
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", &format!("{shown}\n")), &[]);
        assert!(!allowed(&out), "fixture {n}: {out}");
    }
    let data = [
        "HELP='\nA=always\n'\n",
        "cat <<'EOF'\nA=always\nexample \\\nEOF\n",
        "HELP=\"$(cat <<'EOF'\nA=always\nEOF\n)\"\n",
        "cat <<''\nA=always\n\n",
        "cat <<\"E\\\"OF\"\nA=always\nE\"OF\n",
    ];
    for (n, rc) in data.iter().enumerate() {
        let h = home(&format!("data{n}"), Some(rc));
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", "this always succeeds\n"), &[]);
        assert!(allowed(&out), "data fixture {n}: {out}");
    }
}

#[test]
fn local_declarations_and_assignments_inside_compound_commands_are_protected() {
    let rcs = [
        "setup() {\nlocal A=gardenpiano\nprintf '%s' \"$A\"\n}\nsetup\n",
        "setup() { A=gardenpiano; }\nsetup\n",
        "case yes in\n yes) A=gardenpiano;;\nesac\n",
    ];
    for (n, rc) in rcs.iter().enumerate() {
        let h = home(&format!("compound{n}"), Some(rc));
        let out = run(&h, "claude", "PostToolUse", &after("echo hi", "gardenpiano\n"), &[]);
        assert!(withheld(&out, "gardenpiano"), "fixture {n}: {out}");
    }
}

#[test]
fn round_three_inline_forms_are_judged_by_what_they_read() {
    let h = home("inline4", None);
    for command in [
        "python3 -c $'from os import environ\\nprint(dict(environ))'",
        "node -e \"console.log(process[\\\"env\\\"])\"",
        "node -e 'console.log(process.env.valueOf?.())'",
        "node -e 'for (const k\n in process.env) console.log(process.env[k])'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(denied(&out), "{command}: {out}");
    }
    for command in [
        "python3 -c 'import os; print(os.environ[\"env\"])'",
        "ruby -e 'puts ENV[\"env\"]'",
        "php -r 'echo getenv(name: \"FIXTURE_NAME\");'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(allowed(&out), "{command}: {out}");
    }
}

#[test]
fn spaced_inline_code_is_judged_like_the_compact_form() {
    let h = home("spaced", None);
    for command in [
        "python3 -c 'import os; print(dict(os . environ))'",
        "node -e 'console.log(process . env)'",
        "php -r 'var_dump(getenv ());'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(denied(&out), "{command}: {out}");
    }
    for command in [
        "python3 -c 'import os; print(os.environ.get (\"HOME\"))'",
        "ruby -e 'puts ENV.fetch (\"HOME\")'",
    ] {
        let out = run(&h, "claude", "PreToolUse", &before(command), &[]);
        assert!(allowed(&out), "{command}: {out}");
    }
}
