use std::path::Path;
use std::sync::LazyLock;

use guard_common::{emit::emit, env, sys};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::consts::{ATTRIBUTION_PATTERN, OBJECT_ID_PATTERN};
use crate::git::{
    git, git_default, git_identity_ready, python_lines, python_strip, repository_root,
};
use crate::process::ProcessResult;

static ANSI_ESCAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").unwrap_or_else(|_| std::process::abort())
});

pub fn object_id(output: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(output).ok()?;
    if !text.is_ascii() {
        return None;
    }
    let value = python_strip(text);
    let found = OBJECT_ID_PATTERN.find(value)?;
    if found.start() == 0 && found.end() == value.len() {
        Some(value.to_owned())
    } else {
        None
    }
}

pub fn commit_hook_exists(root: &str) -> bool {
    let command = [
        "rev-parse".to_owned(),
        "--git-path".to_owned(),
        "hooks".to_owned(),
    ];
    let Some(completed) = git(&command, root, 20) else {
        return false;
    };
    if completed.returncode != 0 {
        return false;
    }
    let value = String::from_utf8_lossy(&completed.stdout);
    let folder = python_strip(&value);
    let folder = if Path::new(folder).is_absolute() {
        Path::new(folder).to_path_buf()
    } else {
        Path::new(root).join(folder)
    };
    ["pre-commit", "prepare-commit-msg", "commit-msg"]
        .iter()
        .any(|name| {
            let path = folder.join(name);
            path.is_file() && sys::access_executable(&path.to_string_lossy())
        })
}

pub fn commit_detail(output: &[u8]) -> Map<String, Value> {
    let decoded = String::from_utf8_lossy(output);
    let clean = ANSI_ESCAPE.replace_all(&decoded, "");
    let clean = python_strip(&clean);
    if clean.is_empty() {
        return Map::new();
    }
    let lines = python_lines(clean);
    let tail = lines.get(lines.len().saturating_sub(30)..).unwrap_or(&[]);
    let mut shown = tail
        .iter()
        .map(|line| line.chars().take(300).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    let chars: Vec<char> = shown.chars().collect();
    if chars.len() > 2000 {
        shown = chars
            .get(chars.len().saturating_sub(2000)..)
            .unwrap_or(&[])
            .iter()
            .collect();
    }
    let mut detail = Map::new();
    match crate::output::withheld_because("git commit", &Value::String(shown.clone())).ok().flatten() {
        Some(reason) => {
            detail.insert("detail_withheld".to_owned(), json!(reason));
        }
        None => {
            detail.insert("detail".to_owned(), Value::String(shown));
        }
    }
    detail
}

pub fn commit_operation_failed(results: &[Option<&ProcessResult>]) -> (i32, Value) {
    let mut output = Vec::new();
    for result in results.iter().flatten() {
        if result.returncode != 0 {
            output.extend_from_slice(&result.stdout);
            output.extend_from_slice(&result.stderr);
        }
    }
    let lowered = output.to_ascii_lowercase();
    let status = if lowered
        .windows(b"index.lock".len())
        .any(|piece| piece == b"index.lock")
    {
        "lock_held"
    } else {
        "operation_failed"
    };
    let mut payload = json!({"tool": "git", "operation": "commit", "status": status});
    if let Value::Object(ref mut map) = payload {
        map.extend(commit_detail(&output));
    }
    (2, payload)
}

pub fn git_commit_result(messages: &[String], cwd: &str) -> (i32, Value) {
    let commit_message = python_strip(&messages.join("\n\n")).to_owned();
    if commit_message.is_empty()
        || commit_message.len() > 16 * 1024
        || (env::env_flag("AGENT_SAFEGUARDS_BLOCK_ATTRIBUTION")
            && ATTRIBUTION_PATTERN.is_match(&commit_message))
        || matches!(
            crate::output::sensitive_output("git commit", &Value::String(commit_message)),
            Ok(true)
        )
    {
        return (
            2,
            json!({"tool": "git", "operation": "commit", "status": "invalid_message"}),
        );
    }
    let Some(root) = repository_root(cwd) else {
        return (
            2,
            json!({"tool": "git", "operation": "commit", "status": "not_repository"}),
        );
    };
    if !git_identity_ready(&root) {
        return (
            1,
            json!({"tool": "git", "operation": "commit", "status": "identity_missing"}),
        );
    }
    let staged = git(
        &[
            "diff".into(),
            "--cached".into(),
            "--quiet".into(),
            "--exit-code".into(),
        ],
        &root,
        20,
    );
    let Some(staged_result) = staged.as_ref() else {
        return commit_operation_failed(&[None]);
    };
    if staged_result.returncode != 0 && staged_result.returncode != 1 {
        return commit_operation_failed(&[Some(staged_result)]);
    }
    if staged_result.returncode == 0 {
        return (
            1,
            json!({"tool": "git", "operation": "commit", "status": "no_staged_changes"}),
        );
    }
    let candidate = git(&["write-tree".into()], &root, 20);
    let paths = git(
        &[
            "diff".into(),
            "--cached".into(),
            "--name-only".into(),
            "-z".into(),
        ],
        &root,
        20,
    );
    let candidate_tree = candidate
        .as_ref()
        .filter(|result| result.returncode == 0)
        .and_then(|result| object_id(&result.stdout));
    let paths_ok = paths.as_ref().is_some_and(|result| result.returncode == 0);
    let Some(candidate_tree) = candidate_tree else {
        return commit_operation_failed(&[candidate.as_ref(), paths.as_ref()]);
    };
    if !paths_ok {
        return commit_operation_failed(&[candidate.as_ref(), paths.as_ref()]);
    }
    let mut arguments = vec![
        "commit".to_owned(),
        "--quiet".to_owned(),
        "--no-status".to_owned(),
    ];
    for paragraph in messages {
        arguments.extend(["--message".to_owned(), paragraph.to_owned()]);
    }
    let completed = git_default(&arguments, &root);
    if completed
        .as_ref()
        .is_none_or(|result| result.returncode != 0)
    {
        let mut output = Vec::new();
        if let Some(result) = completed.as_ref() {
            output.extend_from_slice(&result.stdout);
            output.extend_from_slice(&result.stderr);
        }
        let lowered = output.to_ascii_lowercase();
        let contains = |needle: &[u8]| lowered.windows(needle.len()).any(|piece| piece == needle);
        let status = if contains(b"index.lock") {
            "lock_held"
        } else if contains(b"hook") {
            "hook_failed"
        } else if contains(b"sign") || contains(b"gpg") {
            "signing_failed"
        } else if contains(b"unmerged") || contains(b"conflict") {
            "unmerged_changes"
        } else if commit_hook_exists(&root) {
            "hook_failed"
        } else {
            "commit_failed"
        };
        let mut payload = json!({"tool": "git", "operation": "commit", "status": status});
        if let Value::Object(ref mut map) = payload {
            map.extend(commit_detail(&output));
        }
        return (1, payload);
    }
    let commit = git(
        &["rev-parse".into(), "--verify".into(), "HEAD".into()],
        &root,
        20,
    );
    let tree = git(
        &["rev-parse".into(), "--verify".into(), "HEAD^{tree}".into()],
        &root,
        20,
    );
    let commit_id = commit
        .as_ref()
        .filter(|result| result.returncode == 0)
        .and_then(|result| object_id(&result.stdout));
    let tree_id = tree
        .as_ref()
        .filter(|result| result.returncode == 0)
        .and_then(|result| object_id(&result.stdout));
    let (Some(commit_id), Some(tree_id)) = (commit_id, tree_id) else {
        return (
            2,
            json!({"tool": "git", "operation": "commit", "status": "verification_failed"}),
        );
    };
    let status = if tree_id == candidate_tree {
        "committed"
    } else {
        "committed_tree_changed"
    };
    let file_count = paths
        .as_ref()
        .map(|result| result.stdout.iter().filter(|byte| **byte == 0).count())
        .unwrap_or(0);
    let payload = json!({
        "tool": "git", "operation": "commit", "status": status,
        "commit": commit_id, "tree": tree_id, "files": file_count,
    });
    (if status == "committed" { 0 } else { 2 }, payload)
}

pub fn git_commit(messages: &[String]) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (code, payload) = git_commit_result(messages, &cwd);
    emit(&payload);
    code
}

pub fn commit_messages(arguments: &[String]) -> Option<Vec<String>> {
    let mut messages = Vec::new();
    let mut index = 0usize;
    while let Some(argument) = arguments.get(index) {
        if (argument == "-m" || argument == "--message")
            && arguments.get(index.saturating_add(1)).is_some()
        {
            messages.push(arguments.get(index.saturating_add(1))?.to_owned());
            index = index.saturating_add(2);
        } else if let Some(message) = argument.strip_prefix("--message=") {
            messages.push(message.to_owned());
            index = index.saturating_add(1);
        } else {
            return None;
        }
    }
    if messages.is_empty() {
        None
    } else {
        Some(messages)
    }
}

#[cfg(test)]
mod tests {
    use super::{commit_detail, commit_hook_exists, commit_messages, git_commit_result, object_id};
    use crate::git::{assert_mock_consumed, mock_git_calls};
    use crate::process::ProcessResult;
    use serde_json::{json, Value};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    fn finished(code: i32, stdout: &[u8], stderr: &[u8]) -> Option<ProcessResult> {
        Some(ProcessResult {
            returncode: code,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        })
    }

    fn repository_calls(root: &str) -> Vec<(Vec<String>, Option<ProcessResult>)> {
        vec![
            (
                vec!["rev-parse".into(), "--show-toplevel".into()],
                finished(0, format!("{root}\n").as_bytes(), b""),
            ),
            (
                vec!["var".into(), "GIT_AUTHOR_IDENT".into()],
                finished(0, b"configured\n", b""),
            ),
            (
                vec!["var".into(), "GIT_COMMITTER_IDENT".into()],
                finished(0, b"configured\n", b""),
            ),
        ]
    }

    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex pair");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    #[test]
    fn message_arguments_preserve_paragraphs() {
        assert_eq!(
            commit_messages(&["-m".into(), "one".into(), "--message=two".into()]),
            Some(vec!["one".into(), "two".into()])
        );
        assert_eq!(commit_messages(&["--message".into()]), None);
    }

    #[test]
    fn object_ids_are_ascii_and_exact() {
        assert_eq!(
            object_id(format!("{}\n", "a".repeat(40)).as_bytes()),
            Some("a".repeat(40))
        );
        assert_eq!(object_id(format!("{}x", "a".repeat(40)).as_bytes()), None);
        assert_eq!(object_id(&[0xff]), None);
    }

    #[test]
    fn details_keep_only_tail_lines() {
        let text = (0..100)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let detail = commit_detail(text.as_bytes());
        let shown = detail.get("detail").and_then(Value::as_str).unwrap_or("");
        assert!(shown.contains("line 99"));
        assert!(!shown.contains("line 0\n"));
    }

    #[test]
    fn scripted_git_commit_classifies_success_and_failures_without_git_writes() {
        let root = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("s7-commit-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("fixture root");
        let root = root.to_str().expect("utf8 path");
        let message = ["subject".to_owned()];
        let tree = "a".repeat(40);
        let commit = "b".repeat(40);

        let mut calls = repository_calls(root);
        calls.push((
            vec![
                "diff".into(),
                "--cached".into(),
                "--quiet".into(),
                "--exit-code".into(),
            ],
            finished(0, b"", b""),
        ));
        mock_git_calls(calls);
        let (code, payload) = git_commit_result(&message, root);
        assert_eq!(
            (code, payload.get("status").and_then(Value::as_str)),
            (1, Some("no_staged_changes"))
        );
        assert_mock_consumed();

        let mut calls = repository_calls(root);
        calls.push((
            vec![
                "diff".into(),
                "--cached".into(),
                "--quiet".into(),
                "--exit-code".into(),
            ],
            finished(2, b"", b"index.lock held"),
        ));
        mock_git_calls(calls);
        let (code, payload) = git_commit_result(&message, root);
        assert_eq!(
            (code, payload.get("status").and_then(Value::as_str)),
            (2, Some("lock_held"))
        );
        assert_mock_consumed();

        for (observed_tree, expected_code, expected_status) in [
            (tree.clone(), 0, "committed"),
            ("c".repeat(40), 2, "committed_tree_changed"),
        ] {
            let mut calls = repository_calls(root);
            calls.extend([
                (
                    vec![
                        "diff".into(),
                        "--cached".into(),
                        "--quiet".into(),
                        "--exit-code".into(),
                    ],
                    finished(1, b"", b""),
                ),
                (vec!["write-tree".into()], finished(0, tree.as_bytes(), b"")),
                (
                    vec![
                        "diff".into(),
                        "--cached".into(),
                        "--name-only".into(),
                        "-z".into(),
                    ],
                    finished(0, b"file.txt\0", b""),
                ),
                (
                    vec![
                        "commit".into(),
                        "--quiet".into(),
                        "--no-status".into(),
                        "--message".into(),
                        "subject".into(),
                    ],
                    finished(0, b"", b""),
                ),
                (
                    vec!["rev-parse".into(), "--verify".into(), "HEAD".into()],
                    finished(0, commit.as_bytes(), b""),
                ),
                (
                    vec!["rev-parse".into(), "--verify".into(), "HEAD^{tree}".into()],
                    finished(0, observed_tree.as_bytes(), b""),
                ),
            ]);
            mock_git_calls(calls);
            let (code, payload) = git_commit_result(&message, root);
            assert_eq!(code, expected_code);
            assert_eq!(
                payload.get("status").and_then(Value::as_str),
                Some(expected_status)
            );
            assert_eq!(payload.get("files").and_then(Value::as_u64), Some(1));
            assert_mock_consumed();
        }

        let mut calls = repository_calls(root);
        calls.extend([
            (
                vec![
                    "diff".into(),
                    "--cached".into(),
                    "--quiet".into(),
                    "--exit-code".into(),
                ],
                finished(1, b"", b""),
            ),
            (vec!["write-tree".into()], finished(0, tree.as_bytes(), b"")),
            (
                vec![
                    "diff".into(),
                    "--cached".into(),
                    "--name-only".into(),
                    "-z".into(),
                ],
                finished(0, b"file.txt\0", b""),
            ),
            (
                vec![
                    "commit".into(),
                    "--quiet".into(),
                    "--no-status".into(),
                    "--message".into(),
                    "subject".into(),
                ],
                finished(1, b"", b"hook rejected"),
            ),
        ]);
        mock_git_calls(calls);
        let (code, payload) = git_commit_result(&message, root);
        assert_eq!(
            (code, payload.get("status").and_then(Value::as_str)),
            (1, Some("hook_failed"))
        );
        assert_mock_consumed();

        std::fs::remove_dir(root).expect("remove fixture root");
    }

    #[test]
    fn scripted_commit_vectors_match_python_without_git_writes() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/git.json");
        let source = std::fs::read_to_string(path).expect("run python3 tests/gen_git.py first");
        let records: Vec<Value> = serde_json::from_str(&source).expect("vectors");
        let root = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("s7-commit-vectors-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("fixture root");
        let root = root.to_str().expect("utf8 path");
        for record in records.iter().filter(|record| {
            record.get("fn").and_then(Value::as_str) == Some("git_commit_scripted")
        }) {
            let mut calls = repository_calls(root);
            let script = record
                .get("args")
                .and_then(Value::as_array)
                .and_then(|args| args.first())
                .and_then(Value::as_array)
                .expect("script");
            for step in script {
                let fields = step.as_array().expect("step");
                let command = fields
                    .first()
                    .and_then(Value::as_array)
                    .expect("command")
                    .iter()
                    .map(|word| word.as_str().expect("word").to_owned())
                    .collect();
                let code = fields.get(1).and_then(Value::as_i64).expect("code") as i32;
                let stdout = unhex(fields.get(2).and_then(Value::as_str).expect("stdout"));
                let stderr = unhex(fields.get(3).and_then(Value::as_str).expect("stderr"));
                calls.push((command, finished(code, &stdout, &stderr)));
            }
            mock_git_calls(calls);
            let (code, payload) = git_commit_result(&["subject".to_owned()], root);
            assert_eq!(
                json!([code, payload]),
                *record.get("ret").expect("expected")
            );
            assert_mock_consumed();
        }
        std::fs::remove_dir(root).expect("remove fixture root");
    }

    #[test]
    fn hook_presence_uses_executable_file_in_resolved_folder() {
        let root = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("s7-hook-{}", std::process::id()));
        let hooks = root.join("hooks");
        std::fs::create_dir_all(&hooks).expect("fixture hooks");
        let hook = hooks.join("pre-commit");
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&hook)
            .expect("fixture hook");
        drop(opened);
        mock_git_calls(vec![(
            vec!["rev-parse".into(), "--git-path".into(), "hooks".into()],
            finished(0, b"hooks\n", b""),
        )]);
        assert!(commit_hook_exists(root.to_str().expect("root path")));
        assert_mock_consumed();
        std::fs::remove_file(&hook).expect("remove hook");
        std::fs::remove_dir(&hooks).expect("remove hooks");
        std::fs::remove_dir(&root).expect("remove root");
    }
}
