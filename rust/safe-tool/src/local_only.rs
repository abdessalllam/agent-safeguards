use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

use guard_common::{env, shell, sys};

use crate::consts::{DEFAULT_LOCAL_ONLY, LOCAL_ONLY_ENTRY_FULL};
use crate::git::{git, python_lines, python_strip, repository_root};
use crate::git_rules::git_subcommand;
use crate::process::ProcessResult;
use crate::words::{is_self, normalized, tokenize, unwrap};

#[derive(Debug, Eq, PartialEq)]
pub enum LocalOnlyError {
    UnresolvableCommand,
    EmbeddedNul,
}

#[derive(Debug)]
pub enum OpenError {
    IndexError,
    ValueError,
    Io(io::Error),
}

#[derive(Debug, Eq, PartialEq)]
pub enum EnsureError {
    UnicodeDecodeError,
    ValueError,
}

impl From<io::Error> for OpenError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<shell::UnresolvableCommand> for LocalOnlyError {
    fn from(_: shell::UnresolvableCommand) -> Self {
        Self::UnresolvableCommand
    }
}

impl From<sys::EmbeddedNul> for LocalOnlyError {
    fn from(_: sys::EmbeddedNul) -> Self {
        Self::EmbeddedNul
    }
}

pub fn local_only_entries() -> Vec<String> {
    let entries = env::env_list("AGENT_SAFEGUARDS_LOCAL_ONLY").unwrap_or_else(|| {
        DEFAULT_LOCAL_ONLY
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect()
    });
    entries
        .into_iter()
        .filter(|entry| {
            LOCAL_ONLY_ENTRY_FULL.is_match(entry)
                && entry
                    .chars()
                    .any(|character| character.is_ascii_alphanumeric())
                && !entry.split('/').any(|part| part == "..")
        })
        .collect()
}

pub fn local_only_paths() -> Vec<String> {
    local_only_entries()
        .into_iter()
        .map(|entry| entry.trim_end_matches('/').to_owned())
        .collect()
}

pub fn local_only_exclude_patterns() -> Vec<String> {
    local_only_entries()
        .into_iter()
        .map(|entry| format!("/{entry}"))
        .collect()
}

fn absolute_path(root: &str, value: &str) -> PathBuf {
    let source = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        Path::new(root).join(value)
    };
    let mut out = PathBuf::new();
    for component in source.components() {
        match component {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
            Component::Prefix(part) => out.push(part.as_os_str()),
        }
    }
    out
}

pub fn git_exclude_path(root: &str) -> Option<String> {
    let command = [
        "rev-parse".to_owned(),
        "--git-path".to_owned(),
        "info/exclude".to_owned(),
    ];
    let completed = git(&command, root, 20)?;
    if completed.returncode != 0 {
        return None;
    }
    let raw = std::str::from_utf8(&completed.stdout).ok()?;
    let value = python_strip(raw);
    let path = absolute_path(root, value);
    let rendered = path.to_string_lossy().into_owned();
    if !rendered.ends_with("/info/exclude") {
        return None;
    }
    Some(rendered)
}

pub fn open_without_symlinks(path: &str) -> Result<File, OpenError> {
    if path.split('/').all(str::is_empty) {
        return Err(OpenError::IndexError);
    }
    if path.contains('\0') {
        return Err(OpenError::ValueError);
    }
    sys::open_without_symlinks(path).map_err(OpenError::Io)
}

pub fn ensure_local_excludes(cwd: &str) -> Result<bool, EnsureError> {
    let patterns = local_only_exclude_patterns();
    if patterns.is_empty() {
        return Ok(false);
    }
    let Some(root) = repository_root(cwd) else {
        return Ok(false);
    };
    let Some(path) = git_exclude_path(&root) else {
        return Ok(false);
    };
    if sys::realpath(&path) != path {
        return Ok(false);
    }
    let mut handle = match open_without_symlinks(&path) {
        Ok(handle) => handle,
        Err(OpenError::ValueError) => return Err(EnsureError::ValueError),
        Err(_) => return Ok(false),
    };
    let Ok(metadata) = handle.metadata() else {
        return Ok(false);
    };
    if !metadata.is_file() || metadata.file_type().is_fifo() || metadata.file_type().is_socket() {
        return Ok(false);
    }
    if handle.lock().is_err() {
        return Ok(false);
    }
    let outcome = (|| -> io::Result<()> {
        let mut content = String::new();
        handle.read_to_string(&mut content)?;
        let existing: HashSet<&str> = python_lines(&content).into_iter().collect();
        let missing: Vec<&str> = patterns
            .iter()
            .map(String::as_str)
            .filter(|pattern| !existing.contains(pattern))
            .collect();
        if !missing.is_empty() {
            handle.seek(SeekFrom::End(0))?;
            if !content.is_empty() && !content.ends_with('\n') {
                handle.write_all(b"\n")?;
            }
            for pattern in missing {
                handle.write_all(pattern.as_bytes())?;
                handle.write_all(b"\n")?;
            }
            handle.flush()?;
            handle.sync_all()?;
        }
        Ok(())
    })();
    let unlocked = handle.unlock().is_ok();
    if outcome
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
    {
        return Err(EnsureError::UnicodeDecodeError);
    }
    Ok(outcome.is_ok() && unlocked)
}

pub fn decoded_paths(result: Option<&ProcessResult>) -> HashSet<String> {
    let Some(result) = result else {
        return HashSet::new();
    };
    if result.returncode != 0 {
        return HashSet::new();
    }
    let Ok(text) = std::str::from_utf8(&result.stdout) else {
        return HashSet::new();
    };
    text.split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn untracked_local_only_paths(root: &str) -> HashSet<String> {
    let paths = local_only_paths();
    if paths.is_empty() {
        return HashSet::new();
    }
    let mut visible = vec![
        "ls-files".to_owned(),
        "--others".to_owned(),
        "--exclude-standard".to_owned(),
        "-z".to_owned(),
        "--".to_owned(),
    ];
    visible.extend(paths.iter().cloned());
    let mut ignored = vec![
        "ls-files".to_owned(),
        "--others".to_owned(),
        "--ignored".to_owned(),
        "--exclude-standard".to_owned(),
        "-z".to_owned(),
        "--".to_owned(),
    ];
    ignored.extend(paths);
    let a = git(&visible, root, 20);
    let b = git(&ignored, root, 20);
    decoded_paths(a.as_ref())
        .union(&decoded_paths(b.as_ref()))
        .cloned()
        .collect()
}

pub fn new_staged_local_only_paths(root: &str) -> HashSet<String> {
    let paths = local_only_paths();
    if paths.is_empty() {
        return HashSet::new();
    }
    let mut command = vec![
        "diff".to_owned(),
        "--cached".to_owned(),
        "--name-only".to_owned(),
        "--diff-filter=A".to_owned(),
        "-z".to_owned(),
        "--".to_owned(),
    ];
    command.extend(paths);
    let staged = git(&command, root, 20);
    decoded_paths(staged.as_ref())
}

pub fn is_force_git_add(raw_words: &[String]) -> Result<bool, LocalOnlyError> {
    let (words, _) = unwrap(raw_words)?;
    let (subcommand, arguments) = git_subcommand(&words);
    if subcommand.as_deref() != Some("add") {
        return Ok(false);
    }
    Ok(arguments.iter().any(|argument| {
        argument == "--force"
            || (argument.starts_with('-')
                && !argument.starts_with("--")
                && argument.get(1..).is_some_and(|flags| flags.contains('f')))
    }))
}

pub fn is_safe_tool_commit(raw_words: &[String]) -> Result<bool, LocalOnlyError> {
    let (words, _) = unwrap(raw_words)?;
    if words.len() < 3 || !is_self(words.first().map(String::as_str).unwrap_or(""))? {
        return Ok(false);
    }
    Ok(words.get(1).is_some_and(|word| normalized(word) == "git")
        && words
            .get(2)
            .is_some_and(|word| normalized(word) == "commit"))
}

pub fn requires_local_artifact_approval(
    command: &str,
    cwd: Option<&str>,
) -> Result<bool, LocalOnlyError> {
    let Some(cwd) = cwd else {
        return Ok(false);
    };
    if local_only_entries().is_empty() {
        return Ok(false);
    }
    let Some(root) = repository_root(cwd) else {
        return Ok(false);
    };
    let chunks = tokenize(command);
    let mut adds = false;
    for chunk in &chunks {
        if is_force_git_add(chunk)? {
            adds = true;
            break;
        }
    }
    if adds && !untracked_local_only_paths(&root).is_empty() {
        return Ok(true);
    }
    let mut commits = false;
    for chunk in &chunks {
        if is_safe_tool_commit(chunk)? {
            commits = true;
            break;
        }
    }
    Ok(commits && !new_staged_local_only_paths(&root).is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        decoded_paths, ensure_local_excludes, is_force_git_add, is_safe_tool_commit,
        open_without_symlinks, requires_local_artifact_approval, EnsureError,
    };
    use crate::git::{assert_mock_consumed, mock_git_calls};
    use crate::process::ProcessResult;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn finished(code: i32, stdout: &[u8]) -> Option<ProcessResult> {
        Some(ProcessResult {
            returncode: code,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        })
    }

    fn root_call(root: &str) -> (Vec<String>, Option<ProcessResult>) {
        (
            vec!["rev-parse".into(), "--show-toplevel".into()],
            finished(0, format!("{root}\n").as_bytes()),
        )
    }

    #[test]
    fn force_add_is_the_bypass() {
        assert_eq!(
            is_force_git_add(&["git".into(), "add".into(), "-Af".into()]),
            Ok(true)
        );
        assert_eq!(
            is_force_git_add(&["git".into(), "add".into(), "--force".into()]),
            Ok(true)
        );
        assert_eq!(
            is_force_git_add(&["git".into(), "add".into(), "-A".into()]),
            Ok(false)
        );
        assert_eq!(
            is_safe_tool_commit(&["safe-tool".into(), "git".into(), "commit".into()]),
            Ok(true)
        );
    }

    #[test]
    fn decoded_paths_require_valid_utf8_and_success() {
        let valid = ProcessResult {
            returncode: 0,
            stdout: b"a\0b\0".to_vec(),
            stderr: vec![],
        };
        assert_eq!(decoded_paths(Some(&valid)).len(), 2);
        let invalid = ProcessResult {
            returncode: 0,
            stdout: vec![255, 0],
            stderr: vec![],
        };
        assert!(decoded_paths(Some(&invalid)).is_empty());
    }

    #[test]
    fn opens_plain_file_but_rejects_links() {
        let parent = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let base = PathBuf::from(guard_common::sys::realpath(&parent.to_string_lossy()))
            .join(format!("s7-open-{}", std::process::id()));
        let plain = base.join("plain");
        std::fs::create_dir_all(&plain).expect("create fixture");
        let file = plain.join("exclude");
        let opened = open_without_symlinks(file.to_str().expect("path")).expect("open plain file");
        drop(opened);
        let linked_file = plain.join("linked");
        symlink(&file, &linked_file).expect("link file");
        assert!(open_without_symlinks(linked_file.to_str().expect("path")).is_err());
        let linked_parent = base.join("linked-parent");
        symlink(&plain, &linked_parent).expect("link parent");
        let via_parent = linked_parent.join("exclude");
        assert!(open_without_symlinks(via_parent.to_str().expect("path")).is_err());
        std::fs::remove_file(&linked_file).expect("remove file link");
        std::fs::remove_file(&linked_parent).expect("remove parent link");
        std::fs::remove_file(&file).expect("remove plain file");
        std::fs::remove_dir(&plain).expect("remove plain directory");
        std::fs::remove_dir(&base).expect("remove fixture root");
    }

    #[test]
    fn scripted_local_file_queries_and_excludes_need_no_git_writes() {
        let previous = std::env::var("AGENT_SAFEGUARDS_LOCAL_ONLY").ok();
        std::env::set_var("AGENT_SAFEGUARDS_LOCAL_ONLY", "CLAUDE.local.md");
        let root = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("s7-local-{}", std::process::id()));
        let info = root.join("meta/info");
        std::fs::create_dir_all(&info).expect("fixture info");
        let root_text = root.to_str().expect("root path");
        let exclude = info.join("exclude");
        std::fs::write(&exclude, "existing").expect("seed fixture exclude");

        let staged = vec![
            root_call(root_text),
            (
                vec![
                    "diff".into(),
                    "--cached".into(),
                    "--name-only".into(),
                    "--diff-filter=A".into(),
                    "-z".into(),
                    "--".into(),
                    "CLAUDE.local.md".into(),
                ],
                finished(0, b"CLAUDE.local.md\0"),
            ),
        ];
        mock_git_calls(staged);
        assert_eq!(
            requires_local_artifact_approval("safe-tool git commit -m subject", Some(root_text)),
            Ok(true)
        );
        assert_mock_consumed();

        let untracked = vec![
            root_call(root_text),
            (
                vec![
                    "ls-files".into(),
                    "--others".into(),
                    "--exclude-standard".into(),
                    "-z".into(),
                    "--".into(),
                    "CLAUDE.local.md".into(),
                ],
                finished(0, b""),
            ),
            (
                vec![
                    "ls-files".into(),
                    "--others".into(),
                    "--ignored".into(),
                    "--exclude-standard".into(),
                    "-z".into(),
                    "--".into(),
                    "CLAUDE.local.md".into(),
                ],
                finished(0, b"CLAUDE.local.md\0"),
            ),
        ];
        mock_git_calls(untracked);
        assert_eq!(
            requires_local_artifact_approval("git add -f CLAUDE.local.md", Some(root_text)),
            Ok(true)
        );
        assert_mock_consumed();

        mock_git_calls(vec![
            root_call(root_text),
            (
                vec![
                    "ls-files".into(),
                    "--others".into(),
                    "--exclude-standard".into(),
                    "-z".into(),
                    "--".into(),
                    "CLAUDE.local.md".into(),
                ],
                finished(0, b""),
            ),
            (
                vec![
                    "ls-files".into(),
                    "--others".into(),
                    "--ignored".into(),
                    "--exclude-standard".into(),
                    "-z".into(),
                    "--".into(),
                    "CLAUDE.local.md".into(),
                ],
                finished(0, b""),
            ),
        ]);
        assert_eq!(
            requires_local_artifact_approval(
                "git add -f CLAUDE.local.md;git add -f CLAUDE.local.md",
                Some(root_text)
            ),
            Ok(false)
        );
        assert_mock_consumed();

        for _ in 0..2 {
            mock_git_calls(vec![
                root_call(root_text),
                (
                    vec![
                        "rev-parse".into(),
                        "--git-path".into(),
                        "info/exclude".into(),
                    ],
                    finished(0, b"meta/info/exclude\n"),
                ),
            ]);
            assert_eq!(ensure_local_excludes(root_text), Ok(true));
            assert_mock_consumed();
        }
        assert_eq!(
            std::fs::read_to_string(&exclude).expect("read fixture exclude"),
            "existing\n/CLAUDE.local.md\n"
        );
        std::fs::write(&exclude, "existing\r/CLAUDE.local.md").expect("seed alternate line break");
        mock_git_calls(vec![
            root_call(root_text),
            (
                vec![
                    "rev-parse".into(),
                    "--git-path".into(),
                    "info/exclude".into(),
                ],
                finished(0, b"meta/info/exclude\n"),
            ),
        ]);
        assert_eq!(ensure_local_excludes(root_text), Ok(true));
        assert_mock_consumed();
        assert_eq!(
            std::fs::read_to_string(&exclude).expect("read fixture exclude"),
            "existing\r/CLAUDE.local.md"
        );
        std::fs::write(&exclude, [0xff]).expect("seed malformed UTF-8");
        mock_git_calls(vec![
            root_call(root_text),
            (
                vec![
                    "rev-parse".into(),
                    "--git-path".into(),
                    "info/exclude".into(),
                ],
                finished(0, b"meta/info/exclude\n"),
            ),
        ]);
        assert_eq!(
            ensure_local_excludes(root_text),
            Err(EnsureError::UnicodeDecodeError)
        );
        assert_mock_consumed();
        mock_git_calls(vec![
            root_call(root_text),
            (
                vec![
                    "rev-parse".into(),
                    "--git-path".into(),
                    "info/exclude".into(),
                ],
                finished(0, b"meta/\0/info/exclude\n"),
            ),
        ]);
        assert_eq!(
            ensure_local_excludes(root_text),
            Err(EnsureError::ValueError)
        );
        assert_mock_consumed();
        std::fs::remove_file(&exclude).expect("remove fixture exclude");
        std::fs::remove_dir(&info).expect("remove info");
        std::fs::remove_dir(root.join("meta")).expect("remove meta");
        std::fs::remove_dir(&root).expect("remove fixture root");
        if let Some(value) = previous {
            std::env::set_var("AGENT_SAFEGUARDS_LOCAL_ONLY", value);
        } else {
            std::env::remove_var("AGENT_SAFEGUARDS_LOCAL_ONLY");
        }
    }
}
