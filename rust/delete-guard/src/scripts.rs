use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::Duration;

use guard_common::env::user_home;
use guard_common::locale::{message, FormatValue};
use guard_common::shell::{
    command_substitutions, expand_braces, heredocs, strip_wrappers, HEREDOC_FORBIDDEN,
};
use guard_common::sys::realpath;
use regex::Regex;

use crate::check::{check_command_weighted, NESTED_FRAMES};
use crate::consts::{
    self, MAX_SCRIPT_BYTES, MAX_SCRIPT_DEPTH, SHELL_SHEBANG, TEXT_HEREDOC_OWNER, TEXT_HEREDOC_TAIL,
    VETTED_COMMANDS, VETTED_MENTION,
};
use crate::errors::{Denied, Stop};
use crate::find::stdin_files;
use crate::globs::glob_matches;
use crate::places::inside;
use crate::targets::repository_root;
use crate::tokens::{base, expand, tokenize, variables_changed_state};

#[derive(Clone, Hash, Eq, PartialEq)]
struct ScriptKey {
    path: String,
    size: u64,
    mtime_ns: i128,
    cwd: Option<String>,
    stdin: Vec<(String, Option<String>)>,
    variables: Vec<String>,
}

thread_local! {
    static SCRIPT_STACK: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static SCRIPT_CACHE: RefCell<HashMap<ScriptKey, bool>> = RefCell::new(HashMap::new());
    static VETTED_CACHE: RefCell<VecDeque<(Option<String>, bool)>> = const { RefCell::new(VecDeque::new()) };
}

static TEXT_HEAD_SPLIT: LazyLock<Regex> = LazyLock::new(|| regex(r"&&|\|\||;|\||&"));
static TEXT_OWNER_FULL: LazyLock<Regex> =
    LazyLock::new(|| regex(&format!(r"\A(?:{})\z", TEXT_HEREDOC_OWNER.as_str())));
static SCRIPT_WILDCARD: LazyLock<Regex> = LazyLock::new(|| regex(r"[*?\[]"));
static BRACE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    regex(
        r"\{([^{}]*,[^{}]*)\}|\{(-?\d{1,30}|[A-Za-z])\.\.(-?\d{1,30}|[A-Za-z])(?:\.\.(-?\d{1,30}))?\}",
    )
});

fn regex(pattern: &str) -> Regex {
    guard_common::pyre::new(pattern).unwrap_or_else(|error| panic!("fixed regex: {error}"))
}

fn value(text: &str) -> FormatValue {
    FormatValue::Text(text.to_owned())
}

fn denial(key: &str, values: &[(&str, FormatValue)]) -> Stop {
    Stop::Denied(Denied::new(message(key, values)))
}

fn byte_index(text: &str, char_index: usize) -> usize {
    text.char_indices()
        .nth(char_index)
        .map_or(text.len(), |(at, _)| at)
}

fn chars(text: &str, start: usize, end: usize) -> &str {
    text.get(byte_index(text, start)..byte_index(text, end))
        .unwrap_or("")
}

pub fn is_reviewed_script(path: &str, data: &[u8]) -> Result<bool, Stop> {
    let dirname = Path::new(path)
        .parent()
        .map_or("", |part| part.to_str().unwrap_or(""));
    let Some(root) = repository_root(Some(dirname)) else {
        return Ok(false);
    };
    let Some(git) = consts::git_path() else {
        return Ok(false);
    };
    if !inside(path, &root) {
        return Ok(false);
    }
    let Some(relative) = Path::new(path).strip_prefix(&root).ok() else {
        return Ok(false);
    };
    let argument = format!("HEAD:{}", relative.to_string_lossy());
    if argument.contains('\0') || root.contains('\0') {
        return Err(Stop::Internal);
    }
    let mut child = match Command::new(git)
        .args(["-C", &root, "cat-file", "blob", &argument])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", user_home())
        .env("LC_ALL", "C")
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return Ok(false),
    };
    let stdout = child.stdout.take().map(|mut stream| {
        std::thread::spawn(move || {
            let mut output = Vec::new();
            stream.read_to_end(&mut output).map(|_| output)
        })
    });
    let stderr = child.stderr.take().map(|mut stream| {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stream, &mut std::io::sink());
        })
    });
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = stdout
                    .and_then(|handle| handle.join().ok())
                    .and_then(Result::ok);
                if let Some(handle) = stderr {
                    let _ = handle.join();
                }
                return Ok(status.success() && output.as_deref() == Some(data));
            }
            Ok(None) if start.elapsed() < Duration::from_secs(3) => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(false);
            }
            Err(_) => return Ok(false),
        }
    }
}

pub fn script_excluded(path: &str) -> bool {
    let (parent, filename) = path.rsplit_once('/').unwrap_or(("", path));
    let parent = if parent.is_empty() && path.starts_with('/') {
        "/"
    } else {
        parent
    };
    (parent == user_home() && filename.starts_with('.'))
        || consts::etc_paths().iter().any(|root| inside(path, root))
}

pub fn read_regular_file(path: &str, limit: usize) -> Result<Option<Vec<u8>>, Stop> {
    if path.contains('\0') {
        return Err(Stop::Internal);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    options.custom_flags(4);
    #[cfg(target_os = "linux")]
    options.custom_flags(2048);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    match file.metadata() {
        Ok(metadata) if metadata.is_file() => {}
        _ => return Ok(None),
    }
    let mut data = Vec::new();
    let mut remaining = limit.saturating_add(1);
    while remaining > 0 {
        let mut buffer = vec![0u8; remaining.min(65536)];
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                data.extend_from_slice(buffer.get(..count).unwrap_or(&[]));
                remaining = remaining.saturating_sub(count);
            }
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(data))
}

pub fn without_text_heredocs(text: &str) -> String {
    let mut pieces = Vec::new();
    let mut position = 0;
    for document in heredocs(text) {
        if document.outer.is_some() || !document.quoted || document.body_start < position {
            continue;
        }
        let head = chars(text, document.line_start, document.marker_start);
        let tail = TEXT_HEAD_SPLIT.split(head).last().unwrap_or("");
        if TEXT_OWNER_FULL.is_match(tail)
            && !TEXT_HEREDOC_TAIL.is_match(chars(text, document.delimiter_end, document.line_end))
        {
            pieces.push(chars(text, position, document.body_start));
            position = document.end;
        }
    }
    pieces.push(chars(text, position, text.chars().count()));
    let stripped = pieces.join("");
    if HEREDOC_FORBIDDEN.is_match(&stripped) {
        text.to_owned()
    } else {
        stripped
    }
}

pub fn check_script(raw: &str, cwd: Option<&str>, shell: bool) -> Result<(), Stop> {
    check_script_file(raw, cwd, shell)?;
    if (raw.contains('{') && BRACE_PATTERN.is_match(raw)) || SCRIPT_WILDCARD.is_match(raw) {
        let variants = expand_braces(raw)
            .map_err(|_| Stop::Internal)?
            .ok_or_else(|| {
                denial(
                    "delete_guard.reason.expansion",
                    &[("verb", value("script")), ("raw", value(raw))],
                )
            })?;
        for variant in variants {
            let matches = glob_matches(&variant, cwd, "script").map_err(Stop::from)?;
            let names = if matches.is_empty() && !SCRIPT_WILDCARD.is_match(&variant) {
                vec![variant]
            } else {
                matches
            };
            for name in names {
                check_script_file(&name, cwd, shell)?;
            }
        }
    }
    Ok(())
}

pub fn check_script_file(raw: &str, cwd: Option<&str>, shell: bool) -> Result<(), Stop> {
    let Some(resolved) = expand(raw, cwd).map_err(Stop::from)? else {
        return Ok(());
    };
    if SCRIPT_STACK.with(|stack| {
        stack.borrow().contains(&resolved) || stack.borrow().len() >= MAX_SCRIPT_DEPTH
    }) || script_excluded(&resolved)
    {
        return Ok(());
    }
    let Some(data) = read_regular_file(&resolved, MAX_SCRIPT_BYTES)? else {
        return Ok(());
    };
    if data.len() > MAX_SCRIPT_BYTES || data.get(..data.len().min(1024)).unwrap_or(&[]).contains(&0)
    {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&data);
    if !shell
        && SHELL_SHEBANG
            .find(&text)
            .is_none_or(|found| found.start() != 0)
    {
        return Ok(());
    }
    let status = match fs::metadata(&resolved) {
        Ok(status) => status,
        Err(_) => return Ok(()),
    };
    let mut variables: Vec<String> = variables_changed_state().into_iter().collect();
    variables.sort();
    let key = ScriptKey {
        path: resolved.clone(),
        size: status.len(),
        mtime_ns: i128::from(status.mtime())
            .saturating_mul(1_000_000_000)
            .saturating_add(i128::from(status.mtime_nsec())),
        cwd: cwd.map(str::to_owned),
        stdin: stdin_files(),
        variables,
    };
    if SCRIPT_CACHE.with(|cache| cache.borrow().get(&key).copied().unwrap_or(false)) {
        return Ok(());
    }
    if is_reviewed_script(&resolved, &data)? {
        SCRIPT_CACHE.with(|cache| {
            cache.borrow_mut().insert(key, true);
        });
        return Ok(());
    }
    SCRIPT_STACK.with(|stack| stack.borrow_mut().push(resolved.clone()));
    let result = check_command_weighted(&without_text_heredocs(&text), cwd, NESTED_FRAMES);
    SCRIPT_STACK.with(|stack| {
        stack.borrow_mut().pop();
    });
    match result {
        Ok(()) => {
            SCRIPT_CACHE.with(|cache| {
                cache.borrow_mut().insert(key, true);
            });
            Ok(())
        }
        Err(Stop::Denied(reason)) => {
            let text = message(
                "delete_guard.reason.in_script",
                &[
                    ("script", value(&resolved)),
                    ("reason", value(reason.reason())),
                ],
            );
            Err(Stop::Denied(if reason.is_remote() {
                Denied::remote(text)
            } else {
                Denied::new(text)
            }))
        }
        Err(other) => Err(other),
    }
}

pub fn search_path(name: &str) -> Option<String> {
    if name.contains('\0') {
        return None;
    }
    if name.contains('/') {
        return guard_common::sys::access_executable(name).then(|| realpath(name));
    }
    let raw_path = std::env::var("PATH").unwrap_or_default();
    let path = format!(
        "{raw_path}:{}",
        Path::new(user_home()).join(".local/bin").to_string_lossy()
    );
    for directory in path.split(':') {
        let candidate = Path::new(if directory.is_empty() { "." } else { directory }).join(name);
        if guard_common::sys::access_executable(&candidate.to_string_lossy()) {
            return Some(realpath(&candidate.to_string_lossy()));
        }
    }
    None
}

pub fn without_heredoc_bodies(text: &str) -> String {
    let mut pieces = Vec::new();
    let mut position = 0;
    for document in heredocs(text) {
        if document.outer.is_none() && document.body_start >= position {
            pieces.push(chars(text, position, document.body_start));
            position = document.end;
        }
    }
    pieces.push(chars(text, position, text.chars().count()));
    pieces.join("")
}

pub fn runs_checker(text: &str, depth: usize) -> bool {
    if depth > MAX_SCRIPT_DEPTH || !VETTED_MENTION.is_match(text) {
        return false;
    }
    let without = without_heredoc_bodies(text);
    if command_substitutions(&without)
        .iter()
        .any(|body| runs_checker(body, depth.saturating_add(1)))
    {
        return true;
    }
    for chunk in tokenize(&without).unwrap_or_default() {
        let Ok(words) = strip_wrappers(&chunk.words, &HashSet::<&str>::new()) else {
            continue;
        };
        if words.len() > 1
            && words
                .first()
                .is_some_and(|word| base(word) == "delete-guard")
            && words
                .get(1)
                .is_some_and(|word| VETTED_COMMANDS.contains(&word.as_str()))
        {
            return true;
        }
    }
    false
}

pub fn vets_deletes(path: Option<&str>) -> Result<bool, Stop> {
    let key = path.map(str::to_owned);
    if let Some(value) = VETTED_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let index = cache.iter().position(|(name, _)| *name == key)?;
        let pair = cache.remove(index)?;
        let value = pair.1;
        cache.push_back(pair);
        Some(value)
    }) {
        return Ok(value);
    }
    let value = if let Some(path) = path {
        if script_excluded(path) {
            false
        } else {
            let data = read_regular_file(path, 65536)?;
            data.is_some_and(|bytes| {
                runs_checker(
                    &String::from_utf8_lossy(bytes.get(..bytes.len().min(65536)).unwrap_or(&[])),
                    0,
                )
            })
        }
    } else {
        false
    };
    VETTED_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= 32 {
            cache.pop_front();
        }
        cache.push_back((key, value));
    });
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{check_script_file, runs_checker, without_heredoc_bodies, without_text_heredocs};
    use std::fs;

    #[test]
    fn quoted_cat_heredoc_is_text_but_pipeline_is_not() {
        let text = "cat <<'EOF'\nrm -rf /\nEOF\necho done\n";
        assert!(!without_text_heredocs(text).contains("rm -rf /"));
        let pipeline = "cat <<'EOF' | sh\nrm -rf /\nEOF\n";
        assert_eq!(without_text_heredocs(pipeline), pipeline);
    }

    #[test]
    fn checker_must_run_as_a_command() {
        assert!(runs_checker("sudo delete-guard check-remote x", 0));
        assert!(runs_checker("value=$(delete-guard remote-preflight x)", 0));
        assert!(!runs_checker("echo 'delete-guard check-remote x'", 0));
        assert!(!runs_checker(
            "cat <<EOF\ndelete-guard check-remote x\nEOF\n",
            0
        ));
        assert!(!runs_checker("delete-guard check-remote x", 4));
    }

    #[test]
    fn all_heredoc_bodies_are_removed_from_checker_scan() {
        let text = "cat <<EOF\ndelete-guard check-remote x\nEOF\necho done\n";
        assert!(!without_heredoc_bodies(text).contains("delete-guard check-remote"));
    }

    #[test]
    fn changed_script_is_rechecked_after_a_clean_cache_entry() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("d4-cache-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&root).expect("directory");
        let script = root.join("task.sh");
        fs::write(&script, "#!/bin/sh\necho okay\n").expect("safe script");
        let raw = script.to_string_lossy();
        let cwd = root.to_string_lossy();
        assert!(check_script_file(&raw, Some(&cwd), true).is_ok());
        fs::write(&script, "#!/bin/sh\nrm -rf /\n").expect("changed script");
        assert!(check_script_file(&raw, Some(&cwd), true).is_err());
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
