use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::fs::{self, DirEntry};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use guard_common::env::user_home;
use guard_common::locale::{message, FormatValue};
use guard_common::shell::{brace_options, expand_braces};
use guard_common::sys::realpath;

use crate::consts::{
    self, LOCATION_SCHEME, MATCH_MARK, REMOTE_UNSAFE_AFTER_QUOTES, REMOTE_UNSAFE_PATH, TRASH_URI,
};
use crate::errors::{Denied, Stop};
use crate::globs::{glob_matches, holds_trash, GlobError};
use crate::places::{glob_base, inside, names_trash, protected, trash_roots};
use crate::tokens::{expand, is_computed};

thread_local! {
    static REMOTE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    static REMOTE_TARGETS: RefCell<Vec<(String, bool)>> = const { RefCell::new(Vec::new()) };
    static QUOTED_WORDS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

type CachedRoot = (Option<String>, Option<String>);
static REPOSITORY_CACHE: LazyLock<Mutex<VecDeque<CachedRoot>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

fn denial(key: &str, values: &[(&str, FormatValue)]) -> Stop {
    Stop::Denied(Denied::new(message(key, values)))
}

fn remote_denial(key: &str, values: &[(&str, FormatValue)]) -> Stop {
    Stop::Denied(Denied::remote(message(key, values)))
}

fn expansion(verb: &str, raw: &str) -> Stop {
    denial(
        "delete_guard.reason.expansion",
        &[
            ("verb", FormatValue::Text(verb.to_owned())),
            ("raw", FormatValue::Text(raw.to_owned())),
        ],
    )
}

fn path_value(path: &str) -> FormatValue {
    FormatValue::Text(path.to_owned())
}

pub fn set_remote(roots: Option<Vec<String>>) {
    REMOTE.with(|slot| *slot.borrow_mut() = roots);
}
pub fn remote() -> Option<Vec<String>> {
    REMOTE.with(|slot| slot.borrow().clone())
}
pub fn remote_targets() -> Vec<(String, bool)> {
    REMOTE_TARGETS.with(|slot| slot.borrow().clone())
}
pub fn clear_remote_targets() {
    REMOTE_TARGETS.with(|slot| slot.borrow_mut().clear());
}
pub fn set_quoted_words(words: HashSet<String>) {
    QUOTED_WORDS.with(|slot| *slot.borrow_mut() = words);
}
pub fn quoted_words() -> HashSet<String> {
    QUOTED_WORDS.with(|slot| slot.borrow().clone())
}

pub fn is_folder_path(path: &str, verb: &str, raw: &str) -> Result<bool, Stop> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            Ok(false)
        }
        Err(_) => Err(expansion(verb, raw)),
    }
}

pub fn is_plain_folder(entry: &DirEntry, verb: &str, raw: &str) -> Result<bool, Stop> {
    entry
        .file_type()
        .map(|kind| kind.is_dir())
        .map_err(|_| expansion(verb, raw))
}

pub fn check_match_mark(raw: &str, verb: &str) -> Result<(), Stop> {
    if raw.contains(MATCH_MARK) {
        return Err(denial(
            "delete_guard.reason.match_path",
            &[
                ("verb", path_value(verb)),
                ("raw", path_value(&raw.replace(MATCH_MARK, "{}"))),
            ],
        ));
    }
    Ok(())
}

pub fn check_resolved(
    resolved: &str,
    cwd: Option<&str>,
    recursive: bool,
    verb: &str,
) -> Result<(), Stop> {
    if protected(resolved) {
        return Err(denial(
            "delete_guard.reason.protected_folder",
            &[("verb", path_value(verb)), ("path", path_value(resolved))],
        ));
    }
    if consts::temp_roots()
        .iter()
        .any(|root| inside(resolved, root))
    {
        return Ok(());
    }
    let root = repository_root(cwd);
    let Some(root) = root else {
        return Err(denial(
            "delete_guard.reason.outside_repository",
            &[("verb", path_value(verb)), ("path", path_value(resolved))],
        ));
    };
    if !inside(resolved, &root) {
        return Err(denial(
            "delete_guard.reason.outside_repository",
            &[("verb", path_value(verb)), ("path", path_value(resolved))],
        ));
    }
    if resolved == root {
        return Err(denial(
            "delete_guard.reason.repository_root",
            &[("verb", path_value(verb)), ("path", path_value(resolved))],
        ));
    }
    let git = format!("{root}/.git");
    if resolved == git || inside(resolved, &git) {
        return Err(denial(
            "delete_guard.reason.git_metadata",
            &[("verb", path_value(verb)), ("path", path_value(resolved))],
        ));
    }
    if recursive
        && fs::metadata(resolved).is_ok_and(|metadata| metadata.is_dir())
        && fs::metadata(format!("{resolved}/.git")).is_ok_and(|metadata| metadata.is_file())
    {
        return Err(denial(
            "delete_guard.reason.worktree",
            &[("path", path_value(resolved))],
        ));
    }
    Ok(())
}

pub fn check_sendable(resolved: &str) -> Result<(), Stop> {
    if in_trash(resolved) || trash_roots().iter().any(|root| inside(root, resolved)) {
        return Err(denial(
            "delete_guard.reason.trash_inside",
            &[("path", path_value(resolved))],
        ));
    }
    if protected(resolved) {
        return Err(denial(
            "delete_guard.reason.trash_protected",
            &[("path", path_value(resolved))],
        ));
    }
    Ok(())
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes.get(index) == Some(&b'%') {
            if let (Some(&hi), Some(&lo)) = (
                bytes.get(index.saturating_add(1)),
                bytes.get(index.saturating_add(2)),
            ) {
                let digit = |value: u8| -> Option<u8> {
                    match value {
                        b'0'..=b'9' => Some(value - b'0'),
                        b'a'..=b'f' => Some(value - b'a' + 10),
                        b'A'..=b'F' => Some(value - b'A' + 10),
                        _ => None,
                    }
                };
                if let (Some(hi), Some(lo)) = (digit(hi), digit(lo)) {
                    decoded.push(hi.saturating_mul(16).saturating_add(lo));
                    index = index.saturating_add(3);
                    continue;
                }
            }
        }
        if let Some(&byte) = bytes.get(index) {
            decoded.push(byte)
        }
        index = index.saturating_add(1);
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn invalid_nfkc_netloc_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{2047}'
            | '\u{2048}'
            | '\u{2049}'
            | '\u{2100}'
            | '\u{2101}'
            | '\u{2105}'
            | '\u{2106}'
            | '\u{2a74}'
            | '\u{fe13}'
            | '\u{fe16}'
            | '\u{fe55}'
            | '\u{fe56}'
            | '\u{fe5f}'
            | '\u{fe6b}'
            | '\u{ff03}'
            | '\u{ff0f}'
            | '\u{ff1a}'
            | '\u{ff1f}'
            | '\u{ff20}'
    )
}

pub fn location_path(raw: &str, verb: &str, strict: bool) -> Result<String, GlobError> {
    if remote().is_some()
        || TRASH_URI.find(raw).is_some_and(|found| found.start() == 0)
        || LOCATION_SCHEME
            .find(raw)
            .is_none_or(|found| found.start() != 0)
    {
        return Ok(raw.to_owned());
    }
    let cleaned: String = raw
        .chars()
        .filter(|ch| !matches!(ch, '\n' | '\r' | '\t'))
        .collect();
    let Some(colon) = cleaned.find(':') else {
        return Ok(raw.to_owned());
    };
    let scheme = cleaned.get(..colon).unwrap_or("");
    let rest = cleaned.get(colon.saturating_add(1)..).unwrap_or("");
    let (netloc, path) = if let Some(authority) = rest.strip_prefix("//") {
        let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        (
            &authority.get(..end).unwrap_or(""),
            authority.get(end..).unwrap_or(""),
        )
    } else {
        (&"", rest)
    };
    if netloc.chars().any(invalid_nfkc_netloc_char) {
        return Err(GlobError::Value(format!(
            "netloc '{netloc}' contains invalid characters under NFKC normalization"
        )));
    }
    if netloc.contains('[') || netloc.contains(']') {
        let Some(open) = netloc.find('[') else {
            return Err(GlobError::Value("Invalid IPv6 URL".to_owned()));
        };
        let Some(close) = netloc.find(']') else {
            return Err(GlobError::Value("Invalid IPv6 URL".to_owned()));
        };
        if close < open {
            return Err(GlobError::Value("Invalid IPv6 URL".to_owned()));
        }
        let host = netloc.get(open.saturating_add(1)..close).unwrap_or("");
        if let Some(rest) = host.strip_prefix('v') {
            let valid = rest.split_once('.').is_some_and(|(version, address)| {
                !version.is_empty()
                    && version.chars().all(|ch| ch.is_ascii_hexdigit())
                    && !address.is_empty()
            });
            if !valid {
                return Err(GlobError::Value("IPvFuture address is invalid".to_owned()));
            }
        } else if host.parse::<Ipv4Addr>().is_ok() {
            return Err(GlobError::Value(
                "An IPv4 address cannot be in brackets".to_owned(),
            ));
        } else if host.parse::<Ipv6Addr>().is_err() {
            return Err(GlobError::Value(format!(
                "'{host}' does not appear to be an IPv4 or IPv6 address"
            )));
        }
    }
    if scheme.eq_ignore_ascii_case("file") && (netloc.is_empty() || *netloc == "localhost") {
        let end = path.find(['?', '#']).unwrap_or(path.len());
        return Ok(unquote(path.get(..end).unwrap_or("")));
    }
    if strict {
        Err(denial(
            "delete_guard.reason.location",
            &[("verb", path_value(verb)), ("raw", path_value(raw))],
        )
        .into())
    } else {
        Ok(raw.to_owned())
    }
}

pub fn in_trash(path: &str) -> bool {
    names_trash(path)
        || inside(path, "/boot/trash")
        || trash_roots().iter().any(|root| inside(path, root))
}

pub fn quoted_literal_words(text: &str) -> HashSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut words = HashSet::new();
    let mut patterns = HashSet::new();
    let mut current = String::new();
    let mut risky = false;
    let mut started = false;
    let mut index = 0usize;
    while index <= chars.len() {
        let character = chars.get(index).copied().unwrap_or(' ');
        if " \t\n;|&<>".contains(character) {
            if started {
                if risky {
                    patterns.insert(current.clone());
                } else {
                    words.insert(current.clone());
                }
            }
            current.clear();
            risky = false;
            started = false;
            index = index.saturating_add(1);
        } else if character == '\'' {
            let closing = chars
                .iter()
                .enumerate()
                .skip(index.saturating_add(1))
                .find_map(|(at, &ch)| (ch == '\'').then_some(at));
            let Some(closing) = closing else { break };
            current.extend(chars.get(index.saturating_add(1)..closing).unwrap_or(&[]));
            started = true;
            index = closing.saturating_add(1);
        } else if character == '"' {
            index = index.saturating_add(1);
            started = true;
            while let Some(&ch) = chars.get(index) {
                if ch == '"' {
                    break;
                }
                if ch == '\\'
                    && chars
                        .get(index.saturating_add(1))
                        .is_some_and(|next| "\"\\$`".contains(*next))
                {
                    if let Some(&next) = chars.get(index.saturating_add(1)) {
                        current.push(next)
                    }
                    index = index.saturating_add(2);
                    continue;
                }
                if ch == '$' || ch == '`' {
                    risky = true
                }
                current.push(ch);
                index = index.saturating_add(1);
            }
            index = index.saturating_add(1);
        } else if character == '\\' && index.saturating_add(1) < chars.len() {
            if chars.get(index.saturating_add(1)) != Some(&'\n') {
                if let Some(&next) = chars.get(index.saturating_add(1)) {
                    current.push(next)
                }
                started = true;
            }
            index = index.saturating_add(2);
        } else {
            if consts::RELAXED_CHARACTERS.contains(&character.to_string().as_str())
                || character == '$'
                || character == '`'
            {
                risky = true
            }
            current.push(character);
            started = true;
            index = index.saturating_add(1);
        }
    }
    words.difference(&patterns).cloned().collect()
}

pub fn remote_literal(raw: &str) -> Option<String> {
    let path = if raw == "/" {
        raw
    } else {
        raw.trim_end_matches('/')
    };
    let anchored = path.starts_with("~/") || path.starts_with('/');
    let components: Vec<&str> = if anchored {
        path.split('/').skip(1).collect()
    } else {
        Vec::new()
    };
    let quoted = QUOTED_WORDS.with(|slot| slot.borrow().contains(raw));
    let unsafe_pattern = if quoted {
        &*REMOTE_UNSAFE_AFTER_QUOTES
    } else {
        &*REMOTE_UNSAFE_PATH
    };
    if !anchored
        || unsafe_pattern.is_match(path)
        || components.is_empty()
        || components
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        None
    } else {
        Some(path.to_owned())
    }
}

pub fn remote_trash_protected(path: &str) -> bool {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if path.starts_with("~/") {
        return parts.len() < 3;
    }
    let top = format!("/{}", parts.first().copied().unwrap_or(""));
    if consts::REMOTE_TRASH_SYSTEM_TREES.contains(&top.as_str()) {
        return true;
    }
    if consts::REMOTE_HOME_PARENTS.contains(&top.as_str()) {
        return parts.len() < 4;
    }
    if top == "/root" || consts::in_system_roots(&top) {
        return parts.len() < 3;
    }
    parts.len() < 2
}

pub fn repository_root(cwd: Option<&str>) -> Option<String> {
    let key = cwd.map(str::to_owned);
    {
        let mut cache = REPOSITORY_CACHE
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(index) = cache.iter().position(|(cached, _)| cached == &key) {
            if let Some((cached, value)) = cache.remove(index) {
                cache.push_back((cached, value.clone()));
                return value;
            }
        }
    }
    let result = cwd.and_then(|cwd| {
        if consts::git_path().is_none()
            || !fs::metadata(cwd).is_ok_and(|metadata| metadata.is_dir())
        {
            None
        } else {
            repository_root_uncached(cwd)
        }
    });
    let mut cache = REPOSITORY_CACHE
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if cache.len() >= 32 {
        cache.pop_front();
    }
    cache.push_back((key, result.clone()));
    result
}

fn repository_root_uncached(cwd: &str) -> Option<String> {
    let git = consts::git_path()?;
    let mut child = Command::new(git)
        .args(["-C", cwd, "rev-parse", "--show-toplevel"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", user_home())
        .env("LC_ALL", "C")
        .spawn()
        .ok()?;
    let deadline = Instant::now().checked_add(Duration::from_secs(5))?;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let completed = child.wait_with_output().ok()?;
    if !completed.status.success() {
        return None;
    }
    let root = realpath(String::from_utf8_lossy(&completed.stdout).trim());
    if root.is_empty() || protected(&root) {
        None
    } else {
        Some(root)
    }
}

pub fn check_remote_target(raw: &str, verb: &str) -> Result<(), Stop> {
    let path = remote_literal(raw);
    let allowed = path.as_deref().is_some_and(|path| {
        remote()
            .unwrap_or_default()
            .iter()
            .any(|root| path.starts_with(&format!("{root}/")))
    });
    if !allowed {
        return Err(remote_denial(
            "delete_guard.reason.remote_target",
            &[("verb", path_value(verb)), ("raw", path_value(raw))],
        ));
    }
    let Some(path) = path else { return Ok(()) };
    let entered = raw.ends_with('/') && raw != "/";
    REMOTE_TARGETS.with(|slot| {
        let mut targets = slot.borrow_mut();
        targets.push((path.clone(), entered || verb.starts_with("rsync")));
        if verb.starts_with("rsync") && !entered {
            targets.push((path, false));
        }
    });
    Ok(())
}

pub fn check_remote_trash_target(raw: &str) -> Result<(), Stop> {
    let path = remote_literal(raw);
    let Some(path) = path else {
        return Err(remote_denial(
            "delete_guard.reason.remote_trash",
            &[("raw", path_value(raw))],
        ));
    };
    if remote_trash_protected(&path) {
        return Err(remote_denial(
            "delete_guard.reason.remote_trash",
            &[("raw", path_value(raw))],
        ));
    }
    if names_trash(&path) {
        return Err(remote_denial(
            "delete_guard.reason.trash_inside",
            &[("path", path_value(raw))],
        ));
    }
    Ok(())
}

pub fn check_target(
    raw: &str,
    cwd: Option<&str>,
    recursive: bool,
    verb: &str,
    literal: Option<bool>,
) -> Result<(), GlobError> {
    if names_trash(raw) {
        return Err(denial(
            "delete_guard.reason.trash_purge",
            &[("verb", path_value(verb)), ("path", path_value(raw))],
        )
        .into());
    }
    if remote().is_some() {
        return check_remote_target(raw, verb).map_err(Into::into);
    }
    check_match_mark(raw, verb)?;
    let literal = literal.unwrap_or_else(|| QUOTED_WORDS.with(|slot| slot.borrow().contains(raw)));
    if !literal && raw.contains('{') && brace_options(raw).is_ok() {
        match expand_braces(raw) {
            Ok(Some(variants)) => {
                for variant in variants {
                    check_target(&variant, cwd, recursive, verb, Some(false))?;
                }
                return Ok(());
            }
            Err(_) => return Err(GlobError::Value("invalid brace expansion".to_owned())),
            Ok(None) => return Err(expansion(verb, raw).into()),
        }
    }
    if is_computed(raw) {
        if recursive {
            return Err(denial(
                "delete_guard.reason.computed_path",
                &[("verb", path_value(verb)), ("raw", path_value(raw))],
            )
            .into());
        }
        return Ok(());
    }
    let base = if literal {
        raw.to_owned()
    } else {
        glob_base(raw)
    };
    if base != raw && recursive && base.trim_matches(['.', '/']).is_empty() {
        return Err(denial(
            "delete_guard.reason.bare_glob",
            &[("verb", path_value(verb)), ("raw", path_value(raw))],
        )
        .into());
    }
    if !literal && recursive {
        if let Some(wildcard) = raw.find(['*', '?', '[']) {
            if let Some(slash) = raw
                .get(wildcard..)
                .and_then(|tail| tail.find('/'))
                .map(|at| at.saturating_add(wildcard))
            {
                if !raw.get(slash..).unwrap_or("").trim_matches('/').is_empty() {
                    return Err(denial(
                        "delete_guard.reason.glob_midpath",
                        &[("verb", path_value(verb)), ("raw", path_value(raw))],
                    )
                    .into());
                }
            }
        }
    }
    let resolved = match expand(&base, cwd) {
        Ok(Some(path)) => path,
        Ok(None) => {
            return Err(denial(
                "delete_guard.reason.unresolvable",
                &[("verb", path_value(verb)), ("raw", path_value(raw))],
            )
            .into())
        }
        Err(_) => return Err(GlobError::Value("embedded null byte".to_owned())),
    };
    if in_trash(&resolved) {
        return Err(denial(
            "delete_guard.reason.trash_purge",
            &[("verb", path_value(verb)), ("path", path_value(&resolved))],
        )
        .into());
    }
    if !literal {
        for matched in glob_matches(raw, cwd, verb)? {
            let found = realpath(&matched);
            if names_trash(&matched)
                || in_trash(&found)
                || (recursive && is_folder_path(&found, verb, raw)? && holds_trash(&found))
            {
                return Err(denial(
                    "delete_guard.reason.trash_purge",
                    &[("verb", path_value(verb)), ("path", path_value(&matched))],
                )
                .into());
            }
            check_resolved(&found, cwd, recursive, verb)?;
        }
    }
    if recursive && base == raw && is_folder_path(&resolved, verb, raw)? && holds_trash(&resolved) {
        return Err(denial(
            "delete_guard.reason.trash_holder",
            &[("verb", path_value(verb)), ("path", path_value(&resolved))],
        )
        .into());
    }
    if base != raw && consts::temp_roots().contains(&resolved) {
        let suffix = raw.chars().skip(base.chars().count()).collect::<String>();
        let first = suffix
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("");
        let prefix = first.split(['*', '?', '[']).next().unwrap_or("");
        if prefix
            .chars()
            .any(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Ok(());
        }
    }
    check_resolved(&resolved, cwd, recursive, verb).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{
        check_remote_target, quoted_literal_words, remote_literal, remote_targets,
        remote_trash_protected, set_quoted_words, set_remote,
    };
    use std::collections::HashSet;

    #[test]
    fn quoted_route_names_are_literal_remote_targets() {
        set_quoted_words(quoted_literal_words("rm '~/ci/[lang]/page.tsx'"));
        assert_eq!(
            remote_literal("~/ci/[lang]/page.tsx"),
            Some("~/ci/[lang]/page.tsx".to_owned())
        );
        set_quoted_words(HashSet::new());
        assert_eq!(remote_literal("~/ci/[lang]/page.tsx"), None);
    }

    #[test]
    fn remote_roots_are_strict_and_rsync_records_entered_target() {
        set_remote(Some(vec!["~/ci".to_owned()]));
        super::clear_remote_targets();
        assert!(check_remote_target("~/ci/run", "rsync --delete").is_ok());
        assert_eq!(
            remote_targets(),
            vec![
                ("~/ci/run".to_owned(), true),
                ("~/ci/run".to_owned(), false)
            ]
        );
        assert!(check_remote_target("~/ci", "rm").is_err());
        assert!(check_remote_target("~/ci/../other", "rm").is_err());
        set_remote(None);
    }

    #[test]
    fn remote_trash_depth_protects_home_and_system_trees() {
        assert!(remote_trash_protected("~/ci"));
        assert!(!remote_trash_protected("~/ci/run"));
        assert!(remote_trash_protected("/usr/local/bin"));
        assert!(remote_trash_protected("/home/user"));
        assert!(!remote_trash_protected("/home/user/project/file"));
    }
}
