use std::fs::{self, DirEntry};
use std::io::ErrorKind;
use std::sync::LazyLock;

use guard_common::locale::{message, FormatValue};
use regex::Regex;

use crate::budget::{hook_budget_seconds, Budget};
use crate::consts::{self, TRASH_FILE_NAME, TRASH_FOLDER};
use crate::errors::{Denied, Stop};
use crate::places::trash_roots;
use crate::targets::{is_folder_path, is_plain_folder};
use crate::tokens::home_expanded;

static TRASH_FOLDER_FULL: LazyLock<Regex> = LazyLock::new(|| full_regex(TRASH_FOLDER.as_str()));
static TRASH_FILE_FULL: LazyLock<Regex> = LazyLock::new(|| full_regex(TRASH_FILE_NAME.as_str()));

// The recursive walk shares one budget and one refusal context across every branch.
#[derive(Clone, Copy)]
struct GlobWalkContext<'a> {
    verb: &'a str,
    raw: &'a str,
    folders_only: bool,
    budget: &'a Budget,
}

#[derive(Debug)]
pub enum GlobError {
    Stop(Stop),
    Regex,
    Attribute,
    Value(String),
}

impl From<GlobError> for Stop {
    fn from(value: GlobError) -> Self {
        match value {
            GlobError::Stop(stop) => stop,
            GlobError::Regex | GlobError::Attribute | GlobError::Value(_) => Stop::Internal,
        }
    }
}

impl From<Stop> for GlobError {
    fn from(value: Stop) -> Self {
        Self::Stop(value)
    }
}

fn full_regex(source: &str) -> Regex {
    guard_common::pyre::new(&format!(r"\A(?:{source})\z"))
        .unwrap_or_else(|error| panic!("invalid fixed regex: {error}"))
}

fn expansion(verb: &str, raw: &str) -> Stop {
    Stop::Denied(Denied::new(message(
        "delete_guard.reason.expansion",
        &[
            ("verb", FormatValue::Text(verb.to_owned())),
            ("raw", FormatValue::Text(raw.to_owned())),
        ],
    )))
}

fn missing(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

pub fn holds_trash(path: &str) -> bool {
    let roots = trash_roots();
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if missing(&error) => return false,
        Err(_) => return true,
    };
    let budget = Budget::new(hook_budget_seconds());
    for (count, entry) in entries.enumerate() {
        if budget.check().is_err() || count >= consts::max_trash_scan() {
            return true;
        }
        let Ok(entry) = entry else { return true };
        let name = entry.file_name().to_string_lossy().into_owned();
        if TRASH_FOLDER_FULL.is_match(&name)
            && (TRASH_FILE_FULL.is_match(&name) || is_folder(&entry))
        {
            return true;
        }
        let path = entry.path().to_string_lossy().into_owned();
        if roots.contains(&path) || roots.contains(&guard_common::sys::realpath(&path)) {
            return true;
        }
    }
    false
}

pub fn is_folder(entry: &DirEntry) -> bool {
    match entry.path().metadata() {
        Ok(metadata) => metadata.is_dir(),
        Err(error) if missing(&error) => false,
        Err(_) => true,
    }
}

pub fn glob_matches(raw: &str, cwd: Option<&str>, verb: &str) -> Result<Vec<String>, GlobError> {
    if !raw.contains(['*', '?', '[']) {
        return Ok(Vec::new());
    }
    let mut pattern = home_expanded(raw);
    if !pattern.starts_with('/') {
        let Some(cwd) = cwd else {
            return Ok(Vec::new());
        };
        pattern = if cwd.ends_with('/') {
            format!("{cwd}{pattern}")
        } else {
            format!("{cwd}/{pattern}")
        };
    }
    let folders_only = pattern.ends_with('/');
    let parts: Vec<String> = pattern
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    let mut matches = Vec::new();
    let mut visits = consts::glob_visits();
    let budget = Budget::new(hook_budget_seconds());
    let context = GlobWalkContext {
        verb,
        raw,
        folders_only,
        budget: &budget,
    };
    glob_walk_inner("/", &parts, &mut matches, &mut visits, &context)?;
    Ok(matches)
}

pub fn glob_entries(
    base: &str,
    visits: &mut usize,
    verb: &str,
    raw: &str,
    budget: &Budget,
) -> Result<Vec<DirEntry>, Stop> {
    let entries = match fs::read_dir(base) {
        Ok(entries) => entries,
        Err(error) if missing(&error) => return Ok(Vec::new()),
        Err(_) => return Err(expansion(verb, raw)),
    };
    let mut found = Vec::new();
    for entry in entries.take(visits.saturating_add(1)) {
        budget.check()?;
        found.push(entry.map_err(|_| expansion(verb, raw))?);
    }
    if found.len() > *visits {
        return Err(expansion(verb, raw));
    }
    *visits = visits.saturating_sub(found.len());
    Ok(found)
}

pub fn glob_walk(
    base: &str,
    parts: &[String],
    matches: &mut Vec<String>,
    visits: &mut usize,
    verb: &str,
    raw: &str,
    folders_only: bool,
) -> Result<(), GlobError> {
    let budget = Budget::new(hook_budget_seconds());
    let context = GlobWalkContext {
        verb,
        raw,
        folders_only,
        budget: &budget,
    };
    glob_walk_inner(base, parts, matches, visits, &context)
}

thread_local! {
    static WALK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn glob_walk_inner(
    base: &str,
    parts: &[String],
    matches: &mut Vec<String>,
    visits: &mut usize,
    context: &GlobWalkContext<'_>,
) -> Result<(), GlobError> {
    guard_common::depth::with_depth(&WALK_DEPTH, 978, || glob_walk_level(base, parts, matches, visits, context))
}

fn glob_walk_level(
    base: &str,
    parts: &[String],
    matches: &mut Vec<String>,
    visits: &mut usize,
    context: &GlobWalkContext<'_>,
) -> Result<(), GlobError> {
    let GlobWalkContext {
        verb,
        raw,
        folders_only,
        budget,
    } = *context;
    budget.check()?;
    let Some(part) = parts.first() else {
        if folders_only && !is_folder_path(base, verb, raw)? {
            return Ok(());
        }
        matches.push(base.to_owned());
        return if matches.len() > consts::max_matches() {
            Err(expansion(verb, raw).into())
        } else {
            Ok(())
        };
    };
    let rest = parts.get(1..).unwrap_or(&[]);
    if part == "**" && (!rest.is_empty() || folders_only) {
        glob_walk_inner(base, rest, matches, visits, context)?;
        for entry in glob_entries(base, visits, verb, raw, budget)? {
            budget.check()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.') && is_plain_folder(&entry, verb, raw)? {
                let path = entry.path().to_string_lossy().into_owned();
                glob_walk_inner(&path, parts, matches, visits, context)?;
            }
        }
    } else if part.contains(['*', '?', '[']) {
        let tokens = glob_tokens(part)?;
        for entry in glob_entries(base, visits, verb, raw, budget)? {
            budget.check()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if (part.starts_with('.') || !name.starts_with('.')) && glob_match(&tokens, &name)? {
                let path = entry.path().to_string_lossy().into_owned();
                glob_walk_inner(&path, rest, matches, visits, context)?;
            }
        }
    } else {
        let path = if base.ends_with('/') {
            format!("{base}{part}")
        } else {
            format!("{base}/{part}")
        };
        match fs::symlink_metadata(&path) {
            Ok(_) => glob_walk_inner(&path, rest, matches, visits, context)?,
            Err(error) if missing(&error) => {}
            Err(_) => return Err(expansion(verb, raw).into()),
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum GlobToken {
    Star,
    Question,
    Literal(char),
    Set(guard_common::pyengine::PyRegex),
}

fn python_escape(character: char) -> String {
    if "()[]{}?*+-|^$\\.&~# \t\n\r\x0b\x0c".contains(character) {
        format!("\\{character}")
    } else {
        character.to_string()
    }
}

pub fn glob_tokens(pattern: &str) -> Result<Vec<GlobToken>, GlobError> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        let Some(&character) = chars.get(index) else {
            break;
        };
        match character {
            '*' => {
                if !matches!(tokens.last(), Some(GlobToken::Star)) {
                    tokens.push(GlobToken::Star)
                }
            }
            '?' => tokens.push(GlobToken::Question),
            '\\' if index.saturating_add(1) < chars.len() => {
                index = index.saturating_add(1);
                if let Some(&next) = chars.get(index) {
                    tokens.push(GlobToken::Literal(next));
                }
            }
            '[' => {
                let mut position = index.saturating_add(1);
                let negate = chars
                    .get(position)
                    .is_some_and(|ch| *ch == '!' || *ch == '^');
                if negate {
                    position = position.saturating_add(1)
                }
                let mut members = String::new();
                let mut first = true;
                while let Some(&ch) = chars.get(position) {
                    if ch == ']' && !first {
                        break;
                    }
                    first = false;
                    if ch == '[' && chars.get(position.saturating_add(1)) == Some(&':') {
                        let end = (position.saturating_add(2)..chars.len().saturating_sub(1)).find(
                            |&at| {
                                chars.get(at) == Some(&':')
                                    && chars.get(at.saturating_add(1)) == Some(&']')
                            },
                        );
                        if let Some(end) = end {
                            let name: String = chars
                                .get(position.saturating_add(2)..end)
                                .unwrap_or(&[])
                                .iter()
                                .collect();
                            let value = if negate {
                                consts::posix_class_ascii(&name)
                            } else {
                                consts::posix_class(&name)
                            };
                            if let Some(value) = value {
                                members.push_str(value);
                                position = end.saturating_add(2);
                                continue;
                            }
                        }
                    }
                    if ch == '-' {
                        members.push('-')
                    } else {
                        members.push_str(&python_escape(ch))
                    }
                    position = position.saturating_add(1);
                }
                if position >= chars.len() {
                    tokens.push(GlobToken::Literal(character));
                } else {
                    let source = format!("[{}{}]", if negate { "^" } else { "" }, members);
                    tokens.push(GlobToken::Set(
                        guard_common::pyengine::PyRegex::new(&source).map_err(|_| GlobError::Regex)?,
                    ));
                    index = position;
                }
            }
            _ => tokens.push(GlobToken::Literal(character)),
        }
        index = index.saturating_add(1);
    }
    Ok(tokens)
}

pub fn glob_token_matches(token: &GlobToken, character: char) -> Result<bool, GlobError> {
    match token {
        GlobToken::Star => Err(GlobError::Attribute),
        GlobToken::Question => Ok(true),
        GlobToken::Literal(value) => Ok(*value == character),
        GlobToken::Set(pattern) => Ok(pattern.fullmatch_chars(&[character]).is_some()),
    }
}

pub fn glob_match(tokens: &[GlobToken], name: &str) -> Result<bool, GlobError> {
    let name: Vec<char> = name.chars().collect();
    let mut token = 0usize;
    let mut position = 0usize;
    let mut star = None;
    let mut mark = 0usize;
    while position < name.len() {
        if let (Some(next), Some(&character)) = (tokens.get(token), name.get(position)) {
            if !matches!(next, GlobToken::Star) && glob_token_matches(next, character)? {
                token = token.saturating_add(1);
                position = position.saturating_add(1);
                continue;
            }
            if matches!(next, GlobToken::Star) {
                star = Some(token);
                mark = position;
                token = token.saturating_add(1);
                continue;
            }
        }
        if let Some(previous) = star {
            token = previous.saturating_add(1);
            mark = mark.saturating_add(1);
            position = mark;
        } else {
            return Ok(false);
        }
    }
    while matches!(tokens.get(token), Some(GlobToken::Star)) {
        token = token.saturating_add(1)
    }
    Ok(token == tokens.len())
}

#[cfg(test)]
mod tests {
    use super::{glob_match, glob_tokens};

    #[test]
    fn shell_classes_and_stars_match_named_cases() {
        for (pattern, name, expected) in [
            ("a[b-d]?", "acx", true),
            ("a[b-d]?", "aex", false),
            ("[!a]*", "bcd", true),
            ("[!a]*", "abc", false),
            ("[]x]", "]", true),
            (r"\*a", "*a", true),
            ("a[", "a[", true),
            ("a.b", "axb", false),
            ("*a*a*ab", "aaaaaaaab", true),
            ("[[:digit:]]x", "7x", true),
            ("[[:digit:]]x", "ax", false),
        ] {
            assert_eq!(
                glob_match(&glob_tokens(pattern).expect("tokens"), name).expect("match"),
                expected,
                "{pattern} on {name}"
            );
        }
    }

    #[test]
    fn doubled_hyphens_keep_python_range_rules() {
        assert!(glob_tokens("[a--]").is_err());
        assert!(glob_tokens("[--*]").is_err());
        let range = glob_tokens("[--a]").expect("range");
        assert!(glob_match(&range, "0").expect("match"));
        assert!(!glob_match(&range, "é").expect("match"));
    }
}
