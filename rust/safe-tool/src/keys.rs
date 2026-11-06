use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::LazyLock;

use guard_common::env;
use guard_common::shlex::Lexer;
use guard_common::sys::{self, EmbeddedNul};
use regex::Regex;

use crate::consts;

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\A([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)\z")
        .unwrap_or_else(|_| std::process::abort())
});
static KEYWORD_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A-[A-Za-z]+\z").unwrap_or_else(|_| std::process::abort()));
static SUBSTITUTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\([^()]*\)|`[^`]*`").unwrap_or_else(|_| std::process::abort()));

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(at) => path.get(..at).unwrap_or(""),
        None => "",
    }
}

pub fn startup_key_file(requested: Option<&str>) -> Result<Option<String>, EmbeddedNul> {
    let requested = requested.unwrap_or("~/.zshrc");
    let home = env::user_home();
    let expanded = requested
        .strip_prefix("~/")
        .map_or_else(|| requested.to_owned(), |rest| format!("{home}/{rest}"));
    if !expanded.starts_with('/')
        || sys::try_realpath(dirname(&expanded))? != home
        || !consts::STARTUP_KEY_FILES.contains(&basename(&expanded))
    {
        return Ok(None);
    }
    if std::fs::symlink_metadata(&expanded).is_ok() {
        let target = sys::try_realpath(&expanded)?;
        if !format!("{target}/").starts_with(&format!("{home}/"))
            || !consts::STARTUP_KEY_FILES.iter().any(|name| {
                basename(&target)
                    .to_lowercase()
                    .contains(name.trim_start_matches('.'))
            })
        {
            return Ok(None);
        }
    }
    Ok(Some(expanded))
}

pub fn apply_command(words: &[String], found: &mut HashSet<String>) {
    let mut words = words;
    while words
        .first()
        .is_some_and(|word| ["then", "do", "else", "!"].contains(&word.as_str()))
    {
        words = words.get(1..).unwrap_or(&[]);
    }
    let Some(first) = words.first() else {
        return;
    };
    if first == "unset" {
        for word in words.iter().skip(1).filter(|word| !word.starts_with('-')) {
            found.remove(word);
        }
        return;
    }
    let keyword = ["export", "readonly", "declare", "typeset"].contains(&first.as_str());
    let mut rest = if keyword {
        words.get(1..).unwrap_or(&[])
    } else {
        words
    };
    while keyword
        && rest
            .first()
            .is_some_and(|word| KEYWORD_OPTION.is_match(word))
    {
        rest = rest.get(1..).unwrap_or(&[]);
    }
    let mut assignments = Vec::new();
    for token in rest {
        if let Some(captures) = ASSIGNMENT.captures(token) {
            let name = captures.get(1).map_or("", |part| part.as_str());
            let value = captures.get(2).map_or("", |part| part.as_str());
            assignments.push((name, value));
        } else if !keyword {
            return;
        }
    }
    for (name, value) in assignments {
        if value.is_empty() {
            found.remove(name);
        } else {
            found.insert(name.to_owned());
        }
    }
}

pub fn apply_line(line: &str, found: &mut HashSet<String>) {
    let replaced = SUBSTITUTION.replace_all(line, "x");
    let Ok(tokens) = Lexer::new(&replaced)
        .posix(true)
        .punctuation_chars(";&|")
        .whitespace_split(true)
        .commenters("#")
        .tokens()
    else {
        return;
    };
    let mut command = Vec::new();
    for token in tokens {
        if !token.is_empty() && token.chars().all(|ch| ";&|".contains(ch)) {
            apply_command(&command, found);
            command.clear();
        } else {
            command.push(token);
        }
    }
    apply_command(&command, found);
}

pub fn keys_set_in(path: &str) -> Result<(HashSet<String>, bool), EmbeddedNul> {
    if path.contains('\0') {
        return Err(EmbeddedNul);
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HashSet::new(), true))
        }
        Err(_) => return Ok((HashSet::new(), false)),
    };
    let mut reader = BufReader::new(file);
    let mut found = HashSet::new();
    let mut pending = String::new();
    let mut number = 0usize;
    loop {
        let mut bytes = Vec::new();
        let read = match reader.read_until(b'\n', &mut bytes) {
            Ok(read) => read,
            Err(_) => return Ok((HashSet::new(), false)),
        };
        if read == 0 {
            break;
        }
        if number >= consts::MAX_STARTUP_FILE_LINES
            || pending.chars().count() > consts::MAX_STARTUP_LINE_CHARS
        {
            return Ok((found, false));
        }
        number = number.saturating_add(1);
        let line = format!("{pending}{}", String::from_utf8_lossy(&bytes));
        if let Some(continued) = line.strip_suffix("\\\n") {
            pending = continued.to_owned();
        } else {
            pending.clear();
            apply_line(&line, &mut found);
        }
    }
    Ok((found, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_and_unset() {
        let mut found = HashSet::new();
        apply_line("export A=1 B=2; unset B", &mut found);
        assert!(found.contains("A"));
        assert!(!found.contains("B"));
        apply_line("A=", &mut found);
        assert!(found.is_empty());
    }
}
