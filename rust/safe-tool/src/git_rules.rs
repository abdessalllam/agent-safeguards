use std::sync::LazyLock;

use guard_common::shell;
use regex::Regex;

use crate::{consts, words};

static DESCRIPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?:describe|decorate)\b").unwrap_or_else(|_| std::process::abort())
});
static REF_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%\(([^)]*)\)").unwrap_or_else(|_| std::process::abort()));

pub fn git_subcommand(words: &[String]) -> (Option<String>, Vec<String>) {
    let normalized: Vec<String> = words.iter().map(|word| words::normalized(word)).collect();
    let Some(mut index) = normalized
        .iter()
        .position(|word| word == "git")
        .map(|at| at.saturating_add(1))
    else {
        return (None, Vec::new());
    };
    while let Some(argument) = words.get(index) {
        if shell::GIT_VALUE_OPTIONS.contains(argument.as_str()) {
            index = index.saturating_add(2);
        } else if argument.starts_with('-') {
            index = index.saturating_add(1);
        } else {
            return (
                Some(words::normalized(argument)),
                words.get(index.saturating_add(1)..).unwrap_or(&[]).to_vec(),
            );
        }
    }
    (None, Vec::new())
}

pub fn log_format_is_safe(template: &str) -> bool {
    if consts::SAFE_PRETTY_NAMES.contains(&template) {
        return true;
    }
    let mut template = template;
    if let Some(rest) = template
        .strip_prefix("tformat:")
        .or_else(|| template.strip_prefix("format:"))
    {
        template = rest;
    } else if !template.contains('%') && !template.is_empty() {
        return false;
    }
    let chars: Vec<char> = template.chars().collect();
    let mut index = 0usize;
    while let Some(character) = chars.get(index).copied() {
        if character != '%' {
            index = index.saturating_add(1);
            continue;
        }
        index = index.saturating_add(1);
        while chars.get(index).is_some_and(|ch| "+- ".contains(*ch)) {
            index = index.saturating_add(1);
        }
        let Some(letter) = chars.get(index).copied() else {
            return false;
        };
        index = index.saturating_add(1);
        match letter {
            '%' => (),
            'x' => {
                if !chars.get(index).is_some_and(char::is_ascii_hexdigit)
                    || !chars
                        .get(index.saturating_add(1))
                        .is_some_and(char::is_ascii_hexdigit)
                {
                    return false;
                }
                index = index.saturating_add(2);
            }
            'C' => {
                if chars.get(index) == Some(&'(') {
                    let Some(closing) = chars
                        .iter()
                        .enumerate()
                        .skip(index)
                        .find(|(_, ch)| **ch == ')')
                        .map(|(at, _)| at)
                    else {
                        return false;
                    };
                    index = closing.saturating_add(1);
                } else {
                    while chars.get(index).is_some_and(char::is_ascii_alphabetic) {
                        index = index.saturating_add(1);
                    }
                }
            }
            'w' | '<' | '>' => {
                if letter != 'w' {
                    while chars.get(index).is_some_and(|ch| "<>|".contains(*ch)) {
                        index = index.saturating_add(1);
                    }
                }
                if chars.get(index) != Some(&'(') {
                    return false;
                }
                let Some(closing) = chars
                    .iter()
                    .enumerate()
                    .skip(index)
                    .find(|(_, ch)| **ch == ')')
                    .map(|(at, _)| at)
                else {
                    return false;
                };
                index = closing.saturating_add(1);
            }
            '(' => {
                let Some(closing) = chars
                    .iter()
                    .enumerate()
                    .skip(index)
                    .find(|(_, ch)| **ch == ')')
                    .map(|(at, _)| at)
                else {
                    return false;
                };
                let body: String = chars
                    .iter()
                    .skip(index)
                    .take(closing.saturating_sub(index))
                    .collect();
                if !DESCRIPTION.is_match(&body) {
                    return false;
                }
                index = closing.saturating_add(1);
            }
            'a' | 'c' | 'g' => {
                let Some((_, allowed)) = consts::SAFE_LOG_DATE_LETTERS
                    .iter()
                    .find(|(name, _)| name.starts_with(letter))
                else {
                    return false;
                };
                if !chars.get(index).is_some_and(|ch| allowed.contains(*ch)) {
                    return false;
                }
                index = index.saturating_add(1);
            }
            'G' => {
                if chars.get(index) != Some(&'?') {
                    return false;
                }
                index = index.saturating_add(1);
            }
            _ => {
                if !consts::in_safe_log_placeholders(&letter.to_string()) {
                    return false;
                }
            }
        }
    }
    true
}

pub fn ref_format_is_safe(template: &str) -> bool {
    for found in REF_FIELD.captures_iter(template) {
        let Some(name) = found
            .get(1)
            .map(|value| value.as_str().trim_start_matches('*'))
        else {
            continue;
        };
        let (base, argument) = name.split_once(':').unwrap_or((name, ""));
        if base == "contents" {
            if !matches!(argument, "subject" | "size") {
                return false;
            }
        } else if !consts::in_safe_for_each_ref_fields(base) {
            return false;
        }
    }
    true
}

pub fn safe_history_arguments(arguments: &[String], _show: bool) -> bool {
    let mut effective: Option<&str> = None;
    for argument in arguments {
        if argument == "--" {
            break;
        }
        let lowered = argument.to_lowercase();
        if lowered == "--oneline" {
            effective = Some("oneline");
        } else if lowered.starts_with("--format=") || lowered.starts_with("--pretty=") {
            effective = Some(argument.split_once('=').map(|(_, tail)| tail).unwrap_or(""));
        } else if lowered == "--format" || lowered == "--pretty" {
            effective = Some("default");
        }
    }
    match effective {
        Some("default") | None => false,
        Some("") => true,
        Some(format) => log_format_is_safe(format),
    }
}

pub fn shows_only_blobs(arguments: &[String]) -> bool {
    let operands: Vec<&str> = arguments
        .iter()
        .take_while(|argument| *argument != "--")
        .filter(|argument| !argument.starts_with('-'))
        .map(String::as_str)
        .collect();
    !operands.is_empty()
        && operands
            .iter()
            .all(|argument| consts::git_blob_spec_fullmatch(argument).is_some())
}

pub fn formats_are_unsafe(arguments: &[String], headers: &[&str], refs: bool) -> bool {
    let mut format: Option<&str> = None;
    let mut index = 0usize;
    while let Some(argument) = arguments.get(index) {
        index = index.saturating_add(1);
        if argument == "--" {
            break;
        }
        if headers.contains(&argument.as_str()) {
            return true;
        }
        let lowered = argument.to_lowercase();
        if lowered.starts_with("--format=") || lowered.starts_with("--pretty=") {
            format = Some(argument.split_once('=').map(|(_, tail)| tail).unwrap_or(""));
        } else if lowered == "--format" || lowered == "--pretty" {
            format = Some(arguments.get(index).map(String::as_str).unwrap_or(""));
            index = index.saturating_add(1);
        }
    }
    match format {
        None => false,
        Some(format) if refs => !ref_format_is_safe(format),
        Some(format) => !log_format_is_safe(format),
    }
}

pub fn safe_git_config(words: &[String]) -> bool {
    let normalized: Vec<String> = words.iter().map(|word| words::normalized(word)).collect();
    let Some(index) = normalized.iter().position(|word| word == "git") else {
        return false;
    };
    let mut rest = words.get(index.saturating_add(1)..).unwrap_or(&[]);
    if rest.first().map(String::as_str) == Some("-C") && rest.len() >= 3 {
        rest = rest.get(2..).unwrap_or(&[]);
    }
    if rest.first().map(String::as_str) != Some("config") {
        return false;
    }
    let arguments = rest.get(1..).unwrap_or(&[]);
    let scopes: Vec<&str> = arguments
        .iter()
        .map(String::as_str)
        .filter(|argument| consts::CONFIG_SCOPES.contains(argument))
        .collect();
    let mut operands: Vec<String> = arguments
        .iter()
        .filter(|argument| !consts::CONFIG_SCOPES.contains(&argument.as_str()))
        .cloned()
        .collect();
    if scopes.len() > 1 {
        return false;
    }
    if operands.len() == 2 && matches!(operands.first().map(String::as_str), Some("unset" | "get"))
    {
        if let Some(first) = operands.first_mut() {
            *first = format!("--{first}");
        }
    }
    let key = operands
        .get(1)
        .map(|key| key.to_lowercase())
        .unwrap_or_default();
    if operands.len() == 2
        && matches!(
            operands.first().map(String::as_str),
            Some("--unset" | "--unset-all")
        )
    {
        return matches!(scopes.as_slice(), [] | ["--local"] | ["--worktree"])
            && consts::in_safe_config_keys(&key);
    }
    if operands.len() == 2
        && matches!(
            operands.first().map(String::as_str),
            Some("--get" | "--get-all")
        )
    {
        return consts::in_safe_config_keys(&key);
    }
    operands.len() == 1
        && operands.first().is_some_and(|operand| {
            !operand.starts_with('-') && consts::in_safe_config_keys(&operand.to_lowercase())
        })
}

pub fn runs_git_config(raw_words: &[String]) -> bool {
    let Ok((words, _)) = words::unwrap(raw_words) else {
        return false;
    };
    git_subcommand(&words).0.as_deref() == Some("config")
}

pub fn sensitive_git_command(words: &[String]) -> bool {
    let (subcommand, arguments) = git_subcommand(words);
    match subcommand.as_deref() {
        Some("config") => !safe_git_config(words),
        Some(
            "blame" | "cat-file" | "commit" | "format-patch" | "request-pull" | "send-email"
            | "shortlog" | "whatchanged",
        ) => true,
        Some("var") => arguments.iter().any(|argument| {
            matches!(
                argument.to_uppercase().as_str(),
                "GIT_AUTHOR_IDENT" | "GIT_COMMITTER_IDENT"
            )
        }),
        Some("log") => !safe_history_arguments(&arguments, false),
        Some("show") => !(safe_history_arguments(&arguments, true) || shows_only_blobs(&arguments)),
        Some("remote") => arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-v" | "--verbose" | "get-url")),
        Some("rev-list") => formats_are_unsafe(&arguments, &["--header"], false),
        Some("for-each-ref") => formats_are_unsafe(&arguments, &[], true),
        _ => false,
    }
}

pub fn prints_definitions(command: &str, arguments: &[String]) -> bool {
    let flags: String = arguments
        .iter()
        .filter(|argument| {
            (argument.starts_with('-') || argument.starts_with('+'))
                && !argument.starts_with("--")
                && !argument.starts_with("++")
        })
        .flat_map(|argument| argument.chars().skip(1))
        .collect();
    let operands: Vec<&str> = arguments
        .iter()
        .filter(|argument| !argument.starts_with('-') && !argument.starts_with('+'))
        .map(String::as_str)
        .collect();
    match command {
        "fc" | "functions" | "history" | "whence" | "where" => true,
        "type" => !flags.contains('t'),
        "alias" => operands.is_empty() || operands.iter().any(|operand| !operand.contains('=')),
        "declare" | "local" | "typeset" => {
            operands.is_empty()
                || "fFp".chars().any(|flag| flags.contains(flag))
                || operands.iter().any(|operand| !operand.contains('='))
        }
        "export" | "readonly" => operands.is_empty() || flags.contains('p'),
        "set" => arguments.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_reject_identity_fields_and_accept_safe_fields() {
        assert!(log_format_is_safe("format:%h %ad %s"));
        assert!(!log_format_is_safe("%h %an"));
        assert!(ref_format_is_safe("%(refname:short) %(contents:subject)"));
        assert!(!ref_format_is_safe("%(authorname)"));
    }

    #[test]
    fn last_format_and_scope_rules() {
        let args = vec!["--format=%an", "--format=%h"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert!(safe_history_arguments(&args, false));
        let config = vec!["git", "config", "--local", "--unset", "core.hooksPath"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert!(safe_git_config(&config));
        let blocked = vec!["git", "config", "--global", "--unset", "core.hooksPath"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert!(!safe_git_config(&blocked));
    }

    #[test]
    fn blob_show_and_history_identity_rules() {
        let safe_blob = ["git", "show", "HEAD:src/main.rs"].map(String::from);
        let unsafe_show = ["git", "show", "HEAD"].map(String::from);
        let safe_log = ["git", "log", "--format=%h%x09%s"].map(String::from);
        let unsafe_log = ["git", "log", "--format=%an"].map(String::from);
        assert!(!sensitive_git_command(&safe_blob));
        assert!(sensitive_git_command(&unsafe_show));
        assert!(!sensitive_git_command(&safe_log));
        assert!(sensitive_git_command(&unsafe_log));
    }

    #[test]
    fn ref_headers_and_definition_printers() {
        assert!(formats_are_unsafe(
            &["--header".to_owned()],
            &["--header"],
            false
        ));
        assert!(!formats_are_unsafe(
            &["--format=%h".to_owned()],
            &["--header"],
            false
        ));
        assert!(prints_definitions("type", &[]));
        assert!(!prints_definitions(
            "type",
            &["-t".to_owned(), "git".to_owned()]
        ));
        assert!(!prints_definitions("alias", &["x=y".to_owned()]));
        assert!(prints_definitions("alias", &["x".to_owned()]));
    }
}
