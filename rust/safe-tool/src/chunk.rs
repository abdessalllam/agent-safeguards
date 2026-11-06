use std::collections::HashSet;
use std::sync::LazyLock;

use guard_common::shell;
use guard_common::sys::EmbeddedNul;
use regex::Regex;

use crate::{consts, git_rules, paths, words};

static DOCKER_ENVIRONMENT_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\{\{-?[\s\u{001c}-\u{001f}]*(?:[\p{L}\p{N}_]+[\s\u{001c}-\u{001f}]+|\()*[.$](?:\.?(?:Config|Spec|ContainerSpec|TaskTemplate))?[\s\u{001c}-\u{001f})]*-?(?:\}\}|\|)")
        .unwrap_or_else(|_| std::process::abort())
});
static ENV_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)env").unwrap_or_else(|_| std::process::abort()));
static PY_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[\p{L}\p{N}_]\z").unwrap_or_else(|_| std::process::abort()));
static PS_FORMAT_FIELDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\s\u{001c}-\u{001f},]+").unwrap_or_else(|_| std::process::abort())
});
static PS_FIELD_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[=:]").unwrap_or_else(|_| std::process::abort()));
static PS_LONG_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(--[A-Za-z][A-Za-z-]*)([=:]?)(?s:(.*))\z")
        .unwrap_or_else(|_| std::process::abort())
});

pub fn sensitive_chunk(raw_words: &[String]) -> Result<bool, EmbeddedNul> {
    if raw_words.iter().all(|word| {
        shell::ASSIGNMENT.is_match(word) || shell::SHELL_KEYWORDS.contains(word.as_str())
    }) {
        return Ok(false);
    }
    let (words, used_proxy) = match words::unwrap(raw_words) {
        Ok(value) => value,
        Err(_) => return Ok(true),
    };
    if words.is_empty() {
        return Ok(raw_words
            .iter()
            .any(|word| words::normalized(word) == "env"));
    }
    let normalized: Vec<String> = words.iter().map(|word| words::normalized(word)).collect();
    let executable = normalized.first().map(String::as_str).unwrap_or("");
    if executable == consts::TOOL_NAME {
        return Ok(!words::is_self(
            words.first().map(String::as_str).unwrap_or(""),
        )?);
    }
    if consts::in_trace_commands(executable)
        && paths::traces_commands(executable, normalized.get(1..).unwrap_or(&[]))
    {
        return Ok(true);
    }
    if executable == "eval" && words.len() > 1 {
        return crate::command::sensitive_command(&words.get(1..).unwrap_or(&[]).join(" "), false);
    }
    if matches!(executable, "bash" | "sh" | "zsh") {
        for (index, argument) in words.iter().take(words.len().saturating_sub(1)).enumerate() {
            if consts::SHELL_COMMAND_OPTION_FULL.is_match(argument) {
                return crate::command::sensitive_command(
                    words
                        .get(index.saturating_add(1))
                        .map(String::as_str)
                        .unwrap_or(""),
                    false,
                );
            }
        }
    }
    if used_proxy && !consts::in_safe_proxy_commands(executable) {
        return Ok(true);
    }
    if consts::DIRECT_IDENTITY_COMMANDS.contains(&executable) {
        return Ok(true);
    }
    if consts::CREDENTIAL_COMMANDS.contains(&executable)
        || (consts::PRINTING_COMMANDS.contains(&executable)
            && words
                .iter()
                .skip(1)
                .any(|word| consts::SECRET_VARIABLE_PATTERN.is_match(word)))
    {
        return Ok(true);
    }
    let printer = if executable == "builtin" && normalized.len() > 1 {
        normalized.get(1..).unwrap_or(&[])
    } else {
        normalized.as_slice()
    };
    if let Some(command) = printer.first() {
        if consts::in_definition_printers(command)
            && git_rules::prints_definitions(command, printer.get(1..).unwrap_or(&[]))
        {
            return Ok(true);
        }
    }
    if normalized.iter().any(|word| {
        consts::in_sensitive_flags(word.split_once('=').map_or(word.as_str(), |(head, _)| head))
    }) {
        return Ok(true);
    }
    if normalized.iter().any(|word| word == "git")
        && git_rules::git_subcommand(&words).0.as_deref() == Some("config")
        && raw_words
            .iter()
            .any(|word| shell::ASSIGNMENT.is_match(word))
    {
        return Ok(true);
    }
    if normalized.iter().any(|word| word == "git") {
        let subcommand = git_rules::git_subcommand(&words).0;
        if git_rules::sensitive_git_command(&words)
            || subcommand
                .as_deref()
                .unwrap_or("")
                .starts_with("credential")
        {
            return Ok(true);
        }
    }

    let arguments = words::without_global_options(executable, normalized.get(1..).unwrap_or(&[]));
    let first = arguments.first().map(String::as_str).unwrap_or("");
    let second = arguments.get(1).map(String::as_str).unwrap_or("");
    let raw_arguments = words::without_global_options(executable, words.get(1..).unwrap_or(&[]));
    let startup_operand = raw_arguments
        .first()
        .is_some_and(|arg| consts::startup_file_pattern_search(&format!(" {arg}")).is_some());
    if matches!(executable, "coderabbit" | "cr")
        && matches!(first, "auth" | "doctor" | "stats" | "usage")
    {
        return Ok(true);
    }
    if matches!(executable, "ack" | "ag" | "egrep" | "fgrep" | "grep" | "rg")
        && paths::searches_home(executable, words.get(1..).unwrap_or(&[]))?
    {
        return Ok(true);
    }
    if executable == "ps" && ps_shows_environment(&raw_arguments) {
        return Ok(true);
    }
    if executable == "launchctl" && consts::ENVIRONMENT_SERVICE_ACTIONS.contains(&first) {
        return Ok(true);
    }
    if executable == "op" && !matches!(first, "" | "--version" | "-v" | "help" | "run") {
        return Ok(true);
    }
    if executable == "doppler" && matches!(first, "configs" | "secrets") {
        return Ok(true);
    }
    if executable == "vault"
        && matches!(
            first,
            "kv" | "login" | "print" | "read" | "token" | "transit" | "unwrap"
        )
    {
        return Ok(true);
    }
    if executable == "sops"
        && arguments
            .iter()
            .any(|arg| matches!(arg.as_str(), "-d" | "--decrypt" | "decrypt"))
    {
        return Ok(true);
    }
    if executable == "ansible-vault" && matches!(first, "decrypt" | "view") {
        return Ok(true);
    }
    if executable == "docker" && docker_inspect_shows_environment(words.get(1..).unwrap_or(&[])) {
        return Ok(true);
    }
    if executable == "kubectl"
        && matches!(first, "describe" | "get")
        && raw_arguments
            .iter()
            .skip(1)
            .flat_map(|arg| arg.split(','))
            .any(|part| {
                matches!(
                    part.split('/')
                        .next()
                        .unwrap_or("")
                        .split('.')
                        .next()
                        .unwrap_or("")
                        .to_lowercase()
                        .as_str(),
                    "secret" | "secrets"
                )
            })
    {
        return Ok(true);
    }
    if matches!(executable, "jq" | "gojq" | "yq")
        && words
            .iter()
            .skip(1)
            .any(|arg| consts::jq_environment_search(arg).is_some())
    {
        return Ok(true);
    }
    if executable == "gh"
        && (first == "auth" || (first == "api" && matches!(second, "user" | "/user")))
    {
        return Ok(true);
    }
    if matches!(executable, "npm" | "pnpm" | "yarn")
        && matches!(
            first,
            "adduser" | "login" | "logout" | "profile" | "token" | "whoami"
        )
    {
        return Ok(true);
    }
    if executable == "aws"
        && ((first == "sts" && second == "get-caller-identity") || first == "configure")
    {
        return Ok(true);
    }
    if executable == "gcloud" && matches!(first, "auth" | "config") {
        return Ok(true);
    }
    if executable == "az" && first == "account" {
        return Ok(true);
    }
    if executable == "kubectl" && first == "config" {
        return Ok(true);
    }
    if executable == "security"
        && matches!(
            first,
            "dump-keychain" | "find-generic-password" | "find-identity" | "find-internet-password"
        )
    {
        return Ok(true);
    }
    if matches!(executable, "gpg" | "gpg2") && arguments.iter().any(|arg| arg.starts_with("--list"))
    {
        return Ok(true);
    }
    if executable == "ssh-add"
        && arguments
            .iter()
            .any(|arg| matches!(arg.as_str(), "-l" | "-L"))
    {
        return Ok(true);
    }
    if startup_operand || consts::in_plain_utilities(executable) {
        return Ok(false);
    }
    if matches!(first, "doctor" | "whoami") {
        return Ok(true);
    }
    if first == "status" && !matches!(executable, "git" | "pm2" | "systemctl") {
        return Ok(true);
    }
    if consts::in_generic_private_subcommands(first)
        && (second.is_empty() || consts::in_generic_private_actions(second))
    {
        return Ok(true);
    }
    if first == "config"
        && executable != "git"
        && arguments.iter().skip(1).any(|arg| {
            consts::in_generic_private_actions(arg)
                || matches!(arg.as_str(), "--list" | "-l" | "dump" | "view")
        })
    {
        return Ok(true);
    }
    Ok(false)
}

pub fn docker_inspect_shows_environment(arguments: &[String]) -> bool {
    let value_options: HashSet<&str> = consts::DOCKER_VALUE_OPTIONS.iter().copied().collect();
    let letters: String = consts::DOCKER_VALUE_LETTERS.join("");
    let Some(index) = shell::first_operand(arguments, &letters, &value_options) else {
        return false;
    };
    let mut rest = arguments.get(index.saturating_add(1)..).unwrap_or(&[]);
    let first = arguments.get(index).map(String::as_str).unwrap_or("");
    if matches!(first, "container" | "image" | "service" | "task") {
        if rest.first().map(String::as_str) != Some("inspect") {
            return false;
        }
        rest = rest.get(1..).unwrap_or(&[]);
    } else if first != "inspect" {
        return false;
    }
    let mut chosen: Option<&str> = None;
    let mut position = 0usize;
    while let Some(argument) = rest.get(position) {
        position = position.saturating_add(1);
        if argument == "--" {
            break;
        }
        if matches!(argument.as_str(), "-f" | "--format") {
            if let Some(value) = rest.get(position) {
                chosen = Some(value);
                position = position.saturating_add(1);
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            chosen = Some(value);
        } else if argument.starts_with("-f") && !argument.starts_with("--") && argument.len() > 2 {
            chosen = argument.get(2..);
        } else if argument == "--type" {
            position = position.saturating_add(1);
        }
    }
    chosen.is_none_or(|value| {
        let stripped = value
            .trim_matches(|ch: char| ch.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&ch));
        stripped.is_empty() || stripped == "json" || docker_format_has_environment(value)
    })
}

// Keep Python's word boundary around Env separate from the template pattern.
fn docker_format_has_environment(value: &str) -> bool {
    if DOCKER_ENVIRONMENT_FORMAT.is_match(value) {
        return true;
    }
    ENV_TOKEN.find_iter(value).any(|found| {
        let before = value.get(..found.start()).unwrap_or("").chars().last();
        let after = value.get(found.end()..).unwrap_or("").chars().next();
        before.is_none_or(|ch| !python_word(ch)) && after.is_none_or(|ch| !python_word(ch))
    })
}

pub(crate) fn python_word(ch: char) -> bool {
    PY_WORD.is_match(&ch.to_string())
}

pub fn ps_shows_environment(arguments: &[String]) -> bool {
    let target = consts::ps_target();
    let Some((unix_values, bsd_values)) = consts::ps_profile(&target) else {
        return false;
    };
    ps_walk(arguments, unix_values, bsd_values)
}

pub fn ps_format_shows_environment(value: &str) -> bool {
    PS_FORMAT_FIELDS
        .split(value)
        .filter(|item| !item.is_empty())
        .any(|item| {
            PS_FIELD_SUFFIX
                .split(item)
                .next()
                .unwrap_or("")
                .to_lowercase()
                == "environ"
        })
}

pub fn ps_walk(arguments: &[String], unix_values: &[char], bsd_values: &[char]) -> bool {
    let mut index = 0usize;
    while let Some(word) = arguments.get(index) {
        index = index.saturating_add(1);
        if word == "--" {
            break;
        }
        if word.starts_with("--") {
            let (name, equals, attached) = match PS_LONG_OPTION.captures(word) {
                Some(caps) => (
                    caps.get(1).map_or(word.as_str(), |hit| hit.as_str()),
                    caps.get(2).map_or("", |hit| hit.as_str()),
                    caps.get(3).map_or("", |hit| hit.as_str()),
                ),
                None => (word.as_str(), "", ""),
            };
            if name == "--format"
                && ps_format_shows_environment(if equals.is_empty() {
                    arguments.get(index).map(String::as_str).unwrap_or("")
                } else {
                    attached
                })
            {
                return true;
            }
            if equals.is_empty() && consts::in_ps_long_value_options(name) {
                index = index.saturating_add(1);
            }
            continue;
        }
        let dashed = word.starts_with('-') && word.chars().count() > 1;
        let body = if dashed {
            word.get(1..).unwrap_or("")
        } else {
            word.as_str()
        };
        let prefix: Vec<char> = body
            .chars()
            .take_while(|ch| ch.is_ascii_alphabetic())
            .collect();
        let values = if dashed { unix_values } else { bsd_values };
        let position = prefix.iter().position(|letter| values.contains(letter));
        if let Some(place) = position {
            if matches!(prefix.get(place), Some('o' | 'O')) {
                let following = arguments
                    .get(index)
                    .filter(|next| !next.starts_with('-'))
                    .map(String::as_str)
                    .unwrap_or("");
                let attached: String = body.chars().skip(place.saturating_add(1)).collect();
                if ps_format_shows_environment(if attached.is_empty() {
                    following
                } else {
                    &attached
                }) {
                    return true;
                }
            }
        }
        let keeps_value = if consts::ps_target() == "darwin" {
            "oO"
        } else {
            "oOC"
        };
        let letters = if let Some(place) = position.filter(|place| {
            prefix
                .get(*place)
                .is_some_and(|letter| keeps_value.contains(*letter))
        }) {
            prefix.get(..=place).unwrap_or(&[])
        } else {
            prefix.as_slice()
        };
        if letters.iter().any(|letter| matches!(letter, 'e' | 'E')) {
            return true;
        }
        if position.is_some_and(|place| place == body.chars().count().saturating_sub(1))
            && arguments
                .get(index)
                .is_some_and(|next| !next.starts_with('-'))
        {
            index = index.saturating_add(1);
        }
    }
    false
}

pub fn prints_secret_variable(command: &str) -> bool {
    if consts::HERE_STRING_SECRET.is_match(command) {
        return true;
    }
    let secrets: Vec<usize> = consts::SECRET_VARIABLE_PATTERN
        .find_iter(command)
        .map(|found| command.get(..found.start()).unwrap_or("").chars().count())
        .collect();
    let Some(last) = secrets.last().copied() else {
        return false;
    };
    let chars: Vec<char> = command.chars().collect();
    for found in consts::heredoc_start_finditer(command) {
        let start = command.get(..found.start).unwrap_or("").chars().count();
        let end = command.get(..found.end).unwrap_or("").chars().count();
        let line_start = chars
            .get(..start)
            .unwrap_or(&[])
            .iter()
            .rposition(|ch| *ch == '\n')
            .map_or(0, |place| place.saturating_add(1));
        let prefix = chars.get(line_start..start).unwrap_or(&[]);
        if end <= last && !prefix.contains(&'>') {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_wrappers_and_private_subcommands() {
        assert_eq!(sensitive_chunk(&["timeout".into(), "5".into()]), Ok(false));
        assert_eq!(sensitive_chunk(&["env".into()]), Ok(true));
        assert_eq!(sensitive_chunk(&["tool".into(), "doctor".into()]), Ok(true));
    }

    #[test]
    fn docker_and_ps_formats() {
        assert!(docker_inspect_shows_environment(&["inspect".into()]));
        assert!(!docker_inspect_shows_environment(&[
            "inspect".into(),
            "--format={{.Id}}".into()
        ]));
        assert!(ps_format_shows_environment("pid,environ=ENV"));
    }
}
