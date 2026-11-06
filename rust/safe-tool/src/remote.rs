use std::collections::HashSet;

use guard_common::locale::{self, FormatValue};
use guard_common::secret_scan::contains_secret;
use guard_common::shell::{first_operand, split_options};
use guard_common::shlex;
use guard_common::sys::EmbeddedNul;

use crate::{command, consts};

fn text(value: &str) -> FormatValue {
    FormatValue::Text(value.to_owned())
}

fn reason(key: &str, name: &str, detail: &str, field: &str) -> String {
    locale::message(key, &[("name", text(name)), (field, text(detail))])
}

fn values<'a>(words: &'a [&'a str]) -> HashSet<&'a str> {
    words.iter().copied().collect()
}

fn entry<'a>(table: &'a [(&str, &'a [&str])], name: &str) -> &'a [&'a str] {
    table
        .iter()
        .find(|(key, _)| *key == name)
        .map_or(&[], |(_, value)| value)
}

fn letters<'a>(table: &'a [(&str, &'a str)], name: &str) -> &'a str {
    table
        .iter()
        .find(|(key, _)| *key == name)
        .map_or("", |(_, value)| value)
}

fn char_slice(chars: &[char], start: usize, end: usize) -> String {
    chars.get(start..end).unwrap_or(&[]).iter().collect()
}

pub fn remote_stages(command: &str) -> Option<Vec<Vec<String>>> {
    let chars: Vec<char> = command.chars().collect();
    if chars.len() > consts::REMOTE_MAX_CHARS
        || chars
            .iter()
            .any(|ch| matches!(ch, '\n' | '\r' | '\0' | '`'))
        || command.contains("$(")
        || command.contains("${")
    {
        return None;
    }
    let mut stages = Vec::new();
    let (mut start, mut index, length) = (0usize, 0usize, chars.len());
    let mut braces = Vec::new();
    let mut word_start = true;
    let mut word_begin = 0usize;
    while index < length {
        let character = *chars.get(index)?;
        if character == '#' && word_start {
            break;
        }
        let was_start = word_start;
        if was_start && !matches!(character, ' ' | '\t' | '|') {
            word_begin = index;
        }
        if matches!(character, '*' | '?' | '[')
            && !chars.get(word_begin..index).unwrap_or(&[]).contains(&'/')
        {
            return None;
        }
        word_start = matches!(character, ' ' | '\t' | '|');
        if character == '\\' {
            word_start = false;
            index = index.saturating_add(2);
            continue;
        }
        if character == '\'' {
            word_start = false;
            let closing = chars
                .get(index.saturating_add(1)..)?
                .iter()
                .position(|ch| *ch == '\'')?;
            index = index.saturating_add(closing).saturating_add(2);
            continue;
        }
        if character == '"' {
            word_start = false;
            index = index.saturating_add(1);
            while index < length && chars.get(index) != Some(&'"') {
                index = index.saturating_add(if chars.get(index) == Some(&'\\') {
                    2
                } else {
                    1
                });
            }
            if index >= length {
                return None;
            }
            index = index.saturating_add(1);
            continue;
        }
        if ";&<>()".contains(character) {
            return None;
        }
        if character == '$' && matches!(chars.get(index.saturating_add(1)), Some('\'' | '"')) {
            return None;
        }
        if character == '{' {
            braces.push(false);
        } else if !braces.is_empty()
            && (character == ','
                || (character == '.' && chars.get(index.saturating_add(1)) == Some(&'.')))
        {
            if let Some(last) = braces.last_mut() {
                *last = true;
            }
        } else if character == '}' && braces.pop().unwrap_or(false) {
            return None;
        }
        if character == '|' {
            if chars.get(index.saturating_add(1)) == Some(&'|') {
                return None;
            }
            stages.push(char_slice(&chars, start, index));
            start = index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    stages.push(char_slice(&chars, start, index));
    let mut words = Vec::new();
    for stage in stages {
        let split = shlex::split(&stage).ok()?;
        if split.is_empty() {
            return None;
        }
        words.push(split);
    }
    Some(words)
}

pub fn shown(value: &str) -> String {
    let mut chars = value.chars();
    let acceptable = match chars.next() {
        None => true,
        Some(first) => {
            first.is_ascii_alphabetic()
                && value.chars().count() <= 31
                && chars.all(|ch| ch.is_ascii_alphanumeric() || "_+-".contains(ch))
        }
    };
    if acceptable && !contains_secret(value) {
        value.to_owned()
    } else {
        "?".to_owned()
    }
}

pub fn may_take_next(argument: &str, values: &str, flags: &[&str], attached_only: &str) -> bool {
    if argument.starts_with("--") {
        return argument.chars().count() > 2
            && !argument.contains('=')
            && !flags.iter().any(|flag| flag.starts_with(argument));
    }
    if argument.starts_with('-') && argument.chars().count() > 1 {
        let len = argument.chars().count();
        for (position, letter) in argument.chars().enumerate().skip(1) {
            if values.contains(letter) {
                return position.saturating_add(1) == len && !attached_only.contains(letter);
            }
        }
    }
    false
}

pub fn resolve_long_options(
    arguments: &[String],
    value_options: &[&str],
    flags: &[&str],
) -> Option<Vec<String>> {
    let mut resolved = Vec::new();
    for argument in arguments {
        if argument == "--" {
            resolved.extend(arguments.get(resolved.len()..)?.iter().cloned());
            return Some(resolved);
        }
        if argument.starts_with("--") && argument.chars().count() > 2 {
            let (name, equals, value) = match argument.split_once('=') {
                Some((name, value)) => (name, "=", value),
                None => (argument.as_str(), "", ""),
            };
            let known: HashSet<&str> = value_options.iter().chain(flags.iter()).copied().collect();
            let candidates: Vec<&str> = if known.contains(name) {
                vec![name]
            } else {
                known
                    .into_iter()
                    .filter(|option| option.starts_with(name))
                    .collect()
            };
            if candidates.len() != 1 {
                return None;
            }
            resolved.push(format!("{}{equals}{value}", candidates.first()?));
        } else {
            resolved.push(argument.clone());
        }
    }
    Some(resolved)
}

pub fn remote_option_problem(name: &str, arguments: &[String]) -> Option<String> {
    let refused = |option: &str| reason("safe_tool.remote.reason.option", name, option, "option");
    let exact = entry(consts::REMOTE_FORBIDDEN_OPTIONS, name);
    let long_options = entry(consts::REMOTE_FORBIDDEN_LONG, name);
    let forbidden_letters = letters(consts::REMOTE_FORBIDDEN_LETTERS, name);
    let value_letters = letters(consts::REMOTE_VALUE_LETTERS, name);
    let exact_long = entry(consts::REMOTE_EXACT_LONG, name);
    let mut previous = "";
    for argument in arguments {
        if argument == "--" && name != "find" {
            if (!exact.is_empty() || !long_options.is_empty() || !forbidden_letters.is_empty())
                && may_take_next(
                    previous,
                    value_letters,
                    entry(consts::REMOTE_FLAG_LONG, name),
                    letters(consts::REMOTE_ATTACHED_LETTERS, name),
                )
            {
                return Some(refused("--"));
            }
            break;
        }
        previous = argument;
        if exact.contains(&argument.as_str()) {
            return Some(refused(argument));
        }
        if argument.starts_with("--") {
            let option = argument.split('=').next().unwrap_or("");
            let forbidden = if exact_long.contains(&option) {
                None
            } else {
                long_options
                    .iter()
                    .find(|item| option.chars().count() > 2 && item.starts_with(option))
            };
            if let Some(item) = forbidden {
                return Some(refused(item));
            }
        } else if argument.starts_with('-')
            && !argument
                .get(1..)
                .unwrap_or("")
                .chars()
                .all(|ch| ch.is_ascii_digit())
        {
            for letter in argument.chars().skip(1) {
                if forbidden_letters.contains(letter) {
                    return Some(refused(&format!("-{letter}")));
                }
                if value_letters.contains(letter) {
                    break;
                }
            }
        }
    }
    if name == "date" {
        let operands = split_options(arguments, "dfr", &values(consts::DATE_VALUE_OPTIONS));
        if operands.iter().any(|operand| !operand.starts_with('+')) {
            return Some(locale::message(
                "safe_tool.remote.reason.operand",
                &[("name", text(name))],
            ));
        }
    }
    if name == "uniq" {
        let operands = split_options(arguments, "fsw", &values(consts::UNIQ_VALUE_OPTIONS));
        if operands.len() > 1 {
            return Some(locale::message(
                "safe_tool.remote.reason.operand",
                &[("name", text(name))],
            ));
        }
    }
    if name == "docker" {
        return remote_docker_problem(arguments);
    }
    if name == "systemctl" {
        let resolved = resolve_long_options(
            arguments,
            consts::SYSTEMCTL_VALUE_OPTIONS,
            entry(consts::REMOTE_FLAG_LONG, "systemctl"),
        );
        let Some(resolved) = resolved else {
            return Some(refused("--"));
        };
        let index = first_operand(
            &resolved,
            "HMPnopst",
            &values(consts::SYSTEMCTL_VALUE_OPTIONS),
        );
        let subcommand = index
            .and_then(|at| resolved.get(at))
            .map_or("", String::as_str);
        if !entry(consts::REMOTE_SUBCOMMANDS, name).contains(&subcommand) {
            return Some(reason(
                "safe_tool.remote.reason.subcommand",
                name,
                &shown(subcommand),
                "subcommand",
            ));
        }
    }
    if name == "pm2" {
        let (subcommand, no_stream, problem) = pm2_read(arguments);
        if problem.is_some() {
            return problem;
        }
        if !entry(consts::REMOTE_SUBCOMMANDS, name).contains(&subcommand.as_str()) {
            return Some(reason(
                "safe_tool.remote.reason.subcommand",
                name,
                &shown(&subcommand),
                "subcommand",
            ));
        }
        if subcommand == "logs" && !no_stream {
            return Some(reason(
                "safe_tool.remote.reason.option",
                "pm2 logs",
                "without --nostream",
                "option",
            ));
        }
    }
    None
}

static PM2_LOGS_FLAGS: &[&str] = &[
    "--err",
    "--format",
    "--json",
    "--no-color",
    "--nostream",
    "--out",
    "--raw",
];
static PM2_LOGS_VALUE_OPTIONS: &[&str] = &["--lines", "--name", "--namespace", "-n"];

pub fn pm2_read(arguments: &[String]) -> (String, bool, Option<String>) {
    let mut subcommand = String::new();
    let mut ends = false;
    let mut index = 0usize;
    while index < arguments.len() {
        let Some(argument) = arguments.get(index) else {
            break;
        };
        index = index.saturating_add(1);
        if argument == "--" {
            if subcommand.is_empty() {
                if let Some(next) = arguments.get(index) {
                    subcommand = next.clone();
                }
            }
            break;
        }
        if !argument.starts_with('-') || argument == "-" {
            if subcommand.is_empty() {
                subcommand = argument.clone();
            }
            continue;
        }
        let (name, equals) = match argument.split_once('=') {
            Some((name, _)) => (name, true),
            None => (argument.as_str(), false),
        };
        if PM2_LOGS_VALUE_OPTIONS.contains(&name) {
            if !equals {
                index = index.saturating_add(1);
            }
        } else if PM2_LOGS_FLAGS.contains(&name) && !equals {
            ends = ends || name == "--nostream";
        } else {
            return (
                subcommand,
                false,
                Some(reason(
                    "safe_tool.remote.reason.option",
                    "pm2",
                    &shown(name),
                    "option",
                )),
            );
        }
    }
    (subcommand, ends, None)
}

pub fn flag_is_set(arguments: &[String], flag: &str, value_options: &[&str]) -> bool {
    let mut state = false;
    let mut index = 0usize;
    while index < arguments.len() {
        let Some(argument) = arguments.get(index) else {
            break;
        };
        index = index.saturating_add(1);
        if argument == "--" {
            break;
        }
        let (option, equals, value) = match argument.split_once('=') {
            Some((name, value)) => (name, true, value),
            None => (argument.as_str(), false, ""),
        };
        if value_options.contains(&option) && !equals {
            index = index.saturating_add(1);
            continue;
        }
        if option != flag {
            continue;
        }
        if !equals || consts::BOOLEAN_TRUE.contains(&value) {
            state = true;
        } else if consts::BOOLEAN_FALSE.contains(&value) {
            state = false;
        } else {
            return false;
        }
    }
    state
}

pub fn docker_follows(arguments: &[String]) -> bool {
    let mut state = false;
    for argument in arguments {
        if argument == "--" {
            break;
        }
        if argument.starts_with("--") {
            let (name, equals, value) = match argument.split_once('=') {
                Some((name, value)) => (name, true, value),
                None => (argument.as_str(), false, ""),
            };
            if name != "--follow" {
                continue;
            }
            if !equals || consts::BOOLEAN_TRUE.contains(&value) {
                state = true;
            } else if consts::BOOLEAN_FALSE.contains(&value) {
                state = false;
            } else {
                return true;
            }
        } else if argument.starts_with('-') && argument.chars().count() > 1 {
            let short = argument.get(1..).unwrap_or("");
            let (letters, value) = short
                .split_once('=')
                .map_or((short, None), |(left, right)| (left, Some(right)));
            let size = letters.chars().count();
            for (position, letter) in letters.chars().enumerate() {
                if letter == 'n' {
                    break;
                }
                if letter != 'f' {
                    continue;
                }
                if position.saturating_add(1) != size
                    || value.is_none()
                    || value.is_some_and(|v| consts::BOOLEAN_TRUE.contains(&v))
                {
                    state = true;
                } else if value.is_some_and(|v| consts::BOOLEAN_FALSE.contains(&v)) {
                    state = false;
                } else {
                    return true;
                }
            }
        }
    }
    state
}

pub fn remote_docker_problem(arguments: &[String]) -> Option<String> {
    let index = first_operand(arguments, "Hcl", &values(consts::DOCKER_VALUE_OPTIONS));
    let subcommand = index
        .and_then(|at| arguments.get(at))
        .map_or("", String::as_str);
    if !entry(consts::REMOTE_SUBCOMMANDS, "docker").contains(&subcommand) {
        return Some(reason(
            "safe_tool.remote.reason.subcommand",
            "docker",
            &shown(subcommand),
            "subcommand",
        ));
    }
    for argument in arguments.get(..index.unwrap_or(0)).unwrap_or(&[]) {
        if argument.starts_with("--") {
            let named = argument.split('=').next().unwrap_or("");
            if ["--host", "--context", "--config", "--tlskey"].contains(&named) {
                return Some(reason(
                    "safe_tool.remote.reason.option",
                    "docker",
                    named,
                    "option",
                ));
            }
        } else if argument.starts_with('-') {
            for letter in argument.chars().skip(1) {
                if "Hc".contains(letter) {
                    return Some(reason(
                        "safe_tool.remote.reason.option",
                        "docker",
                        &format!("-{letter}"),
                        "option",
                    ));
                }
                if "Hcl".contains(letter) {
                    break;
                }
            }
        }
    }
    let mut rest = index
        .and_then(|at| arguments.get(at.saturating_add(1)..))
        .unwrap_or(&[]);
    let mut effective = subcommand;
    if subcommand == "compose" {
        let position = first_operand(rest, "fp", &values(consts::COMPOSE_VALUE_OPTIONS));
        effective = position
            .and_then(|at| rest.get(at))
            .map_or("", String::as_str);
        if !consts::REMOTE_COMPOSE_SUBCOMMANDS.contains(&effective) {
            return Some(reason(
                "safe_tool.remote.reason.subcommand",
                "docker compose",
                &shown(effective),
                "subcommand",
            ));
        }
        rest = position
            .and_then(|at| rest.get(at.saturating_add(1)..))
            .unwrap_or(&[]);
    }
    if effective == "logs" && docker_follows(rest) {
        return Some(reason(
            "safe_tool.remote.reason.option",
            "docker logs",
            "-f",
            "option",
        ));
    }
    if subcommand == "stats"
        && !flag_is_set(rest, "--no-stream", consts::DOCKER_STATS_VALUE_OPTIONS)
    {
        return Some(reason(
            "safe_tool.remote.reason.option",
            "docker stats",
            "without --no-stream",
            "option",
        ));
    }
    None
}

fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let initial_slashes = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part != ".."
            || (initial_slashes.is_empty() && parts.is_empty())
            || parts.last() == Some(&"..")
        {
            parts.push(part);
        } else if !parts.is_empty() {
            parts.pop();
        }
    }
    let joined = format!("{initial_slashes}{}", parts.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

pub fn remote_check(command_text: &str) -> Result<Option<String>, EmbeddedNul> {
    let Some(stages) = remote_stages(command_text) else {
        return Ok(Some(locale::message("safe_tool.remote.reason.shape", &[])));
    };
    for words in &stages {
        let mut words = words.as_slice();
        if words.first().is_some_and(|word| word == "sudo") {
            words = if words.get(1).is_some_and(|word| word == "-n") {
                words.get(2..).unwrap_or(&[])
            } else {
                words.get(1..).unwrap_or(&[])
            };
        }
        let Some(name) = words.first() else {
            return Ok(Some(locale::message("safe_tool.remote.reason.shape", &[])));
        };
        if !consts::in_remote_read_commands(name) {
            return Ok(Some(locale::message(
                "safe_tool.remote.reason.command",
                &[("name", text(&shown(name)))],
            )));
        }
        if let Some(problem) = remote_option_problem(name, words.get(1..).unwrap_or(&[])) {
            return Ok(Some(problem));
        }
    }
    let decoded = stages
        .iter()
        .map(|words| {
            words
                .iter()
                .map(|word| shlex::quote(word))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let plain = stages
        .iter()
        .map(|words| {
            words
                .iter()
                .map(|word| {
                    shlex::quote(&if word.contains('/') {
                        normpath(word)
                    } else {
                        word.clone()
                    })
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let previous = consts::ps_target();
    consts::set_ps_target("linux");
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            consts::set_ps_target(&self.0);
        }
    }
    let _restore = Restore(previous);
    let sensitive = consts::remote_secret_paths_search(command_text).is_some()
        || consts::remote_secret_paths_search(&decoded).is_some()
        || consts::remote_secret_paths_search(&plain).is_some()
        || command::sensitive_command(command_text, false)?
        || command::sensitive_command(&decoded, false)?
        || command::sensitive_command(&plain, false)?;
    if sensitive {
        Ok(Some(locale::message(
            "safe_tool.remote.reason.sensitive",
            &[],
        )))
    } else {
        Ok(None)
    }
}

pub fn remote_readonly(command_text: &str) -> Result<i32, EmbeddedNul> {
    let Some(problem) = remote_check(command_text)? else {
        return Ok(0);
    };
    let mut commands: Vec<&str> = consts::REMOTE_READ_COMMANDS.to_vec();
    commands.sort_unstable();
    eprintln!(
        "{}",
        locale::message(
            "safe_tool.remote.refused",
            &[
                ("reason", text(&problem)),
                ("commands", text(&commands.join(", ")))
            ]
        )
    );
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_and_option_policy() {
        assert!(remote_stages("ls | head").is_some());
        assert!(remote_stages("ls && rm x").is_none());
        assert!(remote_stages("ls *").is_none());
        assert_eq!(
            remote_check("docker stats --no-stream").ok().flatten(),
            None
        );
        assert!(remote_check("docker stats").ok().flatten().is_some());
        assert!(remote_check("pm2 logs app").ok().flatten().is_some());
        assert_eq!(remote_check("pm2 logs app --nostream").ok().flatten(), None);
    }
}
