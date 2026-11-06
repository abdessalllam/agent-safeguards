use std::sync::LazyLock;

use guard_common::sys::EmbeddedNul;
use guard_common::{env, pyglob, shell, shlex, sys};
use regex::Regex;

use crate::{consts, words};

const SEARCH_VALUE_OPTIONS: &[&str] = &[
    "--after-context",
    "--before-context",
    "--binary-files",
    "--color",
    "--colour",
    "--context",
    "--depth",
    "--devices",
    "--directories",
    "--encoding",
    "--exclude",
    "--exclude-dir",
    "--exclude-from",
    "--file",
    "--file-search-regex",
    "--glob",
    "--iglob",
    "--ignore",
    "--ignore-file",
    "--include",
    "--label",
    "--max-columns",
    "--max-count",
    "--max-depth",
    "--path-to-ignore",
    "--pre",
    "--regexp",
    "--sort",
    "--sortr",
    "--threads",
    "--type",
    "--type-add",
    "--type-not",
];
const SEARCH_PATTERN_OPTIONS: &[&str] = &["-e", "--regexp", "-f", "--file"];
const MAX_GLOB_MATCHES: usize = shell::MAX_GLOB_MATCHES;

static RG_SHORT: LazyLock<Regex> = LazyLock::new(|| compile(r"\A-[A-Za-z]+\z"));
static GREP_RECURSIVE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\A-[A-Za-z0-9]*[rR][A-Za-z0-9]*\z"));
static SHELL_O: LazyLock<Regex> = LazyLock::new(|| compile(r"\A[-+][A-Za-z]*o\z"));
static NULL_REDIRECT: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\d*>>?[\s\u{001c}-\u{001f}]*(?:/dev/null|&\d)"));

fn compile(pattern: &str) -> Regex {
    guard_common::pyre::new(pattern).unwrap_or_else(|_| std::process::abort())
}

pub fn working_folder() -> String {
    match std::env::current_dir() {
        Ok(path) => sys::realpath(path.to_string_lossy().as_ref()),
        Err(_) => env::user_home().to_owned(),
    }
}

pub fn covers_home(operand: &str) -> Result<bool, EmbeddedNul> {
    covers_home_at(operand, env::user_home(), &working_folder())
}

fn home_prefix_replaced(operand: &str, home: &str) -> String {
    for prefix in ["~", "$HOME", concat!("$", "{HOME}")] {
        if let Some(tail) = operand.strip_prefix(prefix) {
            if tail.is_empty() || tail.starts_with('/') || tail == "\n" {
                return format!("{home}{tail}");
            }
        }
    }
    operand.to_owned()
}

pub fn covers_home_at(operand: &str, home: &str, cwd: &str) -> Result<bool, EmbeddedNul> {
    let mut expanded = home_prefix_replaced(operand, home);
    if expanded.starts_with('~') {
        expanded = pyglob::expanduser(&expanded)?;
    }
    if !expanded.starts_with('/') {
        expanded = if cwd.is_empty() || cwd.ends_with('/') {
            format!("{cwd}{expanded}")
        } else {
            format!("{cwd}/{expanded}")
        };
    }
    let paths = if expanded.contains(['*', '?', '[']) {
        pyglob::iglob(&expanded, MAX_GLOB_MATCHES)?
    } else {
        vec![expanded]
    };
    let folders: Vec<String> = consts::STARTUP_FOLDER_PATHS
        .iter()
        .chain(consts::STARTUP_HISTORY_FOLDER_PATHS.iter())
        .map(|folder| format!("{home}/.{folder}/"))
        .collect();
    let home_slash = format!("{home}/");
    for path in paths {
        let target = format!("{}/", sys::try_realpath(&path)?.trim_end_matches('/'));
        if home_slash.starts_with(&target)
            || folders
                .iter()
                .any(|folder| folder.starts_with(&target) || target.starts_with(folder))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn search_targets(executable: &str, arguments: &[String]) -> (Vec<String>, bool) {
    let letters = match executable {
        "ack" => "ABCgm",
        "ag" => "ABCGgmp",
        "egrep" | "fgrep" | "grep" => "ABCDdefm",
        "rg" => "ABCEdefgjMmrTt",
        _ => "",
    };
    let mut operands = Vec::new();
    let (mut pattern_option, mut recursive_directories, mut after_options) = (false, false, false);
    let mut index = 0usize;
    while let Some(argument) = arguments.get(index) {
        index = index.saturating_add(1);
        if after_options || !argument.starts_with('-') || argument == "-" {
            operands.push(argument.clone());
            continue;
        }
        if argument == "--" {
            after_options = true;
            continue;
        }
        let (mut option, mut value) = (String::new(), String::new());
        if argument.starts_with("--") {
            let (head, tail) = argument.split_once('=').unwrap_or((argument, ""));
            option = head.to_owned();
            value = tail.to_owned();
            if !argument.contains('=') && SEARCH_VALUE_OPTIONS.contains(&option.as_str()) {
                if let Some(next) = arguments.get(index) {
                    value = next.clone();
                    index = index.saturating_add(1);
                }
            }
        } else {
            let chars: Vec<char> = argument.chars().collect();
            for (position, letter) in chars.iter().enumerate().skip(1) {
                if letters.contains(*letter) {
                    option = format!("-{letter}");
                    value = chars.iter().skip(position.saturating_add(1)).collect();
                    if value.is_empty() {
                        if let Some(next) = arguments.get(index) {
                            value = next.clone();
                            index = index.saturating_add(1);
                        }
                    }
                    break;
                }
            }
        }
        pattern_option |= SEARCH_PATTERN_OPTIONS.contains(&option.as_str());
        recursive_directories |=
            (option == "-d" || option == "--directories") && value == "recurse";
    }
    if pattern_option {
        (operands, recursive_directories)
    } else {
        (
            operands.into_iter().skip(1).collect(),
            recursive_directories,
        )
    }
}

pub fn searches_home(executable: &str, arguments: &[String]) -> Result<bool, EmbeddedNul> {
    searches_home_at(executable, arguments, env::user_home(), &working_folder())
}

pub fn searches_home_at(
    executable: &str,
    arguments: &[String],
    home: &str,
    cwd: &str,
) -> Result<bool, EmbeddedNul> {
    if !consts::startup_rules() {
        return Ok(false);
    }
    let options: Vec<&str> = arguments
        .iter()
        .map(String::as_str)
        .filter(|arg| arg.starts_with('-'))
        .collect();
    let (targets, recursive_directories) = search_targets(executable, arguments);
    let recursive = match executable {
        "grep" | "egrep" | "fgrep" => {
            recursive_directories
                || options.iter().any(|arg| {
                    *arg == "--recursive"
                        || *arg == "--dereference-recursive"
                        || GREP_RECURSIVE.is_match(arg)
                })
        }
        "rg" => {
            let unrestricted = options
                .iter()
                .filter(|arg| RG_SHORT.is_match(arg))
                .map(|arg| arg.chars().filter(|ch| *ch == 'u').count())
                .sum::<usize>()
                .saturating_add(
                    options
                        .iter()
                        .filter(|arg| **arg == "--unrestricted")
                        .count(),
                );
            options.contains(&"--hidden") || options.contains(&"-.") || unrestricted >= 2
        }
        _ => true,
    };
    if !recursive {
        return Ok(false);
    }
    let targets = if targets.is_empty() {
        vec![".".to_owned()]
    } else {
        targets
    };
    for target in &targets {
        if covers_home_at(target, home, cwd)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn traces_commands(executable: &str, arguments: &[String]) -> bool {
    let names: Vec<String> = arguments
        .iter()
        .map(|arg| arg.replace(&['_', '-'][..], "").to_lowercase())
        .collect();
    if executable == "setopt" {
        return names
            .iter()
            .any(|name| consts::TRACE_OPTION_NAMES.contains(&name.as_str()));
    }
    if executable == "shopt" {
        return names
            .iter()
            .any(|name| consts::TRACE_OPTION_NAMES.contains(&name.as_str()))
            && arguments
                .iter()
                .any(|arg| arg.starts_with('-') && arg.contains('o'));
    }
    let mut index = 0usize;
    while let Some(argument) = arguments.get(index) {
        if !((argument.starts_with('-') || argument.starts_with('+'))
            && argument != "-"
            && argument != "--")
        {
            break;
        }
        if consts::TRACE_OPTION_FULL.is_match(argument)
        {
            return true;
        }
        if SHELL_O.is_match(argument) {
            if names
                .get(index.saturating_add(1))
                .is_some_and(|name| consts::TRACE_OPTION_NAMES.contains(&name.as_str()))
            {
                return true;
            }
            index = index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    false
}

pub fn chunks_with_separators(command: &str) -> Vec<(Vec<String>, String, String)> {
    let normalized = shell::normalize_command(command, None);
    let tokens = match shlex::Lexer::new(&normalized)
        .posix(true)
        .punctuation_chars(";&|()\n")
        .whitespace(" \t\r")
        .whitespace_split(true)
        .commenters("")
        .tokens()
    {
        Ok(tokens) => tokens,
        Err(_) => return Vec::new(),
    };
    let mut parts = Vec::new();
    let mut current = Vec::new();
    let mut before = String::new();
    for token in tokens
        .into_iter()
        .filter(|token| token != shell::REDIRECTION_MARKER)
    {
        if !token.is_empty() && token.chars().all(|ch| ";&|()\n".contains(ch)) {
            if !current.is_empty() {
                parts.push((current, before, token.clone()));
                current = Vec::new();
                before = token;
            } else {
                before.push_str(&token);
            }
        } else {
            current.push(token);
        }
    }
    if !current.is_empty() {
        parts.push((current, before, String::new()));
    }
    parts
}

pub fn grep_prints_nothing_private(arguments: &[String]) -> Option<String> {
    let (mut counting, mut plain, mut names) = (false, true, false);
    let mut operands = Vec::new();
    let mut index = 0usize;
    let mut after_options = false;
    while let Some(word) = arguments.get(index) {
        index = index.saturating_add(1);
        if !operands.is_empty() && word.starts_with('-') && word != "-" && !after_options {
            return None;
        }
        if after_options || !word.starts_with('-') || word == "-" {
            operands.push(word);
        } else if word == "--" {
            after_options = true;
        } else if word.starts_with("--") {
            let name = word.split_once('=').map_or(word.as_str(), |(name, _)| name);
            if consts::GREP_COUNTING_OPTIONS.contains(&name) {
                counting = true;
                names |= name == "--files-with-matches" || name == "--files-without-match";
            } else if consts::GREP_PLAIN_OPTIONS.contains(&name) {
                names |= name == "--with-filename";
            } else {
                plain = false;
            }
        } else {
            let chars: Vec<char> = word.chars().collect();
            for (position, flag) in chars.iter().enumerate().skip(1) {
                let text = flag.to_string();
                if consts::GREP_VALUE_FLAGS.contains(&text.as_str()) {
                    plain = false;
                    if position == chars.len().saturating_sub(1) {
                        index = index.saturating_add(1);
                    }
                    break;
                }
                if consts::GREP_COUNTING_FLAGS.contains(&text.as_str()) {
                    counting = true;
                    names |= *flag == 'l' || *flag == 'L';
                } else if consts::GREP_PLAIN_FLAGS.contains(&text.as_str()) {
                    names |= *flag == 'H';
                } else {
                    plain = false;
                }
            }
        }
    }
    if !plain || operands.is_empty() {
        return None;
    }
    if !counting && !consts::in_safe_config_words(&operands.first()?.to_lowercase()) {
        return None;
    }
    Some(
        if names || operands.len() > 2 {
            "names"
        } else {
            "quiet"
        }
        .to_owned(),
    )
}

pub fn prints_nothing_private(raw_words: &[String]) -> Option<String> {
    let executable = words::normalized(raw_words.first()?);
    let arguments = raw_words.get(1..)?;
    if arguments
        .iter()
        .any(|arg| arg.starts_with("--files0") || consts::UNRESOLVED_WORD.is_match(arg))
    {
        return None;
    }
    if matches!(executable.as_str(), "[" | "[[" | "test") {
        return Some("quiet".to_owned());
    }
    if consts::METADATA_COMMANDS.contains(&executable.as_str()) {
        return Some("names".to_owned());
    }
    if consts::GREP_COMMANDS.contains(&executable.as_str()) {
        return grep_prints_nothing_private(arguments);
    }
    None
}

pub fn names_sensitive_path(lowered: &str, code: &str) -> bool {
    let total = consts::sensitive_path_pattern_finditer(lowered).len();
    if total == 0 {
        return false;
    }
    let redirects = NULL_REDIRECT.replace_all(lowered, "");
    if consts::SHADOWING_PATTERN.is_match(lowered)
        || redirects.contains('<')
        || redirects.contains('>')
    {
        return true;
    }
    let parts = chunks_with_separators(code);
    if consts::GREP_ENVIRONMENT.is_match(lowered)
        || parts.iter().any(|(chunk, _, _)| {
            chunk
                .first()
                .is_some_and(|word| !consts::in_neighbor_commands(&words::normalized(word)))
        })
    {
        return true;
    }
    let mut harmless = 0usize;
    for (chunk, before, after) in parts {
        let text = chunk.join(" ").to_lowercase();
        let mentions = consts::sensitive_path_pattern_finditer(&text).len();
        if mentions == 0 {
            continue;
        }
        let kind = prints_nothing_private(&chunk);
        if kind.is_none() || consts::git_config_path_pattern_finditer(&text).len() != mentions {
            return true;
        }
        if kind.as_deref() == Some("names")
            && (!consts::SEPARATORS_AFTER_QUIET.contains(&before.as_str())
                || !consts::SEPARATORS_AFTER_QUIET.contains(&after.as_str()))
        {
            return true;
        }
        harmless = harmless.saturating_add(mentions);
    }
    harmless != total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_options_and_trace_flags_follow_python() {
        assert_eq!(
            search_targets("grep", &["-drecurse", "K", "~"].map(String::from)),
            (vec!["~".to_owned()], true)
        );
        assert_eq!(
            search_targets("rg", &["-e", "K", "src"].map(String::from)),
            (vec!["src".to_owned()], false)
        );
        assert!(traces_commands("bash", &["-x".to_owned()]));
        assert!(!traces_commands(
            "bash",
            &["build.sh".to_owned(), "-x".to_owned()]
        ));
    }

    #[test]
    fn quiet_grep_and_separator_policy() {
        assert_eq!(
            grep_prints_nothing_private(&["-c", "x"].map(String::from)),
            Some("quiet".to_owned())
        );
        assert_eq!(
            grep_prints_nothing_private(&["--files-with-matches", "x"].map(String::from)),
            Some("names".to_owned())
        );
        assert_eq!(
            chunks_with_separators("git config; wc -l"),
            vec![
                (
                    vec!["git".to_owned(), "config".to_owned()],
                    String::new(),
                    ";".to_owned()
                ),
                (
                    vec!["wc".to_owned(), "-l".to_owned()],
                    ";".to_owned(),
                    String::new()
                )
            ]
        );
    }

    #[test]
    fn recursive_home_search_and_sensitive_path_policy() {
        let home = "/private/tmp/s2-home";
        let cwd = "/private/tmp/s2-home/project";
        assert_eq!(covers_home_at("..", home, cwd), Ok(true));
        assert_eq!(
            searches_home_at("grep", &["-r", "K", ".."].map(String::from), home, cwd),
            Ok(true)
        );
        assert_eq!(
            searches_home_at("grep", &["K", ".."].map(String::from), home, cwd),
            Ok(false)
        );
        assert!(!names_sensitive_path("ls .gitconfig", "ls .gitconfig"));
        assert!(names_sensitive_path("cat .gitconfig", "cat .gitconfig"));
    }
}
