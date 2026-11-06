use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use guard_common::env::user_home;
use guard_common::locale::{message, FormatValue};
use guard_common::shell::{
    command_substitutions, expand_braces, normalize_command, split_options,
    strip_wrappers_with_directory, unquoted_text, GIT_VALUE_OPTIONS, MAX_COMMAND_CHARS,
    SHELL_KEYWORDS,
};
use guard_common::shlex;
use guard_common::sys::try_realpath;
use regex::Regex;

use crate::commands::{gio, kio_command, mv, rm, trash};
use crate::consts::{
    self, DISKUTIL_ERASE, ERASE_TOOL, FINDER_TEXT, HADOOP_PURGE_OPTIONS, INTERPRETERS,
    KDE_TRASH_TOOL, KIO_REMOVE_VERBS, KIO_TOOL, QUICK_SCAN, REMOTE_COMMAND_NAMES,
    REMOTE_COMMAND_PATTERN, SHELLS, STDIN_OPERATORS, SYSTEM_PROGRAM_FOLDERS, TRASH_EMPTY_TOOL,
    TRASH_TOOLS, WINDOWS_SHELLS, WINDOWS_TEXT,
};
use crate::errors::{Denied, Stop};
use crate::find::{find, set_stdin_files, stdin_files, xargs};
use crate::globs::glob_matches;
use crate::places::inside;
use crate::remote::{check_remote_command, remote_command_words, rsync, wrapper_directories};
use crate::scripts::{check_script, search_path, vets_deletes, without_text_heredocs};
use crate::targets::{
    check_target, location_path, quoted_literal_words, quoted_words, remote, set_quoted_words,
};
use crate::tokens::{
    base, expand, is_computed, set_variables_changed, tokenize, variables_changed,
    variables_changed_state,
};

static DEVICE_WRITE_OK: LazyLock<Regex> = LazyLock::new(|| {
    fixed_regex(
        r"\A/dev/(?:null|zero|full|stdout|stderr|stdin|tty[\p{L}\p{N}_]*|console|random|urandom|ptmx|(?:fd|pts|shm|tcp|udp)/.*)\z",
    )
});
static DEVICE_REDIRECT: LazyLock<Regex> =
    LazyLock::new(|| fixed_regex(r"(?:>|<>)[&|!]?!?[\s\x1c-\x1f]*/+dev/"));
static FILE_DESCRIPTOR_OPERAND: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r"\A(?:\d+-?|-)\z"));
static BRACE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    fixed_regex(
        r"\{([^{}]*,[^{}]*)\}|\{(-?\d{1,30}|[A-Za-z])\.\.(-?\d{1,30}|[A-Za-z])(?:\.\.(-?\d{1,30}))?\}",
    )
});
static GLOB_ACTIVE: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r"[*?\[]"));
static QUOTE_CHARACTERS: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r#"[\\'\"]"#));
static CD_WORD: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r"\b(?:cd|pushd|popd)\b"));
static DELETE_WORD: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r"-delete\b"));
static SHELL_OPTION_CONTENT: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r"[\s\x1c-\x1f;|&=]"));
static SHELL_OPTION_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| fixed_regex(r"\A[-+]+[A-Za-z-]{0,40}=?"));
static REMOTE_NAME_SPLIT: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r"[:,\s\x1c-\x1f]+"));

fn fixed_regex(pattern: &str) -> Regex {
    guard_common::pyre::new(pattern).unwrap_or_else(|error| panic!("fixed regex: {error}"))
}

fn fullmatch(pattern: &Regex, text: &str) -> bool {
    pattern
        .find(text)
        .is_some_and(|found| found.start() == 0 && found.end() == text.len())
}

fn match_start(pattern: &Regex, text: &str) -> bool {
    pattern.find(text).is_some_and(|found| found.start() == 0)
}

fn value(text: &str) -> FormatValue {
    FormatValue::Text(text.to_owned())
}

fn denied(key: &str, values: &[(&str, FormatValue)]) -> Stop {
    Stop::Denied(Denied::new(message(key, values)))
}

pub fn check_one_chunk(
    words: &[String],
    cwd: Option<&str>,
    command_text: &str,
    trusted: bool,
) -> Result<(Option<String>, bool), Stop> {
    let (stripped, directories) =
        match strip_wrappers_with_directory(words, &HashSet::<&str>::new()) {
            Ok(value) => value,
            Err(_) if QUICK_SCAN.is_match(command_text) => {
                return Err(denied("delete_guard.reason.unparseable", &[]));
            }
            Err(_) => return Ok((cwd.map(str::to_owned), false)),
        };
    if stripped.is_empty() {
        return Ok((cwd.map(str::to_owned), false));
    }
    let wrapped = stripped.len() != words.len();
    let shell_cwd = cwd.map(str::to_owned);
    let cwd_owned = if directories.is_empty() {
        shell_cwd.clone()
    } else {
        wrapper_directories(&directories, cwd)?
    };
    let cwd = cwd_owned.as_deref();
    let word0 = stripped.first().map(String::as_str).unwrap_or("");
    let name = base(word0);
    if name == "popd" {
        return Ok((None, false));
    }
    if name == "cd" || name == "pushd" {
        if wrapped || remote().is_some() {
            return Ok((None, false));
        }
        let targets: Vec<&str> = stripped
            .iter()
            .skip(1)
            .filter(|word| *word == "-" || !word.starts_with('-'))
            .map(String::as_str)
            .collect();
        if targets.is_empty() {
            return Ok(if trusted && !variables_changed_state().contains("HOME") {
                (Some(user_home().to_owned()), true)
            } else {
                (None, false)
            });
        }
        if targets.len() > 1 {
            return Ok((None, false));
        }
        let target = targets.first().copied().unwrap_or("");
        if target == "-" || is_computed(target) {
            return Ok((None, false));
        }
        if !["/", "./", "../", "~", "$"]
            .iter()
            .any(|prefix| target.starts_with(prefix))
            && target != "."
            && target != ".."
            && (variables_changed_state().contains("CDPATH")
                || std::env::var_os("CDPATH").is_some_and(|text| !text.is_empty()))
        {
            return Ok((None, false));
        }
        let resolved = expand(target, cwd).map_err(Stop::from)?;
        return Ok(match resolved {
            Some(path) if trusted && Path::new(&path).is_dir() => (Some(path), true),
            _ => (None, false),
        });
    }
    if SHELLS.contains(&name) {
        check_shell(&stripped, cwd)?;
        return Ok((shell_cwd, false));
    }
    if (name == "source" || name == ".") && stripped.len() > 1 && remote().is_none() {
        check_script(stripped.get(1).map(String::as_str).unwrap_or(""), cwd, true)?;
        return Ok((shell_cwd, false));
    }
    let wrapper = if name.ends_with(".sh") {
        if word0.contains('/') {
            expand(word0, cwd).map_err(Stop::from)?
        } else {
            search_path(word0)
        }
    } else {
        None
    };
    let vetted = vets_deletes(wrapper.as_deref())?;
    if REMOTE_COMMAND_NAMES.contains(&name)
        || fullmatch(&REMOTE_COMMAND_PATTERN, name)
        || configured_remote_names().contains(name)
        || vetted
    {
        let text = remote_command_words(name, &stripped)?.join(" ");
        if !text.is_empty() && !(vetted && (text.contains('$') || text.contains('`'))) {
            check_remote_command(&text)?;
        }
        if vetted && remote().is_none() {
            if let Some(path) = wrapper.as_deref() {
                check_script(path, cwd, false)?;
            }
        }
        return Ok((shell_cwd, false));
    }
    if name == "eval" {
        check_command(
            &stripped
                .iter()
                .skip(1)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            cwd,
        )?;
        return Ok((shell_cwd, false));
    }
    let heredoc = command_text.split_once("<<").map_or("", |(_, tail)| tail);
    if INTERPRETERS.contains(&name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')) {
        let rest = stripped
            .iter()
            .skip(1)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        if consts::inline_recursive_delete_search(&rest).is_some()
            || consts::inline_recursive_delete_search(heredoc).is_some()
        {
            return Err(denied("delete_guard.reason.inline_delete", &[]));
        }
        if name == "osascript" && FINDER_TEXT.is_match(&format!("{rest}\n{heredoc}")) {
            return Err(denied(
                "delete_guard.reason.trash_empty",
                &[("name", value(name))],
            ));
        }
    }
    let rest = stripped.get(1..).unwrap_or(&[]);
    if ["rm", "unlink", "rmdir"].contains(&name) {
        rm(&stripped, cwd)?;
    } else if TRASH_TOOLS.contains(&name) {
        trash(&stripped, cwd)?;
    } else if name == "mv" {
        mv(&stripped, cwd)?;
    } else if fullmatch(&TRASH_EMPTY_TOOL, name) {
        return Err(denied(
            "delete_guard.reason.trash_empty",
            &[("name", value(name))],
        ));
    } else if fullmatch(&KDE_TRASH_TOOL, name) {
        if rest
            .iter()
            .any(|word| word.split('=').next() == Some("--empty"))
        {
            return Err(denied(
                "delete_guard.reason.trash_empty",
                &[("name", value(name))],
            ));
        }
    } else if name == "gvfs-rm" {
        for operand in split_options(rest, "", &HashSet::<&str>::new()) {
            let path = location_path(&operand, "gvfs-rm", true).map_err(Stop::from)?;
            check_target(&path, cwd, false, "gvfs-rm", None).map_err(Stop::from)?;
        }
    } else if fullmatch(&KIO_TOOL, name) {
        let operands = split_options(rest, "", &HashSet::<&str>::new());
        if let Some(verb) = kio_command(&stripped) {
            if KIO_REMOVE_VERBS.contains(&verb.as_str()) {
                if let Some(position) = operands.iter().position(|operand| operand == &verb) {
                    for operand in operands.iter().skip(position.saturating_add(1)) {
                        let full_verb = format!("kioclient {verb}");
                        let path = location_path(operand, &full_verb, true).map_err(Stop::from)?;
                        check_target(&path, cwd, true, &full_verb, None).map_err(Stop::from)?;
                    }
                } else {
                    return Err(Stop::Internal);
                }
            }
        }
    } else if name == "hadoop" || name == "hdfs" {
        if rest
            .iter()
            .any(|word| HADOOP_PURGE_OPTIONS.contains(&word.as_str()))
        {
            return Err(denied(
                "delete_guard.reason.trash_empty",
                &[("name", value(name))],
            ));
        }
    } else if name.eq_ignore_ascii_case("clear-recyclebin")
        || (WINDOWS_SHELLS.contains(&name.to_lowercase().as_str())
            && WINDOWS_TEXT.is_match(&format!(
                "{}\n{heredoc}",
                rest.iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            )))
    {
        return Err(denied(
            "delete_guard.reason.trash_empty",
            &[("name", value(name))],
        ));
    } else if name == "find" {
        find(&stripped, cwd)?;
    } else if name == "xargs" {
        xargs(&stripped, cwd)?;
    } else if name == "rsync" {
        rsync(&stripped, cwd)?;
    } else if fullmatch(&ERASE_TOOL, name) {
        return Err(denied(
            "delete_guard.reason.erase_tool",
            &[("name", value(name))],
        ));
    } else if name == "diskutil" && rest.iter().any(|word| match_start(&DISKUTIL_ERASE, word)) {
        return Err(denied("delete_guard.reason.diskutil", &[]));
    } else if name == "dd" {
        for word in rest {
            if let Some(path) = word.strip_prefix("of=") {
                if is_computed(path) {
                    return Err(denied(
                        "delete_guard.reason.computed_path",
                        &[("verb", value("dd")), ("raw", value(path))],
                    ));
                }
                let resolved = expand(path, cwd).map_err(Stop::from)?;
                if resolved.as_deref().is_none_or(|path| inside(path, "/dev")) {
                    return Err(denied("delete_guard.reason.dd_device", &[]));
                }
            }
        }
    } else if name == "gio" {
        gio(&stripped, cwd)?;
    } else if name == "git" {
        git_clean(&stripped)?;
    } else if remote().is_none()
        && word0.contains('/')
        && !(Path::new(word0).is_absolute()
            && SYSTEM_PROGRAM_FOLDERS
                .iter()
                .any(|folder| word0.starts_with(folder)))
    {
        check_script(word0, cwd, false)?;
    } else if remote().is_none() {
        if let Some(path) = wrapper.as_deref() {
            check_script(path, cwd, false)?;
        }
    }
    Ok((shell_cwd, false))
}

pub fn writes_a_file(operator: &str, operand: &str) -> bool {
    if operand.starts_with('(') {
        return false;
    }
    if operator == ">&" {
        return !FILE_DESCRIPTOR_OPERAND.is_match(operand);
    }
    operator.starts_with('>') || operator.starts_with("<>")
}

pub fn pattern_word(operand: &str) -> String {
    let chars: Vec<char> = operand.chars().collect();
    let mut out = String::new();
    let mut quote = None;
    let mut index = 0usize;
    while let Some(character) = chars.get(index).copied() {
        let literal = |ch: char| match ch {
            '*' => "[*]".to_owned(),
            '?' => "[?]".to_owned(),
            '[' => "[[]".to_owned(),
            _ => ch.to_string(),
        };
        if let Some(mark) = quote {
            if character == mark {
                quote = None;
            } else if mark == '"'
                && character == '\\'
                && matches!(
                    chars.get(index.saturating_add(1)),
                    Some('"' | '\\' | '$' | '`')
                )
            {
                if let Some(next) = chars.get(index.saturating_add(1)) {
                    out.push(*next);
                }
                index = index.saturating_add(2);
                continue;
            } else {
                out.push_str(&literal(character));
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '\\' && chars.get(index.saturating_add(1)).is_some() {
            if let Some(next) = chars.get(index.saturating_add(1)) {
                out.push_str(&literal(*next));
            }
            index = index.saturating_add(2);
            continue;
        } else if character == ' ' || character == '\t' {
            break;
        } else {
            out.push(character);
        }
        index = index.saturating_add(1);
    }
    out
}

pub fn redirection_names(
    word: &str,
    operand: &str,
    cwd: Option<&str>,
) -> Result<Vec<String>, Stop> {
    let active = unquoted_text(operand);
    let braced = active.contains('{') && BRACE_PATTERN.is_match(&active);
    let literals = if braced {
        expand_braces(word).map_err(|_| Stop::Internal)?
    } else {
        Some(vec![word.to_owned()])
    };
    let patterns = if braced {
        expand_braces(&pattern_word(operand)).map_err(|_| Stop::Internal)?
    } else {
        Some(vec![pattern_word(operand)])
    };
    let (Some(literals), Some(patterns)) = (literals, patterns) else {
        return Err(denied(
            "delete_guard.reason.expansion",
            &[("verb", value("a redirection")), ("raw", value(word))],
        ));
    };
    let mut names = Vec::new();
    for (literal, pattern) in literals.iter().zip(patterns.iter()) {
        names.push(literal.clone());
        if GLOB_ACTIVE.is_match(&active) {
            names.extend(glob_matches(pattern, cwd, "a redirection").map_err(Stop::from)?);
        }
    }
    Ok(names)
}

pub fn check_device_writes(
    redirections: &[(String, String, String)],
    cwd: Option<&str>,
) -> Result<(), Stop> {
    for (_, operator, operand) in redirections {
        if !writes_a_file(operator, operand) {
            continue;
        }
        let Ok(words) = shlex::split(operand) else {
            continue;
        };
        let Some(word) = words.first() else { continue };
        if word.is_empty() {
            continue;
        }
        if is_computed(word) {
            if word.contains("/dev") && (word.starts_with("/dev/") || word.starts_with('$')) {
                return Err(denied(
                    "delete_guard.reason.computed_path",
                    &[("verb", value("a redirection")), ("raw", value(word))],
                ));
            }
            continue;
        }
        for name in redirection_names(word, operand, cwd)? {
            let Some(resolved) = expand(&name, cwd).map_err(Stop::from)? else {
                continue;
            };
            if inside(&resolved, "/dev") && !DEVICE_WRITE_OK.is_match(&resolved) {
                return Err(denied(
                    "delete_guard.reason.device_redirect",
                    &[("path", value(&resolved))],
                ));
            }
        }
    }
    Ok(())
}

pub fn line_input_files(command: &str) -> Vec<(String, Option<String>)> {
    let mut redirects = Vec::new();
    normalize_command(command, Some(&mut redirects));
    redirects
        .into_iter()
        .filter_map(|(_, operator, operand)| {
            if !STDIN_OPERATORS.contains(&operator.as_str()) {
                return None;
            }
            shlex::split(&operand)
                .ok()?
                .into_iter()
                .next()
                .map(|word| (word, None))
        })
        .collect()
}

pub fn check_shell(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    let mut options = Vec::new();
    let mut operands = Vec::new();
    let mut index = 1usize;
    while let Some(word) = words.get(index) {
        if word == "--" {
            operands.extend(words.iter().skip(index.saturating_add(1)).cloned());
            break;
        }
        if word.chars().count() > 1 && (word.starts_with('-') || word.starts_with('+')) {
            options.push(word.clone());
        } else {
            operands.push(word.clone());
        }
        index = index.saturating_add(1);
    }
    let command_options: Vec<&String> = options
        .iter()
        .filter(|option| {
            option.contains("command")
                || (!option.starts_with("--") && (option.contains('c') || option.contains('C')))
        })
        .collect();
    for option in &options {
        if command_options.contains(&option) || SHELL_OPTION_CONTENT.is_match(option) {
            let prefix = SHELL_OPTION_PREFIX
                .find(option)
                .map_or("", |found| found.as_str());
            let chars: Vec<char> = option.chars().collect();
            for cut in 1..=prefix.chars().count() {
                check_command(&chars.iter().skip(cut).collect::<String>(), cwd)?;
            }
        }
    }
    if !command_options.is_empty() {
        for operand in &operands {
            check_command(operand, cwd)?;
        }
    }
    if remote().is_some() {
        return Ok(());
    }
    for operand in &operands {
        check_script(operand, cwd, true)?;
    }
    if operands.is_empty()
        || options
            .iter()
            .any(|option| !option.starts_with("--") && option.contains('s'))
    {
        for (name, folder) in stdin_files() {
            check_script(&name, folder.as_deref(), true)?;
        }
    }
    Ok(())
}

pub fn git_clean(words: &[String]) -> Result<(), Stop> {
    let mut index = 1usize;
    while words.get(index).is_some_and(|word| word.starts_with('-')) {
        index = index.saturating_add(
            if words
                .get(index)
                .is_some_and(|word| GIT_VALUE_OPTIONS.contains(word.as_str()))
            {
                2
            } else {
                1
            },
        );
    }
    if words.get(index).map(String::as_str) != Some("clean") {
        return Ok(());
    }
    let mut dry_run = false;
    let mut position = index.saturating_add(1);
    while let Some(option) = words.get(position) {
        if option == "--" {
            break;
        }
        position = position.saturating_add(1);
        if option.starts_with("--") {
            let name = option.split('=').next().unwrap_or("");
            if name == "--dry-run" {
                dry_run = true;
            } else if name == "--no-dry-run" {
                dry_run = false;
            } else if name == "--exclude" && !option.contains('=') {
                position = position.saturating_add(1);
            }
        } else if option.starts_with('-') && option.chars().count() > 1 {
            let letters: Vec<char> = option.chars().skip(1).collect();
            for (offset, letter) in letters.iter().enumerate() {
                if *letter == 'n' {
                    dry_run = true;
                } else if *letter == 'e' {
                    if offset == letters.len().saturating_sub(1) {
                        position = position.saturating_add(1);
                    }
                    break;
                }
            }
        }
    }
    if dry_run {
        Ok(())
    } else {
        Err(denied("delete_guard.reason.git_clean", &[]))
    }
}

pub fn configured_remote_names() -> HashSet<String> {
    let text = std::env::var("AGENT_SAFEGUARDS_REMOTE_COMMANDS").unwrap_or_default();
    REMOTE_NAME_SPLIT
        .split(&text)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn device_redirect_hint(text: &str) -> bool {
    for found in DEVICE_REDIRECT.find_iter(text) {
        let suffix = text.get(found.end()..).unwrap_or("");
        if ["fd/", "pts/", "shm/", "tcp/", "udp/"]
            .iter()
            .any(|name| suffix.starts_with(name))
        {
            continue;
        }
        let allowed = [
            "null", "zero", "full", "stdout", "stderr", "stdin", "console", "random", "urandom",
            "ptmx",
        ];
        let delimiter = |ch: char| {
            ch.is_whitespace()
                || matches!(ch, '\u{1c}'..='\u{1f}' | ';' | '&' | '|' | '<' | '>' | ')')
        };
        if allowed.iter().any(|name| {
            suffix
                .strip_prefix(name)
                .is_some_and(|tail| tail.chars().next().is_none_or(delimiter))
        }) {
            continue;
        }
        if let Some(tail) = suffix.strip_prefix("tty") {
            let rest = tail.trim_start_matches(|ch: char| ch.is_alphanumeric() || ch == '_');
            if rest.chars().next().is_none_or(delimiter) {
                continue;
            }
        }
        return true;
    }
    false
}

pub fn check_command(command: &str, cwd: Option<&str>) -> Result<(), Stop> {
    let command_owned = if command.contains("<<") {
        without_text_heredocs(command)
    } else {
        command.to_owned()
    };
    let command = command_owned.as_str();
    let bare = QUOTE_CHARACTERS
        .replace_all(&command.replace("\\\n", ""), "")
        .into_owned();
    let delete_words = QUICK_SCAN.is_match(command) || QUICK_SCAN.is_match(&bare);
    let configured = configured_remote_names().iter().any(|name| {
        [command, bare.as_str()].iter().any(|text| {
            text.match_indices(name).any(|(start, _)| {
                let before = text.get(..start).unwrap_or("").chars().next_back();
                let after = text
                    .get(start.saturating_add(name.len())..)
                    .unwrap_or("")
                    .chars()
                    .next();
                before.is_none_or(|ch| {
                    ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}' | ';' | '&' | '|' | '(')
                }) && after.is_none_or(|ch| ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}'))
            })
        })
    });
    if !(delete_words
        || command.contains('>')
        || consts::script_hint_search(command).is_some()
        || consts::script_hint_search(&bare).is_some()
        || configured)
    {
        return Ok(());
    }
    if command.chars().count() > MAX_COMMAND_CHARS {
        if delete_words || device_redirect_hint(&bare) {
            return Err(denied("delete_guard.reason.too_large", &[]));
        }
        return Ok(());
    }
    let substitution_cwd = if CD_WORD.is_match(command) { None } else { cwd };
    let old_files = stdin_files();
    let mut files = old_files.clone();
    files.extend(line_input_files(command));
    set_stdin_files(files);
    let old_variables = variables_changed_state();
    let mut changed = old_variables.clone();
    changed.extend(variables_changed(command));
    set_variables_changed(changed);
    let old_words = quoted_words();
    set_quoted_words(quoted_literal_words(command));
    let result = (|| {
        for body in command_substitutions(command) {
            if !body
                .trim_matches(|ch: char| ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}'))
                .is_empty()
            {
                check_command(&body, substitution_cwd)?;
            }
        }
        check_chunks(command, cwd)
    })();
    set_stdin_files(old_files);
    set_variables_changed(old_variables);
    set_quoted_words(old_words);
    result
}

pub fn check_chunks(command: &str, cwd: Option<&str>) -> Result<(), Stop> {
    let chunks = tokenize(command);
    if chunks.is_none() {
        let mut redirects = Vec::new();
        normalize_command(command, Some(&mut redirects));
        let current = cwd
            .map(try_realpath)
            .transpose()
            .map_err(|_| Stop::Internal)?;
        check_device_writes(&redirects, current.as_deref())?;
        if consts::inline_recursive_delete_search(command).is_some()
            || DELETE_WORD.is_match(command)
        {
            return Err(denied("delete_guard.reason.unparseable", &[]));
        }
        return Ok(());
    }
    let mut current = cwd
        .map(try_realpath)
        .transpose()
        .map_err(|_| Stop::Internal)?;
    let mut grouped = false;
    let mut previous_cd_known = false;
    let mut conditional = false;
    for chunk in chunks.unwrap_or_default() {
        grouped |= chunk.opened;
        if !chunk.redirections.is_empty() {
            check_device_writes(
                &chunk.redirections,
                if conditional && chunk.before.as_deref() != Some("&&") {
                    None
                } else {
                    current.as_deref()
                },
            )?;
        }
        if chunk.words.is_empty() {
            continue;
        }
        if conditional && chunk.before.as_deref() != Some("&&") {
            current = None;
            conditional = false;
        }
        let reached = chunk.before.is_none()
            || chunk.before.as_deref() == Some(";")
            || (chunk.before.as_deref() == Some("&&")
                && (previous_cd_known || chunk.after.as_deref() == Some("&&")));
        let trusted = !grouped
            && (!chunk.redirected || chunk.after.as_deref() == Some("&&"))
            && !SHELL_KEYWORDS.contains(chunk.words.first().map(String::as_str).unwrap_or(""))
            && reached
            && (chunk.after.is_none()
                || [";", "&&"].contains(&chunk.after.as_deref().unwrap_or("")));
        (current, previous_cd_known) =
            crate::remote::check_chunk(&chunk.words, current.as_deref(), command, trusted)?;
        if previous_cd_known
            && chunk.before.as_deref() == Some("&&")
            && chunk.after.as_deref() == Some("&&")
        {
            conditional = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_command, git_clean, pattern_word, writes_a_file};

    #[test]
    fn device_and_git_guards() {
        assert!(!writes_a_file(">&", "2"));
        assert!(writes_a_file(">&", "/dev/disk4"));
        assert_eq!(pattern_word("'/dev/dis*'"), "/dev/dis[*]");
        assert!(git_clean(&["git".into(), "clean".into(), "-fdx".into()]).is_err());
        assert!(git_clean(&["git".into(), "clean".into(), "-ndx".into()]).is_ok());
        assert!(check_command("dd if=/dev/zero of=/dev/disk4", Some("/tmp")).is_err());
    }
}
