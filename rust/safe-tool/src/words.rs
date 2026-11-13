use std::collections::HashSet;

use guard_common::{env, shell, shlex, sys};

use crate::consts::{SELF_PATH, TOOL_NAME};

pub fn normalized(token: &str) -> String {
    token.rsplit('/').next().unwrap_or("").to_lowercase()
}

pub fn is_self(word: &str) -> Result<bool, sys::EmbeddedNul> {
    if word == TOOL_NAME {
        return Ok(true);
    }
    let file = word.rsplit('/').next();
    let file = if cfg!(windows) { file.map(|name| name.strip_suffix(".exe").unwrap_or(name)) } else { file };
    if file != Some(TOOL_NAME) {
        return Ok(false);
    }
    let expanded = if let Some(tail) = word.strip_prefix("$HOME") {
        format!("{}{tail}", env::user_home())
    } else if let Some(tail) = word.strip_prefix("${HOME}") {
        format!("{}{tail}", env::user_home())
    } else if let Some(tail) = word.strip_prefix("~/") {
        format!("{}/{tail}", env::user_home())
    } else {
        word.to_owned()
    };
    Ok(sys::try_realpath(&expanded)? == *SELF_PATH)
}

pub fn tokenize(command: &str) -> Vec<Vec<String>> {
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
    let mut chunks: Vec<Vec<String>> = vec![Vec::new()];
    for token in tokens
        .into_iter()
        .filter(|word| word != shell::REDIRECTION_MARKER)
    {
        if !token.is_empty() && token.chars().all(|ch| ";&|()\n".contains(ch)) {
            if chunks.last().is_some_and(|chunk| !chunk.is_empty()) {
                chunks.push(Vec::new());
            }
            continue;
        }
        if let Some(chunk) = chunks.last_mut() {
            chunk.push(token);
        }
    }
    chunks
        .into_iter()
        .filter(|chunk| !chunk.is_empty())
        .collect()
}

pub fn unwrap(words: &[String]) -> Result<(Vec<String>, bool), shell::UnresolvableCommand> {
    let keep = HashSet::from(["rtk"]);
    let mut words = shell::strip_wrappers(words, &keep)?;
    let mut used_proxy = false;
    if words.first().is_some_and(|word| normalized(word) == "rtk") {
        if words.get(1).is_some_and(|word| normalized(word) == "proxy") {
            used_proxy = true;
            words.drain(..2);
        } else {
            words.drain(..1);
        }
        words = shell::strip_wrappers(&words, &keep)?;
    }
    Ok((words, used_proxy))
}

pub fn without_global_options(executable: &str, arguments: &[String]) -> Vec<String> {
    let Some((_, value_options)) = crate::consts::CLI_GLOBAL_VALUE_OPTIONS
        .iter()
        .find(|(name, _)| *name == executable)
    else {
        return arguments.to_vec();
    };
    let mut index = 0usize;
    while arguments
        .get(index)
        .is_some_and(|argument| argument.starts_with('-'))
    {
        let takes_value = arguments
            .get(index)
            .is_some_and(|argument| value_options.contains(&argument.as_str()));
        index = index.saturating_add(if takes_value { 2 } else { 1 });
    }
    arguments.get(index..).unwrap_or(&[]).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_name_and_executable_are_recognized() {
        assert_eq!(is_self("safe-tool"), Ok(true));
        assert_eq!(is_self(&SELF_PATH), Ok(false));
        assert_eq!(is_self("/tmp/lookalike/safe-tool"), Ok(false));
        assert_eq!(is_self("a\0b/safe-tool"), Err(sys::EmbeddedNul));
    }

    #[test]
    fn punctuation_splits_commands_and_proxy_survives_wrappers() {
        assert_eq!(
            tokenize("git log --oneline; git show HEAD:a"),
            vec![
                vec!["git", "log", "--oneline"],
                vec!["git", "show", "HEAD:a"]
            ]
        );
        let words = vec!["sudo", "rtk", "proxy", "git", "log", "--oneline"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert_eq!(
            unwrap(&words),
            Ok((
                vec!["git", "log", "--oneline"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                true
            ))
        );
    }

    #[test]
    fn global_option_values_are_skipped_before_a_subcommand() {
        let arguments = ["--region", "us-east-1", "sts", "get-caller-identity"].map(String::from);
        assert_eq!(
            without_global_options("aws", &arguments),
            ["sts", "get-caller-identity"].map(String::from)
        );
        assert_eq!(without_global_options("git", &arguments), arguments);
    }
}
