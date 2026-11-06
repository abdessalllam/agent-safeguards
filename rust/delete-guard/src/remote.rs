use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use guard_common::locale::{message, FormatValue};
use guard_common::shell::split_options;
use regex::Regex;

use crate::check::{check_command_weighted, check_one_chunk, NESTED_FRAMES};
use crate::consts::{
    MOSH_FLAG_LETTERS, MOSH_LONG_FLAGS, MOSH_LONG_VALUES, MOSH_VALUE_LETTERS, QUICK_SCAN,
    QUOTED_TILDE, REMOTE_COMMAND_NAMES, RSYNC_VALUE_LETTERS, RSYNC_VALUE_OPTIONS, SSH_FLAG_LETTERS,
    SSH_VALUE_LETTERS,
};
use crate::decision::remote_roots;
use crate::errors::{Denied, Stop};
use crate::find::{set_stdin_files, stdin_files};
use crate::targets::{check_target, remote, set_remote};
use crate::tokens::{expand, is_computed};

static RSYNC_REMOTE: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r"\A[^/\s\x1c-\x1f]+:"));
static QUOTE_CHARACTERS: LazyLock<Regex> = LazyLock::new(|| fixed_regex(r#"[\\'\"]"#));

fn fixed_regex(pattern: &str) -> Regex {
    guard_common::pyre::new(pattern).unwrap_or_else(|error| panic!("fixed regex: {error}"))
}

fn value(text: &str) -> FormatValue {
    FormatValue::Text(text.to_owned())
}

fn denied(key: &str, values: &[(&str, FormatValue)]) -> Stop {
    Stop::Denied(Denied::new(message(key, values)))
}

pub fn remote_command_words(name: &str, words: &[String]) -> Result<Vec<String>, Stop> {
    let rest = words.get(1..).unwrap_or(&[]);
    if !REMOTE_COMMAND_NAMES.contains(&name) {
        return Ok(rest.to_vec());
    }
    let mosh = name == "mosh";
    let flags = if mosh {
        MOSH_FLAG_LETTERS
    } else {
        SSH_FLAG_LETTERS
    };
    let values = if mosh {
        MOSH_VALUE_LETTERS
    } else {
        SSH_VALUE_LETTERS
    };
    let mut host = false;
    let mut index = 0usize;
    while let Some(word) = rest.get(index) {
        if word == "--" {
            index = index.saturating_add(1);
            if !host && index < rest.len() {
                index = index.saturating_add(1);
            }
            return Ok(rest.get(index..).unwrap_or(&[]).to_vec());
        }
        if mosh && word.starts_with("--") {
            let option = word
                .split_once('=')
                .map_or(word.as_str(), |(prefix, _)| prefix);
            if MOSH_LONG_VALUES.contains(&option) {
                index = index.saturating_add(if word.contains('=') { 1 } else { 2 });
            } else if MOSH_LONG_FLAGS.contains(&option) {
                index = index.saturating_add(1);
            } else {
                return Err(denied("delete_guard.reason.unparseable", &[]));
            }
        } else if word.starts_with('-') && word.chars().count() > 1 {
            let letters: Vec<char> = word.chars().collect();
            let mut takes_next = false;
            for (position, letter) in letters.iter().copied().enumerate().skip(1) {
                let letter = letter.to_string();
                if values.contains(&letter.as_str()) {
                    takes_next = position.saturating_add(1) >= letters.len();
                    break;
                }
                if !flags.contains(&letter.as_str()) {
                    return Err(denied("delete_guard.reason.unparseable", &[]));
                }
            }
            index = index.saturating_add(if takes_next { 2 } else { 1 });
        } else if !host {
            host = true;
            index = index.saturating_add(1);
        } else {
            return Ok(rest.get(index..).unwrap_or(&[]).to_vec());
        }
    }
    Ok(Vec::new())
}

pub fn check_remote_command(text: &str) -> Result<(), Stop> {
    let previous = remote();
    set_remote(Some(remote_roots()));
    let result = (|| {
        let joined = text.replace("\\\n", "");
        let bare = QUOTE_CHARACTERS.replace_all(&joined, "");
        if (QUICK_SCAN.is_match(text) || QUICK_SCAN.is_match(&bare)) && QUOTED_TILDE.is_match(text)
        {
            return Err(Stop::Denied(Denied::remote(message(
                "delete_guard.reason.remote_target",
                &[
                    ("verb", value("delete")),
                    ("raw", value("a quoted or escaped ~")),
                ],
            ))));
        }
        check_command_weighted(text, None, NESTED_FRAMES)
    })();
    set_remote(previous);
    result
}

pub fn check_rsync_operand(operand: &str, cwd: Option<&str>, verb: &str) -> Result<(), Stop> {
    if RSYNC_REMOTE.is_match(operand) {
        return Err(denied("delete_guard.reason.rsync_remote", &[]));
    }
    check_target(operand, cwd, true, verb, None).map_err(Stop::from)
}

pub fn rsync(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    let deleting = words.iter().any(|word| word.starts_with("--delete"));
    let removing = words.iter().any(|word| word == "--remove-source-files");
    if !deleting && !removing {
        return Ok(());
    }
    let letters: String = RSYNC_VALUE_LETTERS.iter().copied().collect();
    let options: HashSet<&str> = RSYNC_VALUE_OPTIONS.iter().copied().collect();
    let operands = split_options(words.get(1..).unwrap_or(&[]), &letters, &options);
    if operands.is_empty() {
        return Ok(());
    }
    if deleting {
        if let Some(destination) = operands.last() {
            check_rsync_operand(destination, cwd, "rsync --delete")?;
        }
    }
    if removing {
        for source in operands
            .get(..operands.len().saturating_sub(1))
            .unwrap_or(&[])
        {
            check_rsync_operand(source, cwd, "rsync --remove-source-files")?;
        }
    }
    Ok(())
}

pub fn wrapper_directory(value: &str, base: Option<&str>) -> Result<Option<String>, Stop> {
    if value.is_empty() || is_computed(value) {
        return Ok(None);
    }
    let resolved = expand(value, base).map_err(Stop::from)?;
    Ok(resolved.filter(|path| Path::new(path).is_dir()))
}

pub fn wrapper_directories(values: &[String], start: Option<&str>) -> Result<Option<String>, Stop> {
    let mut folder = start.map(str::to_owned);
    let mut lost = false;
    for value in values {
        lost |= value.is_empty();
        folder = if lost {
            None
        } else {
            wrapper_directory(value, folder.as_deref())?
        };
    }
    Ok(folder)
}

pub fn check_chunk(
    words: &[String],
    cwd: Option<&str>,
    command_text: &str,
    trusted: bool,
) -> Result<(Option<String>, bool), Stop> {
    let held = stdin_files();
    set_stdin_files(
        held.iter()
            .map(|(name, folder)| {
                (
                    name.clone(),
                    folder.clone().or_else(|| cwd.map(str::to_owned)),
                )
            })
            .collect(),
    );
    let result = check_one_chunk(words, cwd, command_text, trusted);
    set_stdin_files(held);
    result
}

#[cfg(test)]
mod tests {
    use super::{
        check_chunk, check_remote_command, check_rsync_operand, remote_command_words,
        wrapper_directory,
    };
    use crate::find::{set_stdin_files, stdin_files};
    use crate::targets::{remote, set_remote};

    #[test]
    fn remote_options_skip_the_host_and_option_values() {
        let ssh = ["ssh", "-p", "22", "host", "rm", "x"].map(str::to_owned);
        assert_eq!(
            remote_command_words("ssh", &ssh).expect("ssh"),
            vec!["rm", "x"]
        );
        let mosh = ["mosh", "--port=60001", "host", "rm", "x"].map(str::to_owned);
        assert_eq!(
            remote_command_words("mosh", &mosh).expect("mosh"),
            vec!["rm", "x"]
        );
        let unknown = ["ssh", "-Z", "host", "rm", "x"].map(str::to_owned);
        assert!(remote_command_words("ssh", &unknown).is_err());
    }

    #[test]
    fn remote_rsync_source_is_refused() {
        assert!(check_rsync_operand("host:/data", None, "rsync --delete").is_err());
        assert_eq!(wrapper_directory("$DIR", None).expect("computed"), None);
    }

    #[test]
    fn quoted_tilde_is_refused_and_remote_state_restored() {
        set_remote(None);
        let result = check_remote_command("rm -rf '~/ci/run'");
        assert!(result.is_err_and(|stop| stop.is_remote()));
        assert_eq!(remote(), None);
    }

    #[test]
    fn chunk_restores_unbound_stdin_files() {
        let held = vec![("input.sh".to_owned(), None)];
        set_stdin_files(held.clone());
        let words = ["echo".to_owned(), "okay".to_owned()];
        let result = check_chunk(&words, Some("/tmp"), "echo okay", true);
        assert!(result.is_ok());
        assert_eq!(stdin_files(), held);
    }
}
