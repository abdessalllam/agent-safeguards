use std::collections::HashSet;

use guard_common::locale::{message, FormatValue};
use guard_common::shell::{
    expand_braces, split_options, strip_wrappers, strip_wrappers_with_directory,
};
use guard_common::sys::try_realpath;

use crate::consts::{
    BASH_SINGLE_DASH_LONG, GIO_DELETE_VERBS, KIO_COMMANDS, KIO_REMOVE_VERBS, KIO_TOOL,
    RM_LONG_OPTIONS, SHELLS, SHELL_LONG_WITH_VALUE, TRASH_TOOLS, TRASH_URI, TRASH_VALUE_OPTIONS,
    XARGS_DELETERS,
};
use crate::errors::{Denied, Stop};
use crate::globs::glob_matches;
use crate::places::{check_repository, glob_base, names_trash};
use crate::targets::{
    check_match_mark, check_remote_trash_target, check_sendable, check_target, in_trash,
    is_folder_path, location_path, quoted_words, remote,
};
use crate::tokens::{base, expand, is_computed};

fn value(text: &str) -> FormatValue {
    FormatValue::Text(text.to_owned())
}

fn denied(key: &str, values: &[(&str, FormatValue)]) -> Stop {
    Stop::Denied(Denied::new(message(key, values)))
}

fn no_keep() -> HashSet<&'static str> {
    HashSet::new()
}

pub fn rm(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    let mut recursive = false;
    let mut targets = Vec::new();
    let mut options_done = false;
    for word in words.iter().skip(1) {
        if !options_done && word == "--" {
            options_done = true;
        } else if !options_done && word.starts_with("--") {
            let name = word.get(2..).unwrap_or("").split('=').next().unwrap_or("");
            let exact: Vec<_> = RM_LONG_OPTIONS
                .iter()
                .filter(|option| **option == name)
                .collect();
            let matches: Vec<_> = if exact.is_empty() {
                RM_LONG_OPTIONS
                    .iter()
                    .filter(|option| option.starts_with(name))
                    .collect()
            } else {
                exact
            };
            recursive |= matches.len() != 1
                || matches
                    .first()
                    .is_some_and(|option| matches!(**option, "recursive" | "dir"));
        } else if !options_done && word.starts_with('-') && word.chars().count() > 1 {
            recursive |= word.chars().skip(1).any(|ch| matches!(ch, 'r' | 'R' | 'd'));
        } else {
            targets.push(word);
        }
    }
    let verb = format!(
        "{}{}",
        base(words.first().map(String::as_str).unwrap_or("")),
        if recursive { " -r" } else { "" }
    );
    for target in targets {
        check_target(target, cwd, recursive, &verb, None).map_err(Stop::from)?;
    }
    Ok(())
}

pub fn trash(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    let mut targets = Vec::new();
    let mut options_done = false;
    let mut skip = false;
    for word in words.iter().skip(1) {
        if skip {
            skip = false;
        } else if !options_done && word == "--" {
            options_done = true;
        } else if !options_done && word.starts_with("--") {
            if matches!(word.split('=').next(), Some("--empty" | "--secure")) {
                return Err(denied(
                    "delete_guard.reason.trash_empty",
                    &[(
                        "name",
                        value(base(words.first().map(String::as_str).unwrap_or(""))),
                    )],
                ));
            }
            skip = TRASH_VALUE_OPTIONS.contains(&word.as_str());
        } else if !options_done && word.starts_with('-') && word.chars().count() > 1 {
            if word.chars().skip(1).any(|ch| matches!(ch, 'e' | 's')) {
                return Err(denied(
                    "delete_guard.reason.trash_empty",
                    &[(
                        "name",
                        value(base(words.first().map(String::as_str).unwrap_or(""))),
                    )],
                ));
            }
        } else {
            targets.push(word);
        }
    }
    for target in targets {
        if TRASH_URI
            .find(target)
            .is_some_and(|found| found.start() == 0)
        {
            continue;
        }
        if remote().is_some() {
            check_remote_trash_target(target)?;
            continue;
        }
        let literal = quoted_words().contains(target);
        let variants = if literal || !target.contains('{') {
            Some(vec![target.to_owned()])
        } else {
            expand_braces(target).map_err(|_| Stop::Internal)?
        };
        let Some(variants) = variants else {
            return Err(denied(
                "delete_guard.reason.expansion",
                &[("verb", value("trash")), ("raw", value(target))],
            ));
        };
        for variant in variants {
            let location = location_path(&variant, "trash", false).map_err(Stop::from)?;
            trash_one(&location, cwd, literal)?;
        }
    }
    Ok(())
}

pub fn mv(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    if remote().is_some() {
        return Ok(());
    }
    let mut destination: Option<String> = None;
    for (index, word) in words.iter().enumerate().skip(1) {
        if word == "--" {
            break;
        }
        let following = words.get(index.saturating_add(1)).cloned();
        if word == "--target-directory" {
            destination = following;
        } else if let Some(rest) = word.strip_prefix("--target-directory=") {
            destination = Some(rest.to_owned());
        } else if word.starts_with('-') && !word.starts_with("--") {
            if let Some(position) = word.find('t') {
                destination = word
                    .get(position.saturating_add(1)..)
                    .filter(|tail| !tail.is_empty())
                    .map(str::to_owned)
                    .or(following);
            }
        }
    }
    let options: HashSet<&str> = ["--target-directory", "--suffix"].into_iter().collect();
    let mut operands = split_options(words.get(1..).unwrap_or(&[]), "tS", &options);
    let destination = match destination {
        Some(path) => path,
        None => {
            if operands.len() < 2 {
                return Ok(());
            }
            operands.pop().unwrap_or_default()
        }
    };
    if is_computed(&destination) {
        return Ok(());
    }
    let place = expand(&destination, cwd)?;
    let Some(place) = place else {
        return Ok(());
    };
    if !in_trash(&place) && !names_trash(&destination) {
        return Ok(());
    }
    for operand in &operands {
        if is_computed(operand) {
            continue;
        }
        let literal = quoted_words().contains(operand);
        let variants = if literal {
            Some(vec![operand.to_owned()])
        } else {
            expand_braces(operand).map_err(|_| Stop::Internal)?
        };
        let Some(variants) = variants else {
            return Err(denied(
                "delete_guard.reason.expansion",
                &[("verb", value("mv")), ("raw", value(operand))],
            ));
        };
        for variant in variants {
            if literal || glob_base(&variant) == variant {
                if let Some(resolved) = expand(&variant, cwd)? {
                    check_repository(&resolved, "mv").map_err(Stop::from)?;
                }
            } else {
                for matched in glob_matches(&variant, cwd, "mv").map_err(Stop::from)? {
                    check_repository(
                        &try_realpath(&matched).map_err(|_| Stop::Internal)?,
                        "mv",
                    )
                    .map_err(Stop::from)?;
                }
            }
        }
    }
    Ok(())
}

pub fn trash_one(target: &str, cwd: Option<&str>, literal: bool) -> Result<(), Stop> {
    if names_trash(target) {
        return Err(denied(
            "delete_guard.reason.trash_inside",
            &[("path", value(target))],
        ));
    }
    check_match_mark(target, "trash")?;
    if is_computed(target) {
        if target.contains("$(") || target.contains('`') {
            return Err(denied(
                "delete_guard.reason.trash_computed",
                &[("raw", value(target))],
            ));
        }
        return Ok(());
    }
    let basis = if literal {
        target.to_owned()
    } else {
        glob_base(target)
    };
    let Some(resolved) = expand(&basis, cwd)? else {
        return Ok(());
    };
    check_sendable(&resolved)?;
    if !literal {
        for matched in glob_matches(target, cwd, "trash").map_err(Stop::from)? {
            let found = try_realpath(&matched).map_err(|_| Stop::Internal)?;
            if names_trash(&matched)
                || (is_folder_path(&found, "trash", target)? && crate::globs::holds_trash(&found))
            {
                return Err(denied(
                    "delete_guard.reason.trash_inside",
                    &[("path", value(&matched))],
                ));
            }
            check_sendable(&found)?;
            check_repository(&found, "trash").map_err(Stop::from)?;
        }
    }
    let named = literal || glob_base(target) == target;
    if named {
        check_repository(&resolved, "trash").map_err(Stop::from)?;
    }
    if named && is_folder_path(&resolved, "trash", target)? && crate::globs::holds_trash(&resolved)
    {
        return Err(denied(
            "delete_guard.reason.trash_inside",
            &[("path", value(&resolved))],
        ));
    }
    Ok(())
}

pub fn gio(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    let verb = words.get(1).map(String::as_str).unwrap_or("");
    if verb == "trash" {
        trash(words.get(1..).unwrap_or(&[]), cwd)?;
    } else if matches!(verb, "remove" | "rm") {
        for operand in split_options(words.get(2..).unwrap_or(&[]), "", &no_keep()) {
            let location = location_path(&operand, "gio remove", true).map_err(Stop::from)?;
            check_target(&location, cwd, false, "gio remove", None).map_err(Stop::from)?;
        }
    }
    Ok(())
}

pub fn kio_command(words: &[String]) -> Option<String> {
    split_options(words.get(1..).unwrap_or(&[]), "", &no_keep())
        .into_iter()
        .find(|word| KIO_COMMANDS.contains(&word.as_str()))
}

pub fn deletes_files(command: &[String]) -> bool {
    let Ok(stripped) = strip_wrappers(command, &no_keep()) else {
        return true;
    };
    let Some(first) = stripped.first() else {
        return false;
    };
    let name = base(first);
    if XARGS_DELETERS.contains(&name) || TRASH_TOOLS.contains(&name) {
        return true;
    }
    if name == "gio" {
        return stripped
            .get(1)
            .is_some_and(|word| GIO_DELETE_VERBS.contains(&word.as_str()));
    }
    if KIO_TOOL
        .find(name)
        .is_some_and(|found| found.start() == 0 && found.end() == name.len())
    {
        return kio_command(&stripped)
            .is_some_and(|word| KIO_REMOVE_VERBS.contains(&word.as_str()));
    }
    false
}

pub fn shell_gets_a_name(command: &[String], marker: &str, appended: bool) -> bool {
    let Ok(stripped) = strip_wrappers(command, &no_keep()) else {
        return false;
    };
    let Some(first) = stripped.first() else {
        return false;
    };
    let name = base(first);
    if !SHELLS.contains(&name) {
        return false;
    }
    let fish = name == "fish";
    let (options, operands) = shell_words(stripped.get(1..).unwrap_or(&[]), fish);
    if options
        .iter()
        .any(|option| is_command_option(option, fish).unwrap_or(false))
    {
        return false;
    }
    if stripped.iter().skip(1).any(|word| word.contains(marker)) {
        return true;
    }
    let reads_input = options
        .iter()
        .any(|option| option.starts_with('-') && bundle_letters(option, fish).contains('s'))
        && !options
            .iter()
            .any(|option| option.starts_with('+') && bundle_letters(option, fish).contains('s'));
    appended && operands.is_empty() && !reads_input
}

pub fn is_short(option: &str) -> bool {
    !option.starts_with("--") && !BASH_SINGLE_DASH_LONG.contains(&option)
}

pub fn value_letters(fish: bool) -> &'static str {
    if fish {
        "CdDfoOP"
    } else {
        "oO"
    }
}

pub fn bundle_letters(option: &str, fish: bool) -> String {
    if !is_short(option) {
        return String::new();
    }
    let letters: Vec<char> = option.chars().skip(1).collect();
    for (position, letter) in letters.iter().enumerate() {
        if value_letters(fish).contains(*letter) {
            return letters.iter().take(position).collect();
        }
    }
    letters.iter().collect()
}

pub fn is_command_option(option: &str, fish: bool) -> Result<bool, Stop> {
    if option == "--command" || option.starts_with("--command=") {
        return Ok(true);
    }
    let Some(first) = option.chars().next() else {
        return Err(Stop::Internal);
    };
    Ok(first == '-' && bundle_letters(option, fish).contains('c'))
}

pub fn shell_words(words: &[String], fish: bool) -> (Vec<String>, Vec<String>) {
    let mut options = Vec::new();
    let mut operands = Vec::new();
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        index = index.saturating_add(1);
        if word == "--" {
            operands.extend_from_slice(words.get(index..).unwrap_or(&[]));
            break;
        }
        if word.chars().count() > 1 && (word.starts_with('-') || word.starts_with('+')) {
            options.push(word.to_owned());
            if SHELL_LONG_WITH_VALUE.contains(&word.as_str())
                || (is_short(word) && value_is_next(word, fish))
            {
                index = index.saturating_add(1);
            }
        } else {
            operands.extend_from_slice(words.get(index.saturating_sub(1)..).unwrap_or(&[]));
            break;
        }
    }
    (options, operands)
}

pub fn value_is_next(option: &str, fish: bool) -> bool {
    let letters: Vec<char> = option.chars().skip(1).collect();
    for (position, letter) in letters.iter().enumerate() {
        if value_letters(fish).contains(*letter) {
            return position == letters.len().saturating_sub(1);
        }
    }
    false
}

pub fn moves_and_deletes(command: &[String]) -> bool {
    let Ok((stripped, directories)) = strip_wrappers_with_directory(command, &no_keep()) else {
        return false;
    };
    !directories.is_empty() && !stripped.is_empty() && deletes_files(&stripped)
}

#[cfg(test)]
mod tests {
    use super::{
        bundle_letters, deletes_files, is_command_option, rm, shell_gets_a_name, shell_words,
    };

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn recursive_rm_detects_ambiguous_long_option() {
        let result = rm(&words(&["rm", "--r", "/"]), None);
        assert!(result.is_err());
    }

    #[test]
    fn shell_script_name_depends_on_command_and_input_options() {
        assert!(shell_gets_a_name(&words(&["bash"]), "{}", true));
        assert!(!shell_gets_a_name(&words(&["bash", "-s"]), "{}", true));
        assert!(!shell_gets_a_name(
            &words(&["bash", "-c", "echo {}"]),
            "{}",
            true
        ));
        assert!(shell_gets_a_name(&words(&["bash", "{}"]), "{}", false));
        assert_eq!(
            shell_words(&words(&["-o", "errexit", "script"]), false),
            (vec!["-o".to_owned()], vec!["script".to_owned()])
        );
        assert_eq!(bundle_letters("-oc", false), "");
        assert_eq!(
            is_command_option("", false).err(),
            Some(crate::errors::Stop::Internal)
        );
    }

    #[test]
    fn wrapped_delete_is_detected() {
        assert!(deletes_files(&words(&["sudo", "rm", "x"])));
        assert!(!deletes_files(&words(&["echo", "x"])));
    }
}
