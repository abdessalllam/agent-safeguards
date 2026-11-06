use std::cell::RefCell;
use std::collections::HashSet;

use guard_common::locale::{message, FormatValue};
use guard_common::shell::strip_wrappers;

use crate::commands::{deletes_files, moves_and_deletes, shell_gets_a_name};
use crate::consts::{
    self, FIND_EXEC_PREDICATES, FIND_GLOBAL_OPTIONS, FIND_NEWER_PREDICATE, MATCH_MARK, TRASH_TOOLS,
};
use crate::errors::{Denied, Stop};
use crate::targets::{check_target, remote};
use crate::tokens::base;

thread_local! {
    static STDIN_FILES: RefCell<Vec<(String, Option<String>)>> = const { RefCell::new(Vec::new()) };
}

pub fn stdin_files() -> Vec<(String, Option<String>)> {
    STDIN_FILES.with(|slot| slot.borrow().clone())
}

pub fn set_stdin_files(files: Vec<(String, Option<String>)>) {
    STDIN_FILES.with(|slot| *slot.borrow_mut() = files);
}

fn value(text: &str) -> FormatValue {
    FormatValue::Text(text.to_owned())
}

fn denied(key: &str, values: &[(&str, FormatValue)]) -> Stop {
    Stop::Denied(Denied::new(message(key, values)))
}

fn stripped(words: &[String]) -> Result<Vec<String>, guard_common::shell::UnresolvableCommand> {
    strip_wrappers(words, &HashSet::<&str>::new())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindParts {
    pub starts: Vec<String>,
    pub executions: Vec<(String, Vec<String>)>,
    pub deletes: bool,
    pub follows: bool,
    pub global_follow: Vec<String>,
    pub input_roots: bool,
}

pub fn find_parts(words: &[String]) -> FindParts {
    let mut starts = Vec::new();
    let mut executions = Vec::new();
    let mut global_follow = Vec::new();
    let mut index = 1usize;
    while let Some(word) = words.get(index) {
        if !FIND_GLOBAL_OPTIONS.contains(&word.as_str())
            && !word.starts_with("-D")
            && !word.starts_with("-O")
            && word != "-f"
        {
            break;
        }
        if word == "-f" && words.get(index.saturating_add(1)).is_some() {
            if let Some(start) = words.get(index.saturating_add(1)) {
                starts.push(start.clone());
            }
            index = index.saturating_add(1);
        } else if matches!(word.as_str(), "-D" | "-O") {
            index = index.saturating_add(1);
        } else if matches!(word.as_str(), "-L" | "-H") {
            global_follow.push(word.clone());
        }
        index = index.saturating_add(1);
    }
    while let Some(word) = words.get(index) {
        if word.starts_with('-') || matches!(word.as_str(), "(" | "!" | "\\(") {
            break;
        }
        starts.push(word.clone());
        index = index.saturating_add(1);
    }
    let mut deletes = false;
    let mut follows = false;
    let mut input_roots = false;
    while let Some(word) = words.get(index) {
        if FIND_EXEC_PREDICATES.contains(&word.as_str()) {
            let mut end = index.saturating_add(1);
            while let Some(candidate) = words.get(end) {
                if matches!(candidate.as_str(), ";" | "\\;")
                    || (candidate == "+"
                        && words
                            .get(end.saturating_sub(1))
                            .is_some_and(|previous| previous == "{}"))
                {
                    break;
                }
                end = end.saturating_add(1);
            }
            executions.push((
                word.clone(),
                words
                    .get(index.saturating_add(1)..end)
                    .unwrap_or(&[])
                    .to_vec(),
            ));
            index = end;
        } else if word == "-delete" {
            deletes = true;
        } else if word == "-follow" {
            follows = true;
        } else if word == "-files0-from" {
            input_roots = true;
            index = index.saturating_add(1);
        } else if word == "-fprintf" {
            index = index.saturating_add(2);
        } else if consts::in_find_value_predicates(word)
            || FIND_NEWER_PREDICATE
                .find(word)
                .is_some_and(|found| found.start() == 0 && found.end() == word.len())
        {
            index = index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    FindParts {
        starts,
        executions,
        deletes,
        follows,
        global_follow,
        input_roots,
    }
}

pub fn deletes_from_names(command: &[String]) -> bool {
    let Ok(stripped) = stripped(command) else {
        return true;
    };
    let Some(first) = stripped.first() else {
        return false;
    };
    let name = base(first);
    if name == "find" {
        return find_deleting(&stripped);
    }
    name == "rsync"
        && stripped
            .iter()
            .any(|word| word.starts_with("--delete") || word == "--remove-source-files")
}

pub fn find_deleting(words: &[String]) -> bool {
    let parts = find_parts(words);
    parts.deletes
        || parts
            .executions
            .iter()
            .any(|(_, body)| !body.is_empty() && deletes_files(body))
}

pub fn find(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    let parts = find_parts(words);
    let deleting = parts.deletes
        || parts
            .executions
            .iter()
            .any(|(_, body)| !body.is_empty() && deletes_files(body));
    for (predicate, body) in &parts.executions {
        let command: Vec<String> = body
            .iter()
            .filter(|argument| *argument != "{}")
            .map(|argument| argument.replace("{}", MATCH_MARK))
            .collect();
        if !command.is_empty() {
            if shell_gets_a_name(body, "{}", false) {
                return Err(denied(
                    "delete_guard.reason.match_path",
                    &[("verb", value("a shell")), ("raw", value("{}"))],
                ));
            }
            if body.iter().any(|word| word == "{}") && moves_and_deletes(body) {
                return Err(denied(
                    "delete_guard.reason.match_path",
                    &[
                        ("verb", value("a command in another folder")),
                        ("raw", value("{}")),
                    ],
                ));
            }
            if deletes_from_names(&command) {
                return Err(denied("delete_guard.reason.xargs_rm", &[]));
            }
            crate::remote::check_chunk(
                &command,
                if matches!(predicate.as_str(), "-execdir" | "-okdir") {
                    None
                } else {
                    cwd
                },
                &command.join(" "),
                false,
            )?;
        }
    }
    if words.windows(2).any(|pair| {
        pair.first().is_some_and(|first| first == "-maxdepth")
            && pair.get(1).is_some_and(|second| second == "0")
    }) {
        for (_, body) in &parts.executions {
            let Ok(stripped) = stripped(body) else {
                continue;
            };
            if body.iter().any(|word| word == "{}")
                && stripped.first().is_some_and(|first| {
                    TRASH_TOOLS.contains(&base(first)) || matches!(base(first), "gio" | "mv")
                })
            {
                let starts = if parts.starts.is_empty() {
                    vec![".".to_owned()]
                } else {
                    parts.starts.clone()
                };
                for start in starts {
                    let sent: Vec<String> = body
                        .iter()
                        .map(|argument| {
                            if argument == "{}" {
                                start.clone()
                            } else {
                                argument.clone()
                            }
                        })
                        .collect();
                    crate::remote::check_chunk(&sent, cwd, &sent.join(" "), false)?;
                }
            }
        }
    }
    if !deleting {
        return Ok(());
    }
    if parts.input_roots {
        return Err(denied("delete_guard.reason.find_roots", &[]));
    }
    let follow = parts
        .global_follow
        .iter()
        .find(|word| word.as_str() == "-L" || (remote().is_some() && word.as_str() == "-H"));
    let option = follow
        .map(String::as_str)
        .or(if parts.follows { Some("-follow") } else { None });
    if let Some(option) = option {
        return Err(denied(
            "delete_guard.reason.find_follow",
            &[("option", value(option))],
        ));
    }
    let starts = if parts.starts.is_empty() {
        vec![".".to_owned()]
    } else {
        parts.starts
    };
    for start in starts {
        check_target(&start, cwd, true, "find -delete", None).map_err(Stop::from)?;
    }
    Ok(())
}

pub fn xargs(words: &[String], cwd: Option<&str>) -> Result<(), Stop> {
    let mut rest = words.get(1..).unwrap_or(&[]);
    let mut replace: Option<String> = None;
    let mut keeps_input = false;
    while let Some(option) = rest.first() {
        if !option.starts_with('-') || option.chars().count() <= 1 || option == "--" {
            break;
        }
        let mut consumed = 1usize;
        if option.starts_with("--") {
            let (name, equals, attached) = if let Some((name, attached)) = option.split_once('=') {
                (name, true, attached)
            } else {
                (option.as_str(), false, "")
            };
            let raw_name = name.get(2..).unwrap_or("");
            let exact: Vec<_> = consts::XARGS_LONG_OPTIONS
                .iter()
                .filter(|(full, _)| *full == raw_name)
                .collect();
            let candidates: Vec<_> = if exact.is_empty() {
                consts::XARGS_LONG_OPTIONS
                    .iter()
                    .filter(|(full, _)| full.starts_with(raw_name))
                    .collect()
            } else {
                exact
            };
            if candidates.len() != 1 {
                return Err(denied("delete_guard.reason.xargs_option", &[]));
            }
            let Some((resolved, kind)) = candidates.first().copied() else {
                return Err(Stop::Internal);
            };
            if *resolved == "replace" {
                replace = Some(if equals {
                    attached.to_owned()
                } else {
                    "{}".to_owned()
                });
            } else if *kind == "required" && !equals {
                consumed = 2;
            }
            keeps_input |= matches!(*resolved, "arg-file" | "open-tty");
        } else {
            let letters: Vec<char> = option.chars().skip(1).collect();
            for (position, letter) in letters.iter().enumerate() {
                let attached: String = letters.iter().skip(position.saturating_add(1)).collect();
                if matches!(letter, 'i' | 'e' | 'l') {
                    if *letter == 'i' {
                        replace = Some(if attached.is_empty() {
                            "{}".to_owned()
                        } else {
                            attached
                        });
                    }
                    break;
                }
                if consts::XARGS_SHORT_VALUES
                    .iter()
                    .any(|entry| entry.starts_with(*letter))
                {
                    let input = if attached.is_empty() {
                        rest.get(1).cloned().unwrap_or_default()
                    } else {
                        attached.clone()
                    };
                    consumed = if attached.is_empty() { 2 } else { 1 };
                    if *letter == 'I' {
                        replace = Some(input);
                    }
                    keeps_input |= *letter == 'a';
                    break;
                }
                keeps_input |= *letter == 'o';
            }
        }
        rest = rest.get(consumed..).unwrap_or(&[]);
    }
    if rest.first().is_some_and(|word| word == "--") {
        rest = rest.get(1..).unwrap_or(&[]);
    }
    if rest.is_empty() {
        return Ok(());
    }
    let stripped = stripped(rest).map_err(|_| Stop::Internal)?;
    if stripped.is_empty() {
        return Ok(());
    }
    if deletes_files(&stripped) || deletes_from_names(&stripped) {
        return Err(denied("delete_guard.reason.xargs_rm", &[]));
    }
    let marker = replace
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "{}".to_owned());
    if shell_gets_a_name(rest, &marker, true) {
        return Err(denied(
            "delete_guard.reason.match_path",
            &[("verb", value("a shell")), ("raw", value(&marker))],
        ));
    }
    let command: Vec<String> = rest
        .iter()
        .filter(|argument| *argument != &marker)
        .map(|argument| argument.replace(&marker, MATCH_MARK))
        .collect();
    let outer_files = stdin_files();
    if !keeps_input {
        set_stdin_files(Vec::new());
    }
    let checked = crate::remote::check_chunk(&command, cwd, &command.join(" "), false);
    set_stdin_files(outer_files);
    checked.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{find, find_parts, xargs};

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn find_exec_terminator_and_values_are_not_predicates() {
        let parts = find_parts(&words(&[
            "find", "safe", "-name", "-delete", "-exec", "echo", "+", "{}", "+",
        ]));
        assert!(!parts.deletes);
        assert_eq!(parts.executions.len(), 1);
        assert_eq!(
            parts.executions.first().map(|item| item.1.as_slice()),
            Some(words(&["echo", "+", "{}"]).as_slice())
        );
    }

    #[test]
    fn unknown_xargs_deleter_and_shell_script_are_refused() {
        assert!(xargs(&words(&["xargs", "rm"]), None).is_err());
        assert!(xargs(&words(&["xargs", "--unknown", "echo"]), None).is_err());
        assert!(xargs(&words(&["xargs", "sh"]), None).is_err());
    }

    #[test]
    fn deleting_find_rejects_follow_and_unknown_roots() {
        assert!(find(&words(&["find", "-L", ".", "-delete"]), None).is_err());
        assert!(find(&words(&["find", "-files0-from", "roots", "-delete"]), None).is_err());
    }
}
