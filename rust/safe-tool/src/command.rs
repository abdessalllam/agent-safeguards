use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use guard_common::shell::{self, HereDocument};
use guard_common::sys::EmbeddedNul;
use guard_common::{emit, env, locale};
use regex::Regex;

use crate::{chunk, consts, git_rules, paths, process, startup, words};

static DATA_ENV_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.env").unwrap_or_else(|_| std::process::abort()));
static PROXY_PREFIX_PY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"rtk[\s\u{001c}-\u{001f}]+proxy").unwrap_or_else(|_| std::process::abort())
});
static DECISION_MADE: AtomicBool = AtomicBool::new(false);
static BUDGET: Mutex<Timer> = Mutex::new(Timer {
    generation: 0,
    deadline: None,
});
static OUTPUT: Mutex<()> = Mutex::new(());

struct Timer {
    generation: u64,
    deadline: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckTooSlow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItimerError;

fn char_slice(text: &str, start: usize, end: usize) -> String {
    text.chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

fn py_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&ch)
}

pub fn unused_marker(command: &str) -> Option<String> {
    let used: std::collections::HashSet<char> = command.chars().collect();
    (0xe000..0xf900)
        .filter_map(char::from_u32)
        .find(|marker| !used.contains(marker))
        .map(|marker| marker.to_string())
}

pub fn owner_words(line: &str, marker: &str) -> Option<Vec<String>> {
    for chunk in words::tokenize(line) {
        if chunk.iter().any(|word| word == marker) {
            let mut owned: Vec<String> = chunk.into_iter().filter(|word| word != marker).collect();
            while owned
                .first()
                .is_some_and(|word| shell::SHELL_KEYWORDS.contains(word.as_str()))
            {
                owned.remove(0);
            }
            if !owned.is_empty() {
                owned = match words::unwrap(&owned) {
                    Ok((unwrapped, _)) => unwrapped,
                    Err(_) => return None,
                };
            }
            return if owned.is_empty() { None } else { Some(owned) };
        }
    }
    None
}

pub fn is_data_owner(words: Option<&[String]>) -> bool {
    let Some(words) = words else {
        return false;
    };
    let Some(first) = words.first() else {
        return false;
    };
    if !consts::SYSTEM_COMMAND_PATH_FULL.is_match(first) {
        return false;
    }
    let name = words::normalized(first);
    if !consts::HEREDOC_DATA_COMMANDS.contains(&name.as_str()) {
        return false;
    }
    !(name == "jq"
        && words
            .iter()
            .skip(1)
            .any(|argument| consts::JQ_PROGRAM_FILE_FULL.is_match(argument)))
}

pub fn is_data_heredoc(command: &str, document: &HereDocument, marker: &str) -> bool {
    if document.line_end.saturating_sub(document.line_start) > consts::MAX_HEREDOC_LINE_CHARS {
        return false;
    }
    let tail = char_slice(command, document.delimiter_end, document.line_end);
    if consts::pipeline_operator_pattern_search(&tail).is_some() {
        return false;
    }
    let line = format!(
        "{} {marker} {tail}",
        char_slice(command, document.line_start, document.marker_start)
    );
    let owner = owner_words(&line, marker);
    if !is_data_owner(owner.as_deref()) {
        return false;
    }
    if !document.quoted
        && consts::HEREDOC_EXPANSION.is_match(&char_slice(
            command,
            document.body_start,
            document.body_end,
        ))
    {
        return false;
    }
    let Some((line_start, opening, quote)) = &document.outer else {
        return true;
    };
    if *opening < 0 || *line_start < 0 {
        return false;
    }
    let outer_line = format!(
        "{}{quote} {marker} ",
        char_slice(command, *line_start as usize, *opening as usize)
    );
    let Some(outer) = owner_words(&outer_line, marker) else {
        return false;
    };
    if !outer.first().is_some_and(|first| {
        consts::SYSTEM_COMMAND_PATH_FULL.is_match(first) && words::normalized(first) == "gh"
    }) {
        return false;
    }
    let arguments = outer.get(1..).unwrap_or(&[]);
    let last = arguments.last().map(String::as_str).unwrap_or("");
    let (option, equals, value) = match last.split_once('=') {
        Some((option, value)) => (option, true, value),
        None => (last, false, ""),
    };
    let text_argument =
        (equals && consts::GH_TEXT_OPTIONS.contains(&option) && !value.starts_with('@'))
            || (arguments.len() > 1
                && arguments
                    .get(arguments.len().saturating_sub(2))
                    .is_some_and(|previous| consts::GH_TEXT_OPTIONS.contains(&previous.as_str()))
                && !last.starts_with('@'));
    arguments.first().is_some_and(|argument| {
        consts::HEREDOC_ARGUMENT_COMMANDS
            .iter()
            .find(|(name, _)| *name == "gh")
            .is_some_and(|(_, commands)| commands.contains(&argument.as_str()))
    }) && text_argument
}

pub fn plain_enough(code: &str) -> bool {
    if shell::HEREDOC_FORBIDDEN.is_match(code) || consts::SHADOWING_PATTERN.is_match(code) {
        return false;
    }
    let chunks = words::tokenize(code);
    !chunks.is_empty()
        && !chunks.iter().any(|chunk| {
            chunk
                .first()
                .is_some_and(|word| consts::in_compound_words(word))
        })
}

pub fn heredoc_views(command: &str) -> (String, String) {
    let marker = unused_marker(command);
    let documents: Vec<HereDocument> = shell::heredocs(command)
        .into_iter()
        .filter(|document| {
            marker
                .as_deref()
                .is_some_and(|marker| is_data_heredoc(command, document, marker))
        })
        .collect();
    if documents.is_empty() {
        return (command.to_owned(), command.to_owned());
    }
    let mut code = String::new();
    let mut view = String::new();
    let mut position = 0usize;
    for document in documents {
        if document.body_start < position {
            continue;
        }
        let segment = char_slice(command, position, document.body_start);
        code.push_str(&segment);
        view.push_str(&segment);
        if !document.quoted {
            view.push_str(&char_slice(command, document.body_start, document.end));
        }
        position = document.end;
    }
    let remainder = char_slice(command, position, command.chars().count());
    code.push_str(&remainder);
    view.push_str(&remainder);
    if plain_enough(&code) {
        (code, view)
    } else {
        (command.to_owned(), command.to_owned())
    }
}

pub fn tokenize_with_loose_bodies(code: &str) -> Vec<Vec<String>> {
    let mut shell_text = String::new();
    let mut bodies = Vec::new();
    let mut position = 0usize;
    for document in shell::heredocs(code) {
        if !document.quoted {
            return Vec::new();
        }
        if document.body_start < position {
            continue;
        }
        shell_text.push_str(&char_slice(code, position, document.body_start));
        bodies.push(char_slice(code, document.body_start, document.end));
        position = document.end;
    }
    if bodies.is_empty() {
        return Vec::new();
    }
    shell_text.push_str(&char_slice(code, position, code.chars().count()));
    let mut chunks = words::tokenize(&shell_text);
    if chunks.is_empty() {
        return Vec::new();
    }
    for body in bodies {
        for line in body.split('\n') {
            chunks.extend(words::tokenize(line));
        }
    }
    chunks
}

pub fn names_non_template_data_env(lowered: &str) -> bool {
    for found in DATA_ENV_NAME.find_iter(lowered) {
        let before = lowered.get(..found.start()).unwrap_or("").chars().last();
        if before.is_some_and(|ch| chunk::python_word(ch) || matches!(ch, '.' | '-')) {
            continue;
        }
        let after = lowered.get(found.end()..).unwrap_or("");
        if let Some(extension) = after.strip_prefix('.') {
            if ["dist", "example", "sample", "template"]
                .iter()
                .any(|suffix| {
                    extension.starts_with(suffix)
                        && extension
                            .get(suffix.len()..)
                            .and_then(|tail| tail.chars().next())
                            .is_none_or(|ch| !chunk::python_word(ch))
                })
            {
                continue;
            }
        }
        if after
            .chars()
            .next()
            .is_none_or(|ch| !chunk::python_word(ch))
        {
            return true;
        }
    }
    false
}

pub fn sensitive_command(command: &str, data_heredocs: bool) -> Result<bool, EmbeddedNul> {
    if command.chars().count() > shell::MAX_COMMAND_CHARS {
        return Ok(true);
    }
    let (code, command) = if data_heredocs {
        heredoc_views(command)
    } else {
        (command.to_owned(), command.to_owned())
    };
    let lowered = command.to_lowercase();
    if consts::DEFINITION_PARAMETER_PATTERN.is_match(&lowered)
        || paths::names_sensitive_path(&lowered, &code)
        || consts::sensitive_file_pattern_search(&lowered).is_some()
        || consts::PROCESS_ENVIRONMENT_PATTERN.is_match(&lowered)
        || startup::reads_startup_file(&command)?
        || chunk::prints_secret_variable(&command)
        || names_non_template_data_env(&lowered)
    {
        return Ok(true);
    }
    let mut chunks = words::tokenize(&code);
    if chunks.is_empty() {
        chunks = tokenize_with_loose_bodies(&code);
    }
    if chunks.is_empty() {
        return Ok(true);
    }
    for one in &chunks {
        if chunk::sensitive_chunk(one)? {
            return Ok(true);
        }
    }
    if consts::CONFIG_ENVIRONMENT.is_match(&lowered)
        && chunks.iter().any(|one| git_rules::runs_git_config(one))
    {
        return Ok(true);
    }
    for body in shell::command_substitutions(&code) {
        if body.chars().any(|ch| !py_space(ch)) && sensitive_command(&body, false)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn blocked_only_by_startup_file(command: &str) -> Result<bool, EmbeddedNul> {
    consts::set_startup_rules(false);
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            consts::set_startup_rules(true);
        }
    }
    let _restore = Restore;
    Ok(!sensitive_command(command, true)?)
}

pub fn blocked_by_git_format(command: &str) -> Result<bool, shell::UnresolvableCommand> {
    for text in std::iter::once(command.to_owned()).chain(shell::command_substitutions(command)) {
        for one in words::tokenize(&text) {
            let (unwrapped, _) = words::unwrap(&one)?;
            let subcommand = git_rules::git_subcommand(&unwrapped).0;
            if matches!(
                subcommand.as_deref(),
                Some("log" | "show" | "rev-list" | "for-each-ref")
            ) && git_rules::sensitive_git_command(&unwrapped)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn blocked_only_by_proxy(command: &str) -> Result<bool, EmbeddedNul> {
    let without_proxy = without_proxy_prefix(command);
    Ok(without_proxy != command && !sensitive_command(&without_proxy, true)?)
}

pub fn without_proxy_prefix(command: &str) -> String {
    PROXY_PREFIX_PY
        .replace_all(command, |captures: &regex::Captures<'_>| {
            let Some(found) = captures.get(0) else {
                return String::new();
            };
            let before = command.get(..found.start()).unwrap_or("").chars().last();
            let after = command.get(found.end()..).unwrap_or("").chars().next();
            if before.is_none_or(|ch| !chunk::python_word(ch))
                && after.is_none_or(|ch| !chunk::python_word(ch))
            {
                "rtk".to_owned()
            } else {
                found.as_str().to_owned()
            }
        })
        .into_owned()
}

pub fn on_budget_alarm() -> Result<(), CheckTooSlow> {
    if DECISION_MADE.load(Ordering::SeqCst) {
        Ok(())
    } else {
        Err(CheckTooSlow)
    }
}

pub fn set_decision_made(value: bool) {
    DECISION_MADE.store(value, Ordering::SeqCst);
}

pub fn set_budget(seconds: f64) -> Result<(), ItimerError> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(ItimerError);
    }
    let deadline = if seconds == 0.0 {
        None
    } else {
        let duration = Duration::try_from_secs_f64(seconds).map_err(|_| ItimerError)?;
        Instant::now().checked_add(duration)
    };
    let mut timer = BUDGET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    timer.generation = timer.generation.saturating_add(1);
    timer.deadline = deadline;
    Ok(())
}

pub fn check_budget() -> Result<(), CheckTooSlow> {
    let timer = BUDGET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if timer
        .deadline
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        on_budget_alarm()
    } else {
        Ok(())
    }
}

pub fn with_output_lock<T>(work: impl FnOnce() -> T) -> T {
    let _guard = OUTPUT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    work()
}

pub fn run_with_budget<W, S>(seconds: f64, work: W, on_too_slow: S) -> Result<(), ItimerError>
where
    W: FnOnce(),
    S: FnOnce() + Send + 'static,
{
    set_budget(seconds)?;
    let generation = BUDGET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .generation;
    let done = Arc::new(AtomicBool::new(false));
    let signal = Arc::new((Mutex::new(false), Condvar::new()));
    let watcher = if seconds > 0.0 {
        let done = Arc::clone(&done);
        let signal = Arc::clone(&signal);
        Some(thread::spawn(move || {
            let (lock, cvar) = &*signal;
            let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let timeout = Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX);
            let waited = cvar.wait_timeout_while(guard, timeout, |finished| !*finished);
            drop(waited);
            with_output_lock(|| {
                let active = BUDGET
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .generation
                    == generation;
                if active && !done.load(Ordering::SeqCst) && on_budget_alarm().is_err() {
                    on_too_slow();
                }
            });
        }))
    } else {
        None
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
    with_output_lock(|| done.store(true, Ordering::SeqCst));
    if let Ok(mut finished) = signal.0.lock() {
        *finished = true;
    }
    signal.1.notify_all();
    set_budget(0.0)?;
    if let Some(watcher) = watcher {
        let _ = watcher.join();
    }
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
    Ok(())
}

pub fn deny_hook(reason_key: &str) -> serde_json::Value {
    DECISION_MADE.store(true, Ordering::SeqCst);
    let payload = emit::decision_value("deny", &locale::message(reason_key, &[]), "PreToolUse");
    emit::emit(&payload);
    payload
}

pub fn require_rtk() -> bool {
    env::env_flag("AGENT_SAFEGUARDS_REQUIRE_RTK")
        || env::env_flag("CLAUDE_PLUGIN_OPTION_REQUIRE_RTK")
}

pub fn rtk_required(command: &str) -> bool {
    let Some(path) = consts::rtk_path() else {
        return false;
    };
    let Some(completed) = process::run(
        &[path, "rewrite".to_owned(), command.to_owned()],
        &paths::working_folder(),
        consts::RTK_REWRITE_TIMEOUT_SECONDS as u64,
    ) else {
        return false;
    };
    if !matches!(completed.returncode, 0 | 3) {
        return false;
    }
    let Ok(stdout) = String::from_utf8(completed.stdout) else {
        return false;
    };
    let rewritten = stdout.trim_matches(py_space);
    !rewritten.is_empty() && rewritten != command.trim_matches(py_space)
}

pub fn ask_local_artifact_hook() -> serde_json::Value {
    DECISION_MADE.store(true, Ordering::SeqCst);
    let payload = emit::decision_value(
        "ask",
        &locale::message("safe_tool.ask.local_artifact", &[]),
        "PreToolUse",
    );
    emit::emit(&payload);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_documents_are_removed_only_for_plain_owners() {
        let command = "cat <<'EOF'\nthis is prose with a ' quote\nEOF";
        let (code, view) = heredoc_views(command);
        assert_eq!(code, "cat <<'EOF'\n");
        assert_eq!(view, code);
        assert_eq!(sensitive_command(command, true), Ok(false));
        assert_eq!(sensitive_command(command, false), Ok(false));
    }

    #[test]
    fn unquoted_expansions_remain_visible() {
        let command = "cat <<EOF\n$API_TOKEN\nEOF";
        assert_eq!(
            heredoc_views(command),
            ("cat <<EOF\n".to_owned(), command.to_owned())
        );
        assert_eq!(sensitive_command(command, true), Ok(true));
    }

    #[test]
    fn startup_and_proxy_remedies_are_distinct() {
        assert_eq!(blocked_only_by_startup_file("cat .zshrc"), Ok(true));
        assert_eq!(blocked_only_by_startup_file("printenv"), Ok(false));
        assert_eq!(blocked_only_by_proxy("rtk proxy cat README.md"), Ok(true));
        assert_eq!(blocked_only_by_proxy("rtk proxy printenv"), Ok(false));
        assert_eq!(
            blocked_only_by_proxy("rtk\u{001c}proxy cat README.md"),
            Ok(true)
        );
    }

    #[test]
    fn data_env_templates_do_not_trigger() {
        assert!(names_non_template_data_env("cat .env"));
        assert!(!names_non_template_data_env("cat .env.example"));
        assert!(names_non_template_data_env("cat .env.examplex"));
        assert!(!names_non_template_data_env("cat x.env"));
    }

    #[test]
    fn watchdog_interrupts_slow_work_and_disarms_after_fast_work() {
        set_decision_made(false);
        let fired = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&fired);
        assert_eq!(
            run_with_budget(
                0.01,
                || thread::sleep(Duration::from_millis(30)),
                move || captured.store(true, Ordering::SeqCst)
            ),
            Ok(())
        );
        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(check_budget(), Ok(()));
        let fired = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&fired);
        assert_eq!(
            run_with_budget(0.1, || {}, move || captured.store(true, Ordering::SeqCst)),
            Ok(())
        );
        assert!(!fired.load(Ordering::SeqCst));
        let fired = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&fired);
        assert_eq!(
            run_with_budget(
                0.01,
                || {
                    set_budget(0.0).expect("disarm nested timer");
                    thread::sleep(Duration::from_millis(30));
                },
                move || captured.store(true, Ordering::SeqCst)
            ),
            Ok(())
        );
        assert!(!fired.load(Ordering::SeqCst));
    }
}
