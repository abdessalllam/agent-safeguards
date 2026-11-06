use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;

use guard_common::emit::{dumps, emit_decision};
use guard_common::env::fail_open;
use guard_common::locale::{message, FormatValue};
use guard_common::shlex::quote;
use serde_json::{json, Value};

use crate::budget::{hook_budget_seconds, run_with_budget, with_output_lock};
use crate::check::check_command;
use crate::consts::{HOOK_EVENTS, MAX_INPUT_BYTES, TOOL_NAME};
use crate::decision::{emit_ask, emit_deny, pending_ask, remote_roots, set_pending_ask};
use crate::errors::Stop;
use crate::remote::check_remote_command;
use crate::targets::{clear_remote_targets, remote_targets, repository_root};

fn text(value: &str) -> FormatValue {
    FormatValue::Text(value.to_owned())
}

fn command_repr(command: &str) -> String {
    let quote = if command.contains('\'') && !command.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for character in command.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            value if value == quote => {
                out.push('\\');
                out.push(value);
            }
            value if value.is_control() && (value as u32) <= 0xff => {
                out.push_str(&format!("\\x{:02x}", value as u32))
            }
            value if value.is_control() && (value as u32) <= 0xffff => {
                out.push_str(&format!("\\u{:04x}", value as u32))
            }
            value if value.is_control() => out.push_str(&format!("\\U{:08x}", value as u32)),
            value => out.push(value),
        }
    }
    out.push(quote);
    out
}

fn join_path(base: &str, tail: &str) -> String {
    if base.is_empty() || base.ends_with('/') {
        format!("{base}{tail}")
    } else {
        format!("{base}/{tail}")
    }
}

fn emit_stop(key: &str) {
    if !fail_open() {
        emit_decision("deny", &message(key, &[]), "PreToolUse");
    }
}

fn parse_payload(raw: &[u8]) -> Option<Value> {
    if let Some(value) = guard_common::pyjson::loads(raw) {
        return Some(value);
    }
    let mut normalized = Vec::with_capacity(raw.len());
    let mut index = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut changed = false;
    while let Some(&byte) = raw.get(index) {
        if quoted {
            normalized.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            index = index.saturating_add(1);
            continue;
        }
        if byte == b'"' {
            quoted = true;
        } else if let Some(width) = [b"-Infinity".as_slice(), b"Infinity", b"NaN"]
            .iter()
            .find_map(|word| {
                raw.get(index..)
                    .is_some_and(|tail| tail.starts_with(word))
                    .then_some(word.len())
            })
        {
            normalized.extend_from_slice(b"null");
            index = index.saturating_add(width);
            changed = true;
            continue;
        }
        normalized.push(byte);
        index = index.saturating_add(1);
    }
    if changed {
        guard_common::pyjson::loads(&normalized)
    } else {
        None
    }
}

pub fn run_hook(runtime: &str) -> i32 {
    let mut raw = Vec::new();
    let read = std::io::stdin()
        .take((MAX_INPUT_BYTES as u64).saturating_add(1))
        .read_to_end(&mut raw);
    let payload: Value = match read.ok().and_then(|_| parse_payload(&raw)) {
        Some(Value::Object(value)) if raw.len() <= MAX_INPUT_BYTES => Value::Object(value),
        _ => {
            emit_decision(
                "deny",
                &message("delete_guard.deny_input", &[]),
                "PreToolUse",
            );
            return 0;
        }
    };
    let Some(tool_input) = payload.get("tool_input").and_then(Value::as_object) else {
        return 0;
    };
    let Some(command) = tool_input.get("command").and_then(Value::as_str) else {
        return 0;
    };
    let mut cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(workdir) = tool_input
        .get("workdir")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    {
        cwd = Some(match cwd.as_deref() {
            Some(base) if !Path::new(workdir).is_absolute() => join_path(base, workdir),
            _ => workdir.to_owned(),
        });
    }
    set_pending_ask(None);
    let mut outcome = Ok(());
    let budget = run_with_budget(
        hook_budget_seconds(),
        || {
            outcome = check_command(command, cwd.as_deref());
        },
        || {
            emit_stop("delete_guard.deny_too_slow");
            std::process::exit(0);
        },
    );
    with_output_lock(|| {
        if budget.is_err() {
            emit_stop("delete_guard.deny_internal");
        } else {
            match outcome {
                Err(Stop::Denied(ref denial)) => emit_deny(denial),
                Err(Stop::TooSlow) => emit_stop("delete_guard.deny_too_slow"),
                Err(Stop::Internal) => emit_stop("delete_guard.deny_internal"),
                Ok(()) => {
                    if let Some(reason) = pending_ask() {
                        emit_ask(&reason, runtime);
                    }
                }
            }
        }
    });
    0
}

pub fn check_remote_cli(command: &str) -> i32 {
    let mut outcome = Ok(());
    let budget = run_with_budget(
        hook_budget_seconds(),
        || {
            outcome = check_remote_command(command);
        },
        || {
            eprintln!("{}", message("delete_guard.deny_too_slow", &[]));
            std::process::exit(1);
        },
    );
    let error = if budget.is_err() {
        Some(message("delete_guard.deny_internal", &[]))
    } else {
        match outcome {
            Ok(()) => None,
            Err(Stop::Denied(denial)) => Some(message(
                "delete_guard.deny_remote",
                &[
                    ("reason", text(&denial.to_string())),
                    ("roots", text(&remote_roots().join(", "))),
                ],
            )),
            Err(Stop::TooSlow) => Some(message("delete_guard.deny_too_slow", &[])),
            Err(Stop::Internal) => Some(message("delete_guard.deny_internal", &[])),
        }
    };
    if let Some(error) = error {
        with_output_lock(|| eprintln!("{error}"));
        1
    } else {
        0
    }
}

fn folded(name: &str) -> String {
    let mut out = String::new();
    for letter in name.chars() {
        if letter.is_alphabetic() {
            out.push('[');
            out.extend(letter.to_lowercase());
            out.extend(letter.to_uppercase());
            out.push(']');
        } else {
            out.push(letter);
        }
    }
    out
}

pub fn preflight_trash_patterns() -> String {
    let trash = folded(".Trash");
    let components = vec![
        trash.clone(),
        format!("{trash}-*"),
        folded(".Trashes"),
        format!("\\${}", folded("Recycle.Bin")),
        format!("#{}", folded("recycle")),
        format!("@{}", folded("Recycle")),
        folded("files_trashbin"),
        "RECYCLER".into(),
        "RECYCLED".into(),
        "Recycled".into(),
        ".recycle".into(),
        ".FilesByGoogleTrash".into(),
        ".trashed-*".into(),
    ];
    let mut patterns = Vec::new();
    for component in components {
        patterns.push(format!("*/{component}"));
        patterns.push(format!("*/{component}/*"));
    }
    patterns.extend(
        [
            "*/.local/share/Trash",
            "*/.local/share/Trash/*",
            "/boot/trash",
            "/boot/trash/*",
        ]
        .iter()
        .map(|value| (*value).to_owned()),
    );
    patterns.join("|")
}

pub fn script_path(path: &str) -> String {
    if let Some(suffix) = path.strip_prefix("~/") {
        format!("~/{}", quote(suffix))
    } else {
        quote(path)
    }
}

pub fn remote_preflight_script() -> String {
    let mut seen = HashSet::new();
    let targets: Vec<(String, bool)> = remote_targets()
        .into_iter()
        .filter(|entry| seen.insert(entry.clone()))
        .collect();
    let roots = remote_roots();
    if targets.is_empty() || roots.is_empty() {
        return String::new();
    }
    let removed = targets
        .iter()
        .filter(|(_, entered)| !entered)
        .map(|(path, _)| script_path(path))
        .collect::<Vec<_>>()
        .join(" ");
    let entered = targets
        .iter()
        .filter(|(_, entered)| *entered)
        .map(|(path, _)| script_path(path))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "fail=0; check() {{ case \"$1\" in {}) echo \"PREFLIGHT_REFUSED $2\"; fail=1; return;; esac; \
ok=0; for root in {}; do rr=$(cd -P -- \"$root\" 2>/dev/null && pwd) || continue; \
case \"$1\" in \"$rr\"/?*) ok=1;; esac; done; \
[ \"$ok\" = 1 ] || {{ echo \"PREFLIGHT_REFUSED $2\"; fail=1; }}; }}; \
for t in {}; do d=$(dirname -- \"$t\"); b=$(basename -- \"$t\"); [ -d \"$d\" ] || continue; \
check \"$(cd -P -- \"$d\" && pwd)/$b\" \"$t\"; done; \
for t in {}; do [ -d \"$t\" ] || continue; check \"$(cd -P -- \"$t\" && pwd)\" \"$t\"; done; \
[ \"$fail\" = 0 ] && echo PREFLIGHT_OK",
        preflight_trash_patterns(), roots.join(" "), removed, entered
    )
}

pub fn remote_preflight_cli(command: &str) -> i32 {
    clear_remote_targets();
    let code = check_remote_cli(command);
    if code == 0 {
        let script = remote_preflight_script();
        if !script.is_empty() {
            println!("{script}");
        }
    }
    code
}

pub fn self_test() -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let probe = repository_root(cwd.as_deref()).unwrap_or_default();
    let mut blocked: Vec<String> = vec![
        "rm -rf ~/Documents",
        "rm -rf ~",
        "rm -rf /",
        "rm -rf /Users/x",
        "/bin/rm -rf \"$WT\"/",
        "rm -rf $HOME",
        "sudo rm -rf /opt/x",
        "cd ~ && rm -rf Documents",
        "cd ~\nrm -rf Documents",
        "find ~ -mindepth 1 -delete",
        "find ~/Documents -name x -exec rm -rf {} +",
        "find . -type f | xargs rm -f",
        "python3 -c 'import shutil; shutil.rmtree(\"/x\")'",
        "bash -lc 'rm -rf ~/Library'",
        "rm -rf /Volumes/Drive",
        "rm -rf /mnt/data",
        "diskutil eraseDisk APFS X disk4",
        "dd if=/dev/zero of=/dev/disk4",
        "trash ~/Documents",
        "gio trash ~/Documents",
        "rm -rf *",
        "rsync -a --delete src/ ~/Documents/",
        "git clean -fdx",
        "git -C /tmp/r clean -fd",
        "trash-empty",
        "gio trash --empty",
        "rm -rf ~/.Trash/old",
        "rm ~/.local/share/Trash/files/old",
        "trash ~/.local/share/Trash/files/old",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut allowed: Vec<String> = vec![
        "rm -rf /private/tmp/agent-probe",
        "rm -rf /tmp/agent-probe/build",
        "rm -rf /var/tmp/agent-probe",
        "rm -f /tmp/x.log",
        "rmdir empty-dir",
        "trash /private/tmp/old",
        "trash-put /private/tmp/old",
        "gio trash /private/tmp/old",
        "git rm -r --cached x",
        "git worktree remove .worktrees/old",
        "find /tmp/x -name '*.log' -delete",
        "rg -n 'rm -rf' docs",
        "ls -la",
        "echo find this",
        "git clean -ndx",
        "git status --short",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if !probe.is_empty() {
        allowed.push(format!("rm -rf {probe}/build/outputs"));
        blocked.push(format!("rm -rf {probe}"));
        blocked.push(format!("rm -rf {probe}/.git"));
    }
    let mut failures = Vec::new();
    let folder = if probe.is_empty() {
        "/private/tmp"
    } else {
        &probe
    };
    for command in blocked {
        if check_command(&command, Some(folder)).is_ok() {
            failures.push(format!("allowed: {}", command_repr(&command)));
        }
    }
    for command in allowed {
        if let Err(Stop::Denied(denial)) = check_command(&command, Some(folder)) {
            failures.push(format!("blocked: {} ({denial})", command_repr(&command)));
        }
    }
    let status = if failures.is_empty() {
        "self_test_passed"
    } else {
        "self_test_failed"
    };
    let failures_json = dumps(&json!(failures));
    let probe_json = if probe.is_empty() { "false" } else { "true" };
    let output = format!("{{\"tool\": \"{TOOL_NAME}\", \"status\": \"{status}\", \"failures\": {failures_json}, \"repo_probe\": {probe_json}}}");
    let _ = std::io::stdout().write_all(format!("{output}\n").as_bytes());
    if failures.is_empty() {
        0
    } else {
        1
    }
}

pub fn main_args(arguments: &[String]) -> i32 {
    if arguments.first().is_some_and(|value| value == "self-test") {
        return self_test();
    }
    if arguments
        .first()
        .is_some_and(|value| value == "check-remote")
        && arguments.len() == 2
    {
        return check_remote_cli(arguments.get(1).map(String::as_str).unwrap_or(""));
    }
    if arguments
        .first()
        .is_some_and(|value| value == "remote-preflight")
        && arguments.len() == 2
    {
        return remote_preflight_cli(arguments.get(1).map(String::as_str).unwrap_or(""));
    }
    if arguments.first().is_some_and(|value| value == "hook")
        && (2..=3).contains(&arguments.len())
        && arguments
            .get(1)
            .is_some_and(|value| value == "claude" || value == "codex")
        && (arguments.len() == 2
            || arguments
                .get(2)
                .is_some_and(|value| HOOK_EVENTS.contains(&value.as_str())))
    {
        return run_hook(arguments.get(1).map(String::as_str).unwrap_or("claude"));
    }
    eprintln!("{}", message("delete_guard.cli.usage", &[]));
    2
}

pub fn main() -> i32 {
    main_args(&std::env::args().skip(1).collect::<Vec<_>>())
}

const WORK_STACK_BYTES: usize = 512 * 1024 * 1024;

/// Large stack; a panic gets the answer of Python's catch-all.
pub fn guarded_main() -> i32 {
    std::panic::set_hook(Box::new(|_| {}));
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let inner = arguments.clone();
    let worker = std::thread::Builder::new()
        .stack_size(WORK_STACK_BYTES)
        .spawn(move || main_args(&inner));
    let code = worker.ok().and_then(|handle| handle.join().ok());
    if let Some(code) = code {
        return code;
    }
    match arguments.first().map(String::as_str) {
        Some("hook") => {
            with_output_lock(|| emit_stop("delete_guard.deny_internal"));
            0
        }
        Some("check-remote") => {
            eprintln!("{}", message("delete_guard.deny_internal", &[]));
            1
        }
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{command_repr, parse_payload, preflight_trash_patterns, script_path};
    #[test]
    fn preflight_patterns_and_quoting() {
        assert!(preflight_trash_patterns().contains("*/.local/share/Trash/*"));
        assert_eq!(script_path("~/a b"), "~/'a b'");
        assert_eq!(command_repr("rm 'x'"), "\"rm 'x'\"");
        assert_eq!(command_repr("a\nb"), "'a\\nb'");
    }

    #[test]
    fn python_json_constants_preserve_hook_fields() {
        let payload =
            parse_payload(br#"{"tool_input":{"command":"rm /"},"extra":NaN,"other":-Infinity}"#)
                .expect("payload");
        assert_eq!(
            payload
                .get("tool_input")
                .and_then(|field| field.get("command"))
                .and_then(serde_json::Value::as_str),
            Some("rm /")
        );
        assert!(parse_payload(br#"{"command":"NaN"}"#).is_some());
        assert!(parse_payload(br#"{"command":NaNx}"#).is_none());
        let quoted = parse_payload(br#"{"tool_input":{"command":"NaN"},"extra":NaN}"#)
            .expect("quoted payload");
        assert_eq!(
            quoted
                .get("tool_input")
                .and_then(|field| field.get("command"))
                .and_then(serde_json::Value::as_str),
            Some("NaN")
        );
    }
}
