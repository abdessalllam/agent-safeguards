#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::Value;

use comment_guard::limits::{self, Limits, Mode};
use comment_guard::locale::message;
use comment_guard::{judge, judge_after, judge_after_trimming, judge_trimming, Provider, Verdict, MAX_INPUT};

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let first = args.first().map(String::as_str);
    let second = args.get(1).map(String::as_str);
    let third = args.get(2).map(String::as_str);
    match first {
        Some("--version") if args.len() == 1 => {
            say(&format!("comment-guard {}", env!("CARGO_PKG_VERSION")));
            ExitCode::SUCCESS
        }
        Some("check") if args.len() == 1 => {
            let key = if guard_enabled() {
                "comment_guard.check.on"
            } else {
                "comment_guard.check.off"
            };
            say(&message(key, &[]));
            if guard_enabled() {
                let found = load_limits();
                let lines = found.lines.to_string();
                let chars = found.line_chars.to_string();
                say(&message("comment_guard.check.limits", &[("lines", lines.as_str()), ("chars", chars.as_str())]));
                let name = match load_mode() {
                    Mode::Trim => "trim",
                    Mode::Drop => "drop",
                    Mode::Block => "block",
                };
                say(&message("comment_guard.check.mode", &[("mode", name)]));
            }
            ExitCode::SUCCESS
        }
        Some("hook") if args.len() <= 3 => match second {
            Some("claude") => hook(Provider::Claude, third),
            Some("codex") => hook(Provider::Codex, third),
            _ => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    complain(&message("comment_guard.cli.usage", &[]));
    ExitCode::from(2)
}

fn say(text: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{text}");
}

fn complain(text: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{text}");
}

fn home_config() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".config"))
}

fn switch_file() -> Option<PathBuf> {
    let config = match std::env::var("XDG_CONFIG_HOME") {
        Ok(value) => {
            let path = PathBuf::from(&value);
            if path.is_absolute() {
                path
            } else {
                home_config()?
            }
        }
        Err(_) => home_config()?,
    };
    Some(config.join("agent-safeguards").join("comment-guard"))
}

fn load_limits() -> Limits {
    let file = switch_file().and_then(|path| {
        let mut text = String::new();
        std::fs::File::open(path).ok()?.take(4096).read_to_string(&mut text).ok()?;
        Some(text)
    });
    let lines = std::env::var("AGENT_SAFEGUARDS_COMMENT_GUARD_LINES").ok();
    let chars = std::env::var("AGENT_SAFEGUARDS_COMMENT_GUARD_LINE_CHARS").ok();
    limits::parse(file.as_deref(), lines.as_deref(), chars.as_deref())
}

fn load_mode() -> Mode {
    for name in ["AGENT_SAFEGUARDS_COMMENT_GUARD_MODE", "AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM"] {
        if let Some(mode) = std::env::var(name).ok().and_then(|value| Mode::parse(&value)) {
            return mode;
        }
    }
    let file = switch_file().and_then(|path| {
        let mut text = String::new();
        std::fs::File::open(path).ok()?.take(4096).read_to_string(&mut text).ok()?;
        Some(text)
    });
    if let Some(mode) = limits::file_mode(file.as_deref()) {
        return mode;
    }
    match switch_file() {
        Some(path) if path.with_file_name("comment-guard-refuse").exists() => Mode::Block,
        _ => Mode::default(),
    }
}

fn guard_enabled() -> bool {
    if let Ok(value) = std::env::var("AGENT_SAFEGUARDS_COMMENT_GUARD") {
        let value = value.trim();
        if value.eq_ignore_ascii_case("1")
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value.eq_ignore_ascii_case("on")
        {
            return true;
        }
    }
    switch_file().is_some_and(|path| path.exists())
}

fn hook(provider: Provider, event: Option<&str>) -> ExitCode {
    let after = match event {
        None | Some("PreToolUse") => false,
        Some("PostToolUse") => true,
        Some(_) => return usage(),
    };
    if !guard_enabled() {
        return ExitCode::SUCCESS;
    }
    limits::configure(load_limits());
    let mode = load_mode();
    limits::set_mode(mode);
    let trimming = mode != Mode::Block;
    let limit = MAX_INPUT.saturating_add(1) as u64;
    let mut stdin = std::io::stdin().lock().take(limit);
    let mut input = String::new();
    if stdin.read_to_string(&mut input).is_err() || input.len() > MAX_INPUT {
        complain(&message("comment_guard.error.input", &[]));
        return ExitCode::SUCCESS;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if after {
            if trimming {
                judge_after_trimming(&input)
            } else {
                judge_after(&input)
            }
        } else if trimming {
            judge_trimming(&input, provider)
        } else {
            judge(&input, provider)
        }
    }));
    match outcome {
        Ok(Verdict::Allow) => ExitCode::SUCCESS,
        Ok(Verdict::BadInput) => {
            complain(&message("comment_guard.error.input", &[]));
            ExitCode::SUCCESS
        }
        Ok(Verdict::Trimmed { input, note }) => {
            if after {
                print_after_note(&note);
            } else {
                print_trimmed(&input, &note, provider);
            }
            ExitCode::SUCCESS
        }
        Ok(Verdict::Deny(reason)) => {
            if after {
                print_block(&reason);
            } else {
                print_deny(&reason);
            }
            ExitCode::SUCCESS
        }
        Err(_) => {
            complain(&message("comment_guard.error.internal", &[]));
            ExitCode::SUCCESS
        }
    }
}

fn print_block(reason: &str) {
    let mut outer = serde_json::Map::new();
    outer.insert("decision".to_owned(), Value::String("block".to_owned()));
    outer.insert("reason".to_owned(), Value::String(reason.to_owned()));
    if let Ok(text) = serde_json::to_string(&Value::Object(outer)) {
        say(&text);
    }
}

fn print_after_note(note: &str) {
    let mut inner = serde_json::Map::new();
    inner.insert("hookEventName".to_owned(), Value::String("PostToolUse".to_owned()));
    inner.insert("additionalContext".to_owned(), Value::String(note.to_owned()));
    let mut outer = serde_json::Map::new();
    outer.insert("hookSpecificOutput".to_owned(), Value::Object(inner));
    if let Ok(text) = serde_json::to_string(&Value::Object(outer)) {
        say(&text);
    }
}

fn print_trimmed(input: &Value, note: &str, provider: Provider) {
    let mut inner = serde_json::Map::new();
    inner.insert("hookEventName".to_owned(), Value::String("PreToolUse".to_owned()));
    inner.insert("permissionDecision".to_owned(), Value::String("allow".to_owned()));
    if provider == Provider::Claude {
        inner.insert("permissionDecisionReason".to_owned(), Value::String(note.to_owned()));
    }
    inner.insert("updatedInput".to_owned(), input.clone());
    inner.insert("additionalContext".to_owned(), Value::String(note.to_owned()));
    let mut outer = serde_json::Map::new();
    outer.insert("hookSpecificOutput".to_owned(), Value::Object(inner));
    if let Ok(text) = serde_json::to_string(&Value::Object(outer)) {
        say(&text);
    }
}

fn print_deny(reason: &str) {
    let mut inner = serde_json::Map::new();
    inner.insert("hookEventName".to_owned(), Value::String("PreToolUse".to_owned()));
    inner.insert("permissionDecision".to_owned(), Value::String("deny".to_owned()));
    inner.insert(
        "permissionDecisionReason".to_owned(),
        Value::String(reason.to_owned()),
    );
    let mut outer = serde_json::Map::new();
    outer.insert("hookSpecificOutput".to_owned(), Value::Object(inner));
    if let Ok(text) = serde_json::to_string(&Value::Object(outer)) {
        say(&text);
    }
}
