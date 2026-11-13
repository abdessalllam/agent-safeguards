use std::cell::RefCell;
use std::sync::LazyLock;

use regex::Regex;

use guard_common::emit::emit_decision;
use guard_common::locale::{message, FormatValue};

use crate::consts::{self, DEFAULT_REMOTE_ROOTS, REMOTE_UNSAFE_PATH};
use crate::errors::Denied;

thread_local! {
    static PENDING_ASK: RefCell<Option<String>> = const { RefCell::new(None) };
}

static ROOT_SPLIT: LazyLock<Regex> = LazyLock::new(|| match Regex::new(r"[:,\s\x1c-\x1f]+") {
    Ok(regex) => regex,
    Err(error) => panic!("root split failed to compile: {error}"),
});

pub fn pending_ask() -> Option<String> {
    PENDING_ASK.with(|slot| slot.borrow().clone())
}

pub fn set_pending_ask(value: Option<String>) {
    PENDING_ASK.with(|slot| {
        *slot.borrow_mut() = value;
    });
}

pub fn ask(key: &str, values: &[(&str, FormatValue)]) {
    if pending_ask().is_none() {
        set_pending_ask(Some(message(key, values)));
    }
}

pub fn remote_roots() -> Vec<String> {
    let entries: Vec<String> = match std::env::var_os("AGENT_SAFEGUARDS_REMOTE_DELETE_ROOTS") {
        None => DEFAULT_REMOTE_ROOTS.iter().map(|entry| (*entry).to_string()).collect(),
        Some(configured) => {
            let text = configured.to_string_lossy();
            ROOT_SPLIT
                .split(&text)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        }
    };
    let mut roots = Vec::new();
    for entry in entries {
        let entry = entry.trim_end_matches('/').to_string();
        if accept_root(&entry) {
            roots.push(entry);
        }
    }
    roots
}

pub fn emit_ask(reason: &str, runtime: &str) {
    let (decision, text) = ask_text(reason, runtime);
    emit_decision(decision, &text, "PreToolUse");
}

pub fn emit_deny(denial: &Denied) {
    let text = deny_text(denial);
    emit_decision("deny", &text, "PreToolUse");
}

pub fn ask_text(reason: &str, runtime: &str) -> (&'static str, String) {
    if runtime == "claude" {
        (
            "ask",
            message(
                "delete_guard.ask",
                &[("reason", FormatValue::Text(reason.to_string()))],
            ),
        )
    } else {
        (
            "deny",
            message(
                "delete_guard.deny_permission",
                &[("reason", FormatValue::Text(reason.to_string()))],
            ),
        )
    }
}

pub fn deny_text(denial: &Denied) -> String {
    if denial.is_remote() {
        let roots = remote_roots().join(", ");
        message(
            "delete_guard.deny_remote",
            &[
                ("reason", FormatValue::Text(denial.reason().to_string())),
                ("roots", FormatValue::Text(roots)),
            ],
        )
    } else {
        message(
            "delete_guard.deny",
            &[("reason", FormatValue::Text(denial.reason().to_string()))],
        )
    }
}

fn accept_root(entry: &str) -> bool {
    let anchored = entry.starts_with("~/") || guard_common::pathform::is_absolute(entry);
    let parts: Vec<&str> = entry.split('/').collect();
    let mut rest_ok = true;
    match parts.get(1..) {
        Some(rest) => {
            for part in rest {
                if part.is_empty() || *part == "." || *part == ".." {
                    rest_ok = false;
                    break;
                }
            }
        }
        None => rest_ok = false,
    }
    anchored
        && parts.len() >= 2
        && rest_ok
        && REMOTE_UNSAFE_PATH.find(entry).is_none()
        && !consts::in_system_roots(entry)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::deny_text;
    use super::{ask, ask_text, pending_ask, remote_roots, set_pending_ask};
    #[cfg(unix)]
    use crate::errors::Denied;
    use guard_common::locale::FormatValue;

    #[test]
    fn ask_keeps_only_the_first_question() {
        set_pending_ask(None);
        ask("delete_guard.reason.trash_repository", &[("verb", FormatValue::Text("trash".to_string())), ("path", FormatValue::Text("/repo".to_string()))]);
        let first = pending_ask();
        ask("delete_guard.reason.trash_computed", &[("raw", FormatValue::Text("~/x".to_string()))]);
        assert_eq!(pending_ask(), first);
        assert!(first.unwrap_or_default().contains("/repo"));
        set_pending_ask(None);
    }

    #[test]
    fn claude_asks_and_other_runtimes_deny_for_permission() {
        let (decision, text) = ask_text("the whole project", "claude");
        assert_eq!(decision, "ask");
        assert!(text.contains("the whole project"));
        assert!(text.contains("Allow it only if you mean to remove the whole project"));
        let (decision, text) = ask_text("the whole project", "codex");
        assert_eq!(decision, "deny");
        assert!(text.contains("this host cannot ask"));
        assert!(text.contains("the whole project"));
    }

    #[cfg(unix)]
    #[test]
    fn deny_text_uses_the_remote_wording_only_for_remote_denials() {
        let local = deny_text(&Denied::new("outside the repository"));
        assert!(local.contains("outside the repository"));
        assert!(local.contains("git worktree remove"));
        let remote = deny_text(&Denied::remote("not inside a remote root"));
        assert!(remote.contains("not inside a remote root"));
        assert!(remote.contains("~/ci, /tmp"));
        assert!(remote.contains("trash-put"));
    }

    #[test]
    fn default_remote_roots_are_home_ci_and_tmp() {
        assert!(std::env::var_os("AGENT_SAFEGUARDS_REMOTE_DELETE_ROOTS").is_none());
        assert_eq!(remote_roots(), vec!["~/ci".to_string(), "/tmp".to_string()]);
    }
}
