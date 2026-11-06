use guard_common::emit::emit;
use serde_json::json;

use crate::{command, consts, git, output};

pub fn self_test() -> i32 {
    let blocked = [
        "coderabbit auth status",
        "rtk proxy coderabbit auth status",
        "bash -lc 'coderabbit auth status'",
        "git config --get user.email",
        "git -C /tmp/repository config --get user.name",
        "git var GIT_AUTHOR_IDENT",
        "git commit -m test",
        "git log -1",
        "git show HEAD",
        "gh auth status",
        "aws sts get-caller-identity",
        "vendor account show",
        "vendor status",
        "cat ~/.gitconfig",
        "security find-identity -v -p codesigning",
        "rtk proxy security find-identity -v -p codesigning",
        "rtk proxy ./gradlew test",
        "./other/safe-tool env",
        "git config --list",
        "git config --get remote.origin.url",
        "git config --local --unset user.name",
        "git -c include.path=/tmp/x config --get user.name",
        "cat .git/config",
        "grep url .git/config",
        "grep -c -o url .git/config",
        "ls .git/config | xargs cat",
        "export GREP_OPTIONS=-v; grep hooksPath .git/config",
        "npm whoami",
    ];
    let allowed = [
        "safe-tool status coderabbit",
        "safe-tool git identity",
        "safe-tool git commit -m test",
        "git log --oneline -5",
        "git show --format= --stat HEAD",
        "rtk git status --short",
        "rtk proxy git diff --stat",
        "rg \"git config\" AGENTS.md",
        "git config --local --unset core.hooksPath",
        "git config --get core.hooksPath",
        "grep -c hooksPath .git/config",
        "rg -c url .git/config",
        "stat -f '%Sm' .git/config",
        "rm status",
        "make status",
    ];
    let status_payload = git::AuthNode::Array(vec![git::AuthNode::Object(vec![
        (
            "type".to_owned(),
            git::AuthNode::String("status".to_owned()),
        ),
        ("authenticated".to_owned(), git::AuthNode::Bool(true)),
        (
            "email".to_owned(),
            git::AuthNode::String("withheld@example.invalid".to_owned()),
        ),
    ])]);
    let secret_output = json!({"stdout": format!("token=ghp_{}", "A".repeat(32)), "stderr": ""});
    let identity_output = json!({"stdout": "email=owner@corp.internal", "stderr": ""});
    let name_output = json!({"stdout": "name=PrivateUser", "stderr": ""});
    let rtk_checks = consts::rtk_path().is_none()
        || !command::require_rtk()
        || (command::rtk_required("git status --short")
            && !command::rtk_required("rtk git status --short")
            && !command::rtk_required("printf ok"));
    let passed = blocked
        .iter()
        .all(|item| command::sensitive_command(item, true).unwrap_or(false))
        && allowed
            .iter()
            .all(|item| !command::sensitive_command(item, true).unwrap_or(true))
        && git::authentication_state(&status_payload) == Some("ready")
        && output::sensitive_output("tool status", &secret_output).unwrap_or(false)
        && output::sensitive_output("tool status", &identity_output).unwrap_or(false)
        && output::sensitive_output("tool status", &name_output).unwrap_or(false)
        && rtk_checks;
    emit(&json!({
        "tool": consts::TOOL_NAME,
        "status": if passed { "self_test_passed" } else { "self_test_failed" },
    }));
    if passed {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::self_test;

    #[test]
    fn built_in_self_test_passes() {
        assert_eq!(self_test(), 0);
    }
}
