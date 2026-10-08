---
name: setup-agent-safeguards
description: Use when the user asks to verify, test, configure, or troubleshoot agent-safeguards (safe-tool and delete-guard), or when a hook error mentions agent-safeguards. Runs the built-in self-tests and harmless live probes, and explains the settings.
---

# Verify agent-safeguards

Synthetic checks prove the policy. They do not prove the host actually runs the hooks, so finish with the live probes.

## 1. Self-tests

Run both from a Git repository that is not inside a temp folder:

```sh
safe-tool self-test
delete-guard self-test
```

Claude Code puts the plugin's `bin/` folder on the shell `PATH`. In other hosts, run them by their full path inside the plugin folder with `python3 -I`.

Expected: `self_test_passed` from each. Anything else means the policy or the install is broken; report the exact output.

## 2. Live probes

Run each command once and check the result. Both are harmless: the first sends its output to `/dev/null`, so nothing is printed even if the hook is not running, and the second names a folder that does not exist.

| Command | Expected |
| --- | --- |
| `whoami >/dev/null 2>&1` | Blocked with `Sensitive-output command blocked`. |
| `rm -rf ~/agent-safeguards-probe-does-not-exist` | Blocked with `Delete guard:`. |

If a probe runs instead of being blocked, the host is not dispatching the hooks. Ask the user to check that the plugin is enabled and that hooks are not disabled for the session, then restart the session.

## 3. Hook errors

The launcher prints a machine code on stderr and exits 2, which blocks the command:

| Code | Cause | Fix |
| --- | --- | --- |
| `error=python3_not_found` | No `python3` on the hook's `PATH`. | Install Python 3, or set `AGENT_SAFEGUARDS_FAIL_OPEN=1` to let commands through while the hook is broken. |
| `error=hook_failed` | The tool crashed before it could answer. | Reinstall the plugin, then rerun the self-tests. |
| `error=unknown_tool` or `error=unknown_runtime` | The hook file was edited. | Restore the shipped hook file. |

A hook that times out or crashes before it can answer does not block the command. This is a host rule for both Claude Code and Codex, so keep the timeouts short and run the live probes after every upgrade.

## 4. Settings

Settings are environment variables, read by the hook on each call. Set them in the environment that launches the agent, for example the `env` block of the Claude Code settings file or the shell profile.

| Variable | Effect |
| --- | --- |
| `AGENT_SAFEGUARDS_REQUIRE_RTK` | `1` makes safe-tool deny a command that the `rtk` CLI would rewrite, on Claude Code and Codex, so the agent reruns it through `rtk`. On Claude Code the plugin setting `require_rtk` does the same (`claude plugin install agent-safeguards@abdessalllam --config require_rtk=true`). Check it with `safe-tool status rtk`. Off by default. |
| `AGENT_SAFEGUARDS_LOCAL_ONLY` | Claude Code only. Names of machine-local files, separated by `:`. A force-add or `safe-tool git commit` that would newly track one asks the user first. A trailing `/` marks a folder. Default: `CLAUDE.local.md`. Set it empty to turn the check off. |
| `AGENT_SAFEGUARDS_AUTO_EXCLUDE` | `1` adds the files above to the repository's local `.git/info/exclude` at session start (Claude Code). Off by default. |
| `AGENT_SAFEGUARDS_BLOCK_ATTRIBUTION` | `1` makes `safe-tool git commit` reject `Co-authored-by:` and `Generated-by:` trailers. Off by default. |
| `AGENT_SAFEGUARDS_FAIL_OPEN` | `1` lets a command through when a hook hits an internal error or `python3` is missing. By default those cases block. |
| `AGENT_SAFEGUARDS_LOCALE` | Message catalog to use, from the `locales` folder. Default: `en`. |

The hooks only guard the shell tool. File-read tools are not covered, so pair this plugin with a secret scanner or permission deny rules for those.

## 5. Optional Codex rules

Codex can also refuse listed commands before they run, even with the sandbox off. The plugin ships rule files under `extras/codex-rules/`. Copying them into `~/.codex/rules/` is the user's call, so show the command and let them run it:

```sh
cp extras/codex-rules/delete-guard.rules extras/codex-rules/identity.rules ~/.codex/rules/
```
