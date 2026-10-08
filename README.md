<div align="center">

# 🛡️ Agent Safeguards

**Shell-command guardrails for Claude Code and Codex.**<br>
Keep credentials out of the transcript. Keep deletes away from your drive.

[![self-test](https://github.com/abdessalllam/agent-safeguards/actions/workflows/test.yml/badge.svg)](https://github.com/abdessalllam/agent-safeguards/actions/workflows/test.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Claude Code](https://img.shields.io/badge/Claude%20Code-supported-D97757?style=flat-square)
![Codex](https://img.shields.io/badge/Codex-supported-000000?style=flat-square)
![Platforms: macOS and Linux](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey?style=flat-square)
![Dependencies: standard library only](https://img.shields.io/badge/dependencies-stdlib%20only-success?style=flat-square)
![Network: none](https://img.shields.io/badge/network-none-success?style=flat-square)
![Telemetry: none](https://img.shields.io/badge/telemetry-none-success?style=flat-square)

[Quick start](#quick-start) · [What it does](#what-it-does) · [Install](#install) · [Verify](#verify) · [Settings](#settings) · [Limits](#what-it-does-not-do) · [Security policy](SECURITY.md)

<table>
  <tr>
    <td align="center" width="33%"><b>🔐 Secrets stay out</b><br>Blocks commands that print identity or credentials, and withholds output that holds a secret.</td>
    <td align="center" width="33%"><b>🧯 Drives stay safe</b><br>Refuses recursive deletes outside the repository and temp folders.</td>
    <td align="center" width="33%"><b>🪶 Small and local</b><br>Python standard library only. No network, no telemetry, no account.</td>
  </tr>
</table>

</div>

---

## Contents

- [Overview](#overview)
- [Quick start](#quick-start)
- [What it does](#what-it-does)
  - [safe-tool](#safe-tool)
  - [delete-guard](#delete-guard)
- [What it does not do](#what-it-does-not-do)
- [Install](#install)
  - [Claude Code](#claude-code)
  - [Codex](#codex)
  - [From a local clone](#from-a-local-clone)
  - [Already wired by hand?](#already-wired-by-hand)
- [Verify](#verify)
- [Settings](#settings)
  - [Force agents to use RTK (optional)](#force-agents-to-use-rtk-optional)
- [Troubleshooting](#troubleshooting)
- [How it works](#how-it-works)
- [Development](#development)
- [License](#license)

---

## Overview

Shell-command guardrails for Claude Code and Codex. Two small hooks check every shell command an agent runs:

- **safe-tool** keeps identity and credential data out of the transcript. It blocks commands that print it and withholds output that contains it.
- **delete-guard** stops deletes that could wipe a drive. It blocks recursive deletes outside the current repository and temp folders.

Everything runs locally. There is no network access, no telemetry, and no account. The only dependency is `python3` (standard library only), plus `git` for the Git features.

## Quick start

Needs macOS or Linux with `python3` (3.9 or newer) and `git`. Pick your host:

```sh
# Claude Code
claude plugin marketplace add abdessalllam/agent-safeguards
claude plugin install agent-safeguards@abdessalllam

# Codex
codex plugin marketplace add abdessalllam/agent-safeguards
codex plugin add agent-safeguards@abdessalllam
```

Start a new session, then ask the agent to run `whoami >/dev/null 2>&1`. If it comes back blocked, the hooks are live. The [Install](#install) section has details, updating, and the Codex Desktop setting, and [Verify](#verify) has the full probe list.

## What it does

### safe-tool

Before a command runs, safe-tool blocks it if it would print who you are or what you hold:

- has no effect on tokens, but I'd still recommend using it along with a plugin like RTK. They work together great.
- identity and account commands: `whoami`, `env`, `printenv`, `git config`, `git var GIT_AUTHOR_IDENT`, `gh auth ...`, `aws sts get-caller-identity`, `gcloud auth ...`, `az account ...`, `kubectl config ...`, `security find-identity`, `gpg --list...`, `ssh-add -l`, and any tool's `status`, `doctor`, `whoami`, or `auth` subcommand;
- secret-bearing flags such as `--token`, `--password`, `--api-key`;
- commands that print what the shell holds: `alias`, `type`, `whence`, `where`, `functions`, `declare` with `-f` or `-p`, and bare `export`, `readonly` and `set`. An alias or function can carry a host, a key path or a password. `which` and `command -v` still run, and any output that shows an alias or function definition is withheld;
- reading shell startup and history files: `~/.zshrc`, `~/.zshenv`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zsh_history`, `~/.bash_history`, the fish config folder and similar, whatever the command (`cat`, `grep`, `sed`, `< file`, `cp`). They hold exported keys, aliases and typed passwords. `source ~/.zshrc` and `. ~/.zshrc` still work to reload one, and `ls`, `stat`, `test` and `wc` still work on them. To ask whether a key is set, use `safe-tool has-key NAME` (below);
- credential paths such as `~/.ssh/`, `~/.aws/credentials`, `~/.netrc`, `~/.npmrc`, and dotenv files, plus well-known secret file names anywhere (private keys such as `id_rsa` and `id_ed25519`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `kubeconfig`, `credentials.json`, `service-account*.json`, `secrets.yml`, Terraform state and `*.tfvars`, `.pgpass`, `.git-credentials`). Public keys (`*.pub`) and files ending in `.example`, `.sample`, `.template`, or `.dist` are left alone;
- Git history commands that print author details, unless the last format option is a safe one.

It looks through variable prefixes (`FOO=1 cmd`), shell keywords, and the wrappers `sudo`, `env`, `time`, `nice`, `nohup`, `timeout`, `exec`, `stdbuf`, and `command`, and it checks each line of a multi-line command. A bare `env`, or `env` with only options and variables, prints the environment and is blocked; `env FOO=1 ./build.sh` is fine. It also checks the body of every `$(...)`, backtick and `<(...)` substitution, even inside double quotes.

`rtk proxy <tool>` is allowed only for the text tools `awk`, `cat`, `cmp`, `diff`, `du`, `find`, `git`, `grep`, `head`, `ls`, `nl`, `rg`, `sed`, `sort`, `stat`, `tail`, `uniq`, and `wc`. Tools that reshape text so the output scanner can no longer recognise a secret in it (`tr`, `cut`, `rev`, `fold`, `od`, `base64`) and pagers that can hang an agent (`less`, `more`) stay refused. For any other tool the refusal says to run the command without `rtk proxy`, or as `rtk <tool>`: `rtk proxy python3 build.py` is refused, while `python3 build.py` and `rtk python3 build.py` are fine. Reading a file with `rtk proxy cat` is allowed, but the same protections still apply: credential files such as `.env` or `~/.ssh/` are refused before `cat` runs, and any output that holds a secret-shaped value or a real email address is withheld.

Output that shows a private network address is withheld as well: `10.x`, `172.16` to `172.31`, `192.168`, `169.254` and `100.64/10` addresses, and IPv6 link-local (`fe80`), unique-local (`fc00::/7`) and global (`2000::/3`) addresses. A remote machine reports its own addresses in ordinary output (`ip addr`, `hostname -I`, a dev server's network URL), and they are infrastructure details. The Android emulator's fixed `10.0.2.x` and `10.0.3.2` are not touched. Set `AGENT_SAFEGUARDS_SHOW_ADDRESSES=1` to turn this off.

After a command runs, safe-tool withholds the output if it contains a real email address, a secret-shaped value (private key header, JWT, cloud and forge tokens, `password=` style assignments), or a labeled identity field from an account-style command. The agent sees a placeholder instead of the value.

It also ships a small command surface for the things it blocks:

```sh
safe-tool git identity                        # configured | identity_missing | not_repository
safe-tool git commit -m "subject" -m "body"   # commits what is staged, prints JSON only
safe-tool status coderabbit                   # ready | unauthenticated | unavailable
safe-tool has-key OPENAI_API_KEY GITHUB_TOKEN # OPENAI_API_KEY=pass and GITHUB_TOKEN=fail, never the value
safe-tool self-test
```

### delete-guard

Before a command runs, delete-guard refuses:

- recursive `rm`, `find ... -delete` or `-exec rm`, and `rsync --delete` whose target is outside the current repository, worktree, or a temp folder;
- your home folder and its top-level folders, system folders, and mount points, wherever you are, and the root and `.git` of the repository you are working in;
- recursive targets built from variables, command substitution, a bare glob, or a glob followed by `..`;
- `xargs rm`, `git clean` (except a `-n` dry run), inline `rmtree` or `rmSync` code, `dd` onto a device, and disk-erase commands such as `mkfs.*`, `newfs_*`, and `diskutil erase...`.

Temp folders are exempt from all of this, even when a repository lives inside one, so scratch clones can be cleaned up. The temp root itself is not: `rm -rf /tmp` and `rm -rf /tmp/*` are refused, while `rm -rf /tmp/agent-probe-*` is fine. `cd` is followed only when the target exists and the command has no grouping; otherwise relative delete targets are refused because the folder is unknown.

Every refusal says what to do instead: `git worktree remove <path>` for a worktree, the Trash for everything else.

## What it does not do

Read this before relying on it.

- It guards the **shell tool only**. File-read tools are not covered, so pair it with a secret scanner or permission deny rules for those. I love/Use and Recommend using [agent-guard](https://github.com/JeongJaeSoon/agent-guard) from JeongJaeSoon, that covers file reads, writes, and prompts. It works alongside this plugin and is not bundled here (It is a Independent project and not related to this repo in anyway).
- It parses commands heuristically. It is a safety net against mistakes and prompt injection, not a sandbox, and a determined agent can find commands it does not recognize.
- **A hook that times out or crashes before answering does not block the command.** This is how both hosts work. The hooks catch their own internal errors and block in that case, and the launcher blocks when `python3` is missing, but a host-level timeout still lets the command through.
- The settings below are plain environment variables. An agent that can change your environment or your agent settings file can change them, so protect those files the way you protect the hooks themselves.
- Windows is not supported.

## Install

Requires macOS or Linux with `python3` (3.9 or newer, standard library only) and `git`. Install it into the host or hosts you use. 
For Windows Users, Clone the Repo and ask your agent to convert it for you. It would take a few minutes and you'd be good to go.

### Claude Code

```sh
claude plugin marketplace add abdessalllam/agent-safeguards
claude plugin install agent-safeguards@abdessalllam
```

Inside a session the same two steps are `/plugin marketplace add abdessalllam/agent-safeguards` and `/plugin install agent-safeguards@abdessalllam`. Then start a new session, or run `/reload-plugins`, so the hooks load.

The plugin installs for your user account by default. To enable it for one repository only, add `--scope project` (recorded in the repository's shared settings) or `--scope local` (recorded in your local settings for that repository) to the install command.

Claude Code puts the plugin's `bin/` folder on the shell `PATH`, so the agent can run `safe-tool` and `delete-guard` by name.

Update or remove it:

```sh
claude plugin update agent-safeguards@abdessalllam
claude plugin uninstall agent-safeguards@abdessalllam
claude plugin marketplace remove abdessalllam
```

### Codex
If you are using Codex Desktop, you must go to settings -> Hooks and make sure the tool is enabled.

```sh
codex plugin marketplace add abdessalllam/agent-safeguards
codex plugin add agent-safeguards@abdessalllam
```

Then start a new Codex session. Plugins that contain lifecycle hooks install manually like this, and are not eligible for the public plugin directory. Codex keeps approval state for each hook, so if the probes under Verify are not blocked, check that Codex has approved this plugin's hooks, then restart the session.

Update or remove it:

```sh
codex plugin marketplace upgrade abdessalllam
codex plugin remove agent-safeguards@abdessalllam
codex plugin marketplace remove abdessalllam
```

Codex can also refuse listed commands before they run, even with the sandbox off. Optional rule files live in `extras/codex-rules/`. Copy them from a clone of the repository:

```sh
cp extras/codex-rules/delete-guard.rules extras/codex-rules/identity.rules ~/.codex/rules/
```

### From a local clone

```sh
git clone https://github.com/abdessalllam/agent-safeguards.git
claude plugin marketplace add ./agent-safeguards
claude plugin install agent-safeguards@abdessalllam
codex plugin marketplace add ./agent-safeguards
codex plugin add agent-safeguards@abdessalllam
```

Run the Claude Code lines, the Codex lines, or both. Leave the folder where it is, because both hosts read the marketplace from it. To update, run `git pull` in the folder, then start a new Claude Code session (or run `/reload-plugins`), and for Codex run `codex plugin remove agent-safeguards@abdessalllam` followed by `codex plugin add agent-safeguards@abdessalllam` again. `codex plugin marketplace upgrade` only works on Git marketplaces.

### Already wired by hand?

If your settings already call `safe-tool` or `delete-guard` hooks directly, remove those entries after installing the plugin. Otherwise every command is checked twice.

## Verify

Synthetic checks prove the policy, not that your host runs the hooks. Do the live probes first. In a new session, ask the agent to run these two harmless commands. The first sends its output to `/dev/null`, so nothing is printed even if the hook is not running:

| Command | Expected |
| --- | --- |
| `whoami >/dev/null 2>&1` | Blocked with `Sensitive-output command blocked`. |
| `rm -rf ~/agent-safeguards-probe-does-not-exist` | Blocked with `Delete guard:`. |

If either one runs instead of being blocked, the host is not running the hooks. Check that the plugin is enabled (Claude Code: `claude plugin list`; Codex: `codex plugin list`), then start a new session.

To check the policy itself, ask the agent to run `safe-tool self-test` and `delete-guard self-test` (Claude Code), or run them from a clone, in a Git repository that is not inside a temp folder:

```sh
python3 -I bin/safe-tool self-test      # {"status":"self_test_passed","tool":"safe-tool"}
python3 -I bin/delete-guard self-test   # "status": "self_test_passed"
```

The bundled `setup-agent-safeguards` skill walks the agent through this, and the `command-guards` skill teaches it the safe rewrite for every block.

## Settings

Settings are environment variables, read on every call. Set them where the agent starts, for example the `env` block of the Claude Code settings file or your shell profile.

| Variable | Effect |
| --- | --- |
| `AGENT_SAFEGUARDS_REQUIRE_RTK` | `1` makes safe-tool ask the [`rtk`](https://github.com/rtk-ai/rtk) CLI (`rtk rewrite`) about every command and deny the ones RTK would rewrite, so the agent reruns them through `rtk`. Works on Claude Code and Codex. On Claude Code it is also the `require_rtk` plugin setting (see below). Off by default. |
| `AGENT_SAFEGUARDS_LOCAL_ONLY` | Claude Code only, because Codex has no pre-tool `ask` decision. File or folder names, separated by `:`. A force-add or `safe-tool git commit` that would newly track one asks you first. A trailing `/` marks a folder. Default: `CLAUDE.local.md`. Empty turns it off. |
| `AGENT_SAFEGUARDS_AUTO_EXCLUDE` | `1` adds those names to the repository's local `.git/info/exclude` at session start (Claude Code only). Off by default. |
| `AGENT_SAFEGUARDS_BLOCK_ATTRIBUTION` | `1` makes `safe-tool git commit` reject `Co-authored-by:` and `Generated-by:` trailers. Off by default. |
| `AGENT_SAFEGUARDS_FAIL_OPEN` | `1` lets a command through when a hook hits an internal error or `python3` is missing. By default those cases block. |
| `AGENT_SAFEGUARDS_SHOW_ADDRESSES` | `1` stops safe-tool from withholding output that shows private network addresses. Off by default, so addresses stay hidden. |
| `AGENT_SAFEGUARDS_LOCALE` | Message catalog from the `locales` folder. Default: `en`. |

### Force agents to use RTK (optional)

[RTK](https://github.com/rtk-ai/rtk) shrinks command output before it reaches the model. This switch makes the plugin enforce it: when a command is one RTK would rewrite, safe-tool denies it with `RTK is required for this supported shell command. Rerun it through rtk.` and the agent reruns it as `rtk <command>`. Commands RTK does not rewrite are left alone, and so are commands that already start with `rtk`. It needs `rtk` installed, and it is off until you turn it on.

On Claude Code it is a plugin setting. Turn it on when you install, or run the install command again with a new value to change it:

```sh
claude plugin install agent-safeguards@abdessalllam --config require_rtk=true
```

Codex has no plugin settings screen, so set the environment variable where Codex starts, for example `export AGENT_SAFEGUARDS_REQUIRE_RTK=1` in your shell profile. The variable also works on Claude Code.

Check that it is on and that RTK works:

```sh
safe-tool status rtk     # {"enforcement":"on","status":"ready","tool":"rtk"}
```

`status` is `ready`, `unavailable` (rtk is not installed), or `operation_failed`. If `rtk` is missing, or does not answer in time, the switch does nothing and commands run normally. This is deliberate: RTK saves tokens, it is not a security control, so a broken `rtk` never blocks your work.

## Troubleshooting

When the launcher cannot start a hook it exits with code 2, which blocks the command, and prints a machine code on stderr:

| Code | Cause |
| --- | --- |
| `error=python3_not_found` | No `python3` on the hook's `PATH`. Install Python 3. |
| `error=hook_failed` | The tool crashed before it could answer, for example on a broken install. Reinstall the plugin. |
| `error=unknown_tool`, `error=unknown_runtime` | A hook file was edited. Restore the shipped one. |

## How it works

```text
host (Claude Code or Codex)
  PreToolUse  Bash -> scripts/hook.sh -> bin/safe-tool    hook <host>   deny or ask
                   -> scripts/hook.sh -> bin/delete-guard hook <host>   deny
  PostToolUse Bash -> scripts/hook.sh -> bin/safe-tool    hook <host>   withhold output
```

- Each manifest points at its own hook file (`hosts/claude/hooks.json`, `hosts/codex/hooks.json`), so neither host loads the other's.
- `scripts/hook.sh` runs the tool with `python3 -I`, which ignores `PYTHON*` variables and user site packages.
- Git and RTK are looked up in a fixed list of system folders, never in the agent's `PATH`.
- Every user-facing message lives in `locales/en.json`. To add a language, copy the file, translate the values, and keep the keys and `{placeholders}` identical.

## Development

Each tool carries a self-test of its policy. Run both from a Git repository that is not inside a temp folder:

```sh
python3 -I bin/safe-tool self-test
python3 -I bin/delete-guard self-test
```

After a change to a manifest or hook file, also run `claude plugin validate . --strict`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
