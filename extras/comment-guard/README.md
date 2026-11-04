# comment-guard (optional, off by default)

A small Rust program that keeps coding agents from flooding code with comments. It runs as a `PreToolUse` hook for Claude Code (`Edit`, `Write`, `MultiEdit`) and Codex (`apply_patch`), reads the text an edit is about to add, and refuses the call with a reason when the new comments break the rule. The agent then retries with fewer comments.

It is a quality guard, not a security guard. It is **off** until you turn it on, it is not part of the plugin's default hooks, and it fails open: bad input, an internal error or an oversized payload allow the call and print one line on stderr.

## The rule

At most one short rationale comment per file and per tool call, and never narration, history, dates or decision numbers.

| Limit | Value |
| --- | --- |
| New comment lines per file | 2 |
| New comment blocks per file | 1 (a block is a run of adjacent comment lines) |
| Length of a comment line | 100 characters, counted on the trimmed line |
| History markers | a date `YYYY-MM-DD`, a decision number such as `D556`, or one of `previously`, `used to`, `no longer`, `was already`, `originally`, `formerly`, `this change`, `as requested` |

A comment already present in the old text is not new, so moving code together with its comment, or editing the code under it, is never refused. Only whole-line comments count.

These are never counted: a shebang, a PHP `#[attribute]`, and comments that start with a lint, type, license or tooling directive (`noqa`, `type:`, `pragma`, `pylint:`, `eslint-`, `@ts-`, `go:`, `nolint`, `spdx-license-identifier`, `copyright`, `license`, `shellcheck`, `region`, `mark:`, `-*-` and similar; the full list is `EXEMPT` in `src/comments.rs`).

Languages are chosen by file extension: `#` comments for `py pyi rb sh bash zsh fish pl pm r ex exs nim cr`, `//` and `/* */` for `rs go js jsx mjs cjs ts tsx java kt kts swift c h cc cpp cxx hpp hh cs dart scala groovy gradle m mm zig proto sol`, both for `php`, and `--` for `lua sql hs elm`. Markdown, JSON, YAML, TOML and other files are not checked.

## Build and install

Needs a Rust toolchain (1.90 or newer). The one dependency, `serde_json`, is pinned to an exact version in `Cargo.lock`.

```sh
cargo install --path extras/comment-guard --locked --root ~/.local
comment-guard --version
```

`--root ~/.local` puts the program in `~/.local/bin`, which must be on the `PATH` of your agent's hooks (or write the full path in the hook command below).

## Turn it on

Either of these switches the guard on; with neither, `comment-guard hook ...` exits at once without reading anything.

```sh
export AGENT_SAFEGUARDS_COMMENT_GUARD=1                    # this shell, or an env block of a project's settings
mkdir -p ~/.config/agent-safeguards && touch ~/.config/agent-safeguards/comment-guard   # everywhere
comment-guard check
```

`XDG_CONFIG_HOME` replaces `~/.config` when it is set to an absolute path. Remove the file (or unset the variable) to turn the guard off.

## Register the hook

The hook files here are not wired in by default. Merge one into your own settings, next to the plugin's hooks.

- **Claude Code:** add the entry of `hooks/claude.json` to `hooks.PreToolUse` in `~/.claude/settings.json` (or a project's `.claude/settings.json`).
- **Codex:** add the entry of `hooks/codex.json` to `hooks.PreToolUse` in `~/.codex/hooks.json`, then approve the new hook in Codex.
- **Grok** reads the Claude Code settings, so the Claude registration covers it.

## Limits

- The check is per tool call. An agent that is refused nine comment lines can still add them in several small edits of two lines each, and every one of those edits passes. This was seen in a live Claude Code run. The guard slows the flood down and tells the agent the rule; it does not make the limit absolute.
- Comments after code on the same line are not counted, and neither are docstrings (they are strings). An agent that is refused comments may move the text into a docstring.
- `MultiEdit` is handled, but current Claude Code versions no longer offer that tool.
- `NotebookEdit` is not checked.
- The Codex `apply_patch` handling follows the public patch grammar and is covered by payload tests; it has not been run inside a live Codex session.

## Develop

```sh
cd extras/comment-guard
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

The deny text lives in `locales/en.json` under `comment_guard.*` and is compiled into the program. Change a message there and rebuild.
