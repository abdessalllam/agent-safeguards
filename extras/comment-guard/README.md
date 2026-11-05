# comment-guard (optional, off by default)

A small Rust program that keeps coding agents from flooding code with comments. It runs as a `PreToolUse` hook for Claude Code (`Edit`, `Write`, `MultiEdit`) and Codex (`apply_patch`), works out the whole file the edit would leave, and refuses the call with a reason when the comments the session has added to that file break the rule. The agent then retries with fewer comments. A `PostToolUse` hook on `Bash` (with a `PreToolUse` entry that notes when each command starts) reports files that a command wrote with too many comments, and `safe-tool git commit` runs the same rule on the files of the commit about to be made.

It is a quality guard, not a security guard. It is **off** until you turn it on, it is not part of the plugin's default hooks, and it fails open: bad input, an internal error or an oversized payload allow the call and print one line on stderr.

## The rule

At most one short rationale comment per file, and never narration, history, dates or decision numbers.

| Limit | Value |
| --- | --- |
| New comment lines per file | 2 (counted against the file as the session first saw it, see below) |
| New comment blocks per file | 1 (a block is a run of adjacent comment lines) |
| Length of a comment line | 100 characters, counted on the trimmed line |
| History markers | a date `YYYY-MM-DD`, a decision number such as `D556`, or one of `previously`, `used to`, `no longer`, `was already`, `originally`, `formerly`, `this change`, `as requested` |

A comment already present in the old text is not new, so moving code together with its comment, or editing the code under it, is never refused.

These count as comment lines: a whole-line comment, a comment after code on the same line (`x = 1  # why`, `run(); // why`, `{/* why */}`), every line of a block comment (`/* */`, `<!-- -->`, `{- -}`, `--[[ ]]`, Ruby `=begin`, Perl POD, Nim `#[ ]#`), and the text lines of a Python docstring or an Elixir `@doc`/`@moduledoc` heredoc. A comment marker inside a string (`"http://x"`, `'a # b'`), a triple-quoted value assigned to a variable, or a backtick string is data, not a comment. Several comments on one physical line count as one line, and each of them is still checked for history markers and length.

These are never counted: a shebang, a PHP `#[attribute]`, and comments that start with a lint, type, license or tooling directive (`noqa`, `type:`, `pragma`, `pylint:`, `eslint-`, `@ts-`, `go:`, `nolint`, `spdx-license-identifier`, `copyright`, `license`, `shellcheck`, `region`, `mark:`, `-*-` and similar; the full list is `EXEMPT` in `src/comments.rs`).

Languages are chosen by file extension: `#` comments for `py pyi rb sh bash zsh fish pl pm r ex exs nim cr`, `//` and `/* */` for `rs go js jsx mjs cjs ts tsx java kt kts swift c h cc cpp cxx hpp hh cs dart scala groovy gradle m mm zig proto sol`, both for `php`, `--` for `lua sql hs elm`, `<!-- -->` with `//` and `/* */` for `html htm xhtml vue svelte astro`, and `/* */` for `css` (plus `//` for `scss sass less`). Data, configuration and documentation files are not checked: Markdown, JSON, YAML, TOML, XML, INI and the like.

## Across several edits

The first time a session touches a file, the hook records the comments that file already had (under `$XDG_STATE_HOME/agent-safeguards/comment-guard`, or `~/.local/state/agent-safeguards/comment-guard`), and every later `Edit`, `Write` or `apply_patch` of that file in the same session is judged against that record. Two-line edits therefore cannot add up to more than two lines, while moving or keeping existing comments stays free. A new file starts from an empty record. Records are written once, never rewritten, and deleted after 14 days. The record is keyed by the `session_id` in the hook payload (Claude Code and Codex both send it); without one, each call is judged alone.

## Commands that write files

A command's writes (`printf ... > file`, `sed -i`, `tee`, a script) cannot be stopped in advance, so the `PostToolUse` hook on `Bash` looks afterwards. It looks at the source files the command names and the source files under the working folder, keeps only those whose content or status changed since the command started (reading a file changes nothing; the `PreToolUse` entry for `Bash` records the start time under the command's `tool_use_id`, and without one the hook uses the previous check in that folder, or the last 60 seconds for the first), and judges each against the session's record, else against the last commit (`git show HEAD:`, with a size and time limit, and skipped when `git` cannot answer), else, for a file that did not exist before the command, against an empty file. Whichever baseline it uses is recorded, so a later edit of the same file is judged against it too. A violation answers `{"decision":"block","reason":...}` so the agent is told to shorten the comments; it cannot undo the write, and `safe-tool git commit` refuses the result anyway. Files whose first lines say `generated` or `do not edit` are skipped, as are hidden folders, `node_modules`, `target`, `dist`, `build` and similar; the check stops after 40 files, 4000 folder entries or 3 seconds, and does not walk the home folder or `/`. Each working folder keeps its own check time.

## Commit-time check

`safe-tool git commit` runs `comment-guard tree <tree-id>` on the tree it is about to commit, when `comment-guard` is installed in one of safe-tool's trusted folders (`~/.local/bin` is one) and the guard is switched on. The program compares that tree with `HEAD` and applies the same rule to each source file: at most 2 new comment lines in 1 block per file in the whole commit, no history markers, no line over 100 characters. Many small edits that each passed the hook add up here.

- A refusal makes `safe-tool git commit` print `{"status":"comments_blocked","reason":"..."}`, exit 1 and create no commit. The agent shortens or removes the comments in the staged files and commits again.
- A comment already present in the old file is not new. A rename is followed only when git detects it (at least half of the file unchanged, and not more files than git's `diff.renameLimit`); a file moved and mostly rewritten counts as new.
- Nothing is checked while a merge, squash merge, cherry-pick, revert or rebase is in progress (the commit then holds other people's changes), for a file over 2 MiB or that is not UTF-8, for a path that holds a newline or is not valid UTF-8, or past 8 MiB of file content in one commit.
- Any failure (no `git`, an unreadable tree, a timeout) allows the commit; run by hand, the program says why on stderr. The same switch controls the hook and this check.

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

- **Claude Code:** add the `PreToolUse` and `PostToolUse` entries of `hooks/claude.json` to `hooks.PreToolUse` and `hooks.PostToolUse` in `~/.claude/settings.json` (or a project's `.claude/settings.json`). The `PreToolUse` matcher covers `Bash` as well as the edit tools.
- **Codex:** add the `PreToolUse` and `PostToolUse` entries of `hooks/codex.json` to `hooks.PreToolUse` and `hooks.PostToolUse` in `~/.codex/hooks.json`, then approve the new hooks in Codex.
- **Grok** reads the Claude Code settings, so the Claude registration covers it.

## Limits

- The commit-time check does not stop comments spread over several commits (each commit then adds two lines next to the earlier ones), and does not run for a commit made some other way.
- A patch with very many or very large sections stops being judged once its work budget is spent (64 MiB of text, 2000 hunks, 5 million search steps), and so does a `MultiEdit` that spends the budget: the call is allowed.
- The `Bash` check reports after the fact. It sees only the files a command names and the recently changed source files under the working folder, so a script that writes somewhere else is missed. Outside a git repository, an existing file that the session never touched cannot be judged on its first change by a command (its comments are recorded for the next check).
- The commit-time check also refuses a generated or vendored source file that is full of comments. The agent should tell you; turn the guard off for that commit.
- Line-based reading has limits: a heredoc body or a multi-line plain string (not triple-quoted or backtick) can hide or invent a trailing comment, a regex literal that contains ` // ` can read as a comment, and a triple-quoted string that begins a Python line inside brackets reads as a docstring. A bare one-line string statement is not counted as a docstring.
- A comment inside the `${ }` of a JavaScript or TypeScript template literal reads as part of the string and is not counted. Nested block comments are followed for Rust, Swift, Haskell and Elm, not for Kotlin or Scala.
- The `Bash` check cannot tell a command's writes from a change made at the same time by something else (the user's editor, a watcher, a build tool writing into the working folder): such a file can be reported.
- Embedded languages are read with the host file's rules (a `<script>` block in HTML gets `//` and `/* */`, not the language's own forms).
- `MultiEdit` is handled, but current Claude Code versions no longer offer that tool.
- `NotebookEdit` is not checked.
- The Codex `apply_patch` handling follows the public patch grammar and is covered by payload tests; it has not been run inside a live Codex session.

## Develop

```sh
cd extras/comment-guard
cargo test --locked    # needs git: the commit-time tests build small repositories
cargo clippy --locked --all-targets -- -D warnings
```

The deny text lives in `locales/en.json` under `comment_guard.*` and is compiled into the program. Change a message there and rebuild.
