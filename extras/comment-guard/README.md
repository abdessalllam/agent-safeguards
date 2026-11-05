# comment-guard (optional, off by default)

A small Rust program that keeps coding agents from flooding code with comments. It runs as a `PreToolUse` hook for Claude Code (`Edit`, `Write`, `MultiEdit`) and Codex (`apply_patch`), works out the whole file the edit would leave, and refuses the call with a reason when the comments the session has added to that file break the rule. The agent then retries with fewer comments. A `PostToolUse` hook on `Bash` (with a `PreToolUse` entry that notes when each command starts) reports files that a command wrote with too many comments.

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

Only the net increase counts. A comment you reword or rename replaces one that was there, so renaming a word in 200 comments adds none. Lines the file gained beyond the lines it lost count; a line longer than 100 characters counts only when the comments it replaced were not that long; and a date, decision number or history phrase counts only when the replaced comments did not already contain it.

These are never counted: a shebang, a PHP `#[attribute]`, and comments that start with a lint, type, license or tooling directive (`noqa`, `type:`, `pragma`, `pylint:`, `eslint-`, `@ts-`, `go:`, `nolint`, `spdx-license-identifier`, `copyright`, `license`, `shellcheck`, `region`, `mark:`, `-*-` and similar; the full list is `EXEMPT` in `src/comments.rs`).

Languages are chosen by file extension: `#` comments for `py pyi rb sh bash zsh fish pl pm r ex exs nim cr`, `//` and `/* */` for `rs go js jsx mjs cjs ts tsx java kt kts swift c h cc cpp cxx hpp hh cs dart scala groovy gradle m mm zig proto sol`, both for `php`, `--` for `lua sql hs elm`, `<!-- -->` with `//` and `/* */` for `html htm xhtml vue svelte astro`, and `/* */` for `css` (plus `//` for `scss sass less`). Data, configuration and documentation files are not checked: Markdown, JSON, YAML, TOML, XML, INI and the like.

## Upstream and vendored files

Mark the paths of code you did not write in a `.gitattributes` file and the guard leaves them alone, in the edit hook and in the `Bash` check:

```
upstream/** comment-guard=skip
third_party/** linguist-vendored
generated/** linguist-generated
```

`comment-guard=skip` is this program's own mark; `linguist-vendored` and `linguist-generated` are the conventions GitHub uses, so a path that is already marked for them is skipped too. Git decides what a mark covers (patterns, nesting, `.git/info/attributes`), the mark has to be in a repository, and a file that is not marked is judged as before. The check only runs when the guard is about to refuse something, so ordinary edits do not pay for it. A marked file is skipped as a whole, comments an agent adds to it included, and an agent can add the mark itself (it shows in the diff).

## Across several edits

The first time a session touches a file, the hook records the comments that file already had (under `$XDG_STATE_HOME/agent-safeguards/comment-guard`, or `~/.local/state/agent-safeguards/comment-guard`), and every later `Edit`, `Write` or `apply_patch` of that file in the same session is judged against that record. Two-line edits therefore cannot add up to more than two lines, while moving or keeping existing comments stays free. A new file starts from an empty record. Records are written once, never rewritten, and deleted after 14 days. The record is keyed by the `session_id` in the hook payload (Claude Code and Codex both send it); without one, each call is judged alone. If the file is not in a state the guard has seen (you edited it yourself, a merge or `git checkout` changed it), the record is rebuilt from the file as it is then, so comments somebody else added never count against the agent; the record remembers the last eight states it saw.

## Commands that write files

A command's writes (`printf ... > file`, `sed -i`, `tee`, a script) cannot be stopped in advance, so the `PostToolUse` hook on `Bash` looks afterwards. It looks at the source files the command names and the source files under the working folder, keeps only those whose content or status changed since the command started (reading a file changes nothing; the `PreToolUse` entry for `Bash` records the start time under the command's `tool_use_id`, and without one the hook uses the previous check in that folder, or the last 60 seconds for the first), and judges each against the session's record, else against the last commit (`git show HEAD:`, with a size and time limit, and skipped when `git` cannot answer), else, for a file that did not exist before the command, against an empty file. Whichever baseline it uses is recorded, so a later edit of the same file is judged against it too. A violation answers `{"decision":"block","reason":...}` so the agent is told to shorten the comments; it cannot undo the write. Files whose first lines say `generated` or `do not edit` are skipped, as are hidden folders, `node_modules`, `target`, `dist`, `build` and similar; the check stops after 40 files, 4000 folder entries or 3 seconds, and does not walk the home folder or `/`. Each working folder keeps its own check time. A command that only runs git (`merge`, `pull`, `checkout`, `rebase`, `stash`, `add`, `commit` and similar, joined by `&&`, `;` or pipes into read-only tools such as `head`, with no redirect, here-document or substitution) is not judged, because it can only bring in commits; the files it changed get a fresh record. A file outside any git repository is not looked up with git at all.

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

- A patch with very many or very large sections stops being judged once its work budget is spent (64 MiB of text, 2000 hunks, 5 million search steps), and so does a `MultiEdit` that spends the budget: the call is allowed.
- The `Bash` check reports after the fact. It sees only the files a command names and the recently changed source files under the working folder, so a script that writes somewhere else is missed. Outside a git repository, an existing file that the session never touched cannot be judged on its first change by a command (its comments are recorded for the next check).
- JavaScript and TypeScript regex literals are skipped when they follow an operator or opening bracket, so a backtick or quote inside one does not open a string; a regex literal in another position can still be misread.
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
cargo test --locked    # needs git: the Bash-check tests build small repositories
cargo clippy --locked --all-targets -- -D warnings
```

The deny text lives in `locales/en.json` under `comment_guard.*` and is compiled into the program. Change a message there and rebuild.
