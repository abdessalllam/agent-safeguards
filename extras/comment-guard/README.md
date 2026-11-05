# comment-guard (optional, off by default)

A small Rust program that keeps coding agents from flooding code with comments. It runs as a `PreToolUse` hook for Claude Code (`Edit`, `Write`, `MultiEdit`, `NotebookEdit`) and Codex (`apply_patch`), works out the whole file the edit would leave, and refuses the call with a reason when the comments the session has added to that file break the rule. The agent then retries with fewer comments. For a Claude Code `Write` or `Edit` whose extra comments can be cut safely, the hook does not refuse: it lets the edit through without them and tells the agent which lines were left out (see Trimming). A `PostToolUse` hook on `Bash` (with a `PreToolUse` entry that notes when each command starts) reports files that a command wrote with too many comments.

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

Only the net increase counts. A comment you reword or rename replaces one that was there, so renaming a word in 200 comments adds none. Lines the file gained beyond the lines it lost count; a line longer than 100 characters counts only when the comments it replaced were not that long; and a date, decision number or history phrase counts only when the replaced comments did not already contain it. Rewrapping a comment into more lines adds nothing as long as every word in the new lines comes from the comments it replaced (case and punctuation aside, no word more often than before) and the lines are a reflow, not padding (lines of about 24 letters are assumed, so a comment may grow by about one line per 24 letters); a rewrap that also changes a word is judged as a plain replacement (within a session, against the comments the file had when the session first touched it, so rewording a comment you already rewrapped is judged the same way); blank comment lines and comment delimiter lines (`//`, `/*`, `-->`, `----`) are never forgiven that way, but a line you remove offsets one you add. A word that merely contains a history word (`previously_cached`) is not a history phrase.

These are never counted: a shebang, a PHP `#[attribute]`, and tool directives (`noqa`, `type:`, `pragma`, `pylint:`, `eslint-`, `@ts-`, `go:`, `nolint`, `spdx-license-identifier`, `shellcheck`, `-*-` and similar; the full list is `EXEMPT` in `src/comments.rs`). A directive is exempt only while what follows it is its own arguments: `noqa` takes codes only (`E501`), `nolint` linter names, an SPDX line a license expression, `go:` one of the Go directives, and the others at most six arguments that look like codes or rule names (a digit, a hyphen, a slash, a bracket) plus at most two fixed words (`ignore`, `off`, `no cover`). Free text after the prefix (`# noqa: note one`, `# pragma: because ...`) is a comment and counts, as do `region`, `mark:`, `copyright` and `license` lines.

Languages are chosen by file extension, by whole name (`Makefile`, `Dockerfile`, `CMakeLists.txt`, `Jenkinsfile`, `Gemfile`, `Rakefile` and similar), or, for a file with no extension, by the interpreter on its `#!` line. Beyond the forms below, the table covers PowerShell (`#`, `<# #>`), Terraform and HCL, Make, Docker, CMake, Nix, Julia, batch files (`REM`, `::`), Visual Basic, Lisp and Clojure (`;`), Erlang (`%`), OCaml, F# and Pascal, Ada and VHDL (`--`), Fortran, Bazel (Starlark), Verilog, shader languages, SVG, and the ERB, Jinja, Handlebars, Razor and Pug templates (see `TABLE` and `NAMES` in `src/languages.rs`). The code cells of a `.ipynb` notebook are judged as Python, whether the notebook is written, edited as a file or changed with `NotebookEdit`; markdown cells are not. The forms: `#` comments for `py pyi rb sh bash zsh fish pl pm r ex exs nim cr`, `//` and `/* */` for `rs go js jsx mjs cjs ts tsx java kt kts swift c h cc cpp cxx hpp hh cs dart scala groovy gradle m mm zig proto sol`, both for `php`, `--` for `lua sql hs elm`, `<!-- -->` with `//` and `/* */` for `html htm xhtml vue svelte astro`, and `/* */` for `css` (plus `//` for `scss sass less`). Data, configuration and documentation files are not checked: Markdown, JSON, YAML, TOML, XML, INI and the like.

## Trimming

A refusal makes the agent send the whole file or edit again, which costs output. So for a Claude Code `Write` or `Edit` the hook first tries to repair the call: it keeps the first comment lines that fit the rule (at most two, in one block, short, without history markers), leaves out the other new comment lines, rewrites the tool input (`updatedInput`) and answers `allow` with a message (`additionalContext`) that names the lines it left out and says to add a comment again, within the limit, if the file really needs one. The code is written exactly as the agent wrote it; only the left-out lines are missing. The edit is judged again after the rewrite and the session record is settled on what was written.

Only whole-line comments of plain code are cut: a full line that starts with `#`, `//`, `--`, `;`, `%`, `REM` or `::`, or a one-line `/* ... */` or `<!-- ... -->`, and only lines the call added (a comment the file already had stays). Everything else is refused as before, with the reason: a trailing comment, a docstring, a multi-line block comment, a comment in a markup language (`//` in HTML, Vue, templates, Pug), a one-line block that carries meaning (`/*+ hint */`, `/*! */`, `<!--[if IE]>`, `<!--#include`), a comment line that ends in a backslash, a file the scanner cannot read with certainty (an unterminated string, a here-document, a raw or verbatim string, a cgo preamble, a line continuation, `__END__`), a partial or `replace_all` edit, a `MultiEdit`, a `NotebookEdit`, and a Codex `apply_patch`. A command that writes a file cannot be rewritten in advance, so the `Bash` check still only reports.

To get the refusal back (the agent then rewrites the call itself), set `AGENT_SAFEGUARDS_COMMENT_GUARD_TRIM=0`, or create an empty file `comment-guard-refuse` next to the `comment-guard` switch file.

## Upstream and vendored files

Mark the paths of code you did not write in a `.gitattributes` file and the guard leaves them alone, in the edit hook and in the `Bash` check:

```
upstream/** comment-guard=skip
third_party/** linguist-vendored
generated/** linguist-generated
```

`comment-guard=skip` is this program's own mark; `linguist-vendored` and `linguist-generated` are the conventions GitHub uses, so a path that is already marked for them is skipped too. Git decides what a mark covers (patterns, nesting, `.git/info/attributes`), the mark has to be in a repository, and a file that is not marked is judged as before. The check only runs when the guard is about to refuse something, so ordinary edits do not pay for it. A marked file is skipped as a whole, comments an agent adds to it included, and an agent can add the mark itself (it shows in the diff).

## Across several edits

The first time a session touches a file, the hook records the comments that file already had (under `$XDG_STATE_HOME/agent-safeguards/comment-guard`, or `~/.local/state/agent-safeguards/comment-guard`), and every later `Edit`, `Write` or `apply_patch` of that file in the same session is judged against that record. Two-line edits therefore cannot add up to more than two lines, while moving or keeping existing comments stays free. A new file starts from an empty record. Records are written once, never rewritten, and deleted after 14 days. The record is keyed by the `session_id` in the hook payload (Claude Code and Codex both send it); without one, each call is judged alone. If the file is not in a state the guard has seen (you edited it yourself, a merge or `git checkout` changed it), the record is rebuilt from the file as it is then, so comments somebody else added never count against the agent; the record remembers the last eight states it saw. A state counts as seen when its bytes or its set of comments match one of them, so a formatter or a line-ending change resets nothing. Two edits judged against the same file state within three seconds (a host that applies edits in parallel) share one allowance: each hook re-checks the shared note under a lock before it allows, and the same edit judged twice is counted once. Updates to a record are serialised with a lock file.

## Commands that write files

A command's writes (`printf ... > file`, `sed -i`, `tee`, a script) cannot be stopped in advance, so the `PostToolUse` hook on `Bash` looks afterwards. It looks at the source files the command names and the source files under the working folder, keeps only those whose content or status changed since the command started (reading a file changes nothing; the `PreToolUse` entry for `Bash` records the start time under the command's `tool_use_id`, and without one the hook uses the previous check in that folder, or the last 60 seconds for the first), and judges each against the session's record, else against the last commit (`git show HEAD:`, with a size and time limit, and skipped when `git` cannot answer), else, for a file that did not exist before the command, against an empty file. Whichever baseline it uses is recorded, so a later edit of the same file is judged against it too. A violation answers `{"decision":"block","reason":...}` so the agent is told to shorten the comments; it cannot undo the write. Files whose first lines say `generated` or `do not edit` are skipped, as are hidden folders, `node_modules`, `target`, `dist`, `build` and similar; the check stops after 40 changed files (files the command only names, and leaves unchanged, do not count against that), 4000 folder entries or 3 seconds, and does not walk the home folder or `/`. Each working folder keeps its own check time. A command made only of git commands that bring in commits (`merge`, `pull`, `checkout`, `switch`, `restore`, `reset`, `rebase`, `cherry-pick`, `revert`, `stash`, alone or with `add`, `commit`, `status`, `log` and read-only tools such as `head`, joined by `&&`, `;` or pipes, quotes respected) is not judged, because it can only bring in other people's work; the files it changed get a fresh record. It is judged like any other command when it has a redirect, here-document or substitution, an option that can run code (`-c` with any key but a few harmless ones, `--exec`, `--git-dir`, `--work-tree`), or a subcommand such as `submodule`, `checkout-index`, `read-tree`, `update-index`, `apply` or `am`. A command that only runs `git add` or `git commit` is judged like any other, because a hook may have written the files. A new file whose content equals, byte for byte, a file the command names and left unchanged (`cp a.py b.py`, `cp * dest/`, `cp vendor/*.py src/`, `cp -r . dest`, a quoted name with spaces, with or without a redirect, a named folder) is a copy, not new commentary, and its record starts from its own comments. Before a command runs, the source files it names, or finds under a folder it names, are compared with their record, so edits you made yourself first are not blamed on it. A file outside any git repository is not looked up with git at all.

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

- A quoted or escaped pattern (`\*.py`) is still expanded as a glob when the command is searched for copy sources, so a new file equal to an unchanged file the pattern matches is taken as a copy.
- A lock left by a crashed hook is broken after five seconds (a lock dated more than two seconds ahead of the clock at once); two hooks that break it at the very same moment can both enter, and until then every hook on that file waits for it, up to six seconds (the check before a command waits a quarter of a second and skips the refresh).
- A `mv` across file systems deletes its source before the check, so the moved file is judged as new; a glob is expanded only in the last path component, at most 64 glob words of a command are expanded, and the name lookup stops after one second before a command and one and a half seconds after it.
- Content planted in the git index or object store by earlier plumbing commands (`hash-object -w`, `update-index --cacheinfo`) and then brought in with `git checkout` or `git restore` is taken as other people's work.
- A formatter that changes the comments of more than 40 files in one command is not followed past the 40th file; the next edit of such a file starts from its comments as they are.
- The session record matches a file by bytes or by its set of comments, so replacing a file with other code that has the same comments keeps the old allowance.
- A file moved with `mv` keeps its birth time, so it is judged only when it has a record; writing comments into a file of an unchecked type and renaming it is not caught.
- A command that rewrites a file you edited yourself without naming it (a project-wide formatter) is judged against the older record.
- A git hook, alias or script that a history-importing git command runs can write comments unseen.
- Files over 8 MiB are not read: a `Write` to one is allowed and an `Edit` is judged from its own text. A file that is not UTF-8 is read with replacement characters.
- The rewrap allowance is about layout: a long comment may be laid out in up to one line per 24 letters of its own words, so a very long existing comment can be split into many short lines without counting, as long as no new word appears.
- Two edits that the host applies in parallel are judged against the same file state; they share one allowance only when both are judged within three seconds.
- A patch with very many or very large sections stops being judged once its work budget is spent (64 MiB of text, 2000 hunks, 5 million search steps), and so does a `MultiEdit` that spends the budget: the call is allowed.
- The `Bash` check reports after the fact. It sees only the files a command names and the recently changed source files under the working folder, so a script that writes somewhere else is missed. Outside a git repository, an existing file that the session never touched cannot be judged on its first change by a command (its comments are recorded for the next check).
- JavaScript and TypeScript regex literals are skipped when they follow an operator or opening bracket, so a backtick or quote inside one does not open a string; a regex literal in another position can still be misread.
- Line-based reading has limits: a heredoc body or a multi-line plain string (not triple-quoted or backtick) can hide or invent a trailing comment, a regex literal that contains ` // ` can read as a comment, and a triple-quoted string that begins a Python line inside brackets reads as a docstring. A bare one-line string statement is not counted as a docstring.
- A comment inside the `${ }` of a JavaScript or TypeScript template literal reads as part of the string and is not counted. Nested block comments are followed for Rust, Swift, Haskell and Elm, not for Kotlin or Scala.
- The `Bash` check cannot tell a command's writes from a change made at the same time by something else (the user's editor, a watcher, a build tool writing into the working folder): such a file can be reported.
- Embedded languages are read with the host file's rules (a `<script>` block in HTML gets `//` and `/* */`, not the language's own forms).
- `MultiEdit` is handled, but current Claude Code versions no longer offer that tool.
- A write that happens after the command has returned (a background job that sleeps first, a watcher) is not seen, and a hook that runs past its timeout (10 seconds for the edit hook, 20 for the `Bash` check in the sample files, which matters on a machine under very heavy load) lets the call through. A copy of a file that already has comments (`cp`, `mv`) is not new commentary.
- Trimming leaves the file as the agent wrote it except for the left-out lines, but the agent may still believe its comments are there: a later `Edit` that names a left-out line fails and has to read the file again.
- Rule names are an open vocabulary, so a directive such as `# type: ignore[some-name]` can carry one hyphenated word per argument; a sentence cannot pass.
- Racket `#;` (comment out the next datum), a `.ipynb` over 8 MiB edited as text, and a folder the command only names (a save by someone else in it during the command, when the command is not a plain look such as `ls`) are not handled or can be misread.
- A file with no extension, no known name and no `#!` line, or with an extension the table does not know, is not checked: the guard cannot tell it from notes or data.
- Prose in a string or a heredoc (`NOTES = """ ... """`) is data, not a comment, and is not counted.
- A command that writes through a variable the command does not set itself, or through a script that picks its own output path, is only seen when the file is under the working folder or named in the command.
- The Codex `apply_patch` handling follows the public patch grammar and is covered by payload tests; it has not been run inside a live Codex session.

## Develop

```sh
cd extras/comment-guard
cargo test --locked    # needs git: the Bash-check tests build small repositories
cargo clippy --locked --all-targets -- -D warnings
```

The deny text lives in `locales/en.json` under `comment_guard.*` and is compiled into the program. Change a message there and rebuild.
