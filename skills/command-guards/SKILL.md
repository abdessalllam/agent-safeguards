---
name: command-guards
description: Use when a shell command is blocked by safe-tool or delete-guard, or its output was withheld. Messages look like "Sensitive-output command blocked", "Delete guard:", or "[withheld: sensitive output]". Explains the safe rewrite for each block so the work can continue.
---

# Command guards

Two hooks check every shell command before it runs. safe-tool also checks the output after it ran.

- **safe-tool** blocks commands that print identity or credential data and withholds output that contains it, so it never reaches the transcript.
- **delete-guard** blocks deletes that could wipe data outside the current repository or a temp folder.

## A block is a rewrite signal, not a stop

1. Read the message and find its row below.
2. Rewrite the command so it is genuinely safe, then retry. Most blocks clear on the first rewrite.
3. Do not mark the task blocked or hand the command to the user just because a guard fired. Ask only in the cases under "When to ask the user".
4. Never disable, edit, or route around a guard: no hook or config changes, no hiding the command in base64, `eval`, a variable, or a throwaway script. The goal is a command that is safe, not one that slips past.
5. A command whose output was withheld still ran. Never rerun a command that changes state just to see its output.

## safe-tool: blocked before running

The message reads `Sensitive-output command blocked. Use safe-tool or ask the user to run it outside the agent.` Despite the wording, rewrite first. It fires for:

| Trigger | Rewrite |
| --- | --- |
| The command cannot be parsed (unbalanced quotes, often an apostrophe inside inline text or inside a heredoc that a shell or interpreter runs) | Write the script or text to a file with your file-editing tool, then run the file. Or remove the apostrophe. Text given to `cat`, `tee`, `gh` and similar through a quoted heredoc (`<<'EOF'`) in a plain command (no `if`, `case`, group, function, `$'..'` or `${..}`) is not affected. |
| A multi-line command, or a heredoc that a shell or interpreter runs or that is piped onward, with a line that looks like an identity command (each of those lines is checked as its own command) | Write the text to a file with your file-editing tool, or give it to `cat > file <<'EOF'` on its own line without a pipe. |
| `env`, alone or with only options and variables | `env` prints the environment. To run a program with a variable, put the program last: `env FOO=1 ./build.sh`. To check that a variable is set, see the next rows. |
| `git log` or `git show` without a safe format | `git log --oneline -n 20`, `git log --format=%h%x09%s`, `git log --format=%H%x09%ct%x09%s`; `git show --format= --stat <rev>`, `git show --format= <rev> -- <path>`. A file at a revision (`git show <rev>:<path>`) is never refused, because it prints content and no author. |
| `git commit` | `safe-tool git commit -m "<subject>" -m "<body>"` |
| `git config`, `git blame`, `git shortlog`, `git cat-file`, `git format-patch`, `git var GIT_AUTHOR_IDENT`, `git remote -v` or `get-url`, `rev-list --format`, `for-each-ref` with author fields | Identity check: `safe-tool git identity`. Remote names: `git remote`. Repository paths: `git rev-parse --show-toplevel`. A specific config value: ask the user. |
| Any tool's `status`, `doctor`, `whoami`, `auth`, `account`, `profile`, `user`, `org`, `credential(s)`, or `identity` subcommand, or `config get/list/show/view/dump/--list` (Git's own `status` is fine) | Check the effect instead: a file exists, a port answers, a build passes. |
| `env`, `printenv`, `whoami`, `users`, `groups`, `logname`, `finger`, or a flag such as `--token`, `--password`, `--secret`, `--api-key`, `--credential(s)`, `--client-secret`, `--private-key`, `--show-token` | To check that a variable is set without printing it: `[ -n "${NAME+x}" ] && echo present \|\| echo absent`. |
| A credential path anywhere in the command, even inside a search pattern: `/.ssh/`, `/.gitconfig`, `/.git/config`, `/.git/objects/`, `/.aws/credentials`, `/.netrc`, `/.npmrc`, `/.pypirc`, `/.kube/config`, `/.docker/config.json`, `/.config/gh/hosts.yml`, `/.gnupg/`, or a dotenv file name (the `.example`, `.sample`, `.template`, and `.dist` variants are fine) | Drop the mention. Never open these files. |
| `rtk proxy <tool>` for a tool outside the read-only set (`awk`, `cat`, `cmp`, `diff`, `du`, `find`, `git`, `grep`, `head`, `ls`, `nl`, `rg`, `sed`, `sort`, `stat`, `tail`, `uniq`, `wc`) | Run it plainly or as `rtk <tool>`. |
| A script named `safe-tool` that is not the installed one | Run `safe-tool` by its bare name. |
| `bash -c`, `sh -c`, `zsh -c` | The inner string is checked the same way; fix it there. |

## safe-tool: output withheld

The message reads `Sensitive command output was withheld.` (Claude Code shows `[withheld: sensitive output]`). The output contained one of:

- a real email address (anything except `example.com`, `example.net`, `example.org`, `example.test`, `localhost`), even one inside source code;
- a secret-shaped value: a private key header, a JWT, an `AKIA...` key, a `ghp_...`, `github_pat_...`, `glpat-...`, `npm_...`, `sk-...`, `xox...-`, or `sk_live_...` token, an `api_key=`, `access_token=`, or `password=` assignment, or `user:pass@` in a URL;
- a labeled `name=`, `user=`, `account=`, or `org=` field in the output of an account, auth, status, or doctor command.

Narrow the output and retry: list paths only (`rg -l`), count (`rg -c`), drop matching lines (`| rg -v '@'`), select fields with `jq`, or search for structure instead of values. Never print Git authors.

## safe-tool: commands

`safe-tool git commit -m "<subject>" -m "<body>"` commits what is staged and prints JSON. Run it from inside the repository or worktree. The message cannot be empty or over 16 KB and cannot contain an email address or a secret. When the operator enabled `AGENT_SAFEGUARDS_BLOCK_ATTRIBUTION`, it also cannot contain a `Co-authored-by:` or `Generated-by:` trailer.

| `status` | Meaning and next step |
| --- | --- |
| `committed` | Done. Check that `tree` matches the tree you scanned. |
| `committed_tree_changed` | The index changed during the commit; inspect `git show --format= --stat HEAD`. |
| `invalid_message` | Fix the message to fit the limits above and retry. |
| `no_staged_changes` | Stage the intended files first. |
| `not_repository` | `cd` into the repository or worktree. |
| `hook_failed` | A repository commit hook failed. Run that check yourself, fix the cause, and retry. Never skip hooks. safe-tool runs with a minimal `PATH`, so a hook that needs another tool can fail here; report that case. |
| `unmerged_changes` | Resolve the conflicts first. |
| `identity_missing`, `signing_failed` | Stop and tell the user; never set an identity or signing config. |
| `commit_failed`, `operation_failed`, `verification_failed` | Retry once, then report the status. |

- `safe-tool git identity` prints `configured`, `identity_missing`, or `not_repository` without showing the identity.
- `safe-tool status coderabbit` prints `ready`, `unauthenticated`, `unavailable`, `schema_mismatch`, or `operation_failed`.
- `safe-tool self-test` checks the policy itself.

Claude Code puts the plugin's `bin/` folder on the shell `PATH`, so `safe-tool` runs by its bare name. In other hosts, run it by its full path inside the plugin folder.

Two more decisions you may see:

- `RTK is required for this supported shell command. Rerun it through rtk.` appears only when the operator turned on the RTK requirement (the `require_rtk` plugin setting or `AGENT_SAFEGUARDS_REQUIRE_RTK`). Prefix the command with `rtk` and run it again.
- `Tracking a machine-local agent artifact requires explicit user approval.` means a force-add or commit would track a file the operator listed as machine-local. Unstage it instead. This check runs on Claude Code only.

## delete-guard

The refusal reads `Delete guard: <reason>.` It blocks:

- recursive `rm`, `find ... -delete` or `-exec rm`, and `rsync --delete` whose target is outside the current repository, worktree, or a temp folder. Your home folder, its top-level folders, system folders, mount points, and the temp roots themselves (`/tmp`, `/var/folders`) are always refused, and so are the root and `.git` of the repository you are working in. A repository that lives inside a temp folder is exempt;
- recursive targets built from variables (`$X`), command substitution, or a bare glob such as `*`;
- `xargs rm`, `git clean` (except a `-n` dry run), inline code that deletes folders recursively (`shutil.rmtree`, `fs.rmSync` with `recursive`), and disk-erase commands (`mkfs`, `shred`, `diskutil erase...`, `dd of=/dev/...`);
- a recursive delete of a Git worktree folder, outside temp folders;
- a glob before the last path component, a `dd` onto a device, and delete commands hidden behind `sudo`, `env`, `timeout`, or other wrappers.

Rewrites:

- A worktree: `git worktree remove <path>`, then `git branch -d <branch>`.
- Anything else: `trash <path>` on macOS, or `trash-put <path>` or `gio trash <path>` on Linux. These are recoverable.
- A variable or glob: resolve it first (`echo "$X"`, `ls`), check the literal path, and delete that path.
- Build output: prefer the build tool's own clean task.
- A deletion outside the allowed areas that is really needed: ask the user and name the exact path.

## When to ask the user

Only when:

- safe-tool reports `identity_missing` or `signing_failed`;
- the task really needs a credential, an identity value, or a delete outside the allowed areas;
- two honest rewrites still fail. Then report the exact guard message and what you tried, and keep working on everything else.
