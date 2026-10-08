# Changelog

## 0.1.0

First release.

- safe-tool: blocks commands that print identity or credential data, withholds output that contains it, and provides `git identity`, `git commit`, and `status coderabbit`. It looks through variable prefixes, shell keywords and wrappers, checks every line of a multi-line command, catches relative credential paths, and judges Git log formats by the last format option.
- delete-guard: blocks recursive deletes outside the current repository and temp folders, plus disk-erase commands (`mkfs.*`, `newfs_*`, `dd` onto a device). It refuses glob-plus-`..` targets, understands wrapper and `xargs` options, and does not trust a `cd` it cannot follow.
- Both hooks block on unreadable or oversized input and on internal errors, and the launcher blocks when the tool crashes.
- When `rtk proxy` is the only reason a command is refused, the refusal now says so and names the fix. Both tools re-run themselves in isolated Python mode when started directly.
- Output scanning is a single detector (`lib/agent_safeguards/secret_scan.py`) that favours false positives: token shapes for common providers, labelled values (`password`, `secret`, `token`, `api_key`, ...), and unlabelled high-entropy strings. Well-known secret file names are refused before the command runs. `rtk proxy` also allows `nl`, `sort`, and `uniq`.
- safe-tool refuses the printing forms of `alias`, `type`, `whence`, `where`, `functions`, `declare`/`typeset` (`-f`, `-F`, `-p`), `export`, `readonly` and bare `set`, and withholds output that shows an alias or function definition, so an alias that hides a host, a key path or a password is not read back to the agent.
- safe-tool refuses commands that read shell startup and history files (`.zshrc`, `.bashrc`, `.profile`, `.zsh_history` and similar) while still allowing `source` and metadata checks, and adds `safe-tool has-key NAME`, which prints `NAME=pass` or `NAME=fail` and never the value.
- safe-tool withholds output that shows a private network address (IPv4 private, link-local and shared ranges, IPv6 link-local, unique-local and global), except the Android emulator's fixed addresses. `AGENT_SAFEGUARDS_SHOW_ADDRESSES=1` turns it off.
- safe-tool also expands globs and braces when it looks for startup-file reads, keeps its metadata exemption for commands that run alone, checks the string given to `eval`, refuses `echo`, `printf` and `print` of secret-named variables, refuses environment dumps (`ps` environment flags, `/proc/<pid>/environ`, `launchctl getenv`, `$HISTFILE`), and refuses `git credential` and the password-manager and secret-store CLIs.
- Optional RTK enforcement: the `require_rtk` plugin setting on Claude Code, or `AGENT_SAFEGUARDS_REQUIRE_RTK` on any host, denies commands that `rtk rewrite` would change. `safe-tool status rtk` reports readiness and whether it is on.
- Plugin for Claude Code and Codex with a fail-closed launcher.
- Skills `command-guards` and `setup-agent-safeguards`.
- Optional Codex rule files under `extras/codex-rules/`.
- Optional simulator screenshot extras for Claude Code on macOS under `extras/simulator-screenshots/`: `sim-shot` saves a shrunk simulator screenshot as a new file and prints its path, and a hook holds the simulator control tool's crashing `screenshot` action for the user.
- Optional website screenshot extras under `extras/web-screenshots/`: `web-shot` saves an `http` or `https` page as a new PNG within fixed limits (1568 pixels, 1 MB) and prints its path, and a Claude Code hook refuses in-app browser and Chrome extension screenshots that do not ask for a scale of 0.5 or lower. The simulator extras share the same limits through `lib/agent_safeguards/screenshot.py`.
- Message catalog in `locales/en.json`.
- Settings through `AGENT_SAFEGUARDS_*` environment variables.
