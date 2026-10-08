# Changelog

## 0.1.0

First release.

- safe-tool: blocks commands that print identity or credential data, withholds output that contains it, and provides `git identity`, `git commit`, and `status coderabbit`. It looks through variable prefixes, shell keywords and wrappers, checks every line of a multi-line command, catches relative credential paths, and judges Git log formats by the last format option.
- delete-guard: blocks recursive deletes outside the current repository and temp folders, plus disk-erase commands (`mkfs.*`, `newfs_*`, `dd` onto a device). It refuses glob-plus-`..` targets, understands wrapper and `xargs` options, and does not trust a `cd` it cannot follow.
- Both hooks block on unreadable or oversized input and on internal errors, and the launcher blocks when the tool crashes.
- When `rtk proxy` is the only reason a command is refused, the refusal now says so and names the fix. Both tools re-run themselves in isolated Python mode when started directly.
- Optional RTK enforcement: the `require_rtk` plugin setting on Claude Code, or `AGENT_SAFEGUARDS_REQUIRE_RTK` on any host, denies commands that `rtk rewrite` would change. `safe-tool status rtk` reports readiness and whether it is on.
- Plugin for Claude Code and Codex with a fail-closed launcher.
- Skills `command-guards` and `setup-agent-safeguards`.
- Optional Codex rule files under `extras/codex-rules/`.
- Message catalog in `locales/en.json`.
- Settings through `AGENT_SAFEGUARDS_*` environment variables.
