# Security policy

## Scope

Agent Safeguards is a defense-in-depth layer for shell commands run by coding agents. It reduces accidents and prompt-injection damage. It is not a sandbox, a secret manager, or a data-loss-prevention system.

## Known limits

These are design limits, not bugs. Please do not report them as vulnerabilities, but do help improve them.

- Output scanning catches accidental leaks, not deliberate evasion. A command that re-encodes or splits a secret (`base64`, `rev`, `tr`, `cut`, character-by-character output) hides it from the scanner, and a bare 40-character hex string with no label is not flagged because it looks like a Git hash. The scanner prefers false positives, so ordinary output is sometimes withheld too, and output it cannot finish checking within 3 seconds (the hook is killed at 5, which would let the output through) or that exceeds 1 MiB is withheld as well.
- Only the shell tool is checked. File-read, file-write, and network tools are outside this plugin.
- Command parsing is heuristic. Indirection the parser cannot see (obfuscated strings, generated scripts, here-document bodies run by a shell, inline shell in `xargs` or `find -exec`, tools that wrap other tools) can get past it.
- A hook that times out or is killed by the host does not block the command.
- Temp folders are exempt from delete-guard, including a repository that lives inside one.
- `cd` is tracked only for a simple, existing target. Grouped or failed `cd` leaves the folder unknown, and delete-guard then refuses relative targets.
- Each line of a multi-line command is checked as its own command, so a here-document whose text looks like an identity command can be blocked even though it only writes text.
- Codex has no pre-tool `ask` decision, so the local-artifact approval check runs on Claude Code only.
- Settings are environment variables, so anything that controls the agent's environment controls them.

## Reporting a vulnerability

Report a bypass that the documented behavior says should be blocked, or a way to make a hook run attacker-chosen code, through the repository's private vulnerability reporting (GitHub: Security, then Report a vulnerability). Do not open a public issue for it.

Include the host and version, the exact command, what was expected, and what happened. Use fake credentials in reports. Never send real secrets.

## Sample values

Build secret-shaped sample values by concatenation so scanners do not flag the repository.
