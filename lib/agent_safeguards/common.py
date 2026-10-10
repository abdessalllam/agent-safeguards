"""Shared helpers for the agent-safeguards hooks."""

from __future__ import annotations

import json
import os
import pwd
import re
import shlex
import sys
from dataclasses import dataclass
from typing import Any


# Containers often run as a user with no passwd entry, so the lookup falls back to the environment.
def _home_directory() -> str:
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        home = os.environ.get("HOME") or os.sep
    return os.path.realpath(home)


# The plugin root is derived from this file so the hooks never depend on a host-provided variable.
PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
USER_HOME = _home_directory()
DEFAULT_LOCALE = "en"
LOCALE_NAME = re.compile(r"[A-Za-z0-9_-]{1,32}")
TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})
# These directories are fixed so an agent-controlled PATH can never select the Git or RTK binary.
TRUSTED_DIRS = (
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/usr/sbin",
    "/sbin",
    os.path.join(USER_HOME, ".local", "bin"),
)
TRUSTED_PATH = ":".join(TRUSTED_DIRS)

ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.DOTALL)
DURATION = re.compile(r"[0-9.]+[smhd]?")
COMMAND_BOUNDARY = " \t\n;&|("
OPERAND_END = " \t\n;&|<>()"
REDIRECTION_SUFFIX = "&|-"
REDIRECTION_MARKER = "\x1f"
OPENING_QUOTE_MARKER = "\x01"
MAX_HEREDOCS = 16
MAX_HEREDOC_NESTING = 8
HEREDOC_DELIMITER_END = " \t\n;&|()<>"
MAX_SPLIT_STRING_EXPANSIONS = 64
MAX_COMMAND_CHARS = 256 * 1024
GIT_VALUE_OPTIONS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--attr-source"}
)
SHELL_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"})
DIRECTORY_OPTIONS = {
    "env": frozenset({"-C", "--chdir"}),
    "sudo": frozenset({"-D", "--chdir", "-R", "--chroot"}),
}
SPLIT_STRING_OPTIONS = frozenset({"-S", "--split-string"})
# Each wrapper lists the options that take a separate value, so the value is not mistaken for the command.
WRAPPER_VALUE_OPTIONS = {
    "builtin": frozenset(),
    "caffeinate": frozenset({"-t", "-w"}),
    "command": frozenset(),
    "env": frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "exec": frozenset({"-a"}),
    "gtimeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "nohup": frozenset(),
    "rtk": frozenset(),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "sudo": frozenset(
        {
            "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U",
            "--user", "--group", "--host", "--prompt", "--close-from", "--chdir", "--chroot",
            "--command-timeout", "--other-user",
        }
    ),
    "time": frozenset({"-f", "-o", "--format", "--output"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
}

_catalogs: dict[str, dict[str, str]] = {}


def _catalog(locale: str) -> dict[str, str]:
    if locale not in _catalogs:
        path = os.path.join(PLUGIN_ROOT, "locales", locale + ".json")
        try:
            with open(path, encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, ValueError):
            loaded = {}
        _catalogs[locale] = loaded if isinstance(loaded, dict) else {}
    return _catalogs[locale]


def message(key: str, **values: object) -> str:
    locale = os.environ.get("AGENT_SAFEGUARDS_LOCALE", DEFAULT_LOCALE)
    if not LOCALE_NAME.fullmatch(locale):
        locale = DEFAULT_LOCALE
    template = _catalog(locale).get(key) or _catalog(DEFAULT_LOCALE).get(key) or key
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in TRUTHY_VALUES


def env_list(name: str) -> list[str] | None:
    if name not in os.environ:
        return None
    return [entry for entry in os.environ[name].split(os.pathsep) if entry]


def fail_open() -> bool:
    return env_flag("AGENT_SAFEGUARDS_FAIL_OPEN")


def find_executable(name: str) -> str | None:
    for directory in TRUSTED_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


class UnresolvableCommand(Exception):
    pass


def _closing_quote(command: str, index: int) -> int | None:
    quote = command[index]
    index += 1
    while index < len(command) and command[index] != quote:
        index += 2 if command[index] == "\\" and quote == '"' else 1
    return index if index < len(command) else None


def _skip_quoted(command: str, index: int) -> int:
    closing = _closing_quote(command, index)
    return len(command) if closing is None else closing + 1


def _skip_operand(command: str, index: int) -> int:
    length = len(command)
    while index < length and command[index] in " \t":
        index += 1
    if index < length and command[index] == "(":
        return index
    while index < length and command[index] not in OPERAND_END:
        if command[index] in "'\"":
            index = _skip_quoted(command, index)
        else:
            index += 2 if command[index] == "\\" else 1
    return min(index, length)


def _drop_descriptor(kept: list[str]) -> None:
    digits = 0
    while digits < len(kept) and len(kept[-1 - digits]) == 1 and kept[-1 - digits].isdigit():
        digits += 1
    if digits and (digits == len(kept) or (len(kept[-1 - digits]) == 1 and kept[-1 - digits] in COMMAND_BOUNDARY)):
        del kept[len(kept) - digits :]


# The text is rewritten with a quote-aware pass, so a quoted ">" or "#" stays an ordinary word while an unquoted
# comment, redirection, file-descriptor prefix and escaped newline are removed before the command is split.
# Each removed redirection leaves a marker word, because a redirection that fails stops its command from running.
def normalize_command(command: str) -> str:
    length = len(command)
    kept: list[str] = []
    index = 0
    at_word_start = True
    while index < length:
        character = command[index]
        if character in "'\"":
            end = _skip_quoted(command, index)
            kept.append(command[index:end])
            index, at_word_start = end, False
        elif character == "\\":
            if command[index + 1 : index + 2] != "\n":
                kept.append(command[index : index + 2])
                at_word_start = False
            index += 2
        elif character == "#" and at_word_start:
            while index < length and command[index] != "\n":
                index += 1
        elif character == "&" and command[index + 1 : index + 2] == ">":
            index += 1
        elif character in "<>":
            _drop_descriptor(kept)
            end = index
            while end < length and command[end] in "<>":
                end += 1
            if end < length and command[end] in REDIRECTION_SUFFIX:
                end += 1
            index = _skip_operand(command, end)
            kept.append(" " + REDIRECTION_MARKER + " ")
            at_word_start = True
        else:
            kept.append(character)
            at_word_start = character in COMMAND_BOUNDARY
            index += 1
    return "".join(kept)


# What the shell would expand: quoted spans and comments become a space, an escaped character becomes an underscore and an
# escaped newline disappears. Redirections stay, unlike in normalize_command, because their operands can name files too.
def unquoted_text(command: str) -> str:
    length = len(command)
    kept: list[str] = []
    index = 0
    at_word_start = True
    while index < length:
        character = command[index]
        closing = _closing_quote(command, index) if character in "'\"" else None
        if closing is not None:
            kept.append(" ")
            index, at_word_start = closing + 1, False
        elif character == "\\":
            if command[index + 1 : index + 2] != "\n":
                kept.append("_")
                at_word_start = False
            index += 2
        elif character == "#" and at_word_start:
            while index < length and command[index] != "\n":
                index += 1
        else:
            kept.append(character)
            at_word_start = character in COMMAND_BOUNDARY
            index += 1
    return "".join(kept)


# A quote can pair with one in a later line (an apostrophe in a here-document body), which would blank the lines between
# them, so checks that must not miss a command look at each line on its own.
def unquoted_lines(command: str) -> list[str]:
    return [unquoted_text(line) for line in command.replace("\\\n", "").split("\n")]


# The same text with each opening quote replaced by a marker of equal length, so a pattern can tell a quote that opens a
# string from one that closes it without changing any offset.
def mark_opening_quotes(command: str) -> str:
    length = len(command)
    kept: list[str] = []
    index = 0
    while index < length:
        character = command[index]
        closing = _closing_quote(command, index) if character in "'\"" else None
        if closing is not None:
            kept.append(OPENING_QUOTE_MARKER + command[index + 1 : closing + 1])
            index = closing + 1
        elif character == "\\":
            kept.append(command[index : index + 2])
            index += 2
        else:
            kept.append(character)
            index += 1
    return "".join(kept)


# One here-document: where its marker sits, which logical line holds it, and the span of its body and terminator line.
# `outer` is set when the marker is inside a command substitution: (start of the enclosing logical line, index of the
# `$(`, the double quote it sits in or an empty string).
@dataclass(frozen=True)
class HereDocument:
    line_start: int
    marker_start: int
    delimiter_end: int
    line_end: int
    body_start: int
    body_end: int
    end: int
    quoted: bool
    outer: tuple[int, int, str] | None


def _read_delimiter(command: str, index: int) -> tuple[str, bool, int] | None:
    length = len(command)
    pieces: list[str] = []
    quoted = False
    while index < length and command[index] not in HEREDOC_DELIMITER_END:
        character = command[index]
        if character in "'\"":
            closing = _closing_quote(command, index)
            if closing is None:
                return None
            pieces.append(command[index + 1 : closing])
            quoted, index = True, closing + 1
        elif character == "\\":
            if index + 1 >= length:
                return None
            pieces.append(command[index + 1])
            quoted, index = True, index + 2
        else:
            pieces.append(character)
            index += 1
    return "".join(pieces), quoted, index


# The shell ends a body at the first line that equals the delimiter (after leading tabs for <<-), so this stops no later
# than the shell does and never hides a line the shell would run.
def _find_terminator(command: str, start: int, delimiter: str, strip_tabs: bool) -> tuple[int, int] | None:
    length = len(command)
    position = start
    while position < length:
        newline = command.find("\n", position)
        line_end = length if newline == -1 else newline
        line = command[position:line_end]
        if (line.lstrip("\t") if strip_tabs else line) == delimiter:
            return position, (length if newline == -1 else newline + 1)
        if newline == -1:
            return None
        position = newline + 1
    return None


def _read_bodies(command: str, newline: int, pending: list, found: list) -> int:
    position = newline + 1
    documents = []
    for line_start, marker_start, delimiter_end, delimiter, strip_tabs, quoted, outer in pending:
        located = _find_terminator(command, position, delimiter, strip_tabs)
        if located is None:
            return newline + 1
        terminator_start, end = located
        documents.append(HereDocument(line_start, marker_start, delimiter_end, newline, position, terminator_start, end, quoted, outer))
        position = end
    found.extend(documents)
    return position


def _scan_double_quoted(command: str, index: int, found: list, depth: int, line_start: int) -> int:
    length = len(command)
    while index < length:
        character = command[index]
        if character == "\\":
            index += 2
        elif character == '"':
            return index + 1
        elif command.startswith("$(", index):
            index = _scan_code(command, index + 2, True, found, depth + 1, (line_start, index, '"'))
        elif character == "`":
            index = _closing_backtick(command, index + 1) + 1
        else:
            index += 1
    return length


def _scan_code(command: str, index: int, nested: bool, found: list, depth: int, outer: tuple[int, int, str] | None) -> int:
    length = len(command)
    if depth > MAX_HEREDOC_NESTING:
        return length
    line_start = index
    pending: list = []
    parentheses = 0
    while index < length:
        character = command[index]
        if character == "\n":
            newline = index
            index += 1
            if pending:
                index = _read_bodies(command, newline, pending, found)
                pending = []
            line_start = index
        elif character == "'":
            closing = _closing_quote(command, index)
            index = length if closing is None else closing + 1
        elif character == '"':
            index = _scan_double_quoted(command, index + 1, found, depth, line_start)
        elif character == "\\":
            index += 2
        elif character == "`":
            index = _closing_backtick(command, index + 1) + 1
        elif character == "#" and (index == line_start or command[index - 1] in " \t;&|("):
            while index < length and command[index] != "\n":
                index += 1
        elif command.startswith("$(", index):
            index = _scan_code(command, index + 2, True, found, depth + 1, (line_start, index, ""))
        elif character == "(":
            parentheses += 1
            index += 1
        elif character == ")":
            if nested and parentheses == 0:
                return index + 1
            parentheses = max(parentheses - 1, 0)
            index += 1
        elif command.startswith("<<<", index):
            index += 3
        elif command.startswith("<<", index):
            cursor = index + 2
            strip_tabs = command.startswith("-", cursor)
            cursor += 1 if strip_tabs else 0
            while cursor < length and command[cursor] in " \t":
                cursor += 1
            parsed = _read_delimiter(command, cursor)
            if parsed is None or not parsed[0]:
                index += 2
            else:
                delimiter, quoted, delimiter_end = parsed
                # Inside plain parentheses the body can feed a process substitution or a subshell, which this scan
                # does not follow, so such a marker gets an outer that never qualifies as data.
                pending.append((line_start, index, delimiter_end, delimiter, strip_tabs, quoted, outer if parentheses == 0 else (-1, -1, "")))
                index = delimiter_end
        else:
            index += 1
    return length


# Every here-document whose terminator line is found, in the order of their bodies. A marker the scan cannot place with
# certainty (inside quotes, a comment, an unterminated body) is left out, so its lines stay ordinary code.
def heredocs(command: str) -> list[HereDocument]:
    found: list[HereDocument] = []
    _scan_code(command, 0, False, found, 0, None)
    found.sort(key=lambda document: document.body_start)
    return found if len(found) <= MAX_HEREDOCS else []


# Inside an unquoted here-document the quotes are plain characters, but `$(...)` and backticks still run.
def body_substitutions(body: str) -> list[str]:
    bodies: list[str] = []
    length = len(body)
    index = 0
    while index < length:
        character = body[index]
        if character == "\\":
            index += 2
        elif character == "`":
            end = _closing_backtick(body, index + 1)
            bodies.append(body[index + 1 : end])
            index = end + 1
        elif body.startswith("$(", index):
            depth, cursor = 1, index + 2
            while cursor < length and depth:
                if body[cursor] == "\\":
                    cursor += 2
                    continue
                depth += (body[cursor] == "(") - (body[cursor] == ")")
                cursor += 1
            bodies.append(body[index + 2 : cursor - 1] if depth == 0 else body[index + 2 :])
            index = cursor if depth == 0 else length
        else:
            index += 1
    return bodies


def _closing_parenthesis(command: str, start: int) -> int:
    depth = 1
    quote = ""
    index = start
    while index < len(command):
        character = command[index]
        if character == "\\" and quote != "'":
            index += 1
        elif quote:
            quote = "" if character == quote else quote
        elif character in "'\"":
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(command)


def _closing_backtick(command: str, start: int) -> int:
    index = start
    while index < len(command):
        if command[index] == "\\":
            index += 1
        elif command[index] == "`":
            return index
        index += 1
    return len(command)


# Substitutions run as commands even inside double quotes, so their bodies are pulled out for the same checks.
# Single quotes hold literal text, so nothing inside them runs.
def command_substitutions(command: str) -> list[str]:
    bodies: list[str] = []
    length = len(command)
    quote = ""
    index = 0
    while index < length:
        character = command[index]
        if quote == "'":
            quote = "" if character == "'" else quote
            index += 1
        elif character == "\\":
            index += 2
        elif character == "'" and not quote:
            quote = "'"
            index += 1
        elif character == '"':
            quote = "" if quote == '"' else '"'
            index += 1
        elif character == "`":
            end = _closing_backtick(command, index + 1)
            bodies.append(command[index + 1 : end])
            index = end + 1
        elif command.startswith("$(", index) or (not quote and command[index : index + 2] in {"<(", ">("}):
            end = _closing_parenthesis(command, index + 2)
            bodies.append(command[index + 2 : end])
            index = end + 1
        else:
            index += 1
    return bodies


# A short bundle such as -Eu names each option, and the last one may take the next word as its value.
def option_names(option: str, value_options: frozenset[str]) -> tuple[list[str], bool]:
    if option.startswith("--"):
        name = option.split("=", 1)[0]
        return [name], name in value_options and "=" not in option
    names: list[str] = []
    letters = option[1:]
    for position, letter in enumerate(letters):
        names.append("-" + letter)
        if "-" + letter in value_options:
            return names, position == len(letters) - 1
    return names, False


# Both tools classify the command that actually runs, so assignments, shell keywords and wrappers come off first.
# The flag reports a wrapper option that changes the working or root directory for the command that follows.
def strip_wrappers_with_directory(words: list[str], keep: frozenset[str] = frozenset()) -> tuple[list[str], bool]:
    words = list(words)
    moved = False
    expansions = 0
    index = 0
    while index < len(words):
        word = words[index]
        base = os.path.basename(word)
        if ASSIGNMENT.fullmatch(word) or word in SHELL_KEYWORDS:
            index += 1
            continue
        if base not in WRAPPER_VALUE_OPTIONS or base in keep:
            break
        if base == "command":
            lookahead = []
            for candidate in words[index + 1 :]:
                if not candidate.startswith("-") or candidate == "--" or len(candidate) < 2:
                    break
                lookahead.append(candidate)
            if any(("v" in option[1:] or "V" in option[1:]) for option in lookahead if not option.startswith("--")):
                break
        index += 1
        if base == "rtk" and index < len(words) and words[index] == "proxy":
            index += 1
        value_options = WRAPPER_VALUE_OPTIONS[base]
        after_dashes = False
        while index < len(words):
            option = words[index]
            if option == "--" and not after_dashes:
                after_dashes = True
                index += 1
            elif not after_dashes and option.startswith("-") and len(option) > 1:
                names, takes_next = option_names(option, value_options)
                moved = moved or bool(DIRECTORY_OPTIONS.get(base, frozenset()) & set(names))
                if base == "env" and SPLIT_STRING_OPTIONS & set(names):
                    expansions += 1
                    if expansions > MAX_SPLIT_STRING_EXPANSIONS:
                        raise UnresolvableCommand
                    if option.startswith("--"):
                        attached = option.split("=", 1)[1] if "=" in option else None
                    else:
                        attached = option[1:].split("S", 1)[1] or None
                    consumed = 1
                    if attached is None and index + 1 < len(words):
                        attached, consumed = words[index + 1], 2
                    try:
                        expanded = shlex.split(attached or "")
                    except ValueError:
                        expanded = []
                    words[index : index + consumed] = expanded
                    continue
                index += 2 if takes_next else 1
            elif DURATION.fullmatch(option):
                index += 1
            else:
                break
    return words[index:], moved


def strip_wrappers(words: list[str], keep: frozenset[str] = frozenset()) -> list[str]:
    return strip_wrappers_with_directory(words, keep)[0]


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def emit_decision(decision: str, reason: str, event: str = "PreToolUse") -> None:
    emit(
        {
            "hookSpecificOutput": {
                "hookEventName": event,
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )
