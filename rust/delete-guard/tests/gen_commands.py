#!/usr/bin/env python3
"""Generate D3 command oracle records from the Python guard."""

import ast
import copy
import importlib.machinery
import itertools
import json
import os
from pathlib import Path
import random
import tempfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "commands.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_d3_commands", str(ROOT / "bin" / "delete-guard")).load_module()
ROWS = []


def describe(error):
    text = str(error)
    return "embedded null byte" if isinstance(error, ValueError) and "null" in text else text


def replace(value, root):
    if isinstance(value, str):
        return value.replace(root, "@ROOT@")
    if isinstance(value, (list, tuple)):
        return [replace(item, root) for item in value]
    return value


def record(name, args, root, remote=None, quoted=()):
    GUARD._REMOTE[0] = remote
    GUARD._QUOTED_WORDS[0] = frozenset(quoted)
    GUARD._PENDING_ASK[0] = None
    copied = copy.deepcopy(args)
    try:
        ret = getattr(GUARD, "_" + name)(*copied)
        exc = None
    except Exception as error:
        ret, exc = describe(error), type(error).__name__
    ROWS.append({"fn": name, "args": replace(args, root), "ret": replace(ret, root), "exc": exc,
                 "remote": remote, "quoted": replace(list(quoted), root), "ask": replace(GUARD._PENDING_ASK[0], root)})


def words(command):
    chunks = GUARD._tokenize(command)
    return chunks[0].words if chunks and chunks[0].words else []


with tempfile.TemporaryDirectory(prefix="d3-commands-") as temporary:
    root = os.path.realpath(temporary)
    for name in ["u", "u/Documents", "plain", "plain/inner", "pool", "pool/one", "pool/two", "holder", "holder/.Trash", "holder/.Trash/old", "other"]:
        os.makedirs(os.path.join(root, name), exist_ok=True)
    for name in ["plain/a", "pool/one/a", "pool/two/b", "other/f"]:
        Path(root, name).write_text("x")
    GUARD.USER_HOME = root + "/u"
    GUARD.TEMP_ROOTS = (root,)
    cwd = root

    for command in [
        "rm x", "rm -r plain", "rm -rf plain", "rm -d plain", "rm --recursive plain", "rm --rec plain",
        "rm --r plain", "rm --unknown plain", "rm --dir plain", "rm -- --recursive", "rm -r *",
        "rm -r pool/*", "rm -r holder", "rm -f pool/*/a", "rm /", "rm ../x", "rm x\x00y",
        "trash plain", "trash holder", "trash pool/*", "trash -e x", "trash --empty x", "trash --secure=x",
        "trash --trash-dir x plain", "trash --trash-dir / plain", "trash --trash-dir=x plain", "trash -- plain", "trash trash:/x",
        "trash '{plain,pool}'", "trash {plain,pool}", "trash $(echo x)", "trash `echo x`",
        "gio trash plain", "gio trash --empty", "gio remove plain/a", "gio rm /", "gio trash trash:/x",
        "mv plain/a holder/.Trash", "mv -t holder/.Trash plain/a", "mv --target-directory=holder/.Trash pool/*",
        "mv plain/a plain/inner", "mv -ft holder/.Trash plain/a", "mv --target-directory holder/.Trash plain/a",
    ]:
        parsed = words(command)
        if not parsed:
            continue
        name = GUARD._base(parsed[0])
        if name in {"rm", "trash", "gio", "mv"}:
            record(name, [parsed, cwd], root)
    for name in ["rm", "trash", "mv", "gio"]:
        record(name, [[name], cwd], root)
        record(name, [[name, "x\x00y"], cwd], root)
    for name, command in [
        ("rm", ["rm", "-rf", "~/ci/run"]), ("rm", ["rm", "-rf", "/tmp/run"]),
        ("trash", ["trash", "~/ci/run"]), ("trash", ["trash", "/outside/run"]),
        ("mv", ["mv", "~/ci/run", "~/ci/.Trash"]), ("gio", ["gio", "remove", "~/ci/run"]),
    ]:
        for roots in [["~/ci", "/tmp"], []]:
            record(name, [command, cwd], root, remote=roots)
    for command in [["trash", "pool/[lang]"], ["trash", "pool/*"], ["mv", "pool/[lang]", "holder/.Trash"]]:
        record(command[0], [command, cwd], root, quoted=[command[1]])
    for raw in ["", "plain", "holder", "pool/*", "trash:/x", "$(echo x)", "`echo x`", "x\x00y", "/", "holder/.Trash"]:
        for literal in [False, True]:
            record("trash_one", [raw, cwd, literal], root)
    for command in [
        ["gio", "trash", "x"], ["gio", "remove", "x"], ["kioclient", "rm"], ["kioclient5", "copy", "rm"],
        ["kioclient", "--", "delete"], ["kioclient", "-x", "rm"], [], ["rm"], ["sudo", "rm"],
        ["env", "A=1", "gio", "trash"], ["env", "-C", "other", "rm", "x"], ["xargs", "rm"], ["find", ".", "-delete"],
    ]:
        record("kio_command", [command], root)
        record("deletes_files", [command], root)
        record("moves_and_deletes", [command], root)
    for option in ["", "-c", "-ec", "-Cc", "--command", "--command=x", "-norc", "-o", "-oc", "-oerrexit", "+c", "-s", "-so", "-Cd", "-Cfoo", "-c🐟"]:
        record("is_short", [option], root)
        record("bundle_letters", [option, False], root)
        record("bundle_letters", [option, True], root)
        record("is_command_option", [option, False], root)
        record("is_command_option", [option, True], root)
        record("value_is_next", [option, False], root)
        record("value_is_next", [option, True], root)
    for fish in [False, True]:
        record("value_letters", [fish], root)
        for option_words in [[], ["-c", "echo x"], ["-s"], ["-o", "errexit", "script"], ["--command", "echo x"], ["-C", "echo x", "script"], ["--", "-s", "script"], ["script", "-c"], ["-so", "errexit"]]:
            record("shell_words", [option_words, fish], root)
    for command in [
        ["sh"], ["sh", "{}"], ["bash", "-c", "echo {}"], ["bash", "-e", "{}"],
        ["bash", "-s"], ["bash", "+s"], ["bash", "--", "{}"], ["fish", "--command", "echo {}"],
        ["fish", "-C", "echo x", "{}"], ["zsh", "-o", "errexit", "{}"], ["sudo", "sh", "{}"],
        ["env", "A=1", "bash"], ["echo", "{}"], [],
    ]:
        for appended in [False, True]:
            record("shell_gets_a_name", [command, "{}", appended], root)

    test_strings = set()
    for path in (ROOT / "tests").glob("test*.py"):
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith(("rm ", "trash ", "gio ", "mv ")):
                test_strings.add(node.value)
    for command in sorted(test_strings):
        parsed = words(command)
        if parsed and GUARD._base(parsed[0]) in {"rm", "trash", "gio", "mv"}:
            record(GUARD._base(parsed[0]), [parsed, cwd], root)
    rng = random.Random(0xD3C0)
    seeds = [["rm", "-rf", "pool/*"], ["trash", "pool/*"], ["mv", "plain/a", "holder/.Trash"], ["gio", "remove", "plain/a"]]
    alphabet = "ab/-*?[]{}$` \x00é"
    for _ in range(300):
        seed = copy.deepcopy(rng.choice(seeds))
        at = rng.randrange(len(seed))
        text = seed[at]
        pos = rng.randrange(len(text) + 1)
        seed[at] = text[:pos] + rng.choice(alphabet) + text[pos:]
        record(seed[0] if seed[0] in {"rm", "trash", "mv", "gio"} else "deletes_files", [seed, cwd] if seed[0] in {"rm", "trash", "mv", "gio"} else [seed], root)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(ROWS, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
print("command records", len(ROWS))

with (OUT.parent / "exhaustive_commands.txt").open("w", encoding="utf-8") as output:
    alphabet = "-+cCoO0f \n"
    for length in range(6):
        for letters in itertools.product(alphabet, repeat=length):
            option = "".join(letters)
            try:
                command_false = GUARD._is_command_option(option, False)
                command_true = GUARD._is_command_option(option, True)
            except IndexError:
                command_false = command_true = "IndexError"
            result = [GUARD._is_short(option), GUARD._bundle_letters(option, False), GUARD._bundle_letters(option, True),
                      command_false, command_true, GUARD._value_is_next(option, False), GUARD._value_is_next(option, True)]
            output.write(option.encode("utf-8").hex() + "\t" + json.dumps(result, separators=(",", ":")) + "\n")
