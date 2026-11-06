#!/usr/bin/env python3
"""Generate D4 remote and wrapper oracle vectors from the Python guard."""

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
OUT = Path(__file__).resolve().parent / "vectors" / "remote.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_d4_remote", str(ROOT / "bin" / "delete-guard")).load_module()
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


def record(name, args, root, *, remote=None, stdin=(), trusted=True):
    GUARD._REMOTE[0] = remote
    GUARD._REMOTE_TARGETS.clear()
    GUARD._STDIN_FILES[0] = list(stdin)
    GUARD._PENDING_ASK[0] = None
    copied = copy.deepcopy(args)
    try:
        if name == "check_chunk":
            result = GUARD._check_chunk(*copy.deepcopy(args), trusted=trusted)
        else:
            result = getattr(GUARD, "_" + name)(*copy.deepcopy(args))
        exception = None
    except Exception as error:
        result, exception = describe(error), type(error).__name__
    ROWS.append({"fn": name, "args": replace(copied, root), "ret": replace(result, root), "exc": exception,
                 "remote": remote, "stdin": replace(stdin, root), "trusted": trusted,
                 "targets": replace(GUARD._REMOTE_TARGETS, root), "stdin_after": replace(GUARD._STDIN_FILES[0], root),
                 "ask": replace(GUARD._PENDING_ASK[0], root)})


with tempfile.TemporaryDirectory(prefix="d4-remote-") as temporary:
    root = os.path.realpath(temporary)
    for name in ["u", "safe", "safe/sub", "holder", "holder/.Trash", "bin"]:
        (Path(root) / name).mkdir()
    (Path(root) / "safe" / "file").write_text("x")
    GUARD.USER_HOME = root + "/u"
    GUARD.TEMP_ROOTS = (root,)
    remote_options = [
        ["ssh", "host", "rm", "-rf", "~/ci/run"], ["ssh", "-p", "22", "host", "rm", "-rf", "~/ci/run"],
        ["ssh", "-p22", "host", "rm", "-rf", "~/ci/run"], ["ssh", "-Z", "host", "rm", "x"],
        ["ssh", "--", "host", "rm", "x"], ["ssh", "host", "--", "rm", "x"],
        ["ssh", "-o", "StrictHostKeyChecking=yes", "host", "rm", "x"],
        ["mosh", "--ssh=ssh", "host", "rm", "x"], ["mosh", "--port", "60001", "host", "rm", "x"],
        ["mosh", "--unknown", "host", "rm", "x"], ["mosh", "-p", "60001", "host", "rm", "x"],
        ["mosh", "--", "host", "rm", "x"], ["ssh_custom", "host", "rm", "x"],
        ["echo", "ssh", "host", "rm", "x"], ["ssh"], ["mosh"], [],
    ]
    for words in remote_options:
        record("remote_command_words", [words[0] if words else "", words], root)
    randomizer = random.Random(0xD4B2)
    alphabet = "46AaCfGgKkMNnqsTtVvXxYyBDEFIJLOPQRSWbceilmpwo-Z= 0\né"
    for _ in range(600):
        words = copy.deepcopy(randomizer.choice(remote_options[:12]))
        index = randomizer.randrange(len(words))
        word = words[index]
        at = randomizer.randrange(len(word) + 1)
        words[index] = word[:at] + randomizer.choice(alphabet) + word[at:]
        record("remote_command_words", [words[0], words], root)

    for operand in ["", ".", "safe", "safe/", "safe/file", "safe/*", "safe/sub", "holder", "~/ci/run", "/tmp/x", "host:/x", "host::module", "a b:/x", "a\nb:/x", "a\x1cb:/x", "x\x00y"]:
        for remote in [None, ["~/ci", "/tmp"]]:
            record("check_rsync_operand", [operand, root, "rsync --delete"], root, remote=remote)
    for words in [
        ["rsync", "src", "safe"], ["rsync", "--delete", "src", "safe"],
        ["rsync", "--delete-excluded", "src", "safe"], ["rsync", "--remove-source-files", "safe/file", "safe"],
        ["rsync", "--delete", "-e", "ssh", "src", "safe"],
        ["rsync", "--delete", "-e", "ssh", "src", "host:/tmp/x"],
        ["rsync", "--delete", "--exclude", "host:/etc", "src", "safe"],
        ["rsync", "--delete", "src", "~/ci/run"], ["rsync", "--remove-source-files", "host:/etc", "safe"],
        ["rsync", "--delete", "--remove-source-files", "safe/file", "safe"],
    ]:
        for remote in [None, ["~/ci", "/tmp"]]:
            record("rsync", [words, root], root, remote=remote)
    for value in ["", ".", "..", "safe", "safe/sub", "holder", "missing", "/", "~/ci", "$DIR", "$(pwd)", "x\x00y"]:
        for base in [None, root, root + "/safe"]:
            record("wrapper_directory", [value, base], root)
    for values in [[], ["safe"], ["safe", "sub"], ["missing"], ["", "safe"], ["safe", ""], ["$DIR", "safe"], ["safe", "x\x00y"]]:
        record("wrapper_directories", [values, root], root)

    commands = {
        "", "ls", "rm -rf ~/ci/run", "rm -rf ~", "rm -rf /tmp/x", "rm -rf /tmp",
        "rm -rf '~/ci/a b'", "rm -rf \\~/ci/run", "rm -rf ~/ci/../x", "gio trash ~/ci/run",
        "gio trash ~/ci/../x", "rsync --delete src ~/ci/run/", "rsync --delete src ~/",
        "find ~/ci/run -delete", "git clean -fdx", "echo rm -rf ~",
        "sudo rm -rf ~/ci/run", "bash -c 'rm -rf ~/ci/run'",
    }
    for file in (ROOT / "tests").glob("test*.py"):
        try:
            tree = ast.parse(file.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if text.startswith(("rm ", "gio ", "trash ", "rsync ", "find ", "ssh ", "mosh ", "sudo rm ", "bash -c ", "git clean ", "echo rm ")) and len(text) < 500:
                    commands.add(text)
    for text in sorted(commands):
        record("check_remote_command", [text], root)
    seeds = sorted(commands)
    for _ in range(500):
        text = randomizer.choice(seeds)
        at = randomizer.randrange(len(text) + 1)
        text = text[:at] + randomizer.choice("ab/-*?[]{}$'\"\\ \n\x00é") + text[at:]
        record("check_remote_command", [text], root)
    for words in [["echo", "okay"], ["rm", "-rf", "safe"], ["rm", "-rf", "/"], ["cd", "safe"], ["rsync", "--delete", "safe", "safe/sub"]]:
        for trusted in [False, True]:
            record("check_chunk", [words, root, " ".join(words)], root, trusted=trusted, stdin=[("safe/file", None)])

OUT.parent.mkdir(parents=True, exist_ok=True)
encoded = json.dumps(ROWS, ensure_ascii=True, separators=(",", ":"))
encoded = encoded.replace("/ho" "me/", "\\u002fhome\\u002f").replace("/Us" "ers/", "\\u002fUsers\\u002f")
OUT.write_text(encoded, encoding="utf-8")
print("remote records", len(ROWS))

with (OUT.parent / "exhaustive_remote.txt").open("w", encoding="utf-8") as output:
    alphabet = "-aZp=0\n "
    for size in range(6):
        for letters in itertools.product(alphabet, repeat=size):
            word = "".join(letters)
            for name in ["ssh", "mosh"]:
                words = [name, word, "host", "rm", "x"]
                try:
                    result = [GUARD._remote_command_words(name, words), None]
                except Exception as error:
                    result = [describe(error), type(error).__name__]
                output.write(name + "\t" + word.encode().hex() + "\t" + json.dumps(result, separators=(",", ":")) + "\n")
