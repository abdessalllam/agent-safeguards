#!/usr/bin/env python3
"""Generate D3 find and xargs oracle records from the Python guard."""

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
OUT = Path(__file__).resolve().parent / "vectors" / "find.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_d3_find", str(ROOT / "bin" / "delete-guard")).load_module()
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


def record(name, args, root, remote=None):
    GUARD._REMOTE[0] = remote
    GUARD._PENDING_ASK[0] = None
    GUARD._STDIN_FILES[0] = []
    original_check_chunk = GUARD._check_chunk
    delegated = []
    def observed_check_chunk(*values, **named):
        delegated.append(True)
        return original_check_chunk(*values, **named)
    GUARD._check_chunk = observed_check_chunk
    try:
        ret = getattr(GUARD, "_" + name)(*copy.deepcopy(args))
        exc = None
    except Exception as error:
        ret, exc = describe(error), type(error).__name__
    finally:
        GUARD._check_chunk = original_check_chunk
    if delegated:
        return
    ROWS.append({"fn": name, "args": replace(args, root), "ret": replace(ret, root), "exc": exc,
                 "remote": remote, "ask": replace(GUARD._PENDING_ASK[0], root)})


def words(command):
    chunks = GUARD._tokenize(command)
    return chunks[0].words if chunks and chunks[0].words else []


with tempfile.TemporaryDirectory(prefix="d3-find-") as temporary:
    root = os.path.realpath(temporary)
    for name in ["u", "safe", "safe/nested", "holder", "holder/.Trash", "plain"]:
        os.makedirs(os.path.join(root, name), exist_ok=True)
    Path(root, "safe/nested/a").write_text("x")
    GUARD.USER_HOME = root + "/u"
    GUARD.TEMP_ROOTS = (root,)
    cwd = root

    for command in [
        "find", "find .", "find safe -delete", "find holder -delete", "find / -delete",
        "find -L safe -delete", "find -H safe -delete", "find safe -follow -delete",
        "find -f safe -delete", "find -f safe -f holder -name x -delete", "find -D tree safe -delete",
        "find -O2 safe -delete", "find -files0-from roots -delete", "find safe -files0-from roots -delete",
        "find safe -name -delete", "find safe -neweram x -delete", "find safe -fprintf out %p -delete",
        "find safe -exec rm {} \\;", "find safe -exec rm {} +", "find safe -exec rm + {} \\;",
        "find safe -exec trash {} \\;", "find safe -exec gio remove {} \\;",
        "find safe -exec sh {} \\;", "find safe -exec sh -c 'echo x' _ {} \\;",
        "find safe -exec env -C other rm {} \\;", "find safe -exec find {} -delete \\;",
        "find safe -maxdepth 0 -exec trash {} \\;", "find safe -maxdepth 0 -exec gio trash {} \\;",
        "find safe -execdir rm {} \\;", "find safe -okdir trash {} \\;",
        "find safe -exec echo {}.bak \\;", "find safe -exec echo x \\;",
        "find safe -exec rsync --delete {} dest \\;", "find safe -exec xargs rm \\;",
        "find safe -delete -exec echo x \\;", "find safe -name x -delete",
    ]:
        parsed = words(command)
        if not parsed:
            continue
        record("find_parts", [parsed], root)
        record("find_deleting", [parsed], root)
        record("find", [parsed, cwd], root)
        record("deletes_from_names", [parsed], root)
    for parsed in [["find", "-H", "safe", "-delete"], ["find", "-L", "safe", "-delete"], ["find", "-files0-from", "roots", "-delete"]]:
        record("find", [parsed, cwd], root, remote=["/tmp"])
    for command in [
        "xargs rm", "xargs sudo rm -rf", "xargs gio trash", "xargs gio remove",
        "xargs kioclient rm", "xargs find -delete", "xargs rsync --delete",
        "xargs -a names sh", "xargs -I % sh %", "xargs -I % sh -c 'echo %'",
        "xargs bash -s", "xargs bash -c 'echo x'", "xargs -o sh -s",
        "xargs -a names echo", "xargs echo", "xargs -I % echo %", "xargs -r -n1 rm",
        "xargs --replace=% rm %", "xargs --arg-file names echo", "xargs --arg-file=names echo",
        "xargs --unknown echo", "xargs --max-procs=2 echo", "xargs -z echo",
        "xargs -rIXX find XX -delete", "xargs -ra names sh -s", "xargs -e echo",
        "xargs -i echo {}", "xargs -I echo", "xargs -- echo x", "xargs",
    ]:
        parsed = words(command)
        if parsed:
            record("xargs", [parsed, cwd], root)
    for command in [["rsync", "--delete"], ["rsync", "--remove-source-files"], ["sudo", "find", ".", "-delete"], ["env", "find", ".", "-print"], ["echo"], [], ["find", "-exec", "rm", "{}", "+"]]:
        record("deletes_from_names", [command], root)

    test_strings = set()
    for path in (ROOT / "tests").glob("test*.py"):
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith(("find ", "xargs ")):
                test_strings.add(node.value)
    for command in sorted(test_strings):
        parsed = words(command)
        if parsed and parsed[0] == "find":
            record("find_parts", [parsed], root)
            record("find_deleting", [parsed], root)
            record("find", [parsed, cwd], root)
        elif parsed and parsed[0] == "xargs":
            record("xargs", [parsed, cwd], root)

    rng = random.Random(0xD3F1)
    alphabet = "ab/-*?[]{};+! \x00é"
    seeds = [["find", "safe", "-delete"], ["find", "safe", "-exec", "rm", "{}", ";"], ["xargs", "-r", "rm"], ["xargs", "-I", "%", "echo", "%"]]
    for _ in range(350):
        parsed = copy.deepcopy(rng.choice(seeds))
        index = rng.randrange(len(parsed))
        item = parsed[index]
        at = rng.randrange(len(item) + 1)
        parsed[index] = item[:at] + rng.choice(alphabet) + item[at:]
        if parsed[0] == "find":
            record("find_parts", [parsed], root)
            record("find_deleting", [parsed], root)
            record("find", [parsed, cwd], root)
        elif parsed[0] == "xargs":
            record("xargs", [parsed, cwd], root)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(ROWS, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
print("find records", len(ROWS))

with (OUT.parent / "exhaustive_find.txt").open("w", encoding="utf-8") as output:
    alphabet = ["-delete", "-name", "-exec", "rm", "{}", ";", "a", "0", "\n", " "]
    for length in range(6):
        for tail in itertools.product(alphabet, repeat=length):
            command = ["find", *tail]
            result = [GUARD._find_parts(command), GUARD._find_deleting(command), GUARD._deletes_from_names(command)]
            output.write("\x00".join(command).encode("utf-8").hex() + "\t" + json.dumps(result, separators=(",", ":")) + "\n")
