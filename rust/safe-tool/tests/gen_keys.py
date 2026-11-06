#!/usr/bin/env python3
"""Python oracle for S8 startup key parsing on synthetic files only."""

import ast
import copy
import importlib.machinery
import importlib.util
import itertools
import json
import os
from pathlib import Path
import random
import re
import sys
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s8_keys", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def add(name, args, action):
    saved = copy.deepcopy(args)
    try:
        result = action()
        if name == "startup_key_file" and result is not None:
            result = result.replace(str(home), "<HOME>")
        if name in {"apply_line", "apply_command"}:
            result = sorted(result)
        if name == "keys_set_in":
            result = [sorted(result[0]), result[1]]
        records.append({"fn": name, "args": saved, "ret": result, "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": saved, "ret": None, "exc": type(error).__name__})


scratch = os.environ.get("S8_SCRATCH")
with tempfile.TemporaryDirectory(prefix="s8-keys-", dir=scratch) as raw_directory:
    directory = os.path.realpath(raw_directory)
    home = Path(directory) / "home"
    home.mkdir()
    (home / "dotfiles-zshrc").write_text("A=1\n", encoding="utf-8")
    (home / "other-file").write_text("A=1\n", encoding="utf-8")
    (home / "sub").mkdir()
    with mock.patch.object(tool, "USER_HOME", str(home)):
        for variant in ("plain", "missing", "linked_valid", "linked_bad", "linked_outside"):
            path = home / ".zshrc"
            if path.is_symlink() or path.exists():
                path.unlink()
            if variant == "plain":
                path.write_text("A=1\n", encoding="utf-8")
            elif variant == "linked_valid":
                path.symlink_to(home / "dotfiles-zshrc")
            elif variant == "linked_bad":
                path.symlink_to(home / "other-file")
            elif variant == "linked_outside":
                path.symlink_to(Path(directory) / "outside-zshrc")
            for request in (None, "~/.zshrc", "~/.bashrc", "~/.profile", "~/.zshrc/", "~/sub/.zshrc", ".zshrc", "~/.zshrc\x00"):
                def call(request=request):
                    return tool._startup_key_file(request)
                add("startup_key_file", [request, variant], call)

    content = {
        "empty": "",
        "basic": "A=1\nB=\nexport C=3\n",
        "continuation": "A=1 \\\nB=2\nC=$(cmd with args)\nexport D=$(other thing)\n",
        "quotes": "export A='hello there'\nA=\nreadonly -g B=2 # comment\n",
        "invalid_utf8": b"A=\xff\nB=2\n",
        "too_many_lines": "A=1\n" * (tool.MAX_STARTUP_FILE_LINES + 1),
        "long_pending": "A=" + "x" * (tool.MAX_STARTUP_LINE_CHARS + 1) + "\\\nB=2\n",
    }
    for kind, data in content.items():
        path = Path(directory) / kind
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        add("keys_set_in", [kind], lambda path=path: tool._keys_set_in(str(path)))
    add("keys_set_in", ["missing"], lambda: tool._keys_set_in(str(Path(directory) / "missing")))
    add("keys_set_in", ["directory"], lambda: tool._keys_set_in(str(home)))
    add("keys_set_in", ["nul"], lambda: tool._keys_set_in(str(home) + "\x00"))

lines = {
    "", "A=1", "A=", "export A=1 B=2", "readonly -g B=2", "unset A",
    "then export A=1; unset B", "A=1 B=2", "A=1; B=2", "A=1 && B=2",
    "export C=$(cmd with args)", "D=`cmd with args`", "A='a b'", "A=1 # comment",
    "export A=1 | B=2", "export -g A=1", "declare -x A=1", "A=1 \\\nB=2",
    "export A=雪", "A=1\x00B=2", "export A=1 # B=2",
}
for path in (ROOT / "tests").glob("test_*.py"):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if len(value) <= 300 and re.search(r"\b(?:export|unset|readonly|declare|typeset)\b|\b[A-Z][A-Z0-9_]*=", value):
                if "://" not in value and not re.search(r"/(?:home|Users)/[^/]+/", value):
                    lines.add(value)

rng = random.Random(0x5809)
for line in sorted(lines)[:120]:
    for _ in range(2):
        at = rng.randrange(len(line) + 1)
        lines.add(line[:at] + rng.choice("A0=+;|#'\"\\ \n雪") + line[at:])

for line in sorted(lines):
    for initial in ([], ["A"], ["A", "B"]):
        def apply_line(line=line, initial=initial):
            found = set(initial)
            tool._apply_line(line, found)
            return found
        add("apply_line", [line, initial], apply_line)
        try:
            words = tool.shlex.split(line)
        except ValueError:
            continue
        def apply_command(words=words, initial=initial):
            found = set(initial)
            tool._apply_command(words, found)
            return found
        add("apply_command", [words, initial], apply_command)

out = ROOT / "rust" / "safe-tool" / "tests" / "vectors"
out.mkdir(exist_ok=True)
(out / "keys.json").write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))

with (out / "exhaustive_keys.txt").open("w", encoding="utf-8") as handle:
    alphabet = "A0=+;# \n"
    for length in range(6):
        for chars in itertools.product(alphabet, repeat=length):
            line = "".join(chars)
            found = set()
            tool._apply_line(line, found)
            handle.write(line.encode().hex() + "\t" + json.dumps(sorted(found)) + "\n")

print("keys vectors:", len(records), "exhaustive lines recorded")
