#!/usr/bin/env python3
"""Python oracle for S8 remote command checks."""

import ast
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import itertools
import json
from pathlib import Path
import random
import re
import shlex
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s8_remote", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def add(name, *args):
    saved = copy.deepcopy(args)
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            call_args = (args[0], frozenset(args[1]), frozenset(args[2])) if name == "resolve_long_options" else args
            result = getattr(tool, "_" + name)(*call_args)
        record = {"fn": name, "args": saved, "ret": result, "exc": None}
        if not re.search(r"/(?:home|Users)/[^/]+/", json.dumps(record, ensure_ascii=False)):
            records.append(record)
    except Exception as error:
        records.append({"fn": name, "args": saved, "ret": None, "exc": type(error).__name__})


heads = tuple(tool.REMOTE_READ_COMMANDS) + ("sudo", "rm", "echo", "bash", "ssh", "rtk")
commands = {
    "", " ", "ls", "ls | head", "ls && rm x", "ls # ignored", "ls | # ignored",
    "docker ps", "docker stats", "docker stats --no-stream", "docker logs -f app",
    "pm2 logs app --nostream", "pm2 logs app", "systemctl status app",
    "date +%s", "date 010100002000", "find /tmp -name x", "sort -o out in",
    "cat 雪", "ls 😀", "ls \x00", "ls \\| cat", "cat /tmp/../tmp/a",
}
for path in (ROOT / "tests").glob("test_*.py"):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        continue
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value
        if len(value) > 1000 or "://" in value or re.search(r"/(?:home|Users)/[^/]+/", value):
            continue
        if value.split(" ", 1)[0] in heads or any(value.startswith(head + " ") for head in heads):
            commands.add(value)

rng = random.Random(0x5808)
base = sorted(commands)
alphabet = "abZ0-+=/|#;{}*?'\"\\ \t\n\x00雪"
for command in base[:400]:
    for _ in range(2):
        at = rng.randrange(len(command) + 1)
        operation = rng.randrange(3)
        if operation == 0:
            changed = command[:at] + rng.choice(alphabet) + command[at:]
        elif operation == 1:
            changed = command[:at] + command[min(at + 1, len(command)):]
        elif at + 1 < len(command):
            changed = command[:at] + command[at + 1] + command[at] + command[at + 2:]
        else:
            changed = command
        commands.add(changed)

readonly_cases = {"", "ls", "ls && rm x", "docker stats", "docker stats --no-stream", "pm2 logs app", "pm2 logs app --nostream"}
for command in sorted(commands):
    if re.search(r"/(?:home|Users)/[^/]+/", command):
        continue
    for name in (("remote_stages", "remote_check", "remote_readonly") if command in readonly_cases else ("remote_stages", "remote_check")):
        add(name, command)
    stages = tool._remote_stages(command)
    if stages and len(stages) == 1:
        words = stages[0]
        if words and words[0] == "sudo":
            words = words[2:] if words[1:2] == ["-n"] else words[1:]
        if words and words[0] in tool.REMOTE_READ_COMMANDS:
            add("remote_option_problem", words[0], words[1:])

arguments = [
    [], ["--"], ["-f"], ["-f=false"], ["-nf"], ["--follow"],
    ["--follow=false"], ["--follow=bad"], ["--follow", "--follow=false"],
    ["--format", "--no-stream"], ["--no-stream", "--no-stream=false"],
    ["--lines", "2", "logs", "--nostream"], ["logs", "app", "--nostream"],
    ["--", "logs", "--nostream"], ["--host", "x", "ps"], ["compose", "logs", "-f"],
    ["stats", "--no-stream"], ["--context", "x", "ps"],
]
options = ["-f", "-n", "-H", "--follow", "--host", "--no-stream", "--format", "--lines", "--", "x", "0", "雪"]
for _ in range(400):
    arguments.append([rng.choice(options) for _ in range(rng.randrange(6))])
for args in arguments:
    add("pm2_read", args)
    add("flag_is_set", args, "--no-stream", ["--format"])
    add("docker_follows", args)
    add("remote_docker_problem", args)
    add("resolve_long_options", args, list(tool.SYSTEMCTL_VALUE_OPTIONS), list(tool.REMOTE_FLAG_LONG["systemctl"]))
    for name in ("date", "uniq", "docker", "systemctl", "pm2", "tail", "find", "journalctl"):
        add("remote_option_problem", name, args)
    for argument in args:
        add("shown", argument)
        add("may_take_next", argument, "nHf", ["--follow", "--no-stream"], "H")

for value in ("", "a", "a" * 31, "a" * 32, "_", "-f", "--", "--fol", "--follow=", "雪", "a雪", "A_B+0"):
    add("shown", value)
    add("may_take_next", value, "nHf", ["--follow", "--no-stream"], "H")

add("resolve_long_options", ["--fo"], ["--foo"], ["--foo"])

out = ROOT / "rust" / "safe-tool" / "tests" / "vectors"
out.mkdir(exist_ok=True)
(out / "remote.json").write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")).replace("/", "\\/"))

with (out / "exhaustive_remote.txt").open("w", encoding="utf-8") as handle:
    cases = (
        ("shown", "a0_+-? \n", 5),
        ("may_take_next", "-nfH=0a ", 5),
        ("docker_follows", "-nf=0a \n", 5),
        ("flag_is_set", "-n=0a \n", 5),
    )
    for name, alphabet, limit in cases:
        for length in range(limit + 1):
            for chars in itertools.product(alphabet, repeat=length):
                value = "".join(chars)
                if name == "shown":
                    result = tool._shown(value)
                elif name == "may_take_next":
                    result = tool._may_take_next(value, "nfH", frozenset({"--follow", "--no-stream"}), "H")
                elif name == "docker_follows":
                    result = tool._docker_follows([value])
                else:
                    result = tool._flag_is_set([value], "--no-stream", frozenset({"--format"}))
                handle.write(name + "\t" + value.encode().hex() + "\t" + json.dumps(result) + "\n")

print("remote vectors:", len(records), "exhaustive cases recorded")
