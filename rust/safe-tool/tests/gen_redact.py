#!/usr/bin/env python3
"""Generate S9 behavior vectors from the Python safe-tool."""

import ast
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s9", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def add(name, args, action):
    saved = copy.deepcopy(args)
    try:
        ret = action()
        records.append({"fn": name, "args": saved, "ret": ret, "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": saved, "ret": None, "exc": type(error).__name__})


def redact(raw):
    input_stream = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
    output_stream = io.StringIO()
    with mock.patch.object(tool.sys, "stdin", input_stream), contextlib.redirect_stdout(output_stream):
        code = tool._redact()
    return [code, output_stream.getvalue()]


def has_key(arguments, home):
    output_stream = io.StringIO()
    error_stream = io.StringIO()
    with mock.patch.object(tool, "USER_HOME", str(home)), contextlib.redirect_stdout(output_stream), contextlib.redirect_stderr(error_stream):
        code = tool._has_key(arguments)
    return [code, output_stream.getvalue(), error_stream.getvalue()]


def cli(arguments, raw=b""):
    completed = subprocess.run(
        [sys.executable, "-I", str(ROOT / "bin" / "safe-tool"), *arguments],
        input=raw,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        env={"PATH": os.defpath, "HOME": str(home)},
        cwd=home,
    )
    return [completed.returncode, completed.stdout.hex(), completed.stderr.hex()]


octets = [
    "", ".", "0", "255", "256", "999", "-1", "+1", " 1 ", "1..2", "1.2.3.4",
    "01.002.3.4", "1.2.3.256", "１.٢.३.४", "²", "1_0", "0x10", "1\n", "١", "a",
    "0" * 100, "9" * 100, "1\x00", "\u001c1\u001f",
]
ipv6 = [
    "", ":", "::", "::1", "2001:db8::1", "::ffff:192.0.2.1", "1:2:3:4:5:6:7:8",
    "1:2:3:4:5:6:7:8:9", "::1%en0", "::1%", "::1%a%b", "::1%a/b", "::1%é",
    "[::1]", "::1\n", "::ffff:999.1.1.1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
]
randomizer = random.Random(9129)
alphabet = "01.:[]%+-ab \n\u0661"
for _ in range(300):
    target = randomizer.choice(octets if randomizer.randrange(2) else ipv6)
    at = randomizer.randrange(len(target) + 1)
    replacement = randomizer.choice(alphabet)
    operation = randomizer.randrange(3)
    if operation == 0:
        target = target[:at] + replacement + target[at:]
    elif operation == 1 and at < len(target):
        target = target[:at] + target[at + 1:]
    elif at + 1 < len(target):
        target = target[:at] + target[at + 1] + target[at] + target[at + 2:]
    octets.append(target)
    ipv6.append(target)
for candidate in octets:
    add("all_octets", [candidate], lambda candidate=candidate: tool._all_octets(candidate))
for candidate in ipv6:
    add("is_ipv6", [candidate], lambda candidate=candidate: tool._is_ipv6(candidate))

texts = [
    b"", b"plain text\n", b"192.0.2.1 256.1.1.1", b"user@example.invalid",
    b"[::1] ::1 ::ffff:192.0.2.1", b"name@[::1] name@host.invalid",
    b"https://example.invalid/a?x=y", b"20:33:32", b"\xff\xfe invalid utf8",
    b"host=example.invalid\n", b"Last login: Mon Jan 1 00:00:00 on ttys000\n",
    b"token=ghp_" + b"A" * 32,
    b"x" * tool.MAX_OUTPUT_BYTES, b"x" * (tool.MAX_OUTPUT_BYTES + 1),
    b":" * 6000, b"https://" + b"a" * 6000,
]
for file_name in ("test_remote.py", "test_login_banners.py", "test_review_e_fixes.py"):
    tree = ast.parse((ROOT / "tests" / file_name).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, (str, bytes)):
            continue
        value = node.value.encode("utf-8") if isinstance(node.value, str) else node.value
        if len(value) > 8192:
            continue
        decoded = value.decode("utf-8", "replace")
        if any(pattern.search(decoded) for pattern in (
            tool.LOGIN_BANNER_PATTERN, tool.REDACT_URL, tool.REDACT_USER_IPV6,
            tool.REDACT_USER_HOST, tool.REDACT_IPV4, tool.REDACT_IPV6,
        )):
            texts.append(value)
for _ in range(250):
    base = randomizer.choice(texts[:10]).decode("utf-8", "replace")
    at = randomizer.randrange(len(base) + 1)
    base = base[:at] + randomizer.choice(alphabet) + base[at:]
    texts.append(base.encode("utf-8"))
for raw in texts:
    add("redact", [raw.hex()], lambda raw=raw: redact(raw))

scratch = os.environ.get("S9_SCRATCH")
with tempfile.TemporaryDirectory(prefix="s9-keys-", dir=scratch) as directory:
    home = Path(os.path.realpath(directory))
    (home / ".zshrc").write_text("export PRESENT=1\nEMPTY=\nexport LATER=2\nunset LATER\n", encoding="utf-8")
    (home / ".bashrc").write_text("BASH_ONLY=1\n", encoding="utf-8")
    key_cases = [
        [], ["PRESENT"], ["PRESENT", "EMPTY", "MISSING", "LATER"],
        ["BASH_ONLY", "--file", "~/.bashrc"], ["BASH_ONLY", "--file", "<HOME>/.bashrc"],
        ["--file", "~/.zshrc", "PRESENT"], ["--file"], ["--file", "relative", "PRESENT"],
        ["PRESENT", "--file", "~/.zshrc", "--file", "~/.bashrc"],
        ["not-valid"], ["é"], ["A"] * 51, ["--file", "~/.zshrc\x00", "PRESENT"],
    ]
    for arguments in key_cases:
        expanded = [argument.replace("<HOME>", str(home)) for argument in arguments]
        add("has_key", [arguments], lambda expanded=expanded: has_key(expanded, home))
    cases = [
        (["-h"], b""), (["--help"], b""), ([], b""), (["nonsense"], b""),
        (["git", "commit"], b""), (["has-key"], b""), (["has-key", "bad-name"], b""),
        (["remote-readonly", "printf ok"], b""), (["self-test"], b""),
        (["redact"], b"192.0.2.1\n"), (["redact"], b"\xff\n"),
        (["hook", "claude", "PreToolUse"], json.dumps({"tool_name": "Bash", "tool_input": {"command": "printf ok"}}).encode()),
        (["hook", "claude", "PreToolUse"], json.dumps({"tool_name": "Bash", "tool_input": {"command": "git config --list"}}).encode()),
        (["hook", "codex", "PostToolUse"], json.dumps({"tool_name": "Bash", "tool_input": {"command": "printf ok"}, "tool_response": {"stdout": "ok"}}).encode()),
        (["hook", "claude", "PreToolUse"], b"not json"),
        (["hook", "codex", "PostToolUse"], b"not json"),
        (["hook", "claude", "PreToolUse"], b'{"tool_name":"Bash","tool_input":{"command":"printf ok"},"number":NaN}'),
        (["hook", "claude", "PreToolUse"], b'{"tool_name":"Bash","tool_input":{"command":"printf ok"},"number":Infinity}'),
        (["hook", "claude", "PreToolUse"], b'{"tool_name":"Bash","tool_input":{"command":"printf ok"},"number":-Infinity}'),
        (["hook", "claude", "PreToolUse"], b"x" * (tool.MAX_OUTPUT_BYTES + 1)),
    ]
    tree = ast.parse((ROOT / "tests" / "test_safe_tool.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        if node.targets[0].id not in {"BLOCKED_COMMANDS", "ALLOWED_COMMANDS"}:
            continue
        for command in ast.literal_eval(node.value):
            payload = {"tool_name": "Bash", "tool_input": {"command": command}}
            cases.append((["hook", "claude", "PreToolUse"], json.dumps(payload).encode()))
    for arguments, raw in cases:
        add("cli", [arguments, raw.hex()], lambda arguments=arguments, raw=raw: cli(arguments, raw))

vector_path = ROOT / "rust" / "safe-tool" / "tests" / "vectors" / "redact.json"
vector_path.parent.mkdir(parents=True, exist_ok=True)
vector_path.write_text(json.dumps(records, ensure_ascii=True, separators=(",", ":")) + "\n", encoding="utf-8")

alphabet = "02.:%a \n"
exhaustive_path = vector_path.with_name("exhaustive_redact.txt")
with exhaustive_path.open("w", encoding="utf-8") as handle:
    for length in range(6):
        for parts in itertools.product(alphabet, repeat=length):
            candidate = "".join(parts)
            try:
                octet_result = "1" if tool._all_octets(candidate) else "0"
            except ValueError:
                octet_result = "E"
            ipv6_result = "1" if tool._is_ipv6(candidate) else "0"
            handle.write(candidate.encode("utf-8").hex() + "|" + octet_result + "|" + ipv6_result + "\n")
