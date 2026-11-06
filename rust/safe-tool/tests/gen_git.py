#!/usr/bin/env python3
"""Generate S7 oracle vectors without changing a Git repository."""

import ast
import contextlib
import importlib.machinery
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import random
import shlex
import sys
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s7_git", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def record(name, args, action):
    try:
        result = action()
        records.append({"fn": name, "args": args, "ret": result, "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": args, "ret": None, "exc": type(error).__name__})


for payload in (
    None, True, False, "", [], {}, {"status": "ready"}, {"status": "EXPIRED"},
    {"authenticated": True}, {"is_logged_in": False},
    {"nested": [{"other": 4}, {"auth-status": "logged out"}]},
    [{"x": {"isAuthenticated": True}}], {"state": "unknown"},
    {"status": "İ-READY"}, {"status": 3}, {"status": []},
    {"status": "expired", "authenticated": True},
    {"authenticated": True, "status": "expired"},
):
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    record("authentication_state", [encoded], lambda encoded=encoded: tool._authentication_state(json.loads(encoded)))
for encoded in (
    '{"status":"ready","status":"expired"}',
    '{"state":"expired","authenticated":true,"state":"ready"}',
):
    record("authentication_state", [encoded], lambda encoded=encoded: tool._authentication_state(json.loads(encoded)))

settings = (
    None, "", "notes/:ok.txt", "CLAUDE.local.md", ".:..:../escape:-flag:notes/",
    "nested/thing:good-file:up/../no:/absolute:letter_7",
    "A/./B:./.localdocs/:x..y", "😀:雪:abc", "a//b:a/:a",
)
for setting in settings:
    with mock.patch.dict(os.environ, {}, clear=False):
        if setting is None:
            os.environ.pop("AGENT_SAFEGUARDS_LOCAL_ONLY", None)
        else:
            os.environ["AGENT_SAFEGUARDS_LOCAL_ONLY"] = setting
        for name in ("local_only_entries", "local_only_paths", "local_only_exclude_patterns"):
            record(name, [setting], lambda name=name: list(getattr(tool, "_" + name)()))

randomizer = random.Random(0x5707)
commands = [
    [], ["git", "add", "-f"], ["git", "add", "--force"],
    ["git", "add", "-Af", "file"], ["git", "add", "-A"],
    ["git", "commit", "-m", "x"], ["safe-tool", "git", "commit"],
    ["safe-tool", "git", "commit", "-m", "subject"],
    ["rtk", "proxy", "git", "add", "--force"],
    ["sudo", "git", "add", "-f"], ["git", "-C", "/tmp", "add", "-f"],
    ["echo", "git", "add", "-f"], ["safe-tool", "git", "identity"],
]
for node in ast.walk(ast.parse((ROOT / "tests" / "test_safe_tool.py").read_text())):
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        continue
    literal = node.value
    if len(literal) > 500 or not any(part in literal for part in ("git ", "safe-tool ")):
        continue
    if any(part in literal.lower() for part in ("@", "://", "password", "token", "secret")):
        continue
    try:
        parsed = shlex.split(literal)
    except ValueError:
        continue
    if len(parsed) <= 20:
        commands.append(parsed)
alphabet = ["git", "add", "commit", "safe-tool", "-f", "--force", "-Af", "x", "雪", "", "-C"]
for base in list(commands):
    for _ in range(8):
        item = base.copy()
        item.insert(randomizer.randrange(len(item) + 1), randomizer.choice(alphabet))
        commands.append(item)
for word in ("--force", "-Af", "safe-tool", "commit", "add"):
    for _ in range(30):
        position = randomizer.randrange(len(word) + 1)
        inserted = word[:position] + randomizer.choice("-fA0雪 ") + word[position:]
        deleted = word[:position] + word[position + 1:]
        swapped = list(word)
        if len(swapped) > 1:
            at = randomizer.randrange(len(swapped) - 1)
            swapped[at], swapped[at + 1] = swapped[at + 1], swapped[at]
        for variant in (inserted, deleted, "".join(swapped)):
            commands.append(["git", "add", variant])
            commands.append(["safe-tool", "git", variant])
for words in commands:
    for name in ("is_force_git_add", "is_safe_tool_commit"):
        record(name, [words], lambda name=name, words=words: getattr(tool, "_" + name)(words))

messages = [
    [], ["-m", "subject"], ["--message", "subject"], ["--message=subject"],
    ["-m", "first", "-m", "second"], ["--message="], ["-m"], ["--bad", "x"],
    ["-m", "雪"], ["--message=é"], ["-m", "a", "--message=b"],
]
for args in messages:
    record("commit_messages", [args], lambda args=args: tool._commit_messages(args))

objects = [
    b"", b"a" * 40, b"0" * 64 + b"\n", b"a" * 39, b"a" * 40 + b"x",
    b"A" * 40, b"a" * 40 + b"\n\n", b"\xff", ("é" * 40).encode(),
]
for output in objects:
    record("object_id", [output.hex()], lambda output=output: tool._object_id(output))

details = [
    b"", b"\n", b"lint failed: file.txt line 3\n", b"\x1b[31merror\x1b[0m\n",
    ("雪" * 400).encode(),
    "\n".join(f"line {index}" for index in range(100)).encode(),
    b"\xffbad\n", b"first\r\nsecond\rthird", b"a" * 2500,
]
for output in details:
    record("commit_detail", [output.hex()], lambda output=output: tool._commit_detail(output))

paths = [
    None, (0, b""), (0, b"a\0b\0"), (0, "雪\0é\0".encode()),
    (0, b"a\0a\0"), (0, b"\xff\0"), (1, b"a\0"),
]
for item in paths:
    result = None if item is None else tool._ProcessResult(item[0], item[1], b"")
    arg = None if item is None else [item[0], item[1].hex()]
    record("decoded_paths", [arg], lambda result=result: sorted(tool._decoded_paths(result)))

with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as directory:
    fixture = Path(directory)
    (fixture / "plain").mkdir()
    (fixture / "linked-parent").symlink_to(fixture / "plain")
    (fixture / "plain" / "linked-file").symlink_to(fixture / "plain" / "exclude")
    for label in ("plain/exclude", "linked-parent/exclude", "plain/linked-file", "missing/exclude", "", "/", "\0"):
        path = label if label in ("", "/") else str(fixture / label)
        def action(path=path):
            descriptor = tool._open_without_symlinks(path)
            os.close(descriptor)
            return "opened"
        record("open_without_symlinks", [label], action)

failures = [
    [], [(1, b"", b"failed")], [(2, b"index.lock", b"")],
    [(0, b"ignored", b"")], [(1, b"error\n", b"more\n")],
]
for items in failures:
    results = [tool._ProcessResult(code, stdout, stderr) for code, stdout, stderr in items]
    buffer = io.StringIO()
    def action(results=results, buffer=buffer):
        with contextlib.redirect_stdout(buffer):
            code = tool._commit_operation_failed(*results)
        return [code, json.loads(buffer.getvalue())]
    record(
        "commit_operation_failed",
        [[[code, stdout.hex(), stderr.hex()] for code, stdout, stderr in items]],
        action,
    )

invalid_cwd = "/nonexistent/s7-git-fixture"
for name, args in (
    ("repository_root", [invalid_cwd]), ("git_exclude_path", [invalid_cwd]),
    ("untracked_local_only_paths", [invalid_cwd]),
    ("new_staged_local_only_paths", [invalid_cwd]),
    ("git_identity_ready", [invalid_cwd]),
    ("commit_hook_exists", [invalid_cwd]),
    ("ensure_local_excludes", [invalid_cwd]),
    ("requires_local_artifact_approval", ["git add -f x", None]),
    ("requires_local_artifact_approval", ["git add -f x", invalid_cwd]),
):
    def action(name=name, args=args):
        result = getattr(tool, "_" + name)(*args)
        return sorted(result) if isinstance(result, set) else result
    record(name, args, action)

for message in ("", "  ", "a" * 16_385):
    buffer = io.StringIO()
    def action(message=message, buffer=buffer):
        with contextlib.redirect_stdout(buffer):
            code = tool._git_commit([message])
        return [code, json.loads(buffer.getvalue())]
    record("git_commit", [[message]], action)

tree = b"a" * 40
head = b"b" * 40
diff = ["diff", "--cached", "--quiet", "--exit-code"]
write_tree = ["write-tree"]
names = ["diff", "--cached", "--name-only", "-z"]
do_commit = ["commit", "--quiet", "--no-status", "--message", "subject"]
head_query = ["rev-parse", "--verify", "HEAD"]
tree_query = ["rev-parse", "--verify", "HEAD^{tree}"]
def step(command, code, stdout=b"", stderr=b""):
    return (command, code, stdout, stderr)
prefix = [
    step(diff, 1),
    step(write_tree, 0, tree),
    step(names, 0, b"file.txt\0"),
]
scripts = (
    [step(diff, 0)],
    [step(diff, 2, stderr=b"index.lock held")],
    prefix + [step(do_commit, 0), step(head_query, 0, head), step(tree_query, 0, tree)],
    prefix + [step(do_commit, 0), step(head_query, 0, head), step(tree_query, 0, b"c" * 40)],
    prefix + [step(do_commit, 1, stderr=b"hook rejected")],
    prefix + [step(do_commit, 1, stderr=b"signing failed")],
    prefix + [step(do_commit, 1, stderr=b"unmerged paths")],
    prefix + [step(do_commit, 0), step(head_query, 0, b"invalid"), step(tree_query, 0, tree)],
    [step(diff, 1), step(write_tree, 2, stderr=b"tree error"), step(names, 0, b"file.txt\0")],
)
for script in scripts:
    queue = list(script)
    def fake_git(command, cwd, timeout=tool.GIT_TIMEOUT_SECONDS):
        expected, code, stdout, stderr = queue.pop(0)
        assert command == expected
        return tool._ProcessResult(code, stdout, stderr)
    buffer = io.StringIO()
    def action(buffer=buffer):
        with (
            mock.patch.object(tool, "_repository_root", return_value="/fixture"),
            mock.patch.object(tool, "_git_identity_ready", return_value=True),
            mock.patch.object(tool, "_git", side_effect=fake_git),
            contextlib.redirect_stdout(buffer),
        ):
            code = tool._git_commit(["subject"])
        assert not queue
        return [code, json.loads(buffer.getvalue())]
    record(
        "git_commit_scripted",
        [[[command, code, stdout.hex(), stderr.hex()] for command, code, stdout, stderr in script]],
        action,
    )

output = Path(__file__).parent / "vectors" / "git.json"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
counts = {}
for item in records:
    counts[item["fn"]] = counts.get(item["fn"], 0) + 1
print(json.dumps(counts, sort_keys=True))

exhaustive = Path(__file__).parent / "vectors" / "exhaustive_git.txt"
saved_setting = os.environ.get("AGENT_SAFEGUARDS_LOCAL_ONLY")
row_count = 0
with exhaustive.open("w", encoding="ascii") as handle:
    for kind, alphabet in (("F", "-fAx0 \n"), ("L", "a0._/- \n")):
        for length in range(6):
            for characters in itertools.product(alphabet, repeat=length):
                text = "".join(characters)
                if kind == "F":
                    value = tool._is_force_git_add(["git", "add", text])
                else:
                    os.environ["AGENT_SAFEGUARDS_LOCAL_ONLY"] = text
                    value = bool(tool._local_only_entries())
                handle.write(f"{kind}\t{text.encode().hex()}\t{int(value)}\n")
                row_count += 1
if saved_setting is None:
    os.environ.pop("AGENT_SAFEGUARDS_LOCAL_ONLY", None)
else:
    os.environ["AGENT_SAFEGUARDS_LOCAL_ONLY"] = saved_setting
print(f"exhaustive_git rows: {row_count}")
