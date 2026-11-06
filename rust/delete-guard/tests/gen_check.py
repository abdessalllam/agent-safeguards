#!/usr/bin/env python3
"""Generate delete-guard check and whole-run oracle vectors."""

import ast
import copy
import importlib.machinery
import io
import itertools
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "check.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_d5_check", str(ROOT / "bin" / "delete-guard")).load_module()
ROWS = []


def describe(error):
    text = str(error)
    return "embedded null byte" if isinstance(error, ValueError) and "null" in text else text


def normalized(value, root):
    if isinstance(value, str):
        return value.replace(root, "@ROOT@")
    if isinstance(value, (set, frozenset)):
        return [normalized(item, root) for item in sorted(value)]
    if isinstance(value, (tuple, list)):
        return [normalized(item, root) for item in value]
    if isinstance(value, dict):
        return {key: normalized(item, root) for key, item in value.items()}
    return value


def record(name, args, root, remote=None, stdin=(), targets=()):
    GUARD._REMOTE[0] = remote
    GUARD._STDIN_FILES[0] = list(stdin)
    GUARD._VARIABLES_CHANGED[0] = frozenset()
    GUARD._QUOTED_WORDS[0] = frozenset()
    GUARD._PENDING_ASK[0] = None
    GUARD._REMOTE_TARGETS[:] = list(targets)
    copied = copy.deepcopy(args)
    try:
        ret = getattr(GUARD, "_" + name)(*copied)
        exc = None
    except Exception as error:
        ret, exc = describe(error), type(error).__name__
    ROWS.append({"fn": name, "args": normalized(args, root), "ret": normalized(ret, root),
                 "exc": exc, "ask": normalized(GUARD._PENDING_ASK[0], root),
                 "remote": remote, "stdin": normalized(stdin, root), "targets": normalized(targets, root),
                 "configured_env": os.environ.get("AGENT_SAFEGUARDS_REMOTE_COMMANDS", "")})


def words(command):
    chunks = GUARD._tokenize(command)
    return chunks[0].words if chunks and chunks[0].words else []


with tempfile.TemporaryDirectory(prefix="d5-check-") as temporary:
    root = os.path.realpath(temporary)
    for name in ["u", "u/Documents", "plain", "plain/inner", "pool", "pool/one", "holder", "holder/.Trash", "holder/.Trash/old"]:
        Path(root, name).mkdir(parents=True, exist_ok=True)
    for name in ["plain/a", "pool/one/a", "script.sh"]:
        Path(root, name).write_text("echo okay\n", encoding="utf-8")
    GUARD.USER_HOME = root + "/u"
    GUARD.TEMP_ROOTS = (root,)
    os.environ["AGENT_SAFEGUARDS_REMOTE_COMMANDS"] = ""
    for operator in [">", ">>", ">&", "<>", "<", "<<"]:
        for operand in ["", "2", "-", "2-", "file", "(x)", "/dev/disk4"]:
            record("writes_a_file", [operator, operand], root)
    for operand in ["", "abc", "'a*b'", '"a?b"', "a\\*b", "a b", "a\tb", "a{b,c}", "'a{b,c}'", "a[xy]", "a\\[xy]", "é*", '"a\\$b"', "'unclosed", "\\", "x\x00y"]:
        record("pattern_word", [operand], root)
    for operand in ["plain/*", "plain/[ab]", "pool/{one,two}/*", "'plain/*'", "plain/\\*", "plain/a", "plain/[", "x\x00y"]:
        word = GUARD.shlex.split(operand)[0] if GUARD.shlex.split(operand) else ""
        record("redirection_names", [word, operand, root], root)
    for operator, operand in [("", ""), (">", "/dev/null"), (">", "/dev/disk4"), (">>", "/dev/disk4"), ("<&", "/dev/disk4"), ("<>", "/dev/disk4"), (">&", "2"), (">&", "/dev/disk4"), (">", "'/dev/disk4'"), (">", "/dev/disk*"), (">", "$X/dev/disk4"), (">", "x\x00y")]:
        record("check_device_writes", [(("", operator, operand),), root], root)
    for command in ["cat <script.sh", "sh <script.sh", "sh 0<script.sh", "x <<EOF\nhi\nEOF", "cat <'plain/a'", "cat <x\x00y", "cat <'unclosed", "cat <script.sh <plain/a"]:
        record("line_input_files", [command], root)
    for command in ["git clean", "git clean -ndx", "git clean --dry-run", "git clean --no-dry-run", "git -C . clean -fdx", "git clean -en x", "git clean -ne x", "git status", "git clean -- -n"]:
        record("git_clean", [words(command)], root)
    record("configured_remote_names", [], root)
    os.environ["AGENT_SAFEGUARDS_REMOTE_COMMANDS"] = "fleet-run,custom:other"
    record("configured_remote_names", [], root)
    for command in ["fleet-run 'rm -rf /'", "custom 'rm -rf /'", "fleet-runx 'rm -rf /'"]:
        record("check_command", [command, root], root)
        record("check_one_chunk", [words(command), root, command, True], root)
    os.environ["AGENT_SAFEGUARDS_REMOTE_COMMANDS"] = ""
    for command in ["sh", "sh script.sh", "bash -c 'rm -rf /'", "bash --command='rm -rf /'", "fish -C 'rm -rf /'", "sh -s <script.sh", "sh <script.sh", "zsh -o errexit script.sh", "bash -- script.sh"]:
        parsed = words(command)
        if parsed:
            record("check_shell", [parsed, root], root, stdin=[("script.sh", root)])
    commands = [
        "", "echo safe", "rm x", "rm -rf /", "rm -rf plain", "rm -rf $HOME", "rm -rf *",
        "trash plain/a", "trash ~/Documents", "gio trash plain", "gio trash --empty", "gvfs-rm plain/a",
        "kioclient rm plain/a", "hadoop fs -expunge", "clear-recyclebin", "powershell Clear-RecycleBin",
        "find . -name x -delete", "xargs rm -f", "rsync -a --delete src/ plain/", "diskutil eraseDisk APFS X disk4",
        "dd if=/dev/zero of=/dev/disk4", "git clean -fdx", "git clean -ndx", "cd plain && rm -rf inner",
        "cd plain; rm -rf inner", "cd / && rm -rf tmp", "popd; rm -rf plain", "eval 'rm -rf /'",
        "sh -c 'rm -rf /'", "python3 -c 'import shutil; shutil.rmtree(\"/x\")'",
        "echo hi >/dev/disk4", "cat </dev/disk4", "echo hi >/dev/null", "echo hi >/dev/disk*",
        "echo hi >$X/dev/disk4", "echo hi >'/dev/disk4'", "echo hi >'plain/*'", "cat <script.sh | sh",
        "rm x\x00y", "rm -rf x\x00y", "cd x\x00y && rm -rf x", "rm -rf '\u001c'",
        "ssh host rm -rf ~/ci/run", "mosh host -- rm -rf ~/ci/run", "./script.sh", "source script.sh",
        "rm -rf plain/*", "rm -rf pool/*", "rm -rf holder/.Trash", "rm -rf /tmp/x",
    ]
    commands.extend(["echo " + "a" * (GUARD.MAX_COMMAND_CHARS + 1) + " >/dev/disk4",
                     "echo " + "a" * (GUARD.MAX_COMMAND_CHARS + 1) + " >/dev/null"])
    strings = set(commands)
    for path in (ROOT / "tests").glob("test*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and any(term in node.value for term in ("rm ", "trash ", "git clean", "rsync ", "find ", "dd ", "/dev/")) and len(node.value) < 1200:
                strings.add(node.value)
    rng = random.Random(0xD5C0)
    alphabet = "abc/-*?[]{}$`'\" >;&|\n\x00é"
    for _ in range(180):
        seed = rng.choice(commands[2:])
        at = rng.randrange(len(seed) + 1)
        strings.add(seed[:at] + rng.choice(alphabet) + seed[at:])
    for command in sorted(strings):
        record("check_command", [command, root], root)
        if len(command) < 180:
            record("check_chunks", [command, root], root)
        parsed = words(command)
        if parsed and len(command) < 180:
            record("check_one_chunk", [parsed, root, command, True], root)
    for word in ["plain/a", "~/a b", "a'b", "", "é", "~/[lang]", "~", "/tmp/a b"]:
        record("script_path", [word], root)
    record("preflight_trash_patterns", [], root)
    for targets in [()]:
        record("remote_preflight_script", [], root, targets=targets)
    cases = [
        ("hook", "claude", {"tool_input": {"command": "rm -rf /"}, "cwd": root}),
        ("hook", "codex", {"tool_input": {"command": "rm -rf /"}, "cwd": root}),
        ("hook", "claude", {"tool_input": {"command": "echo safe"}, "cwd": root}),
        ("hook", "claude", {"tool_input": {"command": "rm -rf plain"}, "cwd": root}),
        ("hook", "claude", {"tool_input": {"command": "echo hi >/dev/disk4"}, "cwd": root}),
        ("hook", "claude", {"tool_input": {"command": "rm -rf plain", "workdir": "plain"}, "cwd": root}),
        ("hook", "claude", {"tool_input": {"command": "rm -rf plain", "workdir": "plain"}, "cwd": root + "/"}),
        ("hook", "claude", {"tool_input": {"command": "rm -rf plain", "workdir": root}, "cwd": ""}),
        ("hook", "claude", {"tool_input": {"command": "rm -rf build"}, "cwd": ""}),
        ("hook", "codex", {"tool_input": {"command": "rm -rf build"}, "cwd": ""}),
        ("hook", "claude", {"tool_input": {"command": "rm -rf /"}, "cwd": root, "workdir": "plain"}),
        ("hook", "claude", {}), ("hook", "claude", []), ("hook", "claude", "bad"),
    ]
    for mode, runtime, payload in cases:
        raw = json.dumps(payload, ensure_ascii=True).encode()
        done = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "delete-guard"), mode, runtime], input=raw, capture_output=True, check=False)
        ROWS.append({"fn": "whole_run", "args": [mode, runtime, normalized(raw.decode(), root)],
                     "ret": {"code": done.returncode, "stdout": normalized(done.stdout.decode(), root), "stderr": normalized(done.stderr.decode(), root)}, "exc": None})
    for raw in [b"{", b"x" * (GUARD.MAX_INPUT_BYTES + 1),
                b'{"tool_input":{"command":"rm -rf /"},"unused":NaN}',
                b'{"tool_input":{"command":"rm -rf /"},"unused":Infinity}',
                b'{"tool_input":{"command":"rm -rf /"},"unused":-Infinity}',
                b'\xef\xbb\xbf{"tool_input":{"command":"echo safe"}}',
                '{"tool_input":{"command":"rm -rf /"}}'.encode("utf-16"),
                '{"tool_input":{"command":"rm -rf /"}}'.encode("utf-16-le"),
                '{"tool_input":{"command":"rm -rf /"}}'.encode("utf-32-be"),
                ('{"tool_input":{"command":"echo safe"},"number":' + "9" * 4301 + "}").encode(),
                ('{"tool_input":{"command":"echo safe"},"number":' + "9" * 4300 + "}").encode(),
                b'{"$serde_json::private::Number":"0","tool_input":{"command":"echo safe"}}',
                b'{"tool_input":{"command":"echo safe"},"tool_input":{"command":"rm -rf /"}}',
                b'{"tool_input":{"command":"echo safe"}} x',
                b'{"tool_input":{"command":"echo \\ud83d\\ude00"}}']:
        done = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "delete-guard"), "hook", "claude"],
                              input=raw, capture_output=True, check=False)
        try:
            shown, kind = raw.decode(), "whole_run"
        except UnicodeDecodeError:
            shown, kind = raw.hex(), "whole_run_bytes"
        ROWS.append({"fn": kind, "args": ["hook", "claude", shown],
                     "ret": {"code": done.returncode, "stdout": done.stdout.decode(), "stderr": done.stderr.decode()}, "exc": None})
    for arguments in [("self-test",), ("check-remote", "ls ~"), ("check-remote", "rm -rf ~/ci/run"),
                      ("remote-preflight", "ls ~"), ("remote-preflight", "rm -rf ~/ci/run"),
                      ("check-remote",), ("remote-preflight",), ()]:
        done = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "delete-guard"), *arguments], capture_output=True, check=False, cwd=root)
        ROWS.append({"fn": "whole_run", "args": list(arguments),
                     "ret": {"code": done.returncode, "stdout": normalized(done.stdout.decode(), root), "stderr": normalized(done.stderr.decode(), root)}, "exc": None})

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(ROWS, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
counts = {}
for row in ROWS:
    counts[row["fn"]] = counts.get(row["fn"], 0) + 1
print(json.dumps(counts, sort_keys=True))

with (OUT.parent / "exhaustive_check.txt").open("w", encoding="utf-8") as output:
    alphabet = "*?[\\'\" \ta1\n"
    for length in range(6):
        for characters in itertools.product(alphabet, repeat=length):
            word = "".join(characters)
            output.write("pattern_word\t" + word.encode().hex() + "\t" + GUARD._pattern_word(word).encode().hex() + "\n")
    alphabet = "nulxt0 \n"
    for length in range(6):
        for characters in itertools.product(alphabet, repeat=length):
            text = ">/dev/" + "".join(characters)
            output.write("device_redirect_hint\t" + text.encode().hex() + "\t" + ("1" if GUARD.DEVICE_REDIRECT_HINT.search(text) else "0") + "\n")
    for operator in ["", ">", ">>", ">&", "<>", "<", "<<", "|>", ">!", "a>"]:
        for operand in ["", "-", "1", "1-", "a", "(x)", " 1", "\n", "1x", "\x00"]:
            output.write("writes_a_file\t" + operator.encode().hex() + "\t" + operand.encode().hex() + "\t" + ("1" if GUARD._writes_a_file(operator, operand) else "0") + "\n")
