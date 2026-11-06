#!/usr/bin/env python3
"""Generate command-word oracle cases from the Python safe-tool."""

import ast
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import random
import shlex
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s1_words", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def add(name, *args):
    try:
        ret = getattr(tool, "_" + name)(*args)
        records.append({"fn": name, "args": args, "ret": ret, "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": args, "ret": None, "exc": type(error).__name__})


def literals():
    files = ("test_git_formats.py", "test_git_config_reads.py", "test_git_blob_show.py", "test_generic_words.py", "test_definitions.py", "test_bypasses.py", "test_safe_tool.py", "test_wrappers.py")
    for name in files:
        path = ROOT / "tests" / name
        if not path.exists():
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) <= 2000 and any(word in value for word in ("git ", "rtk ", "sudo ", "env ", "alias ", "type ", "declare ", "export ", "kubectl ", "aws ", "gh ")):
                    if not any(word in value.lower() for word in ("password", "access_token", "private key", "api_key", "credential", "secret", "://", "@")):
                        yield value


rng = random.Random(0x51A1)
commands = set(literals())
commands.update(("", "git", "git log --oneline", "git show HEAD:a.txt", "rtk proxy git log --oneline", "sudo -u root rtk proxy git log --oneline", "git log --format='%h %s' && git show HEAD:a", "echo 'a;b'", "echo ;;; git", "echo (git)", "echo 'unterminated", "écho 雪", "a\nb", "git log >out", "git log 2>&1 | head", "# comment\ngit log", "x" * 4096))
alphabet = "git log -C=;|()\n'\"\t雪😀/\\$#"
for base in list(sorted(commands))[:120]:
    for _ in range(3):
        at = rng.randrange(len(base) + 1)
        ch = rng.choice(alphabet)
        commands.add(base[:at] + ch + base[at:])

words = set()
word_lists = set()
for command in sorted(commands):
    add("tokenize", command)
    try:
        parsed = tuple(shlex.split(command))
        if len(parsed) <= 20:
            word_lists.add(parsed)
            words.update(parsed)
    except ValueError:
        pass
    words.update(command.split())

words.update(("", "safe-tool", tool.SELF_PATH, "$HOME/.local/bin/safe-tool", "${HOME}/.local/bin/safe-tool", "~/.local/bin/safe-tool", "./safe-tool", "/tmp/lookalike/safe-tool", "SAFE-TOOL", "///", "éGIT", "雪", "İ"))
for word in sorted(words):
    if len(word) <= 4096:
        add("normalized", word)
        add("is_self", word)

word_lists.update(((), ("git",), ("rtk", "proxy", "git", "log"), ("sudo", "rtk", "proxy", "git", "log"), ("env", "-S", "git log", "HEAD"), ("timeout", "2s", "git", "log"), ("rtk", "git", "status"), ("rtk", "proxy", "sudo", "git", "config", "--list")))
word_lists.add(("env", "-S", "-S " * 150 + "git status"))
for item in sorted(word_lists):
    add("unwrap", list(item))

executables = ("aws", "az", "gcloud", "gh", "kubectl", "git", "unknown")
options = ([], ["--region", "us-east-1", "sts", "get-caller-identity"], ["--profile", "x", "config", "list"], ["--namespace", "ns", "get", "pods"], ["-n", "ns", "get", "pods"], ["--", "status"], ["-x", "-y", "value", "status"], ["-r", "repo", "api", "user"], ["--format=foo", "list"], ["--region"])
for executable in executables:
    for arguments in options:
        add("without_global_options", executable, arguments)

out = Path(__file__).parent / "vectors" / "words.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))
print(f"words vectors: {len(records)}")
