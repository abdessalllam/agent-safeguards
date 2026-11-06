#!/usr/bin/env python3
"""Generate Git and definition-rule oracle cases from the Python safe-tool."""

import ast
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import random
import shlex
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s1_git", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)
records = []


def add(name, *args, **kwargs):
    try:
        ret = getattr(tool, "_" + name)(*args, **kwargs)
        records.append({"fn": name, "args": args, "kwargs": kwargs, "ret": ret, "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": args, "kwargs": kwargs, "ret": None, "exc": type(error).__name__})


def literals():
    files = ("test_git_formats.py", "test_git_config_reads.py", "test_git_blob_show.py", "test_generic_words.py", "test_definitions.py", "test_bypasses.py", "test_safe_tool.py")
    for name in files:
        path = ROOT / "tests" / name
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) <= 2000 and ("git " in value or value.startswith(("alias ", "type ", "declare ", "local ", "typeset ", "export ", "readonly ", "set", "fc", "where ", "whence ", "history"))):
                    if not any(word in value.lower() for word in ("password", "access_token", "private key", "api_key", "credential", "secret", "://", "@")):
                        yield value


rng = random.Random(0x51A2)
commands = set(literals())
commands.update(("git log --oneline", "git log --format=%h%x09%s", "git log --format=%an", "git show HEAD:file", "git show HEAD", "git config --get core.hooksPath", "git config --global --unset core.hooksPath", "git -C /tmp/project config get core.bare", "git for-each-ref --format='%(refname:short) %(contents:subject)'", "git rev-list --header HEAD", "type -t git", "alias x=y", "declare -p x"))
for base in list(sorted(commands))[:140]:
    for _ in range(3):
        at = rng.randrange(len(base) + 1)
        ch = rng.choice("git --format=%an%x41:()<>*雪😀/+=")
        commands.add(base[:at] + ch + base[at:])

word_lists = set()
formats = {"", "%", "%%", "%h", "%an", "%ae", "%ad", "%aD", "%as", "%ci", "%G?", "%GK", "%x41", "%xGG", "%C(red)%h%Creset", "%<(20,trunc)%s", "%(describe:tags)", "%(decorate)", "format:%h", "format:plain", "tformat:%h", "short", "oneline", "reference", "雪%h😀", "%h%", "%(refname)", "%(*refname:short)", "%(contents:subject)", "%(contents:body)", "%(authorname)", "%(if)%(then)x%(end)"}
for command in sorted(commands):
    try:
        parsed = tuple(shlex.split(command))
    except ValueError:
        continue
    if len(parsed) > 32:
        continue
    word_lists.add(parsed)
    for word in parsed:
        if word.startswith(("--format=", "--pretty=")):
            formats.add(word.split("=", 1)[1])

for base in ("%h", "%(refname)", "%an", "%ad", "%x41", "%C(red)"):
    for _ in range(80):
        at = rng.randrange(len(base) + 1)
        ch = rng.choice("%()<>+ -:;aG?x雪😀")
        formats.add(base[:at] + ch + base[at:])
formats.add("x" * 4096 + "%h")
for format_string in sorted(formats):
    add("log_format_is_safe", format_string)
    add("ref_format_is_safe", format_string)

word_lists.update(((), ("alias",), ("git",), ("git", "-C", "/tmp/project", "log", "--oneline"), ("git", "--no-pager", "log", "--oneline"), ("git", "config", "unset", "core.hooksPath"), ("git", "config", "--global", "--local", "--get", "core.bare"), ("git", "config", "--get", "core.bare"), ("git", "config", "--unset", "core.bare"), ("sudo", "git", "config", "--get", "core.hooksPath"), ("rtk", "proxy", "git", "config", "--list"), ("git", "remote", "get-url", "origin"), ("git", "remote", "-v"), ("git", "var", "GIT_AUTHOR_IDENT"), ("git", "show", "HEAD:a.txt", "--", "HEAD")))
for item in sorted(word_lists):
    words = list(item)
    add("git_subcommand", words)
    add("safe_git_config", words)
    add("runs_git_config", words)
    add("sensitive_git_command", words)
    for at, word in enumerate(words):
        if word == "git" and at + 1 < len(words):
            sub = words[at + 1]
            args = words[at + 2:]
            add("prints_definitions", sub, args)
    if words:
        add("prints_definitions", words[0], words[1:])
    add("safe_history_arguments", words, show=False)
    add("safe_history_arguments", words, show=True)
    add("shows_only_blobs", words)
    add("formats_are_unsafe", words, "--header")
    add("formats_are_unsafe", words, refs=True)

for args in ([], ["--format=%h"], ["--format=%an", "--format=%h"], ["--format=%h", "--format=%an"], ["--format", "%h"], ["--pretty", ""], ["--", "--format=%an"], ["--header"], ["--format=%h", "--header"], ["--format=%h", "--", "--header"], ["HEAD:a.txt", "--", "HEAD"]):
    add("formats_are_unsafe", args, "--header")
    add("formats_are_unsafe", args, refs=True)
    add("safe_history_arguments", args, show=False)
    add("shows_only_blobs", args)

out = Path(__file__).parent / "vectors" / "git_rules.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))
print(f"git rule vectors: {len(records)}")
