#!/usr/bin/env python3
"""Generate Python oracle records for delete-guard token and expansion helpers."""

import ast
import importlib.machinery
import json
import os
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "tokens.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_tokens_vectors", str(ROOT / "bin" / "delete-guard")).load_module()
RNG = random.Random(41193)
RECORDS = []


def record(name, *args, changed=None):
    if changed is not None:
        GUARD._VARIABLES_CHANGED[0] = frozenset(changed)
    shown = json.loads(json.dumps(list(args) + ([sorted(changed)] if changed is not None else [])))
    args = json.loads(json.dumps(args))
    try:
        value = getattr(GUARD, name)(*args)
        if name == "_tokenize" and value is not None:
            value = [list(item) for item in value]
        if isinstance(value, (set, frozenset)):
            value = sorted(value)
        if name == "_expand" and isinstance(value, str):
            if args[1] is not None and not os.path.isabs(args[1]) and not os.path.isabs(GUARD._home_expanded(args[0])):
                value = "{CWD_REL}:" + os.path.relpath(value, os.getcwd())
            else:
                value = value.replace(os.path.realpath(os.getcwd()), "{CWD}")
        RECORDS.append({"fn": name[1:], "args": shown, "ret": value, "exc": None})
    except Exception as error:
        RECORDS.append({"fn": name[1:], "args": shown, "ret": None, "exc": type(error).__name__})


def test_literals():
    files = list((ROOT / "tests").glob("test_delete_guard*.py"))
    files += list((ROOT / "tests").glob("test_review_*_fixes.py"))
    files += [ROOT / "tests" / "test_bypasses.py"]
    values = set()
    for path in files:
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 500:
                values.add(node.value)
    return sorted(values)


commands = [
    "", " ", "\n", "rm -rf /tmp/demo", "if rm -rf x; then echo ok; fi",
    "function wipe() { rm -rf x; }", "wipe () { rm -rf x; }", "coproc NAME { rm -rf x; }",
    "case x in y) rm -rf x;; esac", "x) rm -rf x", "(rm -rf x)",
    "echo ';' \"|\" \\; \\& \\|", "echo 'unbalanced", 'echo "unbalanced',
    "HOME=x rm -rf x", "export HOME=x; cd x", "read HOME", "printf -v HOME x",
    "unset CDPATH", "env CDPATH=x rm x", "echo αβγ; rm café", "rm x >out 2>>err",
    "echo a&&\nrm b", "echo a;;;rm b", "echo a # comment\nrm b",
]
commands += [item for item in test_literals() if any(word in item for word in ("rm", "trash", "find", "HOME", "CDPATH", "coproc", "case", "function", "read", "printf", "export", "cd "))]
commands = sorted(set(commands))
for source in commands[:1200]:
    record("_tokenize", source)
    record("_variables_changed", source)
    record("_protect_escaped_separators", source)

alphabet = "ab$`~/;|&()'\"\\\nαβ "+chr(0xE010)
for source in commands[:120]:
    for _ in range(3):
        chars = list(source)
        position = RNG.randrange(len(chars) + 1)
        operation = RNG.randrange(3)
        if operation == 0 or not chars:
            chars.insert(position, RNG.choice(alphabet))
        elif operation == 1 and position < len(chars):
            chars.pop(position)
        elif position < len(chars) - 1:
            chars[position], chars[position + 1] = chars[position + 1], chars[position]
        candidate = "".join(chars)
        record("_tokenize", candidate)
        record("_variables_changed", candidate)
        record("_protect_escaped_separators", candidate)

word_lists = [
    [], ["("], ["((", "rm", "x)"], ["if", "then", "coproc", "NAME", "{", "rm", "x"],
    ["case", "x", "in", "y)", "rm", "x"], ["x)", "rm", "x"],
    ["function", "x()", "{", "rm", "x", "}"], ["x", "()", "{", "rm", "x"],
    ["echo", "a", "b)"], ["", "x", ""], ["α()", "{", "rm"],
]
for source in commands[:500]:
    words = source.split()[:10]
    word_lists.append(words)
for words in word_lists:
    record("_function_header_length", words)
    record("_open_parentheses", words)
    record("_without_syntax_prefix", words)
    for before, after in [(None, None), ("&&", ";")]:
        record("_chunk", words, before, after, True, [["2", ">", "out"]])
    record("_variables_changed_by", words)

paths = [
    "", ".", "..", "/", "//", "a/", "/tmp/x/", "$", "`", "$HOME", "${HOME}",
    "$HOME/", "${HOME}/x", "$HOME/\nx", "~/", "~", "~other", "~/x/../y", "x/$HOME",
    "a`cmd`", "café/$HOME", "a\\b", "αβ", "a\nx", "/tmp/../var/tmp/x",
]
paths += [item for item in test_literals() if len(item) <= 120 and ("/" in item or item.startswith("~"))][:500]
for path in sorted(set(paths)):
    record("_base", path)
    record("_is_computed", path)
    record("_home_expanded", path)
    for cwd in (None, "", ".", "relative/cwd", "/tmp/d1-cwd"):
        for changed in ([], ["HOME"]):
            record("_expand", path, cwd, changed=changed)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(RECORDS, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
