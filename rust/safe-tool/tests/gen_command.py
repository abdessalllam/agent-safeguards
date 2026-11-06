#!/usr/bin/env python3
"""Generate S4 decision vectors from the Python safe-tool oracle."""

import ast
import contextlib
import copy
import dataclasses
import importlib.machinery
import importlib.util
import io
import itertools
import json
from pathlib import Path
import random
import re
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s4_command", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def add(name, *args):
    saved = copy.deepcopy(tuple(dataclasses.asdict(value) if dataclasses.is_dataclass(value) else value for value in args))
    try:
        value = getattr(tool, "_" + name)(*args)
        records.append({"fn": name, "args": saved, "ret": value, "exc": None})
    except BaseException as error:
        records.append({"fn": name, "args": saved, "ret": None, "exc": type(error).__name__})


def test_strings():
    heads = ("cat ", "tee ", "grep ", "rg ", "jq ", "gh ", "git ", "rtk ",
             "sudo ", "bash ", "sh ", "zsh ", "eval ", "echo ", "printf ",
             "ls ", "find ", "docker ", "ps ", "python ", "python3 ",
             "kubectl ", "aws ", "gcloud ", "az ", "npm ", "vault ",
             "sops ", "op ", "source ", "sed ", "awk ", "head ", "tail ")
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            value = node.value
            if len(value) > 1200 or not (any(head in value for head in heads) or "<<" in value):
                continue
            if any(word in value.lower() for word in ("password=", "api_key=", "access_token=", "private key", "://", "@")):
                continue
            if re.search(r"/(?:home|Users)/[^/]+/", value):
                continue
            yield value


rng = random.Random(0x5404)
commands = set(test_strings())
commands.update((
    "", " ", "\x00", "echo ok", "echo 雪", "cat README.md", "cat .env.example",
    "cat .env", "cat .envx", "cat x.env.dist", "cat .env.distinct",
    "cat <<EOF\nhello\nEOF", "cat <<'EOF'\nhello\nEOF",
    "cat <<'EOF'\n$TOKEN\nEOF", "cat <<EOF\n$TOKEN\nEOF",
    "cat <<'EOF'\nthis is prose with a ' quote\nEOF",
    "cat <<EOF\n$API_TOKEN\nEOF",
    "jq -f script.jq <<'EOF'\nhello\nEOF",
    "gh issue create --body - <<'EOF'\nhello\nEOF",
    "echo $(git log --format=%an)", "echo $(git log --oneline)",
    "git log --format=%an", "git log --oneline", "rtk proxy cat README.md",
    "rtk\u001cproxy cat README.md", "rtk\u001fproxy cat README.md",
    "artk proxy cat README.md", "rtk proxyx cat README.md",
    "rtk proxy git log --oneline", "printenv", "source .zshrc",
    "cat project/etc/profile", "echo $API_TOKEN", "echo \u001c snow",
    "cat <<'EOF'\n'\nEOF", "echo $((1+2))",
    "x\x00/safe-tool help", "rg -uu marker \x00",
))
base = sorted(commands)
alphabet = "abc0/:=,{}[]$~.\n \u001c雪\x00'\"<>|()"
for text in base[:180]:
    for _ in range(3):
        index = rng.randrange(len(text) + 1)
        op = rng.randrange(3)
        if op == 0 or not text:
            changed = text[:index] + rng.choice(alphabet) + text[index:]
        elif op == 1:
            changed = text[:index] + text[index + 1:]
        else:
            changed = text[:index] + rng.choice(alphabet) + text[index + 1:]
        commands.add(changed)

for command in sorted(commands):
    add("sensitive_command", command, True)
    add("sensitive_command", command, False)
    add("blocked_only_by_startup_file", command)
    add("blocked_only_by_proxy", command)
    add("blocked_by_git_format", command)
add("sensitive_command", "x" * (tool.MAX_COMMAND_CHARS + 1), True)

for command in sorted(commands):
    if "<<" not in command:
        continue
    add("heredoc_views", command)
    add("tokenize_with_loose_bodies", command)
    add("plain_enough", command)
    marker = tool._unused_marker(command)
    for document in tool.heredocs(command):
        add("is_data_heredoc", command, document, marker)

for line in ("", "cat \ue000", "if cat \ue000", "rtk cat \ue000", "jq -f x \ue000",
             "gh issue create --body - \ue000", "echo x; cat \ue000", "cat 雪 \ue000"):
    add("owner_words", line, "\ue000")
for words in (None, [], ["cat"], ["/bin/cat"], ["./cat"], ["jq"],
              ["jq", "-f", "x"], ["gh", "issue"], ["tee"], ["x"]):
    add("is_data_owner", words)
for command in ("", "\ue000", "\ue000\ue001", "cat <<EOF\n雪\nEOF"):
    add("unused_marker", command)
for text in ("", "echo ok", "if echo ok; then echo yes; fi", "alias cat=x",
             "echo $((1+2))", "echo 雪"):
    add("plain_enough", text)

for value in ("", "0", "1", "true", "false", "yes", "no"):
    old = dict((key, __import__("os").environ.get(key)) for key in (
        "AGENT_SAFEGUARDS_REQUIRE_RTK", "CLAUDE_PLUGIN_OPTION_REQUIRE_RTK"))
    __import__("os").environ["AGENT_SAFEGUARDS_REQUIRE_RTK"] = value
    __import__("os").environ["CLAUDE_PLUGIN_OPTION_REQUIRE_RTK"] = ""
    records.append({"fn": "require_rtk", "args": [value, ""], "ret": tool._require_rtk(), "exc": None})
    for key, previous in old.items():
        if previous is None:
            __import__("os").environ.pop(key, None)
        else:
            __import__("os").environ[key] = previous

old_path = tool.RTK_PATH
for path in (None, "/missing-s4-rtk"):
    tool.RTK_PATH = path
    for command in ("", "ls -la", "git status --short", "雪"):
        try:
            value = tool._rtk_required(command)
            records.append({"fn": "rtk_required", "args": [command, path], "ret": value, "exc": None})
        except Exception as error:
            records.append({"fn": "rtk_required", "args": [command, path], "ret": None, "exc": type(error).__name__})
tool.RTK_PATH = old_path
with tempfile.TemporaryDirectory(prefix="s4-rtk-fixture-") as folder:
    for tag, script in (
        ("rewrite", "#!/bin/sh\nprintf 'rtk %s\\n' \"$2\"\n"),
        ("same", "#!/bin/sh\nprintf '%s\\n' \"$2\"\n"),
        ("code3", "#!/bin/sh\nprintf 'rtk %s\\n' \"$2\"\nexit 3\n"),
        ("code4", "#!/bin/sh\nprintf 'rtk %s\\n' \"$2\"\nexit 4\n"),
    ):
        path = Path(folder) / tag
        path.write_text(script)
        path.chmod(0o700)
        tool.RTK_PATH = str(path)
        for command in ("ls -la", "雪"):
            records.append({"fn": "rtk_required", "args": [command, tag],
                            "ret": tool._rtk_required(command), "exc": None})
tool.RTK_PATH = old_path

for decided in (False, True):
    tool._decision_made[0] = decided
    try:
        tool._on_budget_alarm(0, None)
        records.append({"fn": "on_budget_alarm", "args": [decided], "ret": None, "exc": None})
    except BaseException as error:
        records.append({"fn": "on_budget_alarm", "args": [decided], "ret": None, "exc": type(error).__name__})
tool._decision_made[0] = False
for seconds in (0.0, 0.01, -1.0):
    add("set_budget", seconds)
tool._set_budget(0.0)
for name, args in (("deny_hook", ()), ("deny_hook", ("safe_tool.deny.internal",)),
                   ("ask_local_artifact_hook", ())):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        getattr(tool, "_" + name)(*args)
    records.append({"fn": name, "args": list(args), "ret": json.loads(output.getvalue()), "exc": None})

out = ROOT / "rust" / "safe-tool" / "tests" / "vectors" / "command.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))

exhaustive = out.parent / "exhaustive_command.txt"
with exhaustive.open("w") as stream:
    for size in range(6):
        for chars in itertools.product(".envx0- \n", repeat=size):
            value = "".join(chars)
            expected = int(bool(re.search(r"(?<![\w.-])\.env(?!\.(?:dist|example|sample|template)\b)(?:\b|$)", value)))
            stream.write("data_env\t" + value.encode().hex() + "\t" + str(expected) + "\n")
    for size in range(6):
        for chars in itertools.product("ac! ()\n0", repeat=size):
            value = "".join(chars)
            stream.write("plain_enough\t" + value.encode().hex() + "\t" + str(int(tool._plain_enough(value))) + "\n")
    for size in range(4):
        for words in itertools.product(("cat", "jq", "-f", "x"), repeat=size):
            value = list(words)
            encoded = json.dumps(value, separators=(",", ":")).encode().hex()
            stream.write("is_data_owner\t" + encoded + "\t" + str(int(tool._is_data_owner(value))) + "\n")
    contexts = ("", "a", "0", "_", "-", ".", " ", "\n", "\u001c", "\u0301")
    for before, whitespace, after in itertools.product(contexts, (" ", "\t", "\n", "\u001c", "\u001f"), contexts):
        value = before + "rtk" + whitespace + "proxy" + after
        replaced = tool.PROXY_PREFIX.sub("rtk", value)
        stream.write("proxy_prefix\t" + value.encode().hex() + "\t" + replaced.encode().hex() + "\n")
