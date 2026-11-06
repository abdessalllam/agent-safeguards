#!/usr/bin/env python3
"""Generate S5 differential vectors from the Python safe-tool."""

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
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s5_oracle", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
tool = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tool
loader.exec_module(tool)


def ordered(value):
    return json.loads(json.dumps(value, sort_keys=True, ensure_ascii=False))


records = []


os.environ.pop("AGENT_SAFEGUARDS_SHOW_ADDRESSES", None)


def record(name, *args, flag=False):
    args = copy.deepcopy(args)
    actual = copy.deepcopy(args)
    if flag:
        os.environ["AGENT_SAFEGUARDS_SHOW_ADDRESSES"] = "1"
    else:
        os.environ.pop("AGENT_SAFEGUARDS_SHOW_ADDRESSES", None)
    try:
        if name == "withhold_post_hook":
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                tool._withhold_post_hook(*actual)
            result = json.loads(stream.getvalue())
        elif name == "withheld_shape":
            result = tool._withheld_shape(actual[0], root=actual[1] if len(actual) > 1 else True,
                                          depth=actual[2] if len(actual) > 2 else 0)
        else:
            result = getattr(tool, "_" + name)(*actual)
        exc = None
    except Exception as error:
        result = None
        exc = type(error).__name__
    records.append({"fn": name, "args": args, "ret": result, "exc": exc, "flag": flag})


def corpus_from_tests():
    paths = [
        "test_addresses.py", "test_login_banners.py", "test_definitions.py",
        "test_safe_tool.py", "test_review_r_fixes.py", "test_review_s_fixes.py",
        "test_review_e_fixes.py", "test_review_fixes.py", "test_bypasses.py",
        "test_generic_words.py", "test_false_positives.py", "test_review_f_fixes.py",
        "test_secret_scan.py",
    ]
    values = []
    for name in paths:
        tree = ast.parse((ROOT / "tests" / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) <= 4096:
                    values.append(node.value)
    return values


strings = list(dict.fromkeys([
    "", "plain output", "name=Alice", "account_id=sample", "function hello() { echo x; }",
    "declare -f helper", "user@example.com", "worker@custom.invalid", "éø日😀",
    "\x00", "\n", "255.255.255.255", "127.0.0.1", "0.0.0.0",
    "8.8.8.8", "192.168.1.5", "10.0.2.2", "::1", "fc00::1",
    *corpus_from_tests(),
]))
rng = random.Random(505)
alphabet = "aZ09_.:@=/- \n\x00é😀"
for base in ["name=Alice", "status", "192.168.1.5", "user@example.com", "function foo()", "\x00"]:
    for _ in range(40):
        chars = list(base)
        index = rng.randrange(len(chars) + 1)
        action = rng.randrange(3)
        if action == 0:
            chars.insert(index, rng.choice(alphabet))
        elif action == 1 and chars:
            chars.pop(index % len(chars))
        elif chars:
            chars[index % len(chars)] = rng.choice(alphabet)
        strings.append("".join(chars))
strings = list(dict.fromkeys(strings))

for text in strings:
    value = ordered(text)
    record("response_text", value, 0)
    record("response_values", value, 0)
    record("shows_private_address", text)
    record("shows_host_details", "echo hello", text)
for text in strings[:100]:
    record("shows_private_address", text, flag=True)
    record("shows_host_details", "hostname -I", text, flag=True)

for text in strings[:500]:
    fields = ordered({"content": text, "stdout": text, "label": text})
    for value in [ordered([text, None, 12, True]), fields, ordered({"inner": {"value": text}})]:
        record("response_text", value, 0)
        record("response_values", value, 0)
        record("response_labels", value, 0)

depth_limit = []
for _ in range(66):
    depth_limit = [depth_limit]
complex_labels = ordered({f"k{i:03d}": "z" * 2048 for i in range(130)})
for value in [None, True, False, 0, -1, 1.0, -0.0, 1e-7, 1e20,
              18446744073709551615, ordered({"a": 1, "b": 2.25}),
              ordered({"a": ["x", {"b": "y"}]}), depth_limit, complex_labels]:
    for name in ["response_text", "response_values", "response_labels"]:
        record(name, value, 0)
for depth in [64, 65, 100]:
    for name in ["response_text", "response_values", "response_labels"]:
        record(name, "x", depth)

for candidate in ["", "1.1.1.1", "0.0.0.0", "127.0.0.1", "224.0.0.1",
                  "255.255.255.255", "255.255.255.254", "192.168.0.1",
                  "01.2.3.4", "1.2.3", "1.2.3.256", "1.2.3.4\n", "é"]:
    record("reportable_address", candidate)
for a in [0, 1, 8, 10, 127, 169, 172, 192, 223, 224, 239, 240, 255]:
    for b in [0, 1, 16, 31, 168, 255]:
        record("reportable_address", f"{a}.{b}.1.2")

for chunk in [[], ["ls"], ["FOO=bar", "ls"], ["FOO=bar"],
              ["/usr/bin/grep", "x"], ["status"], ["X=1", "status"],
              ["é=1", "ls"], ["A=1\n", "ls"]]:
    record("plain_chunk", chunk)
for text in strings[:300]:
    for chunk in tool._tokenize(text):
        record("plain_chunk", chunk)

commands = ["echo hello", "status", "account", "auth status", "whoami", "git status",
            "rg name", "identity-check", "cat", "ps", "hostname -I", "echo $(whoami)"]
responses = ["", "plain output", "name=Alice", "user@example.com",
             "sample" + "@" + "sandbox.zz",
             "password" + "=" + "A" * 24,
             "function hello() { echo x; }", "192.168.1.5", "fc00::1",
             "host=8.8.8.8", "password=synthetic", "\x00", {"stdout": "hello"},
             {"stdout": "name=Alice", "stderr": ""}, ["a", "b"], depth_limit]
for command in commands:
    for value in responses:
        value = ordered(value)
        record("withheld_because", command, value)
        record("sensitive_output", command, value)
for value in responses[:10]:
    record("withheld_because", "hostname -I", ordered(value), flag=True)
for text in strings[:450]:
    record("withheld_because", "echo hello", ordered(text))

for name in ["", "a", "A_01", "under_score", "0bad", "space bad", "é", "x" * 32,
             "x" * 33, "stdout", "content", "password"]:
    for position in [0, 3, 100]:
        record("shape_key", name, position)

for value in [None, True, False, 1, -1, 2.3, "hello", ["hello", {"secret": "x"}],
              ordered({"stdout": "hello", "stderr": "error", "interrupted": False}),
              ordered({"content": "hello", "output": "world"}),
              ordered({"!bad": "x", "normal": {"n": 12}}), depth_limit]:
    value = ordered(value)
    record("withheld_shape", value)
    record("withheld_shape", value, False, 6)
for runtime in ["claude", "codex", "other"]:
    for why in [None, "secret", "email", "identity", "definition", "address", "host"]:
        for value in [ordered({"stdout": "hello", "stderr": ""}), "hello", None]:
            record("withhold_post_hook", runtime, value, why)
record("withhold_post_hook", "claude", ordered({"stdout": "hello"}), "secret", ordered({"stdout": "replacement"}))
record("withhold_post_hook", "claude", ordered({"stdout": "hello"}), "unknown")

exhaustive = Path(__file__).parent / "vectors" / "exhaustive_output.txt"
with exhaustive.open("w") as stream:
    for length in range(6):
        for chars in itertools.product("a0=/. \n", repeat=length):
            candidate = "".join(chars)
            encoded = candidate.encode().hex()
            stream.write(f"shape_key\t{encoded}\t{tool._shape_key(candidate, 3)}\n")
            stream.write(f"reportable_address\t{encoded}\t{int(tool._reportable_address(candidate))}\n")
            stream.write(f"plain_chunk\t{encoded}\t{int(tool._plain_chunk([candidate, 'ls']))}\n")

out = Path(__file__).parent / "vectors" / "output.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))
print(f"{len(records)} output vectors and exhaustive predicates written")
