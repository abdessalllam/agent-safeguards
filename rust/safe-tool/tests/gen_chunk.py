#!/usr/bin/env python3
"""Generate Python oracle records for chunk classification."""

import ast
import copy
import importlib.machinery
import importlib.util
import itertools
import json
from pathlib import Path
import random
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s3_chunk", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def add(name, *args):
    saved = copy.deepcopy(args)
    try:
        call_args = args[:-1] if name in {"ps_shows_environment", "ps_walk"} else args
        ret = getattr(tool, "_" + name)(*call_args)
        records.append({"fn": name, "args": saved, "ret": ret, "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": saved, "ret": None, "exc": type(error).__name__})


def test_strings():
    names = (
        "test_bare_wrappers.py", "test_generic_words.py", "test_definitions.py",
        "test_safe_tool.py", "test_bypasses.py", "test_review_a_fixes.py",
        "test_review_b_fixes.py", "test_review_c_fixes.py", "test_review_d_fixes.py",
        "test_review_e_fixes.py", "test_review_f_fixes.py", "test_review_g_fixes.py",
        "test_review_h_fixes.py", "test_review_i_fixes.py", "test_review_j_fixes.py",
        "test_review_k_fixes.py", "test_review_l_fixes.py", "test_review_m_fixes.py",
        "test_review_n_fixes.py", "test_review_o_fixes.py", "test_review_p_fixes.py",
        "test_review_q_fixes.py", "test_review_r_fixes.py", "test_review_s_fixes.py",
        "test_review_t_fixes.py",
    )
    command_heads = ("git ", "rtk ", "sudo ", "timeout ", "time ", "env ", "ps ", "docker ", "kubectl ", "gh ", "aws ", "gcloud ", "az ", "npm ", "bash ", "sh ", "zsh ", "eval ", "cat ", "grep ", "rg ", "echo ", "print ", "printf ", "vault ", "sops ", "ansible-vault ", "op ", "doppler ", "jq ")
    for name in names:
        path = ROOT / "tests" / name
        if not path.is_file():
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) <= 1000 and any(head in value for head in command_heads):
                    if not any(word in value.lower() for word in ("password=", "api_key=", "access_token=", "private key", "://", "@")) and not re.search(r"/(?:home|Users)/[^/]+/", value):
                        yield value


rng = random.Random(0x5303)
commands = set(test_strings())
commands.update((
    "", "timeout", "timeout 5", "time", "env", "rtk", "rtk proxy", "rtk proxy git log --oneline",
    "git config user.name", "git config core.hooksPath", "git credential fill", "git log --oneline",
    "ps ax eww", "ps -o environ", "ps -o pid", "docker inspect demo",
    "docker inspect --format={{.Id}} demo", "docker inspect --format=json demo",
    "kubectl get secret", "kubectl get pods", "gh api user", "gh api repos/demo",
    "aws sts get-caller-identity", "gcloud auth list", "az account show",
    "tool doctor", "tool status", "tool profile list", "tool config view",
    "pass show item", "bw list",
    "cat doctor", "grep account file", "echo $API_TOKEN", "jq '.env' file",
    "USER=1 git config user.name", "rg -uu marker ~", "echo 雪", "ps 😀e",
    "rg -uu marker \x00", "x\x00/safe-tool help",
))
alphabet = "abCDEeOo0/:=,{}[]$~.\n \u001c雪"
for base in sorted(commands)[:120]:
    for _ in range(3):
        at = rng.randrange(len(base) + 1)
        ch = rng.choice(alphabet)
        commands.add(base[:at] + ch + base[at:])
for command in sorted(commands):
    if re.search(r"/(?:home|Users)/[^/]+/", command):
        continue
    for chunk in tool._tokenize(command):
        add("sensitive_chunk", chunk)

lists = [
    [], ["inspect"], ["container", "inspect"], ["image", "inspect", "demo"],
    ["service", "inspect", "--format", "{{.ID}}"], ["inspect", "--format", ""],
    ["inspect", "--format=json"], ["inspect", "--format={{.Config.Env}}"],
    ["inspect", "--format={{json .}}"], ["inspect", "--format={{.Id}}"],
    ["inspect", "--format=env\u0301"], ["inspect", "--format=\u0301env"],
    ["--context", "test", "inspect"], ["inspect", "--", "--format={{.Id}}"],
    ["inspect", "-f", "{{.Id}}", "-f", "json"], ["--type", "container", "inspect"],
]
for arguments in lists:
    add("docker_inspect_shows_environment", arguments)
for base in lists:
    for _ in range(5):
        words = base.copy()
        if words and rng.randrange(2):
            words.pop(rng.randrange(len(words)))
        else:
            words.insert(rng.randrange(len(words) + 1), rng.choice(("-f", "--", "inspect", "{{.Env}}", "--format=json", "雪")))
        add("docker_inspect_shows_environment", words)

ps_args = [
    [], ["aux"], ["ax", "eww"], ["e1"], ["-e"], ["-o", "environ"],
    ["-o", "pid,environ=ENV"], ["-o", "pid"], ["--format", "environ"],
    ["--format=environ"], ["--format:environ"], ["--format", "pid"],
    ["-C", "emacs", "-e"], ["-o", "pid", "-e"], ["--", "-e"],
    ["-q", "environ"], ["-x", "-e"], ["-Oenviron"], ["-oenviron"],
    ["--sort", "e", "-o", "pid"], ["--format=pid", "-e"],
]
for target in ("linux", "darwin"):
    tool._PS_TARGET[0] = target
    unix, bsd = tool.PS_PROFILES[target]
    for args in ps_args:
        add("ps_shows_environment", args, target)
        add("ps_walk", args, sorted(unix), sorted(bsd), target)
    for base in ps_args:
        for _ in range(8):
            args = base.copy()
            if args and rng.randrange(2):
                args.pop(rng.randrange(len(args)))
            else:
                args.insert(rng.randrange(len(args) + 1), rng.choice(("e", "E", "o", "O", "-e", "-C", "--format", "environ", "pid", "雪")))
            add("ps_shows_environment", args, target)
            add("ps_walk", args, sorted(unix), sorted(bsd), target)

for value in ("", "environ", "EnViRoN", "pid,environ=ENV", "pid:20, environ", "environx", "pid\u001cenviron", "snow 雪"):
    add("ps_format_shows_environment", value)
for _ in range(500):
    value = "".join(rng.choice("environ,=: 012\u001c雪") for _ in range(rng.randrange(16)))
    add("ps_format_shows_environment", value)

secret_cases = [
    "", "echo $API_TOKEN", "cat <<EOF\n$API_TOKEN\nEOF", "cat <<'EOF'\n$API_TOKEN\nEOF",
    "cat <<< $API_TOKEN", "echo $x; cat <<EOF\n$API_TOKEN\nEOF",
    "cat >out <<EOF\n$API_TOKEN\nEOF", "echo 雪 <<EOF\n$API_TOKEN\nEOF",
]
secret_cases.extend(test_strings())
for value in secret_cases:
    add("prints_secret_variable", value)
for base in secret_cases[:30]:
    for _ in range(5):
        at = rng.randrange(len(base) + 1)
        add("prints_secret_variable", base[:at] + rng.choice("$<>\n'\"{}雪") + base[at:])

output = ROOT / "rust" / "safe-tool" / "tests" / "vectors" / "chunk.json"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))

exhaustive = output.parent / "exhaustive_chunk.txt"
with exhaustive.open("w") as stream:
    for alphabet in ("$pas<> \n0", "env,=:0\n "):
        for size in range(6):
            for chars in itertools.product(alphabet, repeat=size):
                value = "".join(chars)
                stream.write(value.encode().hex() + "\t" + str(int(tool._prints_secret_variable(value))) + "\t" + str(int(tool._ps_format_shows_environment(value))) + "\t" + str(int(tool._docker_inspect_shows_environment(["inspect", "--format=" + value]))) + "\n")
    for before, after in itertools.product(("", "a", "0", " ", "\n", "\u0301"), repeat=2):
        for word in ("env", "environ", "{{.Env}}", "{{.Config}}"):
            value = before + word + after
            stream.write(value.encode().hex() + "\t" + str(int(tool._prints_secret_variable(value))) + "\t" + str(int(tool._ps_format_shows_environment(value))) + "\t" + str(int(tool._docker_inspect_shows_environment(["inspect", "--format=" + value]))) + "\n")
