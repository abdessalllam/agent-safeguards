#!/usr/bin/env python3
"""Generate Python oracle records for startup file guards."""

import ast
import copy
import importlib.machinery
import importlib.util
import itertools
import json
import os
from pathlib import Path
import random
import re
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s3_startup", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []
FIXTURE_HOME = ""


def portable(value):
    if isinstance(value, str):
        return value.replace(FIXTURE_HOME, "{HOME}") if FIXTURE_HOME else value
    if isinstance(value, (list, tuple)):
        return [portable(item) for item in value]
    return value


def add(name, *args):
    saved = portable(copy.deepcopy(args))
    try:
        call_args = args[:-1] if name == "reads_startup_file" else args
        ret = getattr(tool, "_" + name)(*call_args)
        records.append({"fn": name, "args": saved, "ret": portable(ret), "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": saved, "ret": None, "exc": type(error).__name__})


def test_strings():
    names = (
        "test_startup_files.py", "test_startup_coverage.py", "test_quoted_globs.py",
        "test_safe_tool.py", "test_bypasses.py", "test_review_a_fixes.py",
        "test_review_b_fixes.py", "test_review_c_fixes.py", "test_review_d_fixes.py",
        "test_review_e_fixes.py", "test_review_f_fixes.py", "test_review_g_fixes.py",
        "test_review_h_fixes.py", "test_review_i_fixes.py", "test_review_j_fixes.py",
        "test_review_k_fixes.py", "test_review_l_fixes.py", "test_review_m_fixes.py",
        "test_review_n_fixes.py", "test_review_o_fixes.py", "test_review_p_fixes.py",
        "test_review_q_fixes.py", "test_review_r_fixes.py", "test_review_s_fixes.py",
        "test_review_t_fixes.py",
    )
    markers = ("zsh", "bash", "history", "profile", "find ", "source ", "cat ", "grep ", "rg ", "glob", "dotglob", "HISTFILE")
    for name in names:
        path = ROOT / "tests" / name
        if not path.is_file():
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) <= 1000 and any(marker in value for marker in markers):
                    if not any(word in value.lower() for word in ("password=", "api_key=", "access_token=", "private key", "://", "@")) and not re.search(r"/(?:home|Users)/[^/]+/", value):
                        yield value


rng = random.Random(0x5304)
commands = set(test_strings())
commands.update((
    "", "cat ~/.zshrc", "cat ~/.zsh_history", "cat ~/.z*", "cat ~/.non*",
    "cat '~/.z*'", "cat \"$HOME\"/.z*", "cat $HOME/.z*", "cat ${HOME}/.z*",
    "cat ../.z*", "cd ~; cat .z*", "setopt globdots; cat ~/.z*",
    "find ~ -name '.z*' -exec cat {} \\;", "find ~ -name '.txt' -exec cat {} \\;",
    "find ~ -name '.zshrc'", "find . -name '.z*' | xargs cat",
    "source ~/.zshrc", ". ~/.zshrc", "source ~/.zsh_history",
    "source ~/.zshrc; set -T",
    "ls ~/.zshrc", "stat ~/.zshrc", "test -f ~/.zshrc", "safe-tool has-key API_TOKEN ~/.zshrc",
    "cat ~/.zsh%72c", "cat ~/.z\\shrc", "cat ~/.z\nshrc",
    "jq '.zshrc' file", "echo $HISTFILE", "set -x; source ~/.zshrc",
    "cat /etc/zshrc", "echo 雪; cat ~/.zshrc", "cat /tmp/plain.txt",
    "cat \x00/.z*", "find \x00 -name '.zshrc' -exec cat {} \\;",
    "find\u0301 ~ -name '.z*' -exec cat {} \\;",
    "find \x1c~ -name '.z*' -exec cat {} \\;",
    "cat ~/.zshrc; xargs\u0301", "cd\u0301; cat .z*",
    "cat " + "a" * 513 + "*.z*", "cat ~/.{zshrc,bashrc}",
))
for base in sorted(commands)[:120]:
    for _ in range(3):
        at = rng.randrange(len(base) + 1)
        commands.add(base[:at] + rng.choice("~$/.{}*?[]'\"\\;|()<>\n 雪") + base[at:])

with tempfile.TemporaryDirectory(prefix="s3-startup-") as temp:
    home = Path(temp).resolve() / "home"
    work = home / "project"
    work.mkdir(parents=True)
    for name in (".zshrc", ".bashrc", ".profile", ".zsh_history", "ordinary.txt"):
        (home / name).touch()
    (work / "ordinary.txt").touch()
    old_home, old_cwd = tool.USER_HOME, Path.cwd()
    FIXTURE_HOME = str(home)
    tool.USER_HOME = str(home)
    os.chdir(work)
    try:
        for command in sorted(commands):
            if re.search(r"/(?:home|Users)/[^/]+/", command):
                continue
            value = command.replace("{HOME}", str(home))
            if not any(value.startswith(prefix) for prefix in ("http://", "https://")):
                for name in ("glob_names_startup_file", "find_names_startup_file", "mentions_startup_file", "pipeline_context", "without_safe_sources"):
                    add(name, value)
                for enabled in (True, False):
                    tool._STARTUP_RULES[0] = enabled
                    add("reads_startup_file", value, enabled)
        for pattern in ("", ".z*", "z*", "*.zshrc", ".bash*", "../.z*", "雪*", ".z?hrc", "[.]zshrc"):
            for dotted in (False, True):
                add("could_name_startup_file", pattern, dotted)
        for token in ("", "source ~/.zshrc", "source ~/.bash_history", ". ../.zshrc", "source ~/.{zshrc,bashrc}", "source ~/.z*", "雪", "..", "{", "?", "[", ","):
            add("safe_source", token)
        for _ in range(1000):
            text = "".join(rng.choice(".zshrc*?[]/{}a0\n 雪") for _ in range(rng.randrange(12)))
            add("could_name_startup_file", text, bool(rng.randrange(2)))
            add("safe_source", text)
    finally:
        os.chdir(old_cwd)
        tool.USER_HOME = old_home
        tool._STARTUP_RULES[0] = True

output = ROOT / "rust" / "safe-tool" / "tests" / "vectors" / "startup.json"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))

exhaustive = output.parent / "exhaustive_startup.txt"
with exhaustive.open("w") as stream:
    for alphabet in (".{}*?[a0\n ", "|$()<>a0\n "):
        for size in range(6):
            for chars in itertools.product(alphabet, repeat=size):
                value = "".join(chars)
                stream.write(value.encode().hex() + "\t" + str(int(tool._safe_source(value))) + "\t" + str(int(tool._could_name_startup_file(value, True))) + "\t" + str(int(tool._mentions_startup_file(value))) + "\t" + str(int(tool._pipeline_context(value))) + "\n")
    for before, after in itertools.product(("", "a", "0", " ", "\n", "\u0301"), repeat=2):
        for word in ("find", "cd", "pushd", "xargs", "while", "for", "eval", "exec", "parallel", "-exec", "-okdir", ".zshrc"):
            value = before + word + after
            stream.write(value.encode().hex() + "\t" + str(int(tool._safe_source(value))) + "\t" + str(int(tool._could_name_startup_file(value, True))) + "\t" + str(int(tool._mentions_startup_file(value))) + "\t" + str(int(tool._pipeline_context(value))) + "\n")
