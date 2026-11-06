#!/usr/bin/env python3
"""Generate S2 oracle vectors from the Python safe-tool."""

import ast
import fnmatch
import importlib.machinery
import importlib.util
import itertools
import json
import os
from pathlib import Path
import random
import shlex
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_s2_paths", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

records = []


def add(name, *args):
    try:
        result = getattr(tool, "_" + name)(*args)
        records.append({"fn": name, "args": args, "ret": result, "exc": None})
    except Exception as error:
        records.append({"fn": name, "args": args, "ret": None, "exc": type(error).__name__})


def literals():
    for path in (ROOT / "tests").glob("test_*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) > 2000 or "://" in value or "@" in value:
                    continue
                if any(part in value for part in (
                    "grep ", "egrep ", "fgrep ", "rg ", "ag ", "ack ", "setopt ",
                    "shopt ", "bash ", "zsh ", "gitconfig", "git/config", "git config",
                )):
                    yield value


with tempfile.TemporaryDirectory(prefix="s2-paths-") as temporary:
    root = Path(temporary).resolve()
    home = root / "home"
    cwd = root / "work"
    for path in (
        home / ".config" / "fish",
        home / ".local" / "share" / "zsh",
        home / "project",
        cwd / "src",
        cwd / "nested",
    ):
        path.mkdir(parents=True, exist_ok=True)
    (cwd / "home-link").symlink_to(home)
    (cwd / "glob-home").symlink_to(home)
    (cwd / "glob-other").mkdir()
    prior_home = tool.USER_HOME
    prior_working = tool._working_folder
    tool.USER_HOME = str(home)
    tool._working_folder = lambda: str(cwd)
    try:
        previous_directory = os.getcwd()
        try:
            os.chdir(cwd)
            tool._working_folder = prior_working
            add("working_folder")
            records[-1]["args"] = ["normal"]
            records[-1]["ret"] = "@CWD@"
            gone = root / "gone"
            gone.mkdir()
            os.chdir(gone)
            gone.rmdir()
            add("working_folder")
            records[-1]["args"] = ["deleted"]
            records[-1]["ret"] = "@HOME@"
        finally:
            os.chdir(previous_directory)
            tool._working_folder = lambda: str(cwd)
        for operand in (
            "", ".", "..", "../home", "../ho" "me/", "../ho" "me/project",
            "../ho" "me/.config", "../ho" "me/.config/fish", "../ho" "me/.config/fish/conf.d",
            "../work", "../work/src", "home-link", "glob-*", "glob-hom?",
            "glob-*/.config/fish", "glob-*/missing", "glob-[ho]*",
            "glob-[!o]*", "glob-[[]*", "missing*", "src/*",
            "../ho" "me/project/*",
            "~", "~/project", "~/.config/fish", "$HOME", "$HOME/project",
            "$" + "{HOME}", "$" + "{HOME}/.local/share/zsh",
            str(home), str(root), str(cwd), str(home / ".config" / "fish"),
        ):
            wire = operand.replace(str(root), "@ROOT@")
            add("covers_home", wire)
            records[-1]["ret"] = tool._covers_home(operand)
        search_cases = (
            ("grep", ["-r", "K", "../home"]),
            ("grep", ["-d", "recurse", "K", "../home"]),
            ("grep", ["-drecurse", "K", "../home"]),
            ("grep", ["-e", "K", "../home"]),
            ("grep", ["-rn", "K", "src"]),
            ("grep", ["--recursive", "K"]),
            ("rg", ["--hidden", "K", "../home"]),
            ("rg", ["-uu", "K", "../home"]),
            ("rg", ["-u", "-u", "K", "../home"]),
            ("rg", ["-.", "K", "../home"]),
            ("rg", ["K", "../home"]),
            ("ag", ["K", "../home"]),
            ("ack", ["K", "../home"]),
        )
        for executable, arguments in search_cases:
            add("searches_home", executable, list(arguments))
        tool._STARTUP_RULES[0] = False
        add("searches_home", "grep", ["-r", "K", "../home"])
        records[-1]["disabled"] = True
        tool._STARTUP_RULES[0] = True
    finally:
        tool.USER_HOME = prior_home
        tool._working_folder = prior_working
        tool._STARTUP_RULES[0] = True

commands = set(literals())
commands.update((
    "", " ", "git config --global core.hookspath", "ls .gitconfig",
    "test -f .gitconfig", "grep -c hookspath .gitconfig",
    "grep --with-filename hookspath .gitconfig", "cat .gitconfig",
    "ls .gitconfig; cat other", "ls .gitconfig | wc -l",
    "ls .gitconfig > out",
    "test --files0 .gitconfig", "grep --bogus hookspath .gitconfig",
    "echo .gitconfig > /dev/null", "echo .gitconfig > out",
    "function cat() { ls .gitconfig; }", "alias cat=ls; ls .gitconfig",
    "GREP_OPTIONS=x ls .gitconfig", "ls .gitconfig && wc -l",
    "ls .gitconfig || wc -l", "ls .gitconfig\nwc -l",
    "ls .gitconfig; (wc -l)", "echo 'unterminated", "écho 雪",
    "ls .gitconfig 2>&1", "ls .gitconfig 2>/dev/null",
    "ls .gitconfig 2>>/dev/null", "ls .gitconfig > /dev/null",
    "ls .gitconfig < /dev/null", "ls .gitconfig" * 50,
))
rng = random.Random(0x5202)
alphabet = "abc-;|() \n\t\"'<>$\\é1"
for base in list(sorted(commands))[:180]:
    for _ in range(3):
        index = rng.randrange(len(base) + 1)
        character = rng.choice(alphabet)
        commands.add(base[:index] + character + base[index:])

for command in sorted(commands):
    if len(command) > 4096:
        continue
    add("chunks_with_separators", command)
    add("names_sensitive_path", command.lower(), command)
    try:
        parts = shlex.split(command)
    except ValueError:
        continue
    if len(parts) > 30:
        continue
    add("prints_nothing_private", parts)
    if parts:
        executable, arguments = parts[0].split("/")[-1], parts[1:]
        add("search_targets", executable, arguments)
        add("traces_commands", executable, arguments)
        if executable in ("grep", "egrep", "fgrep", "rg", "ag", "ack"):
            add("grep_prints_nothing_private", arguments)

search_options = (
    [], ["K"], ["K", "~"], ["-e", "K", "~"], ["-f", "patterns", "~"],
    ["-d", "recurse", "K", "~"], ["-drecurse", "K", "~"],
    ["--directories=recurse", "K", "~"], ["--directories", "recurse", "K", "~"],
    ["-A2", "K", "~"], ["--after-context", "2", "K", "~"],
    ["--after-context=2", "K", "~"], ["--", "-pattern", "~"],
    ["--regexp", "K", "~"], ["-r", "K", "~"], ["-R", "K", "~"],
    ["-uu", "K", "~"], ["--hidden", "K", "~"], ["-.", "K", "~"],
    ["--unrestricted", "--unrestricted", "K", "~"],
    ["-e", "K", "--", "-target"], ["--type", "py", "K", "src"],
    ["-g", "*.py", "K", "src"], ["-eK", "src"], ["-fpatterns", "src"],
)
for executable in ("grep", "egrep", "fgrep", "rg", "ag", "ack", "other"):
    for arguments in search_options:
        add("search_targets", executable, list(arguments))

for executable in ("bash", "zsh", "sh", "set", "setopt", "shopt"):
    for arguments in (
        [], ["-x"], ["-v"], ["+x"], ["-o", "xtrace"], ["-o", "verbose"],
        ["+o", "xtrace"], ["-so", "xtrace"], ["--verbose"], ["--xtrace"],
        ["build.sh", "-x"], ["--", "-x"], ["-o", "other", "-x"],
        ["source_trace"], ["source-trace"], ["XTRACE"], ["-x", "build.sh"],
    ):
        add("traces_commands", executable, list(arguments))

grep_options = (
    [], ["-c", "x"], ["-l", "x"], ["-L", "x"], ["-q", "x"],
    ["--count", "x"], ["--files-with-matches", "x"], ["--quiet", "x"],
    ["--with-filename", "hookspath"], ["-n", "hookspath"],
    ["-H", "hookspath"], ["hookspath", ".gitconfig"],
    ["-c", "x", ".gitconfig"], ["-l", "x", ".gitconfig"],
    ["-c", "x", ".gitconfig", "other"], ["-e", "x", ".gitconfig"],
    ["--", "-c", "x"], ["-c", "x", "--weird"], ["-A", "2", "x"],
    ["-A2", "x"], ["--count=1", "x"], ["--files0", "x"],
)
for arguments in grep_options:
    add("grep_prints_nothing_private", list(arguments))
    add("prints_nothing_private", ["grep", *arguments])

out = Path(__file__).parent / "vectors" / "paths.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))

exhaustive = out.parent / "exhaustive_paths.txt"
with exhaustive.open("w") as handle:
    for length in range(6):
        for chars in itertools.product("-+ovx a1\n", repeat=length):
            argument = "".join(chars)
            result = tool._traces_commands("bash", [argument])
            handle.write(f"T\t{argument.encode().hex()}\t{int(result)}\n")
    for length in range(5):
        for chars in itertools.product("-clH a1\n", repeat=length):
            argument = "".join(chars)
            result = tool._grep_prints_nothing_private([argument])
            handle.write(f"G\t{argument.encode().hex()}\t{result or '-'}\n")
    for length in range(5):
        for chars in itertools.product("*?[]!-\\a1\n ", repeat=length):
            pattern = "".join(chars)
            for name in ("", "a", "1", "[", "]", "!", "-", "\\", " ", "a\n"):
                result = fnmatch.fnmatchcase(name, pattern)
                handle.write(
                    f"F\t{pattern.encode().hex()}\t{name.encode().hex()}\t{int(result)}\n"
                )

from collections import Counter

print(dict(Counter(record["fn"] for record in records)))
print("exhaustive rows", sum(1 for _ in exhaustive.open()))
