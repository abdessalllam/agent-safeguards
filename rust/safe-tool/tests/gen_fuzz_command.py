#!/usr/bin/env python3
import ast
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import random
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_fuzz_command", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

JOINERS = ["; ", " && ", " || ", " | ", "\n", " & ", " |& ", "\n\n", " ; "]
WRAPPERS = ["sudo ", "rtk proxy ", "rtk ", "env FOO=1 ", "timeout 5 ", "time ", "nice ", "command ", "exec ", "FOO=bar ", "sudo -u root ", "env -i ", "nohup ", "watch ", "xargs ", "bash -c ", "sh -c ", "eval ", ""]
DECORATIONS = ["", "", "", "'", '"', "$(", "`", " >out", " 2>&1", " < /dev/null", " <<EOF\nbody\nEOF", " <<'EOF'\n$HOME\nEOF", " # note", "\\\n", " --", " -"]
ALPHABET = list("abcdefghijklmnopqrstuvwxyz0123456789 \n\t'\"|&;$`()<>{}[]\\#~*?=.,:/@!-_%") + ["é", "雪", "\x1c", "́", "\x00"]


def test_commands():
    found = set()
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if 3 <= len(value) <= 300 and " " in value and "\x00" not in value:
                    found.add(value)
    return sorted(found)


def main():
    rng = random.Random(0x5C0F22 + int(os.environ.get("FUZZ_SEED", "0")))
    pool = test_commands()
    records = []
    with tempfile.TemporaryDirectory(prefix="fz-s4-") as temporary:
        home = Path(os.path.realpath(temporary)) / "home"
        work = home / "project"
        work.mkdir(parents=True)
        for name in (".zshrc", ".bashrc", ".profile", ".zsh_history", "ordinary.txt"):
            (home / name).touch()
        (work / "ordinary.txt").touch()
        old_home, old_cwd = tool.USER_HOME, Path.cwd()
        tool.USER_HOME = str(home)
        os.chdir(work)
        try:
            for _ in range(24000):
                parts = [rng.choice(pool) for _ in range(rng.choice([1, 1, 2, 2, 3]))]
                command = ""
                for index, part in enumerate(parts):
                    if index:
                        command += rng.choice(JOINERS)
                    command += rng.choice(WRAPPERS) + part + rng.choice(DECORATIONS)
                if rng.random() < 0.35:
                    chars = list(command)
                    for _ in range(rng.randint(1, 3)):
                        position = rng.randrange(len(chars) + 1)
                        operation = rng.randrange(3)
                        if operation == 0 or not chars:
                            chars.insert(position, rng.choice(ALPHABET))
                        elif operation == 1 and position < len(chars):
                            chars.pop(position)
                        elif position < len(chars) - 1:
                            chars[position], chars[position + 1] = chars[position + 1], chars[position]
                    command = "".join(chars)
                flag = rng.random() < 0.3
                tool._PS_TARGET[0] = rng.choice(["linux", "darwin"])
                target = tool._PS_TARGET[0]
                try:
                    ret, exception = tool._sensitive_command(command, flag), None
                except Exception as error:
                    ret, exception = None, type(error).__name__
                records.append({"fn": "sensitive_command", "args": [command, flag, target], "ret": ret, "exc": exception})
                if rng.random() < 0.2:
                    for name in ("blocked_only_by_startup_file", "blocked_by_git_format", "blocked_only_by_proxy"):
                        try:
                            ret, exception = getattr(tool, "_" + name)(command), None
                        except Exception as error:
                            ret, exception = None, type(error).__name__
                        records.append({"fn": name, "args": [command], "ret": ret, "exc": exception})
        finally:
            os.chdir(old_cwd)
            tool.USER_HOME = old_home
    output = ROOT / "rust" / "safe-tool" / "tests" / "vectors" / "fuzz_command.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(records, ensure_ascii=True, separators=(",", ":")))
    print("fuzz command records", len(records))


if __name__ == "__main__":
    main()
