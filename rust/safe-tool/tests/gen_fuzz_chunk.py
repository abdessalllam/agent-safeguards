#!/usr/bin/env python3
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
loader = importlib.machinery.SourceFileLoader("safe_tool_fuzz_chunk", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

CHUNK_PIECES = [
    "git", "config", "log", "show", "-C", "--format=%an", "--format=%h", "credential", "fill", "var", "GIT_AUTHOR_IDENT", "remote", "-v", "get-url", "blame", "cat-file", "user.name", "core.hooksPath",
    "ps", "aux", "ax", "eww", "e", "-e", "-o", "environ", "pid", "--format", "--format=environ", "-C", "emacs", "docker", "inspect", "container", "--format={{.Config.Env}}", "--format={{.Id}}", "-f",
    "kubectl", "get", "secret", "pods", "describe", "view", "gh", "api", "user", "auth", "status", "token", "aws", "sts", "get-caller-identity", "configure", "list", "gcloud", "az", "account", "show",
    "tool", "doctor", "whoami", "identity", "profile", "org", "printenv", "env", "export", "set", "declare", "-p", "echo", "printf", "$API_TOKEN", "$HOME", "$PATH", "cat", "~/.zshrc", ".env",
    "~/.ssh/id_rsa", "id_rsa.pub", "grep", "-r", "rg", "-uu", "sudo", "rtk", "proxy", "timeout", "5", "time", "nice", "-n", "command", "exec", "xargs", "jq", "strenv", "--arg", "source", ".",
    "HISTFILE", "history", "fc", "-l", "alias", "type", "ls", "wc", "test", "-f", "vault", "read", "pass", "show", "bw", "op", "1password", "doppler", "sops", "-d", "ansible-vault", "view", "decrypt",
    "<<<", "<<EOF", "$(", "`", "${", "}", "雪", "\x1c", "a", "b", "=", "--", "-", "ENV=x", "FOO=bar",
]
COMMAND_PIECES = [
    "", " ", "\n", "cat ", "echo ", "grep ", "find ", "xargs ", "source ", ". ", "ls ", "stat ", "test -f ", "cd ", "pushd ", "setopt globdots; ", "set -T; ", "~/", "$HOME/", "${HOME}/", "/", ".", "..",
    ".zshrc", ".bashrc", ".profile", ".zsh_history", ".bash_history", ".z*", ".*", "*", "?", "[", "]", "{", "}", ",", "'", '"', "\\", "$", "`", ";", "|", "&&", "(", ")", "<", ">", "-name ", "-exec ",
    "-print", "\\;", "{} ", "+", "HISTFILE", "雪", "\x1c", "́", "zshrc", "bashrc", "history", "profile", "a", "0", "\t",
]
PS_TARGETS = ("linux", "darwin")


def main():
    rng = random.Random(0x53F022 + int(os.environ.get("FUZZ_SEED", "0")))
    records = []
    used = [False]
    original = tool._sensitive_command

    def watched(*args, **kwargs):
        used[0] = True
        return original(*args, **kwargs)

    tool._sensitive_command = watched

    def add(name, *args, **extra):
        used[0] = False
        saved = copy.deepcopy(args)
        try:
            call_args = args[:1] if name == "sensitive_chunk" else (args[:-1] if name == "reads_startup_file" else args)
            ret = getattr(tool, "_" + name)(*copy.deepcopy(call_args))
            exception = None
        except Exception as error:
            ret, exception = None, type(error).__name__
        records.append({"fn": name, "args": saved, "ret": ret if exception is None else None, "exc": exception, **extra})

    with tempfile.TemporaryDirectory(prefix="fz-s3-") as temporary:
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
            for _ in range(9000):
                words = [rng.choice(CHUNK_PIECES) for _ in range(rng.randint(0, 7))]
                target = rng.choice(PS_TARGETS)
                tool._PS_TARGET[0] = target
                enabled = rng.random() > 0.05
                tool._STARTUP_RULES[0] = enabled
                add("sensitive_chunk", words, target, enabled)
            for _ in range(4000):
                text = "".join(rng.choice(COMMAND_PIECES) for _ in range(rng.randint(0, 10)))
                value = text.replace("~/", str(home) + "/", 1) if rng.random() < 0.3 else text
                for name in ("glob_names_startup_file", "find_names_startup_file", "mentions_startup_file", "pipeline_context", "without_safe_sources", "safe_source"):
                    add(name, value)
                for enabled in (True, False):
                    tool._STARTUP_RULES[0] = enabled
                    add("reads_startup_file", value, enabled)
                tool._STARTUP_RULES[0] = True
                add("could_name_startup_file", text, bool(rng.randrange(2)))
            for _ in range(2500):
                add("prints_secret_variable", "".join(rng.choice(COMMAND_PIECES + ["$API_TOKEN", "<<EOF\n", "EOF\n", "<<<", "$SECRET", "${TOKEN}", "echo "]) for _ in range(rng.randint(0, 9))))
                add("ps_format_shows_environment", "".join(rng.choice("environ,=: 012\u001c雪pid") for _ in range(rng.randint(0, 14))))
                add("docker_inspect_shows_environment", [rng.choice(["inspect", "--format", "{{.Config.Env}}", "--format=json", "-f", "--", "container", "{{.Id}}", "--type", "env"]) for _ in range(rng.randint(0, 5))])
        finally:
            os.chdir(old_cwd)
            tool.USER_HOME = old_home
            tool._STARTUP_RULES[0] = True
    output = ROOT / "rust" / "safe-tool" / "tests" / "vectors" / "fuzz_chunk.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(records, ensure_ascii=True, separators=(",", ":")))
    print("fuzz chunk records", len(records))


if __name__ == "__main__":
    main()
