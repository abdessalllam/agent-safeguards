#!/usr/bin/env python3
import ast
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))
loader = importlib.machinery.SourceFileLoader("safe_tool_fuzz_s58", str(ROOT / "bin" / "safe-tool"))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = tool
loader.exec_module(tool)

JOINERS = ["; ", " && ", " | ", " || ", "\n", " |& "]
REMOTE_HEADS = [
    "ps aux", "ps -ef", "docker ps", "docker logs -f web", "docker logs --tail 20 web", "docker inspect web", "docker stats --no-stream", "systemctl status nginx", "systemctl is-active x", "journalctl -u nginx -n 20",
    "journalctl -f", "tail -n 5 /var/log/syslog", "tail -f /var/log/x", "cat /etc/hostname", "cat ~/.ssh/id_rsa", "ls -la /srv", "grep -c error /var/log/x", "grep -r secret /etc", "pm2 logs", "pm2 list", "pm2 logs --lines 20",
    "df -h", "du -sh /srv", "date", "uptime", "sort x", "uniq -c", "wc -l", "head -n 3", "cut -d: -f1", "tr a b", "jq .name", "free -m", "uname -a", "hostname", "whoami", "id", "env", "printenv", "echo ok", "true",
    "docker compose ps", "docker compose logs", "kubectl get pods", "find /srv -name x", "stat /etc/passwd", "readlink -f x", "ss -tlnp", "netstat -an", "lsof -i", "top -bn1", "w", "last", "who", "mount", "lsblk", "dmesg", "ip addr",
    "curl http://x", "rm -rf x", "sudo ls", "bash -c ls", "sh -c 'ls'", "(ls)", "ls $(id)", "ls `id`", "ls > out", "ls >> out", "ls < in", "cat <<EOF\nx\nEOF", "ls &", "ls;ls", "ls\nls", "ls \\\n -l",
]
REMOTE_BITS = ["", " -n 5", " --tail 5", " -f", " --follow", " -u x", " --no-pager", " -a", " -l", " /var/log/x", " ~/.aws/credentials", " /etc/shadow", " $HOME", " 2>&1", " 2>/dev/null", " | head", " | tail -n 3", " | wc -l", " | grep x", " | tee out", " | xargs rm", " | sh", " -x", " --", " ; ls", " && ls"]
PIECES = [
    "pat@example.com", "jane.doe@gmail.com", "noreply@anthropic.com", "me@acme.io", "git@github.com:org/repo.git", "10.0.0.5", "192.168.1.20", "8.8.8.8", "127.0.0.1", "172.16.4.9", "169.254.1.1", "100.64.0.1",
    "fe80::1", "::1", "2001:db8::1", "fc00::5", "inet 10.1.2.3", "ip address: 8.8.8.8", "Connection to host.example.com port 22", "Connection to localhost port 22", "Connected to dev.acme.io.", "Welcome to Ubuntu 22.04",
    "Last login: Mon Jan 1 from 10.0.0.9", "alias ll='ls -la'", "emulator () {\n ssh x\n}", "declare -f x", "uid=501(me) gid=20(staff)", "name: John Smith", "account: acme", "org: widgets", "username: bob", "email: x@y.io",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", "password=hunter2hunter2", "api_key: abcdefghijklmnop", "AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "sk-abcdefghijklmnopqrstuvwxyz",
    "-----BEGIN PRIVATE KEY-----", "normal text", "ok", "done", "0", "42", "files: 3", "total 8", "drwxr-xr-x 2 me staff 64 Jan 1 .", "http://example.com/a", "https://user:pass@host/x", "雪", "é", "\x1c", "\n", " ", "\t", ":", ".",
]
COMMANDS = ["cat notes.txt", "ls", "git log", "rtk proxy cat x", "gh auth status", "aws sts get-caller-identity", "whoami", "id", "ip addr", "ifconfig", "ssh host uptime", "docker ps", "tool doctor", "kubectl config view", "echo hi", "cat /etc/hosts", "gcloud auth list", "az account show", "npm whoami", "git config user.email", "env", "printenv", "alias", "type ls", "declare -p", "ping -c1 10.0.0.1", "curl ifconfig.me", "hostname -I"]


def text(rng):
    return "".join(rng.choice(PIECES) + rng.choice(["", " ", "\n", ": ", "=", ", "]) for _ in range(rng.randint(0, 7)))


def response(rng):
    kind = rng.random()
    if kind < 0.3:
        return text(rng)
    if kind < 0.7:
        return {"stderr": text(rng), "stdout": text(rng)}
    if kind < 0.8:
        return {"output": [text(rng) for _ in range(rng.randint(0, 3))], "status": rng.choice([0, 1, None, True])}
    if kind < 0.9:
        return {"content": [{"text": text(rng), "type": "text"}], "isError": False}
    if kind < 0.95:
        return [text(rng) for _ in range(rng.randint(0, 3))]
    return rng.choice([None, 0, 5, True, {}, []])


def remote_command(rng):
    parts = []
    for _ in range(rng.choice([1, 1, 2, 3])):
        parts.append(rng.choice(REMOTE_HEADS) + "".join(rng.choice(REMOTE_BITS) for _ in range(rng.randint(0, 2))))
    command = rng.choice(JOINERS).join(parts)
    if rng.random() < 0.3:
        chars = list(command)
        for _ in range(rng.randint(1, 2)):
            position = rng.randrange(len(chars) + 1)
            if rng.random() < 0.5 or not chars:
                chars.insert(position, rng.choice("'\"|&;$`()<>{}[]\\#~*?=.,:/@!- \n\x00é"))
            elif position < len(chars):
                chars.pop(position)
        command = "".join(chars)
    return command


def main():
    rng = random.Random(0x5C58 + int(os.environ.get("FUZZ_SEED", "0")))
    records = []

    def add(name, args, call):
        try:
            result, exception = call(), None
        except Exception as error:
            result, exception = None, type(error).__name__
        records.append({"fn": name, "args": args, "ret": result, "exc": exception})

    for _ in range(9000):
        command = remote_command(rng)
        add("remote_check", [command], lambda: tool._remote_check(command))
        add("remote_stages", [command], lambda: tool._remote_stages(command))
    for _ in range(9000):
        command = rng.choice(COMMANDS) + rng.choice(["", "", " | head", " 2>&1", "; ls"])
        data = response(rng)
        add("sensitive_output", [command, data], lambda: tool._sensitive_output(command, json.loads(json.dumps(data))))
        add("withheld_because", [command, data], lambda: tool._withheld_because(command, json.loads(json.dumps(data))))
    output = ROOT / "rust" / "safe-tool" / "tests" / "vectors" / "fuzz_s58.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(records, ensure_ascii=True, separators=(",", ":")))
    print("fuzz s58 records", len(records))


if __name__ == "__main__":
    main()
