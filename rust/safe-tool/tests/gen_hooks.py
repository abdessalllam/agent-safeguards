#!/usr/bin/env python3
"""Generate offline hook parity vectors from the Python guard."""

import contextlib
import importlib.machinery
import io
import itertools
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
SOURCE = ROOT / "bin" / "safe-tool"
TOOL = importlib.machinery.SourceFileLoader("safe_tool_hooks_vectors", str(SOURCE)).load_module()
DESTINATION = Path(__file__).with_name("vectors") / "hooks.json"
FIXTURE = "$FIXTURE"


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode().hex()


def result(name, args, call):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            answer = call()
        return {"fn": name, "args_hex": encoded(args), "ret_hex": encoded(answer), "exc": None}
    except Exception as error:
        return {"fn": name, "args_hex": encoded(args), "ret_hex": None, "exc": type(error).__name__}


def hook_case(runtime, expected_event, payload, fixture):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    actual = raw.replace(FIXTURE.encode(), str(fixture).encode())
    command = [sys.executable, str(SOURCE), "hook", runtime]
    if expected_event is not None:
        command.append(expected_event)
    environment = {
        "PATH": os.defpath,
        "HOME": str(fixture),
        "AGENT_SAFEGUARDS_REQUIRE_RTK": "0",
        "AGENT_SAFEGUARDS_AUTO_EXCLUDE": "0",
        "AGENT_SAFEGUARDS_FAIL_OPEN": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    completed = subprocess.run(
        command, input=actual, capture_output=True, env=environment, cwd=fixture, timeout=10, check=False
    )
    return {
        "fn": "run_hook",
        "runtime": runtime,
        "expected_event": expected_event,
        "input_hex": raw.hex(),
        "stdout_hex": completed.stdout.hex(),
        "stderr_hex": completed.stderr.hex(),
        "exit": completed.returncode,
    }


def main():
    rows = []
    rng = random.Random(606)
    with tempfile.TemporaryDirectory(prefix="s6-hooks-") as temporary:
        fixture = Path(temporary)
        (fixture / "plain.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
        (fixture / "unicode.txt").write_text("πρώτο\r\n第二行\nthird\n", encoding="utf-8")
        (fixture / "nul.txt").write_bytes(b"before\0after\n")
        (fixture / "empty.txt").write_bytes(b"")
        (fixture / "key.txt").write_text("token=" + "ghp_" + ("A" * 32) + "\n", encoding="utf-8")
        (fixture / "skip.pdf").write_text("placeholder", encoding="utf-8")

        payloads = [
            {}, {"tool_input": {}}, {"tool_input": {"command": "ls"}},
            {"tool_input": {"command": 1}}, {"tool_input": {"command": ""}},
            {"tool_input": {"command": "pwd"}, "tool_name": "Bash"},
            {"tool_input": {"command": "git log --oneline -n 3"}, "tool_name": "Bash"},
            {"tool_input": {"command": "cat /tmp/plain"}, "tool_name": "Bash"},
            {"tool_name": "Read", "tool_input": {"file_path": FIXTURE + "/plain.txt"}},
            {"tool_name": "Read", "tool_input": {"file_path": FIXTURE + "/key.txt"}},
            {"tool_name": "mcp__example", "tool_input": {}},
        ]
        for payload in payloads:
            rows.append(result("command_of", [payload], lambda payload=payload: TOOL._command_of(payload)))
            rows.append(result("content_tool", [payload], lambda payload=payload: TOOL._content_tool(payload)))
        for name in (None, 0, "", "Read", "Write", "Grep", "apply_patch", "mcp__tool", "mcp__", "mcp_"):
            rows.append(result("content_tool_name", [name], lambda name=name: TOOL._content_tool_name(name)))
        alphabet = "mcp_x1\n "
        bits = []
        for length in range(7):
            for characters in itertools.product(alphabet, repeat=length):
                bits.append("1" if TOOL._content_tool_name("".join(characters)) else "0")
        rows.append({"fn": "content_tool_name_exhaustive", "alphabet": alphabet, "max": 6, "bits": "".join(bits)})

        line_values = [
            None, True, False, -5, 0, 1, 200001, 2.0, 2.5, "", " ", "0", "12",
            " 15 ", "-1", "１２", "١٢", "²", "1" * 4301, {}, [],
        ]
        for value in line_values:
            rows.append(result("line_number", [value, 17], lambda value=value: TOOL._line_number(value, 17)))
        alphabet = "01²١x\n "
        for length in range(6):
            for characters in itertools.product(alphabet, repeat=length):
                value = "".join(characters)
                rows.append(result("line_number", [value, 17], lambda value=value: TOOL._line_number(value, 17)))

        for name in ("plain.txt", "unicode.txt", "nul.txt", "empty.txt", "key.txt", "skip.pdf", "missing.txt"):
            for offset, limit in ((None, None), (1, 1), (2, 1), (0, 1), ("bad", 1), (2.0, 1)):
                tool_input = {"file_path": name, "offset": offset, "limit": limit}
                args = [tool_input, FIXTURE]
                rows.append(result("read_lines", args, lambda tool_input=tool_input: TOOL._read_lines(tool_input, str(fixture))))

        redactions = [
            None, 1, True, "hello", {"stdout": "plain", "exit": 0},
            {"stdout": "token=" + "ghp_" + ("A" * 32), "stderr": ""},
            {"token": "ghp_" + ("A" * 32), "other": 2},
            ["plain", {"content": "token=" + "ghp_" + ("A" * 32)}],
        ]
        for value in redactions:
            rows.append(result("redact_keys", [value, 0], lambda value=value: TOOL._redact_keys(value, 0)))
            rows.append(result("redact_keys", [value, 65], lambda value=value: TOOL._redact_keys(value, 65)))

        json_inputs = [
            b"", b"{}", b"[]", b"null", b"1", b"{}\n{}", b"{}\nnot-json",
            b"\xff", b" \n\t ", b"{}\r\n[]", "{}\u2028[]".encode(),
        ]
        for value in json_inputs:
            rows.append(result("json_payloads", [value.hex()], lambda value=value: TOOL._json_payloads(value)))

        base_commands = [
            "ls", "pwd", "echo hello", "git status --short", "git log --oneline -n 3",
            "git config --get user.name", "env", "printenv", "rg needle README.md",
            "cat .gitconfig", "rtk git status", "safe-tool git identity", "python3 --version",
            "curl https://example.com", "git log --format=%h%x09%s",
        ]
        alphabet = "abcXYZ019 -_./'\";&|\n"
        mutations = set(base_commands)
        for command in base_commands:
            for _ in range(4):
                position = rng.randrange(len(command) + 1)
                mutations.add(command[:position] + rng.choice(alphabet) + command[position:])
        for runtime in ("claude", "codex"):
            for event in ("PreToolUse", "PostToolUse", "SessionStart", "Stop"):
                for command in sorted(mutations):
                    payload = {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": command}}
                    if event == "PostToolUse":
                        payload["tool_response"] = {"stdout": "all good", "stderr": "", "interrupted": False}
                    rows.append(hook_case(runtime, None, payload, fixture))
            for content in (
                {"stdout": "all good", "stderr": "", "interrupted": False, "isImage": False},
                {"stdout": "token=" + "ghp_" + ("A" * 32), "stderr": "", "interrupted": False, "isImage": False},
                {"content": ["plain", "token=" + "ghp_" + ("A" * 32)]},
            ):
                for event in ("PreToolUse", "PostToolUse"):
                    rows.append(hook_case(runtime, None, {
                        "hook_event_name": event, "tool_name": "Read",
                        "tool_input": {"file_path": FIXTURE + "/key.txt"}, "tool_response": content,
                    }, fixture))
            for raw in (b"", b"{", b"[]", b"null", b"invalid", b'{"hook_event_name":"PostToolUse",'):
                rows.append(hook_case(runtime, None, raw, fixture))
            for event in ("PreToolUse", "PostToolUse", "SessionStart"):
                rows.append(hook_case(runtime, event, b"not-json", fixture))
        DESTINATION.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {len(rows)} hook vectors")


if __name__ == "__main__":
    main()
