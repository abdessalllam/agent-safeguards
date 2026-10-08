#!/usr/bin/env python3
"""Claude Code PreToolUse hook: refuse browser screenshots and zooms that do not ask for a small scale."""

from __future__ import annotations

import sys

# Run again in isolated mode before any other import, so PYTHON* variables and user site packages cannot shadow the library.
if __name__ == "__main__" and not sys.flags.isolated and sys.executable:
    import posix

    posix.execv(sys.executable, [sys.executable, "-I", *sys.argv])

import json
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), "lib"))

from agent_safeguards.common import emit_decision, message  # noqa: E402

MAX_SCALE = 0.5
CAPTURE_ACTIONS = ("screenshot", "zoom")


def over_limit(tool_input: object) -> bool:
    if not isinstance(tool_input, dict):
        return True
    action = tool_input.get("action")
    if not isinstance(action, str) or action.strip().lower() not in CAPTURE_ACTIONS:
        return False
    scale = tool_input.get("scale")
    return isinstance(scale, bool) or not isinstance(scale, (int, float)) or scale > MAX_SCALE


def violates(tool_input: object) -> bool:
    # A batch call carries its own list of calls, so every screenshot inside it needs the same scale.
    if isinstance(tool_input, dict) and isinstance(tool_input.get("actions"), list):
        return any(isinstance(item, dict) and item.get("name") == "computer" and over_limit(item.get("input")) for item in tool_input["actions"])
    return over_limit(tool_input)


def main() -> int:
    try:
        tool_input = json.load(sys.stdin).get("tool_input")
    except Exception:
        tool_input = None
    if violates(tool_input):
        emit_decision("deny", message("browser_hook.reason", scale=MAX_SCALE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
