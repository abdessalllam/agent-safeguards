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
MAX_NODES = 20000
MAX_DEPTH = 8


def over_limit(node: dict) -> bool:
    action = node.get("action")
    if not isinstance(action, str) or action.strip().lower() not in CAPTURE_ACTIONS:
        return False
    scale = node.get("scale")
    return isinstance(scale, bool) or not isinstance(scale, (int, float)) or not 0 < scale <= MAX_SCALE


# Every nested dictionary is checked, whatever its key or tool name, so a batch of calls, a renamed batch, or an extra key
# next to a real action cannot hide a screenshot. A request too large or too deep to walk is refused.
def violates(tool_input: object) -> bool:
    if not isinstance(tool_input, dict):
        return True
    pending = [(tool_input, 0)]
    visited = 0
    while pending:
        node, depth = pending.pop()
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH:
            return True
        if isinstance(node, dict):
            if over_limit(node):
                return True
            children = node.values()
        else:
            children = node
        pending.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return False


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
