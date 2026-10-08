#!/usr/bin/env python3
"""Claude Code PreToolUse hook: hold the iOS Simulator control tool's screenshot action for the user."""

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


def main() -> int:
    try:
        action = (json.load(sys.stdin).get("tool_input") or {}).get("action")
    except Exception:
        action = None
    # An unreadable, empty or oddly cased action is held too: the hook matcher already limits this script to the one tool.
    name = action.strip().lower() if isinstance(action, str) else None
    if name in (None, "", "screenshot"):
        emit_decision("ask", message("simulator_hook.reason"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
