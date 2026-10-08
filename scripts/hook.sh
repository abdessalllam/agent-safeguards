#!/bin/sh
set -u

case $0 in
  */*) here=${0%/*} ;;
  *) here=. ;;
esac
root=$(CDPATH= cd -- "$here/.." 2>/dev/null && pwd -P) || root=
tool=${1:-}
runtime=${2:-}
event=${3:-}

case "$tool" in
  safe-tool|delete-guard) ;;
  *) printf 'agent-safeguards: error=unknown_tool\n' >&2; exit 2 ;;
esac
case "$runtime" in
  claude|codex) ;;
  *) printf 'agent-safeguards: error=unknown_runtime\n' >&2; exit 2 ;;
esac
case "$event" in
  ""|PreToolUse|PostToolUse|SessionStart) ;;
  *) printf 'agent-safeguards: error=unknown_event\n' >&2; exit 2 ;;
esac

fail_open() {
  case "${AGENT_SAFEGUARDS_FAIL_OPEN:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
  esac
  return 1
}

python=$(command -v python3 2>/dev/null) || python=
if [ -z "$python" ] || [ -z "$root" ]; then
  fail_open && exit 0
  printf 'agent-safeguards: error=python3_not_found\n' >&2
  exit 2
fi

if [ -n "$event" ]; then
  "$python" -I "$root/bin/$tool" hook "$runtime" "$event"
else
  "$python" -I "$root/bin/$tool" hook "$runtime"
fi
status=$?
[ "$status" -eq 0 ] && exit 0
fail_open && exit 0
printf 'agent-safeguards: error=hook_failed\n' >&2
exit 2
