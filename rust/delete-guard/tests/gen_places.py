#!/usr/bin/env python3
"""Generate Python oracle records for delete-guard place helpers."""

import importlib.machinery
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "places.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_places_vectors", str(ROOT / "bin" / "delete-guard")).load_module()
RECORDS = []


def record(name, args, fixture=None):
    GUARD._PENDING_ASK[0] = None
    try:
        value = getattr(GUARD, name)(*args) if name != "_trash_roots" else GUARD._trash_roots()
        if fixture is not None:
            args = [item.replace(fixture, "{FIXTURE}") if isinstance(item, str) else item for item in args]
            if isinstance(value, str):
                value = value.replace(fixture, "{FIXTURE}")
            if isinstance(value, (list, tuple)):
                value = [item.replace(fixture, "{FIXTURE}") if isinstance(item, str) else item for item in value]
        RECORDS.append({"fn": name[1:], "args": args, "ret": value, "exc": None})
    except Exception as error:
        if fixture is not None:
            args = [item.replace(fixture, "{FIXTURE}") if isinstance(item, str) else item for item in args]
        RECORDS.append({"fn": name[1:], "args": args, "ret": None, "exc": type(error).__name__})


paths = ["", ".", "..", "/", "//", "///", "/tmp", "/tmp/", "/tmp/x", "/tmp/x/", "/a/*", "/a/**", "a*b", "ab?cd", "[abc]", "a/[abc]", "αβ/*", "a\\b", "trash:", "TRASH:/x", ".Trash", ".Trashes", ".Trash-1000", "RECYCLER", "recycler", "Recycled", ".trashed-a", "files_trashbin", ".local/share/Trash", ".local/share/Trash/", ".local/share/Trash\n", "x/.local/share/Trash/x", "a\\.Trash\\b"]
paths += [GUARD.USER_HOME, str(Path(GUARD.USER_HOME).parent), str(Path(GUARD.USER_HOME) / "child"), "/Volumes/disk", "/mnt/disk", "/media/disk"]
paths += [name for path in ("/etc", "/var", "/usr") for name in (path, os.path.realpath(path))]
for path in paths:
    record("_glob_base", [path])
    record("_protected", [path])
    record("_names_trash", [path])
    for root in ["", "/", "/tmp", "/tmp/", "/tmp/x", "a", GUARD.USER_HOME]:
        record("_inside", [path, root])

original_data_home = os.environ.get("XDG_DATA_HOME")
try:
    for value in [None, "", "relative/data", "/", "/tmp/d1-data", "/tmp/d1-data/../other", "//tmp/data", "///tmp/data", GUARD.USER_HOME, str(Path(GUARD.USER_HOME) / ".local/share")]:
        if value is None:
            os.environ.pop("XDG_DATA_HOME", None)
        else:
            os.environ["XDG_DATA_HOME"] = value
        record("_trash_roots", [value])
finally:
    if original_data_home is None:
        os.environ.pop("XDG_DATA_HOME", None)
    else:
        os.environ["XDG_DATA_HOME"] = original_data_home

with tempfile.TemporaryDirectory(prefix="d1-oracle-") as temporary:
    fixture = Path(temporary)
    (fixture / "clean").mkdir()
    (fixture / "repo" / ".git").mkdir(parents=True)
    (fixture / "nested" / "one" / "two" / "three" / ".git").mkdir(parents=True)
    (fixture / "too_deep" / "one" / "two" / "three" / "four" / ".git").mkdir(parents=True)
    (fixture / "skipped" / "node_modules" / "pkg" / ".git").mkdir(parents=True)
    (fixture / "limit").mkdir()
    for index in range(GUARD.MAX_REPOSITORY_SCAN + 1):
        (fixture / "limit" / str(index)).touch()
    (fixture / "symlink").symlink_to(fixture / "repo", target_is_directory=True)
    (fixture / "file").write_text("x", encoding="utf-8")
    for name in ["clean", "repo", "repo/.git", "nested", "too_deep", "skipped", "limit", "symlink", "file", "missing"]:
        path = str(fixture / name)
        record("_holds_repository", [path], temporary)
        record("_protected", [path], temporary)
        record("_protected", [os.path.realpath(path)], temporary)
    (fixture / "outer" / ".git").mkdir(parents=True)
    (fixture / "outer" / "plain").mkdir()
    (fixture / "outer" / "cache" / "a" / "b" / ".git").mkdir(parents=True)
    (fixture / "outer" / "vendor" / "lib" / ".git").mkdir(parents=True)
    (fixture / "outer" / ".worktrees" / "w").mkdir(parents=True)
    (fixture / "outer" / ".worktrees" / "w" / ".git").write_text("gitdir: x", encoding="utf-8")
    (fixture / "outer" / "limit").mkdir()
    for index in range(GUARD.MAX_REPOSITORY_SCAN + 1):
        (fixture / "outer" / "limit" / str(index)).touch()
    for name in ["clean", "repo", "nested", "too_deep", "skipped", "limit", "outer", "outer/plain", "outer/cache", "outer/vendor", "outer/.worktrees", "outer/.worktrees/w", "outer/limit", "outer/.git", "outer/missing"]:
        path = str(fixture / name)
        record("_holds_repository", [path, 1], temporary)
        record("_inside_repository", [path], temporary)
    GUARD.TEMP_ROOTS = ()
    for name in ["clean", "repo", "repo/.git", "nested", "too_deep", "skipped", "limit", "symlink", "file", "missing", "outer", "outer/plain", "outer/cache", "outer/cache/a", "outer/vendor", "outer/vendor/lib", "outer/.worktrees", "outer/.worktrees/w", "outer/limit", "outer/.git", "outer/missing"]:
        record("_check_repository", [str(fixture / name), "trash"], temporary)

for path in [".git", ".git/", "missing", "/tmp/d1-absent", "/nonexistent/d1"]:
    record("_holds_repository", [path])
    record("_check_repository", [path, "trash"])

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(RECORDS, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
