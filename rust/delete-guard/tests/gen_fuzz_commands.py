#!/usr/bin/env python3
import importlib.machinery
import json
import os
from pathlib import Path
import random
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_fuzz_targets as fixture

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "fuzz_commands.json"
GUARD = fixture.GUARD

TARGETS = [
    "src", "src/main.rs", "src/*", "*", ".*", "*/", "../plain", "../plain/*", "link_out", "link_out/*", "build", "build/", "node_modules/*", ".git", ".git/hooks", "wt", "wt/*",
    "README", "RE*", "[R]EADME", "missing", "missing/*", "~", "~/", "~/dev/repo", "~/dev/repo/*", "~/.Trash", "~/.Trash/*", "~/Documents/*", "$HOME", "${HOME}/dev/plain/*", "{src,build}",
    "{a,b", "../repo2", "@ROOT@/uhome/dev/repo", "@ROOT@/uhome/dev/repo/src", "@ROOT@/uhome/dev/repo/*", "@ROOT@/uhome/dev/plain", "@ROOT@/uhome/dev/plain/*", "@ROOT@/uhome", "@ROOT@/uhome/*",
    "@ROOT@/vol", "@ROOT@/vol/*", "@ROOT@/vol/.Trashes", "@ROOT@/vol/inner", "@ROOT@/tree", "@ROOT@/tree/*", "@ROOT@/tree/a*", "@ROOT@/tree/a/**", "@ROOT@/tree/a[1]", "@ROOT@/tree/.*",
    "@ROOT@/tree/link_a/*", "@ROOT@/tree/link_*", "@ROOT@/repo2", "@ROOT@/repo2/app", "@ROOT@/work/*", "/", "/*", "/etc", "/tmp", "/tmp/x*", "x\x00y", "trash:/x", "trash:///x",
    "@ROOT@/uhome/.Trash", "@ROOT@/uhome/.Trash/*", "@ROOT@/uhome/.Trash/old/gone", ".Trash", ".Trashes", "-rf", "--", "-",
]
RM_FLAGS = ["-r", "-R", "-f", "-rf", "-fr", "-d", "-i", "-v", "-rv", "--recursive", "--force", "--dir", "--no-preserve-root", "--preserve-root", "--interactive", "--", "--rec", "-I", "-x", "-Rfv", "--r", "--unknown"]
TRASH_FLAGS = ["-e", "--empty", "-f", "--trash-dir", "x", "--trash-dir=x", "-v", "--", "--secure=x", "-r", "-i"]
MV_FLAGS = ["-t", "-T", "-f", "-n", "-v", "-i", "--target-directory=@ROOT@/uhome/.Trash", "--target-directory", "@ROOT@/uhome/.Trash", "--", "-ft", "-S", "--backup"]
GIO_VERBS = ["trash", "remove", "rm", "--empty", "copy", "move", "mount", "list", "info", "-f", "--force", "--", "mkdir"]
FIND_PIECES = [".", "src", "@ROOT@/tree", "@ROOT@/vol", "@ROOT@/uhome/dev/repo", "-name", "*.rs", "-type", "f", "d", "-delete", "-mtime", "+1", "-maxdepth", "1", "0", "-newer", "README", "-prune", "-o", "(", ")", "-not", "!", "-path", "*/x",
               "-print", "-print0", "-follow", "-L", "-H", "-P", "-files0-from", "-depth", "-empty", "-name", ".Trash", "-iname", "x", "-regex", "-size", "+1k", "-user", "root", "-links", "2", "-newermt", "2020-01-01"]
XARGS_FLAGS = ["-0", "-n", "1", "-I", "{}", "-r", "-P", "2", "--", "-t", "-L", "1", "-E", "x", "-a", "README", "--arg-file=README", "-d", "\n", "-s", "100"]
DELETERS = [["rm"], ["rm", "-rf"], ["rm", "-r"], ["trash"], ["unlink"], ["gio", "trash"], ["rm", "-f", "--"], ["echo"], ["cat"], ["ls"]]


def pick(rng, pool, low, high):
    return [rng.choice(pool) for _ in range(rng.randint(low, high))]


def build_words(rng, kind):
    if kind == "rm":
        return ["rm"] + pick(rng, RM_FLAGS, 0, 3) + pick(rng, TARGETS, 0, 3)
    if kind == "trash":
        return ["trash"] + pick(rng, TRASH_FLAGS, 0, 3) + pick(rng, TARGETS, 0, 3)
    if kind == "mv":
        words = ["mv"] + pick(rng, MV_FLAGS, 0, 3) + pick(rng, TARGETS, 0, 3)
        if rng.random() < 0.6:
            words.append(rng.choice(["@ROOT@/uhome/.Trash", "~/.Trash", ".Trash", "@ROOT@/vol/.Trashes/501", "trash:/x", "@ROOT@/uhome/.local/share/Trash/files", "@ROOT@/uhome/.Trash/old", "@ROOT@/tree", "@ROOT@/work"]))
        return words
    if kind == "gio":
        return ["gio", rng.choice(GIO_VERBS)] + pick(rng, GIO_VERBS[:-1] + TARGETS, 0, 3)
    if kind == "find":
        return ["find"] + pick(rng, FIND_PIECES + TARGETS[:20], 1, 8)
    return ["xargs"] + pick(rng, XARGS_FLAGS, 0, 3) + rng.choice(DELETERS) + pick(rng, TARGETS[:30], 0, 2)


def main():
    rng = random.Random(0xD3F022 + int(os.environ.get("FUZZ_SEED", "0")))
    records = []
    with tempfile.TemporaryDirectory(prefix="fz-d3-") as temporary:
        root = os.path.realpath(temporary)
        fixture.build(root)
        GUARD.USER_HOME = root + "/uhome"
        default_temp_roots = GUARD.TEMP_ROOTS
        cwds = [None, "@ROOT@/uhome/dev/repo", "@ROOT@/uhome/dev/repo/src", "@ROOT@/uhome/dev/repo/wt", "@ROOT@/work", "@ROOT@/work/sub", "@ROOT@/repo2/app", "@ROOT@/tree", "@ROOT@/uhome", "@ROOT@/vol", "@ROOT@/missing"]
        options = [{"TEMP_ROOTS": []}, {"TEMP_ROOTS": []}, {"TEMP_ROOTS": ["@ROOT@/tree", "@ROOT@/work"]}, {"TEMP_ROOTS": [], "MAX_MATCHES": 3}, {"TEMP_ROOTS": [], "GLOB_VISITS": 12}, {"TEMP_ROOTS": [], "MAX_TRASH_SCAN": 2}, {}]
        kinds = ["rm", "rm", "trash", "mv", "gio", "find", "xargs"]
        for _ in range(7000):
            kind = rng.choice(kinds)
            words = build_words(rng, kind)
            cwd = rng.choice(cwds)
            overrides = {"USER_HOME": "@ROOT@/uhome", **rng.choice(options)}
            real = json.loads(json.dumps(overrides).replace("@ROOT@", root))
            GUARD.TEMP_ROOTS = tuple(real.get("TEMP_ROOTS", default_temp_roots))
            saved = {name: getattr(GUARD, name) for name in ("MAX_MATCHES", "GLOB_VISITS", "MAX_TRASH_SCAN")}
            for name in saved:
                if name in real:
                    setattr(GUARD, name, real[name])
            GUARD._REMOTE[0] = None
            GUARD._REMOTE_TARGETS.clear()
            GUARD._QUOTED_WORDS[0] = frozenset()
            GUARD._PENDING_ASK[0] = None
            GUARD._repository_root.cache_clear()
            real_words = [item.replace("@ROOT@", root) for item in words]
            real_cwd = cwd.replace("@ROOT@", root) if cwd else None
            try:
                getattr(GUARD, "_" + kind)(real_words, real_cwd)
                result, exception = None, None
            except Exception as error:
                result, exception = str(error).replace(root, "@ROOT@"), type(error).__name__
            ask = GUARD._PENDING_ASK[0]
            ask = ask.replace(root, "@ROOT@") if isinstance(ask, str) else ask
            for name, value in saved.items():
                setattr(GUARD, name, value)
            records.append({"fn": kind, "words": words, "cwd": cwd, "overrides": overrides, "ret": result, "exc": exception, "ask": ask})
    spec = {"directories": fixture.DIRECTORIES, "files": fixture.FILES, "links": fixture.LINKS, "worktree_files": fixture.WORKTREE_FILES, "git_repositories": fixture.GIT_REPOSITORIES}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"fixture": spec, "records": records}, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    print("fuzz command records", len(records))


if __name__ == "__main__":
    main()
