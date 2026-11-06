#!/usr/bin/env python3
import importlib.machinery
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "fuzz_targets.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_fuzz_targets", str(ROOT / "bin" / "delete-guard")).load_module()

DIRECTORIES = [
    "uhome/dev/repo/src/deep", "uhome/dev/repo/node_modules/pkg", "uhome/dev/repo/build", "uhome/dev/plain/inner", "uhome/.Trash/old", "uhome/Documents/notes", "work/sub",
    "repo2/app", "vol/.Trashes/501", "vol/files", "vol/inner/.git", "tree/a/b/c", "tree/.hidden", "tree/ab", "uhome/dev/repo/.git/hooks",
]
FILES = [
    "uhome/dev/repo/src/main.rs", "uhome/dev/repo/src/deep/x.txt", "uhome/dev/repo/README", "uhome/dev/plain/inner/f", "uhome/.Trash/old/gone", "uhome/Documents/notes/n.txt", "work/w.txt",
    "repo2/app/main.py", "vol/files/f", "tree/a/b/c/leaf", "tree/a/top", "tree/ab/z", "tree/.hidden/h", "tree/file1", "tree/file2", "tree/a[1]",
]
LINKS = [("uhome/dev/repo/link_out", "../plain"), ("uhome/dev/link_repo", "repo"), ("tree/link_a", "a"), ("tree/dangling", "missing")]
GIT_REPOSITORIES = ["uhome/dev/repo", "repo2"]
WORKTREE_FILES = {"uhome/dev/repo/wt/.git": "gitdir: ../.git/worktrees/wt\n"}


def build(root):
    for name in DIRECTORIES:
        os.makedirs(os.path.join(root, name), exist_ok=True)
    for name in FILES:
        os.makedirs(os.path.dirname(os.path.join(root, name)), exist_ok=True)
        Path(root, name).write_text("x")
    for name, target in LINKS:
        os.symlink(target, os.path.join(root, name))
    for name, text in WORKTREE_FILES.items():
        os.makedirs(os.path.dirname(os.path.join(root, name)), exist_ok=True)
        Path(root, name).write_text(text)
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    for name in GIT_REPOSITORIES:
        subprocess.run(["git", "init", "-q", os.path.join(root, name)], check=True, env=environment, stdin=subprocess.DEVNULL, capture_output=True)


def main():
    rng = random.Random(0xD2F022 + int(os.environ.get("FUZZ_SEED", "0")))
    records = []
    with tempfile.TemporaryDirectory(prefix="fz-d2-") as temporary:
        root = os.path.realpath(temporary)
        build(root)
        GUARD.USER_HOME = root + "/uhome"
        default_temp_roots = GUARD.TEMP_ROOTS
        raws = [
            "src", "src/main.rs", "src/*", "src/**", "**/*.rs", "*", ".*", "*/", "../plain", "../plain/*", "../work", "link_out", "link_out/*", "build", "build/", "node_modules", "node_modules/*",
            ".git", ".git/", ".git/hooks", ".git/*", "wt", "wt/*", "README", "RE*", "[R]EADME", "missing", "missing/*", "~", "~/", "~/dev/repo", "~/dev/repo/*", "~/.Trash", "~/.Trash/*",
            "~/Documents", "~/Documents/*", "$HOME", "$HOME/dev/repo", "${HOME}/dev/plain/*", "{src,build}", "{src,build}/*", "{a,b", "a{1,2}b", "../repo2", "../../repo2/app",
            "@ROOT@/uhome/dev/repo", "@ROOT@/uhome/dev/repo/src", "@ROOT@/uhome/dev/repo/*", "@ROOT@/uhome/dev/plain", "@ROOT@/uhome/dev/plain/*", "@ROOT@/uhome", "@ROOT@/uhome/*", "@ROOT@/vol", "@ROOT@/vol/*",
            "@ROOT@/vol/.Trashes", "@ROOT@/vol/.Trashes/501", "@ROOT@/vol/inner", "@ROOT@/tree", "@ROOT@/tree/*", "@ROOT@/tree/a*", "@ROOT@/tree/a/*/*", "@ROOT@/tree/a/**",
            "@ROOT@/tree/a[1]", "@ROOT@/tree/a[[]1]", "@ROOT@/tree/.*", "@ROOT@/tree/link_a/*", "@ROOT@/tree/link_*", "@ROOT@/tree/dangling*", "@ROOT@/repo2", "@ROOT@/repo2/app", "@ROOT@/work/*",
            "@ROOT@/uhome/dev/repo/wt", "@ROOT@/uhome/dev/repo/wt/*", "/", "/*", "/etc", "/etc/*", "/tmp", "/tmp/*", "/tmp/x*", "/var/folders/*", "/usr/local/bin/*", "x\x00y", "src/\x00*", "\x00*",
            "@ROOT@/tree/*\x00", "@ROOT@/tree/\x00/*", "@ROOT@/uhome/.Trash", "@ROOT@/uhome/.Trash/*", "@ROOT@/uhome/.Trash/old/gone",
        ]
        cwds = [None, "@ROOT@/uhome/dev/repo", "@ROOT@/uhome/dev/repo/src", "@ROOT@/uhome/dev/repo/src/deep", "@ROOT@/uhome/dev/repo/wt", "@ROOT@/work", "@ROOT@/work/sub", "@ROOT@/repo2/app", "@ROOT@/tree", "@ROOT@/uhome", "@ROOT@/vol", "@ROOT@/vol/inner", "@ROOT@/missing"]
        overrides_options = [
            {"TEMP_ROOTS": []},
            {"TEMP_ROOTS": []},
            {"TEMP_ROOTS": ["@ROOT@/tree", "@ROOT@/work"]},
            {"TEMP_ROOTS": [], "MAX_MATCHES": 3},
            {"TEMP_ROOTS": [], "GLOB_VISITS": 12},
            {"TEMP_ROOTS": [], "MAX_TRASH_SCAN": 2},
            {},
        ]
        for _ in range(7000):
            raw = rng.choice(raws)
            if rng.random() < 0.15:
                raw = raw + rng.choice(["*", "/", "?", "/*", "x", "\n", "[a-z]", "{1,2}"])
            cwd = rng.choice(cwds)
            recursive = rng.random() < 0.6
            literal = rng.choice([None, None, True, False])
            overrides = {"USER_HOME": "@ROOT@/uhome", **rng.choice(overrides_options)}
            real_overrides = json.loads(json.dumps(overrides).replace("@ROOT@", root))
            GUARD.TEMP_ROOTS = tuple(real_overrides.get("TEMP_ROOTS", default_temp_roots))
            saved = {name: getattr(GUARD, name) for name in ("MAX_MATCHES", "GLOB_VISITS", "MAX_TRASH_SCAN")}
            for name in saved:
                if name in real_overrides:
                    setattr(GUARD, name, real_overrides[name])
            GUARD._REMOTE[0] = None
            GUARD._REMOTE_TARGETS.clear()
            GUARD._QUOTED_WORDS[0] = frozenset()
            GUARD._repository_root.cache_clear()
            real_raw = raw.replace("@ROOT@", root)
            real_cwd = cwd.replace("@ROOT@", root) if cwd else None
            try:
                GUARD._check_target(real_raw, real_cwd, recursive=recursive, verb="rm", literal=literal)
                result, exception = None, None
            except Exception as error:
                result, exception = str(error).replace(root, "@ROOT@"), type(error).__name__
            for name, value in saved.items():
                setattr(GUARD, name, value)
            records.append({"fn": "check_target", "raw": raw, "cwd": cwd, "recursive": recursive, "literal": literal, "overrides": overrides, "ret": result, "exc": exception})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    spec = {"directories": DIRECTORIES, "files": FILES, "links": LINKS, "worktree_files": WORKTREE_FILES, "git_repositories": GIT_REPOSITORIES}
    OUT.write_text(json.dumps({"fixture": spec, "records": records}, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    print("fuzz target records", len(records))


main()
