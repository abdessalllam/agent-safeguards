#!/usr/bin/env python3
import fnmatch
import glob
import itertools
import json
import os
from pathlib import Path
import random
import tempfile

OUT = Path(__file__).resolve().parent / "vectors"
OUT.mkdir(parents=True, exist_ok=True)


def hexed(text):
    return text.encode("utf-8", "surrogatepass").hex()


def fnmatch_rows():
    rows = []
    names = ["", "a", "b", "c", "!", "-", "]", "\\", "ab", "a-", "\n", "é"]

    def emit(pattern):
        try:
            compiled = fnmatch.translate(pattern)
            del compiled
        except Exception:
            return
        for name in names:
            try:
                result = int(fnmatch.fnmatchcase(name, pattern))
            except Exception:
                continue
            rows.append("F\t%s\t%s\t%d" % (hexed(pattern), hexed(name), result))

    for length in range(6):
        for combo in itertools.product("[]!-\\abc*?", repeat=length):
            emit("".join(combo))
    for length in range(5):
        for combo in itertools.product("[]!^-\\abz*&~|", repeat=length):
            emit("".join(combo))
    rng = random.Random(0xF00D)
    alphabet = "[]!^-\\abcz*?&~|é\n a"
    for _ in range(40000):
        emit("".join(rng.choice(alphabet) for _ in range(rng.randint(6, 14))))
    (OUT / "fnmatch.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("fnmatch rows", len(rows))


def build_tree(root):
    for folder in ("a/sub/.dothidden", "b", "ab", ".hidden", "sp ace", "link-target"):
        os.makedirs(os.path.join(root, folder))
    for name in ("a/x.txt", "a/.hid", "a/y.py", "a/sub/z.txt", "a/sub/.dothidden/q", "b/x.txt", ".hidden/f", "file1", "file2", ".dot", "a[1]", "we*ird", "sp ace/in", "link-target/x.txt"):
        Path(root, name).write_text("x")
    os.symlink("a", os.path.join(root, "link_a"))
    os.symlink("file1", os.path.join(root, "link_file"))
    os.symlink("missing", os.path.join(root, "dangling"))


def iglob_records():
    records = []
    with tempfile.TemporaryDirectory(prefix="pyglob-") as temporary:
        root = os.path.realpath(temporary)
        build_tree(root)
        base = [
            "*", ".*", "a*", "a?", "?", "[ab]", "[!a]*", "[a-b]/x.txt", "a/*", "a/*/*", "*/x.txt", "*/*", "a/.*", "a/.h*", "*/", "a*/", "link_*", "link_*/",
            "link_*/x.txt", "dangling*", "missing*", "missing/*", "a/missing*", "a/sub/*", "*/sub/*", "a[1]", "a[[]1]", "we[*]ird", "sp*/", "x/y*", "a/x.txt",
            "a", "a/", "file1/*", "file1*/", "a//*", "a/./*", "a/../*", "link_a/*", "link_a/sub/*", "*/*/*", "*/*/*/*", "[", "[]", "*[", "a*/sub*", "?/x.txt",
            "a\0b*", "a\0b/*", "*/a\0b", "a*/b\0c/*", "*\0", "a/\0*", "\0", "a/b\0",
        ]
        patterns = ["@ROOT@/" + item for item in base] + ["@ROOT@", "@ROOT@/", "@ROOT@/*/", "@ROOT@//*"]
        rng = random.Random(0xBEEF)
        pieces = ["a", "b", "ab", "sub", "x.txt", ".hid", "*", "?", "[ab]", "[!a]", "link_a", "link_*", ".", "", "sp ace", "*.txt", ".*", "z*", "\0"]
        for _ in range(3000):
            patterns.append("@ROOT@/" + "/".join(rng.choice(pieces) for _ in range(rng.randint(1, 5))))
        for pattern in patterns:
            real = pattern.replace("@ROOT@", root)
            for limit in (1, 3, 100000):
                try:
                    found = list(itertools.islice(glob.iglob(real), limit))
                    records.append({"pattern": pattern, "limit": limit, "ret": [item.replace(root, "@ROOT@") for item in found], "exc": None})
                except Exception as error:
                    records.append({"pattern": pattern, "limit": limit, "ret": None, "exc": type(error).__name__})
    (OUT / "pyglob.json").write_text(json.dumps(records, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    print("iglob records", len(records))


def expanduser_records():
    records = []
    paths = ["~", "~/", "~/x", "~/x/", "~root", "~root/x", "~nosuchuser_zz", "~nosuchuser_zz/a", "~\n", "~a\0b", "~a\0b/x", "x~", "", "~~", "~/~", "~ ", "~é/x", "~//x", "/~", "~."]
    original = os.environ.get("HOME")
    try:
        for home in (None, "", "/h", "/h/", "/h//", "/"):
            if home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = home
            for path in paths:
                try:
                    records.append({"home": home, "path": path, "ret": os.path.expanduser(path), "exc": None})
                except Exception as error:
                    records.append({"home": home, "path": path, "ret": None, "exc": type(error).__name__})
    finally:
        if original is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original
    (OUT / "expanduser.json").write_text(json.dumps(records, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    print("expanduser records", len(records))


fnmatch_rows()
iglob_records()
expanduser_records()
