#!/usr/bin/env python3
"""Generate delete-guard glob oracle vectors."""

import importlib.machinery
import itertools
import json
from pathlib import Path
import random
import tempfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "globs.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_d2_globs", str(ROOT / "bin" / "delete-guard")).load_module()
ROWS = []


def replace(value, fixture):
    if isinstance(value, str):
        return value.replace(str(fixture), "{FIXTURE}") if fixture else value
    if isinstance(value, list):
        return [replace(item, fixture) for item in value]
    return value


def record(name, args, call, fixture=""):
    try:
        result = call()
        exception = None
    except Exception as error:
        result = None
        exception = type(error).__name__
    ROWS.append({"fn": name, "args": replace(args, fixture), "ret": replace(result, fixture), "exc": exception})


patterns = ["", "*", "?", "**", "a[b-d]?", "[!a]*", "[^a]*", "[]x]", "\\*a", "a[", "[z-a]", "a.b", "*a*b*", "*a*a*ab", "[[:digit:]]x", "[[:alpha:]]*", "[^[:upper:][:digit:]]*", "[[:bogus:]]*", "[[:punct:]]*", "[[:space:]]", "é?", "[αβ]", "[[:cntrl:]]", "[[:word:]]"]
names = ["", "a", "acx", "aex", "bcd", "abc", "]", "*a", "ba", "a[", "a.b", "axb", "xxaxxbxx", "aaaaaaaab", "aaaaaaaac", "7x", "ax", "éx", "α", "\n", "\x1c", ".hidden"]
randomizer = random.Random(20261107)
alphabet = "ab*?[]!^-:éα0 \n"
for _ in range(400):
    base = randomizer.choice(patterns)
    at = randomizer.randrange(len(base) + 1)
    patterns.append(base[:at] + randomizer.choice(alphabet) + base[at:])
    name = randomizer.choice(names)
    at = randomizer.randrange(len(name) + 1)
    names.append(name[:at] + randomizer.choice(alphabet) + name[at:])

probes = ["a", "0", "-", "[", "]", " ", "\n", "\x1c", "é", "α", "*"]
for pattern in patterns:
    def encoded():
        tokens = GUARD._glob_tokens(pattern)
        return [[kind, value if kind == "lit" else [GUARD._glob_token_matches(token, probe) for probe in probes] if kind == "set" else ""] for token in tokens for kind, value in [token]]
    record("glob_tokens", [pattern], encoded)
    for name in names[:35] + randomizer.sample(names, 20):
        record("glob_match", [pattern, name], lambda p=pattern, n=name: GUARD._glob_match(GUARD._glob_tokens(p), n))
    try:
        tokens = GUARD._glob_tokens(pattern)
    except Exception:
        continue
    for index, token in enumerate(tokens):
        for probe in probes:
            record("glob_token_matches", [pattern, index, probe], lambda t=token, p=probe: GUARD._glob_token_matches(t, p))

with tempfile.TemporaryDirectory(prefix="d2-globs-") as temporary:
    fixture = Path(temporary)
    for name in ["pool", "pool/one", "pool/one/two", "pool/.hidden", "pool/files_trashbin", "pool/UPPER", "pool/123", "empty", "holder", "holder/.local/share/Trash"]:
        (fixture / name).mkdir(parents=True, exist_ok=True)
    for name in ["pool/one/record", "pool/one/two/record", "pool/files_trashbin/record", "pool/UPPER/record", "pool/123/record", "pool/.hidden/record", "file", "holder/.local/share/Trash/record"]:
        (fixture / name).write_text("x", encoding="utf-8")
    (fixture / "link").symlink_to(fixture / "pool", target_is_directory=True)
    (fixture / "dangling").symlink_to(fixture / "missing", target_is_directory=True)
    for name in ["pool", "pool/one", "pool/files_trashbin", "holder", "holder/.local/share", "empty", "file", "missing"]:
        path = str(fixture / name)
        record("holds_trash", [path], lambda p=path: GUARD._holds_trash(p), fixture)
    for name in ["pool", "file", "link", "dangling"]:
        entry = next(entry for entry in GUARD.os.scandir(fixture) if entry.name == name)
        record("is_folder", [name], lambda e=entry: GUARD._is_folder(e), fixture)
    for name in ["pool", "empty", "file", "missing"]:
        path = str(fixture / name)
        for limit in [0, 1, 3, 100]:
            def entries_case(p=path, n=limit):
                visits = [n]
                found = GUARD._glob_entries(p, visits, "rm", "x")
                return [[entry.name for entry in found], visits[0]]
            record("glob_entries", [path, limit, "rm", "x"], entries_case, fixture)
    cases = [(["pool", "**", "record"], False), (["pool", "**"], False), (["pool", "**"], True), (["pool", "*"], False), (["pool", "*"], True), (["pool", "[[:digit:]]*"], False), (["missing", "*"], False), (["link", "**", "record"], False)]
    for parts, folders_only in cases:
        for limit in [0, 2, 1000]:
            def walk_case(p=parts, only=folders_only, n=limit):
                found, visits = [], [n]
                GUARD._glob_walk(str(fixture), p, found, visits, "rm", "x", only)
                return [found, visits[0]]
            record("glob_walk", [str(fixture), parts, limit, "rm", "x", folders_only], walk_case, fixture)
    for raw in ["pool/*", "pool/*/", "pool/**/record", "pool/**/", "pool/[[:digit:]]*", "pool/[^t]*", "pool/.h*", "missing/*", "file/*", "pool/ordinary", "", "*", "[z-a]"]:
        record("glob_matches", [raw, str(fixture), "rm"], lambda p=raw: GUARD._glob_matches(p, str(fixture), "rm"), fixture)
        record("glob_matches", [raw, None, "rm"], lambda p=raw: GUARD._glob_matches(p, None, "rm"), fixture)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(ROWS, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")

EXHAUSTIVE = OUT.parent / "exhaustive_globs.txt"
with EXHAUSTIVE.open("w", encoding="utf-8") as output:
    alphabet = "a0*?[]!- \n"
    for length in range(6):
        for letters in itertools.product(alphabet, repeat=length):
            pattern = "".join(letters)
            try:
                tokens = GUARD._glob_tokens(pattern)
                result = [GUARD._glob_match(tokens, name) for name in ("", "a", "0", "]", "é")]
                error = None
            except Exception as exception:
                result = None
                error = type(exception).__name__
            output.write(pattern.encode("utf-8").hex() + "\t" + json.dumps([result, error], separators=(",", ":")) + "\n")

with EXHAUSTIVE.open("a", encoding="utf-8") as output:
    import random as _random

    rng = _random.Random(0x6106)
    longer = ["[z-z--c]", "[--a]", "[a--]", "[!--]", "[^-a-]", "[a-z-0]", "[[:alpha:]-z]", "[]-a]", "[a-\\]]"]
    for _ in range(30000):
        longer.append("".join(rng.choice("[]!^-az0:\\*?é") for _ in range(rng.randint(5, 12))))
    for pattern in longer:
        try:
            tokens = GUARD._glob_tokens(pattern)
            result = [GUARD._glob_match(tokens, name) for name in ("", "a", "0", "]", "é")]
            error = None
        except Exception as exception:
            result = None
            error = type(exception).__name__
        output.write(pattern.encode("utf-8").hex() + "\t" + json.dumps([result, error], separators=(",", ":")) + "\n")
