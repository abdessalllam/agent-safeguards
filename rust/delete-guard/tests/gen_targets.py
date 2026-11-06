#!/usr/bin/env python3
"""Generate delete-guard target oracle vectors."""

import importlib.machinery
import itertools
import json
from pathlib import Path
import random
import tempfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "targets.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_d2_targets", str(ROOT / "bin" / "delete-guard")).load_module()
ROWS = []


def replace(value, fixture):
    if isinstance(value, str):
        return value.replace(str(fixture), "{FIXTURE}") if fixture else value
    if isinstance(value, (list, tuple)):
        return [replace(item, fixture) for item in value]
    return value


def record(name, args, call, fixture="", remote=None, quoted=()):
    GUARD._REMOTE[0] = remote
    GUARD._REMOTE_TARGETS.clear()
    GUARD._QUOTED_WORDS[0] = frozenset(quoted)
    try:
        result = call()
        if name in {"check_remote_target", "check_target"}:
            result = [result, GUARD._REMOTE_TARGETS.copy()]
        exception = None
    except Exception as error:
        result = str(error)
        exception = type(error).__name__
    ROWS.append({"fn": name, "args": replace(args, fixture), "ret": replace(result, fixture), "exc": exception, "remote": remote, "quoted": list(quoted)})


paths = ["", ".", "..", "/", "/tmp", "/tmp/a", "/tmp/a/", "~/ci", "~/ci/a", "~/ci/a/", "~/ci/../a", "/ho" "me/a", "/ho" "me/a/b", "/ho" "me/a/b/c", "/Us" "ers/a/b/c", "/root/a", "/root/a/b", "/usr/a/b", "/srv", "/srv/a", "/srv/a/b", "/a/b", "/a/b/c", "/a//b", "/a/./b", "/a/*/b", "/a/[lang]/b", "/a/(panel)/b", "/a/é/b", "/a/a b", "/a/a\nb", "/a/$b", "trash:/x", "/a/.Trash/b"]
for path in paths:
    record("remote_literal", [path], lambda p=path: GUARD._remote_literal(p))
    record("remote_literal", [path], lambda p=path: GUARD._remote_literal(p), quoted=[path])
    record("remote_trash_protected", [path], lambda p=path: GUARD._remote_trash_protected(p))
    record("check_remote_trash_target", [path], lambda p=path: GUARD._check_remote_trash_target(p))
    for roots in [("~/ci", "/tmp"), ("/srv",), ()]:
        for verb in ["rm", "rsync"]:
            record("check_remote_target", [path, verb], lambda p=path, v=verb: GUARD._check_remote_target(p, v), remote=roots)

for value in ["", "rm /tmp/a", "rm '/tmp/a'", "rm /tmp/\\*", "rm '/tmp/[lang]'", 'rm "/tmp/[lang]"', "rm /tmp/[lang]", "rm /tmp/'[lang]'", "rm /tmp/a\\ b", "rm `echo x`", "rm '$x'", "rm \"$x\"", "rm 'broken", "rm \"broken", "a\\\nb", "a; b", "a|b", "a<b", "a&b"]:
    record("quoted_literal_words", [value], lambda v=value: sorted(GUARD._quoted_literal_words(v)))

randomizer = random.Random(20261107)
alphabet = "ab/*?[]{}()!$'\"\\ \n"
for _ in range(300):
    base = randomizer.choice(paths)
    at = randomizer.randrange(len(base) + 1)
    value = base[:at] + randomizer.choice(alphabet) + base[at:]
    paths.append(value)
    record("remote_literal", [value], lambda v=value: GUARD._remote_literal(v))
    record("remote_literal", [value], lambda v=value: GUARD._remote_literal(v), quoted=[value])
    record("quoted_literal_words", [value], lambda v=value: sorted(GUARD._quoted_literal_words(v)))

for value in ["file:/tmp/a", "file:///tmp/a", "FILE://localhost/tmp/a%20b", "file://other/tmp/a", "sftp://host/a", "trash:/a", "TRASH:/a", "abc:/x", "file:/tmp/%FF", "file:/tmp/a?x#y", "file:///tmp/%C3%A9", "file:/tmp/a%2Fb", "file:/tmp/a\nb", "file:/tmp/a\tb", "file://[bad/path", "file://[bad]/path", "file://[127.0.0.1]/x", "file://[v.bad]/x", "file://[v1.a]/x", "file://[V1.a]/x", "sftp://[bad/path", "file://／localhost/tmp", "sftp://？host/x", "file://a'／b/x", "relative/path", "", "file:/"]:
    for strict in [False, True]:
        record("location_path", [value, "rm", strict], lambda v=value, s=strict: GUARD._location_path(v, "rm", strict=s))
        record("location_path", [value, "rm", strict], lambda v=value, s=strict: GUARD._location_path(v, "rm", strict=s), remote=("/tmp",))

for value in ["", "/", "/tmp", "/tmp/a", "/boot/trash", "/boot/trash/a", "~/ci/a", ".Trash", "x/.Trash/y", "trash:/a"]:
    record("in_trash", [value], lambda v=value: GUARD._in_trash(v))
    record("check_sendable", [value], lambda v=value: GUARD._check_sendable(v))
    record("check_match_mark", [value, "rm"], lambda v=value: GUARD._check_match_mark(v, "rm"))
record("check_match_mark", ["a" + GUARD.MATCH_MARK + "b", "rm"], lambda: GUARD._check_match_mark("a" + GUARD.MATCH_MARK + "b", "rm"))

with tempfile.TemporaryDirectory(prefix="d2-targets-") as temporary:
    fixture = Path(temporary)
    for name in ["plain", "plain/inner", "holder", "holder/.Trash", "pool", "pool/ordinary", "pool/files_trashbin", "repo/.git"]:
        (fixture / name).mkdir(parents=True, exist_ok=True)
    for name in ["file", "pool/ordinary/item", "pool/files_trashbin/item", "repo/.git/HEAD"]:
        (fixture / name).write_text("x", encoding="utf-8")
    (fixture / "link").symlink_to(fixture / "plain", target_is_directory=True)
    for name in ["plain", "file", "link", "missing"]:
        path = str(fixture / name)
        record("is_folder_path", [path, "rm", "x"], lambda p=path: GUARD._is_folder_path(p, "rm", "x"), fixture)
        entry = next((entry for entry in GUARD.os.scandir(fixture) if entry.name == name), None)
        if entry:
            record("is_plain_folder", [name, "rm", "x"], lambda e=entry: GUARD._is_plain_folder(e, "rm", "x"), fixture)
    for name in ["plain", "plain/inner", "holder", "pool", "pool/ordinary", "pool/files_trashbin", "missing", "repo", "repo/.git"]:
        path = str(fixture / name)
        for recursive in [False, True]:
            record("check_resolved", [path, None, recursive, "rm"], lambda p=path, r=recursive: GUARD._check_resolved(p, None, r, "rm"), fixture)
            record("check_target", [path, None, recursive, "rm", None], lambda p=path, r=recursive: GUARD._check_target(p, None, recursive=r, verb="rm"), fixture)
    for raw in ["plain", "plain/*", "plain/*/", "holder", "pool/*", "pool/*/", "pool/**/item", "pool/[[:digit:]]*", "file", "missing", "a*", "*", "./*", "../*", "{plain,file}", "pool/{ordinary,files_trashbin}", "pool/[lang]", "pool/ordinary/item", "pool/$(echo x)", "x\x00y"]:
        for recursive in [False, True]:
            for literal in [None, True, False]:
                record("check_target", [raw, str(fixture), recursive, "rm", literal], lambda p=raw, r=recursive, l=literal: GUARD._check_target(p, str(fixture), recursive=r, verb="rm", literal=l), fixture)
    for name in ["plain", "file", "missing"]:
        path = str(fixture / name)
        record("repository_root", [path], lambda p=path: GUARD._repository_root(p), fixture)
    record("repository_root", [None], lambda: GUARD._repository_root(None), fixture)

GUARD._REMOTE[0] = None
GUARD._QUOTED_WORDS[0] = frozenset()
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(ROWS, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")

EXHAUSTIVE = OUT.parent / "exhaustive_targets.txt"
with EXHAUSTIVE.open("w", encoding="utf-8") as output:
    alphabet = "a0/~*' \n"
    for length in range(6):
        for letters in itertools.product(alphabet, repeat=length):
            value = "".join(letters)
            GUARD._QUOTED_WORDS[0] = frozenset()
            plain = GUARD._remote_literal(value)
            GUARD._QUOTED_WORDS[0] = frozenset({value})
            quoted = GUARD._remote_literal(value)
            words = sorted(GUARD._quoted_literal_words(value))
            protected = GUARD._remote_trash_protected(value)
            output.write(value.encode("utf-8").hex() + "\t" + json.dumps([plain, quoted, words, protected], separators=(",", ":")) + "\n")
