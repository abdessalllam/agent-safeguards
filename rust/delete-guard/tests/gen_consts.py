#!/usr/bin/env python3
"""Record delete-guard constant and regex oracle vectors."""

import ast
import glob
import importlib.machinery
import json
import os
import random

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "consts.json")
MODULE = importlib.machinery.SourceFileLoader("delete_guard_vectors", os.path.join(REPO, "bin", "delete-guard")).load_module()

REGEXES = [
    "QUICK_SCAN",
    "INLINE_RECURSIVE_DELETE",
    "ERASE_TOOL",
    "TRASH_FOLDER",
    "TRASH_HOME_FOLDER",
    "TRASH_URI",
    "TRASH_EMPTY_TOOL",
    "KDE_TRASH_TOOL",
    "KIO_TOOL",
    "TRASH_FILE_NAME",
    "LOCATION_SCHEME",
    "FIND_NEWER_PREDICATE",
    "FINDER_TEXT",
    "WINDOWS_TEXT",
    "REMOTE_UNSAFE_PATH",
    "REMOTE_UNSAFE_AFTER_QUOTES",
    "REMOTE_COMMAND_PATTERN",
    "VETTED_MENTION",
    "SCRIPT_HINT",
    "QUOTED_TILDE",
    "FUNCTION_HEADER",
    "TEXT_HEREDOC_OWNER",
    "TEXT_HEREDOC_TAIL",
    "SHELL_SHEBANG",
    "DISKUTIL_ERASE",
]
COLLECTIONS = [
    "BASH_SINGLE_DASH_LONG",
    "DEFAULT_REMOTE_ROOTS",
    "ETC_PATHS",
    "FIND_EXEC_PREDICATES",
    "FIND_GLOBAL_OPTIONS",
    "FIND_VALUE_PREDICATES",
    "GIO_DELETE_VERBS",
    "HADOOP_PURGE_OPTIONS",
    "HOOK_EVENTS",
    "INTERPRETERS",
    "KIO_COMMANDS",
    "KIO_REMOVE_VERBS",
    "MOSH_FLAG_LETTERS",
    "MOSH_LONG_FLAGS",
    "MOSH_LONG_VALUES",
    "MOSH_VALUE_LETTERS",
    "MOUNT_PARENTS",
    "POSIX_CLASSES",
    "POSIX_CLASSES_ASCII",
    "RELAXED_CHARACTERS",
    "REMOTE_COMMAND_NAMES",
    "REMOTE_HOME_PARENTS",
    "REMOTE_TRASH_SYSTEM_TREES",
    "RM_LONG_OPTIONS",
    "RSYNC_VALUE_LETTERS",
    "RSYNC_VALUE_OPTIONS",
    "SHELLS",
    "SHELL_LONG_WITH_VALUE",
    "SSH_FLAG_LETTERS",
    "SSH_VALUE_LETTERS",
    "STDIN_OPERATORS",
    "SYSTEM_PROGRAM_FOLDERS",
    "SYSTEM_ROOTS",
    "SYSTEM_ROOT_PATHS",
    "TEMP_ROOTS",
    "TRASH_TOOLS",
    "TRASH_VALUE_OPTIONS",
    "VETTED_COMMANDS",
    "WINDOWS_SHELLS",
    "XARGS_DELETERS",
    "XARGS_LONG_OPTIONS",
    "XARGS_SHORT_VALUES",
]
SCALARS = [
    "TOOL_NAME",
    "GIT_PATH",
    "MAX_INPUT_BYTES",
    "MAX_TRASH_SCAN",
    "MAX_MATCHES",
    "MATCH_MARK",
    "GLOB_VISITS",
    "HOOK_BUDGET_SECONDS",
    "MAX_SCRIPT_BYTES",
    "MAX_SCRIPT_DEPTH",
]


def normalize(value):
    if isinstance(value, dict):
        return [[key, item] for key, item in sorted(value.items())]
    if isinstance(value, (set, frozenset, tuple, list)):
        return sorted(value)
    return value


def literals():
    paths = sorted(glob.glob(os.path.join(REPO, "tests", "test_delete_guard*.py")))
    paths += sorted(glob.glob(os.path.join(REPO, "tests", "test_bypasses.py")))
    paths += sorted(glob.glob(os.path.join(REPO, "tests", "test_review_*_fixes.py")))
    found = set()
    for path in paths:
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 2000:
                found.add(node.value)
    return found


def boundaries():
    window = "x" * 1500
    over = "x" * 1501
    return [
        "",
        " ",
        "\n",
        "\t",
        "a",
        "A",
        "/",
        ".",
        "~",
        "~/ci",
        "/tmp",
        "rm",
        "rm ",
        "rm -rf",
        "rm -f",
        "rm -R",
        "rm\t-r",
        "rmtree",
        "removedirs",
        "rmSync",
        "rmdirSync",
        "remove_dir_all",
        "rm_rf",
        "xx rmtree yy",
        "fs.rm(recursive: true)",
        "fs.rm(recursive:false)",
        "fs.rm(recursive: false)",
        "fs.rm(recursive: 0)",
        "fs.rm(recursive: null)",
        "fs.rm(recursive: undefined)",
        "fs.rm(recursive: undefinedx)",
        "fs.rm(recursive: falsehood)",
        ".rm(recursive: yes)",
        ".rm(recursive: false, recursive: true)",
        ".rm(  recursive: true)",
        ".rm(\nrecursive: true)",
        ".rm(recursive : true)",
        ".rm(xrecursive: true)",
        ".rm(" + window + "recursive: true)",
        ".rm(" + over + "recursive: true)",
        "mkfs",
        "mkfs.ext4",
        "newfs_hfs",
        "shred",
        "srm.1",
        ".Trash",
        ".trash",
        ".Trashes",
        ".Trash-501",
        "$Recycle.Bin",
        "RECYCLER",
        "recycler",
        "Recycled",
        ".recycle",
        ".trashed-1",
        ".local/share/Trash",
        ".local/share/Trash\n",
        ".local/share/Trash/",
        ".local/share/Trash\n\n",
        "x/.local/share/Trash",
        "x/.local/share/Trash\n",
        "x/.local/share/Trash\nbar",
        "trash:",
        "TRASH:",
        "trash-empty",
        "trash-rm2",
        "ktrash6",
        "kioclient5",
        "file:/tmp",
        "FILE:/tmp",
        "-newerXY",
        "-neweraa",
        "EMPTY",
        "empty",
        "Trash",
        "recycle",
        "RECYCLE",
        "$",
        "`",
        "*",
        "?",
        "[",
        "]",
        "{",
        "}",
        "!",
        "&",
        "|",
        "<",
        ">",
        "(",
        ")",
        "'",
        '"',
        " ",
        "\x00",
        "\x1c",
        "\x1f",
        "\u00a0",
        "ssh",
        "ssh-foo",
        "ssh_foo",
        " ssh",
        " ssh ",
        "ssh",
        " ssh\n",
        "x ssh y",
        ' "ssh"',
        " sh",
        " sshmore",
        " time ",
        "xargs\n",
        ".sh",
        "a/.sh",
        "cmd.sh\n",
        "foo.sh ",
        "foo.shx",
        "(ssh",
        ";bash ",
        ' ssh"',
        ' command" next',
        "\nssh ",
        "timeout ",
        "|sh ",
        " ssh_",
        " ssh-foo ",
        " fish\n",
        "source ",
        ". ",
        " . ",
        "ksh\t",
        "delete-guard check-remote",
        "delete-guard' remote-preflight",
        'delete-guard" check-remote',
        "#!/bin/sh",
        "#!/usr/bin/env bash",
        "#! /bin/zsh",
        "#!/bin/dash\n",
        "erase",
        "EraseDisk",
        "apfs",
        "APFS",
        "zero",
        "secureErase",
        "function f {",
        "f() {",
        "f(){",
        "name () {",
        "cat",
        "  cat",
        "cat file",
        "|",
        "$(",
        "<(",
        "~",
        " '~",
        '\\~',
        "~'",
        "echo '~'",
        "é",
        "你",
        "α",
        "café.sh",
        "a" * 300,
        "rm -rf " + "a" * 200,
        "clear-recyclebin",
        "Clear-RecycleBin",
        "xxclear-recyclebinyy",
        "mkfs_ext4",
        "cmd.exe",
        "powershell",
        "hadoop",
        "hdfs",
        "osascript",
        "gio",
        "diskutil",
        "dd",
        "unlink",
        "rmdir",
        "mv",
        "find",
        "xargs",
        "clean",
        "rsync",
    ]


def mutations(base):
    alphabet = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-./\\$@#%^&*()[]{}|;:'\",<>?~`!\n\t")
    alphabet += ["é", "你", "α", "\u00a0", "\u001c"]
    rng = random.Random(20261105)
    seeds = [item for item in base if 0 < len(item) <= 80]
    rng.shuffle(seeds)
    out = []
    for text in seeds[:120]:
        chars = list(text)
        if not chars:
            continue
        kind = rng.randrange(3)
        if kind == 0:
            chars.insert(rng.randrange(len(chars) + 1), rng.choice(alphabet))
        elif kind == 1 and len(chars) > 1:
            del chars[rng.randrange(len(chars))]
        elif len(chars) > 1:
            left = rng.randrange(len(chars) - 1)
            chars[left], chars[left + 1] = chars[left + 1], chars[left]
        out.append("".join(chars))
    return out


def main():
    corpus = sorted(literals() | set(boundaries()) | set(mutations(list(literals()) + boundaries())))
    records = []
    for name in SCALARS:
        records.append({"fn": name, "args": [], "ret": getattr(MODULE, name), "exc": None})
    for name in COLLECTIONS:
        records.append({"fn": name, "args": [], "ret": normalize(getattr(MODULE, name)), "exc": None})
    for text in corpus:
        for name in REGEXES:
            compiled = getattr(MODULE, name)
            for method in ("search", "match", "fullmatch"):
                found = getattr(compiled, method)(text)
                ret = None if found is None else [found.start(), found.end()]
                records.append({"fn": name + "." + method, "args": [text], "ret": ret, "exc": None})
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(records, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write("\n")
    print("records", len(records), "corpus", len(corpus))


if __name__ == "__main__":
    main()
