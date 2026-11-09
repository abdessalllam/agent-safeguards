#!/usr/bin/env python3
"""Generate D4 script oracle vectors from the Python guard."""

import ast
import copy
import importlib.machinery
import json
import os
from pathlib import Path
import random
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "scripts.json"
GUARD = importlib.machinery.SourceFileLoader("delete_guard_d4_scripts", str(ROOT / "bin" / "delete-guard")).load_module()
ROWS = []
PHASE = 0


def describe(error):
    text = str(error)
    return "embedded null byte" if isinstance(error, ValueError) and "null" in text else text


def replace(value, root):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, str):
        return value.replace(root, "@ROOT@").replace(str(ROOT), "@REPO@")
    if isinstance(value, (list, tuple)):
        return [replace(item, root) for item in value]
    return value


def record(name, args, root, *, shell=None):
    copied = copy.deepcopy(args)
    try:
        function = getattr(GUARD, "_" + name)
        if shell is None:
            result = function(*copy.deepcopy(args))
        else:
            result = function(*copy.deepcopy(args), shell=shell)
        if isinstance(result, bytes):
            result = result.hex()
        exception = None
    except Exception as error:
        result, exception = describe(error), type(error).__name__
    ROWS.append({"fn": name, "args": replace(copied, root), "ret": replace(result, root), "exc": exception, "shell": shell, "phase": PHASE})


with tempfile.TemporaryDirectory(prefix="d4-scripts-") as temporary:
    root = os.path.realpath(temporary)
    for name in ["u", "bin", "safe", "unsafe", "plain"]:
        (Path(root) / name).mkdir()
    GUARD.USER_HOME = root + "/u"
    GUARD.TEMP_ROOTS = (root,)
    scripts = {
        "safe.sh": "#!/bin/sh\necho okay\n",
        "danger.sh": '#!/bin/sh\nrm -rf "$1"\n',
        "plain.txt": 'rm -rf "$1"\n',
        "binary.sh": b"#!/bin/sh\n\x00rm -rf /\n",
        "vetted.sh": '#!/bin/sh\ndelete-guard check-remote "$1" || exit 3\n',
        "echo.sh": '#!/bin/sh\necho "delete-guard check-remote"\n',
        "heredoc.sh": '#!/bin/sh\ncat <<\'EOF\'\nrm -rf /\nEOF\necho done\n',
        "nested.sh": '#!/bin/sh\nsh danger.sh\n',
    }
    for name, body in scripts.items():
        (Path(root) / name).write_bytes(body if isinstance(body, bytes) else body.encode())
    tool = Path(root) / "bin" / "tool.sh"
    tool.write_text("#!/bin/sh\necho okay\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = root + "/bin" + os.pathsep + original_path
    (Path(root) / "big.sh").write_bytes(b"#!/bin/sh\n" + b"# padding\n" * 40000 + b"rm -rf /\n")
    for name in ["safe.sh", "danger.sh", "plain.txt", "binary.sh", "vetted.sh", "echo.sh", "heredoc.sh", "big.sh", "missing.sh", "safe", "u/.startup"]:
        path = root + "/" + name
        record("script_excluded", [path], root)
        record("read_regular_file", [path, 128], root)
        record("vets_deletes", [path], root)
        record("is_reviewed_script", [path, b""], root)
        for shell in [False, True]:
            record("check_script_file", [path, root], root, shell=shell)
    record("vets_deletes", [None], root)
    record("read_regular_file", [root + "/x\x00y", 12], root)
    record("read_regular_file", [root + "/safe.sh", 0], root)
    record("read_regular_file", [root + "/safe.sh", 1], root)
    record("is_reviewed_script", [str(ROOT / "bin" / "delete-guard"), (ROOT / "bin" / "delete-guard").read_bytes()], root)
    for name in ["safe.sh", "danger.sh", "plain.txt", "binary.sh", "big.sh", "missing.sh", "*.sh", "{safe,danger}.sh", "danger[1].sh"]:
        for shell in [False, True]:
            record("check_script", [name, root], root, shell=shell)
    for name in ["safe.sh", "danger.sh"]:
        record("check_script_file", [name, root], root, shell=True)
        record("check_script_file", [name, root], root, shell=True)
    (Path(root) / "safe.sh").write_text('#!/bin/sh\nrm -rf "$1"\n')
    PHASE = 1
    record("vets_deletes", [root + "/safe.sh"], root)
    record("check_script_file", ["safe.sh", root], root, shell=True)
    for name in ["safe.sh", "missing.sh", "delete-guard", "tool.sh", "x\x00y"]:
        record("search_path", [name], root)
    record("search_path", [root + "/bin/tool.sh"], root)
    record("search_path", ["safe.sh"], root)

    texts = {
        "", "cat <<'EOF'\nrm -rf /\nEOF\n", "echo x; cat <<'END'\nrm -rf /\nEND\n",
        "cat <<EOF\nrm -rf /\nEOF\n", "cat <<'EOF' | sh\nrm -rf /\nEOF\n",
        "cat <<'EOF'\ndelete-guard check-remote x\nEOF\n",
        "delete-guard check-remote /tmp/a", "delete-guard remote-preflight /tmp/a",
        'echo "delete-guard check-remote"', "CHECK='delete-guard check-remote'",
        "# delete-guard check-remote x\n", "sudo delete-guard check-remote x",
        "script=$(delete-guard check-remote x)", "echo $(delete-guard remote-preflight x)",
        "cat <<'EOF'\ntext\nEOF\nrm -rf /\n", "cat <<'EOF'\nrm -rf /\nEOF\nrm -rf /\n",
        "python3 - <<'EOF'\nx = 1\ngit clean -fdx\nEOF\n", "python3.12 - <<'EOF'\nx = 1\nEOF\nrm -rf /\n",
        "node - <<'EOF'\ntrash ~/Documents\nEOF\n", "git commit -F - <<'EOF'\ngit clean -fdx\nEOF\n",
        "gh pr create --body-file - <<'EOF'\nrm -rf /\nEOF\n", "tee notes.txt <<'EOF'\nrm -rf /\nEOF\n",
        "python3 - <<'EOF'\nimport shutil\nshutil.rmtree('/x')\nEOF\n", "python3 - <<EOF\n$(rm -rf /)\nEOF\n",
        "perl - <<'EOF'\n`rm -rf /`\nEOF\n", "bash <<'EOF'\nrm -rf /\nEOF\n", "ssh host <<'EOF'\nrm -rf /\nEOF\n",
        "python3 - <<'EOF' | sh\nrm -rf /\nEOF\n", "sudo python3 - <<'EOF'\nrm -rf /\nEOF\n",
    }
    for file in (ROOT / "tests").glob("test*.py"):
        try:
            tree = ast.parse(file.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if "<<" in text or ("delete-guard" in text and len(text) < 500):
                    texts.add(text)
    rng = random.Random(0xD4A1)
    seed = sorted(texts)
    alphabet = "ab01';|&(){}$`\\ \n\x00é"
    for _ in range(300):
        original = rng.choice(seed)
        at = rng.randrange(len(original) + 1)
        texts.add(original[:at] + rng.choice(alphabet) + original[at:])
    for text in sorted(texts):
        record("without_text_heredocs", [text], root)
        record("without_heredoc_bodies", [text], root)
        for depth in [0, 1, 3, 4]:
            record("runs_checker", [text, depth], root)

OUT.parent.mkdir(parents=True, exist_ok=True)
encoded = json.dumps(ROWS, ensure_ascii=True, separators=(",", ":"))
encoded = encoded.replace("/ho" "me/", "\\u002fhome\\u002f").replace("/Us" "ers/", "\\u002fUsers\\u002f")
OUT.write_text(encoded, encoding="utf-8")
print("scripts records", len(ROWS))
