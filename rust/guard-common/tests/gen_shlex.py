"""Generate shlex vectors from CPython 3.12 and the guard call sites."""

import ast
import json
import random
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "vectors" / "shlex.json"


def record(rows, name, args, call):
    try:
        ret = call()
        exc = None
    except ValueError as error:
        ret = str(error)
        exc = "ValueError"
    rows.append({"fn": name, "args": args, "ret": ret, "exc": exc})


def tokens(text, posix, punctuation, whitespace, whitespace_split, commenters):
    lexer = shlex.shlex(text, posix=posix, punctuation_chars=punctuation)
    lexer.whitespace = whitespace
    lexer.whitespace_split = whitespace_split
    lexer.commenters = commenters
    return list(lexer)


def command_strings():
    found = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if 0 < len(text) <= 400 and any(ch in text for ch in " \t\n'\"\\$|&;<>#`"):
                    found.append(text)
    return found


def mutations(base, count, rng):
    alphabet = list(" abcdefghijklmnop'\"\\$|&;<>#`()[]{}\t\n\r*") + ["é", "你"]
    out = []
    for text in base:
        chars = list(text)
        for _ in range(count):
            if not chars:
                chars = ["a"]
            kind = rng.randrange(3)
            if kind == 0:
                chars.insert(rng.randrange(len(chars) + 1), rng.choice(alphabet))
            elif kind == 1 and chars:
                del chars[rng.randrange(len(chars))]
            elif len(chars) >= 2:
                left = rng.randrange(len(chars))
                right = rng.randrange(len(chars))
                chars[left], chars[right] = chars[right], chars[left]
            out.append("".join(chars))
    return out


def main():
    rows = []
    fixed = [
        "",
        " ",
        "   ",
        "a",
        "a b",
        "a  b\tc",
        "a\nb",
        "a\n\nb",
        "echo 'a b'",
        'echo "a b"',
        'echo "a\\"b"',
        "echo 'a\\'b'",
        "a && b",
        "a||b",
        "a;;b",
        "((a))",
        "a\\\nb",
        "a\\ b",
        '"unterminated',
        "\\",
        "a '' \"\"",
        "$HOME",
        "a >&2",
        "a 2>&1",
        "café",
        "a#b",
        "# comment\nnext",
        "a 'b\nc' d",
        "x y\r\nz",
        "a|&b",
        ";;",
        "&&",
        "||",
        "((",
        "))",
        "\n\n",
        "a\tb",
        "你 好",
        "a\x00b",
        "'",
        '"',
        "''",
        '""',
        "a 'b",
        "\\ ",
        "a\\",
        "a\\\\b",
        "'a''b'",
        "a>&b",
        "2>out",
        "a # c\nb",
        "a\tb\rc",
        "((echo))",
        "a;b|c&d",
        "a\n;b",
        "$*",
        "a~b",
        "a=b",
        "a/b",
    ]
    corpus = []
    seen = set()
    for text in fixed + command_strings():
        if text not in seen and len(text) <= 400:
            seen.add(text)
            corpus.append(text)
    rng = random.Random(20261105)
    seeds = corpus[:80] if len(corpus) > 80 else corpus
    for text in mutations(seeds, 3, rng):
        if text not in seen and len(text) <= 400:
            seen.add(text)
            corpus.append(text)
        if len(corpus) >= 1800:
            break
    configs = [
        (True, ";&|()\n", " \t\r", True, ""),
        (True, ";&|", " \t\r", True, ""),
        (True, "", " \t\r\n", True, ""),
        (True, ";&|()\n", " \t\r\n", True, "#"),
        (False, "", " \t\r\n", False, "#"),
        (True, "();<>|&", " \t\r\n", False, "#"),
    ]
    for text in corpus:
        record(rows, "quote", [text], lambda text=text: shlex.quote(text))
        record(rows, "split", [text], lambda text=text: shlex.split(text))
        for posix, punctuation, whitespace, whitespace_split, commenters in configs:
            args = [{
                "text": text,
                "posix": posix,
                "punctuation_chars": punctuation,
                "whitespace": whitespace,
                "whitespace_split": whitespace_split,
                "commenters": commenters,
            }]
            record(
                rows,
                "tokens",
                args,
                lambda text=text, posix=posix, punctuation=punctuation, whitespace=whitespace, whitespace_split=whitespace_split, commenters=commenters: tokens(
                    text, posix, punctuation, whitespace, whitespace_split, commenters
                ),
            )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"shlex rows {len(rows)} commands {len(corpus)}")


if __name__ == "__main__":
    main()
