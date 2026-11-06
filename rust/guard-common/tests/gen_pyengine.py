#!/usr/bin/env python3
import json
import os
from pathlib import Path
import random
import re
import warnings

warnings.simplefilter("ignore")
OUT = Path(__file__).resolve().parent / "vectors" / "pyengine.json"
SEED = int(os.environ.get("FUZZ_SEED", "0"))
rng = random.Random(0x9E0 + SEED)
ALPHABET = list("abcABC01 -_.\n") + ["é", "É", "İ", "ı", "K", "ſ", "k", "K", "s", "S", "i", "I", "\x1c", "雪"]
SPECIAL = set("\\.^$*+?{}[]|()-")


def literal():
    char = rng.choice(ALPHABET)
    if char in SPECIAL:
        return "\\" + char
    if char == "\n":
        return rng.choice(["\\n", "\n"])
    if char in " #":
        return "\\" + char if rng.random() < 0.5 else char
    return char


def set_item():
    kind = rng.random()
    if kind < 0.15:
        return rng.choice(["\\d", "\\s", "\\w", "\\D", "\\S", "\\W"])
    if kind < 0.45:
        low = rng.choice("abc01")
        high = rng.choice("abcz19")
        return low + "-" + high if low <= high else high + "-" + low
    char = rng.choice(ALPHABET)
    if char in "\\]^-[":
        return "\\" + char
    return char


def char_set():
    items = "".join(set_item() for _ in range(rng.randint(1, 4)))
    return "[" + ("^" if rng.random() < 0.3 else "") + items + "]"


def fixed_atom():
    kind = rng.random()
    if kind < 0.5:
        return literal()
    if kind < 0.65:
        return "."
    if kind < 0.85:
        return char_set()
    return rng.choice(["\\d", "\\s", "\\w", "\\D", "\\S", "\\W"])


def fixed_sequence():
    return "".join(fixed_atom() for _ in range(rng.randint(1, 3)))


class Builder:
    def __init__(self):
        self.groups = 0

    def expression(self, depth):
        branches = [self.sequence(depth) for _ in range(rng.choice([1, 1, 1, 2, 3]))]
        return "|".join(branches)

    def sequence(self, depth):
        return "".join(self.piece(depth) for _ in range(rng.randint(1, 4)))

    def quantifier(self):
        kind = rng.random()
        if kind < 0.5:
            return ""
        base = rng.choice(["*", "+", "?", "{2}", "{0,2}", "{1,3}", "{2,}", "{,2}", "{0}"])
        return base + ("?" if rng.random() < 0.3 else "")

    def piece(self, depth):
        kind = rng.random()
        if kind < 0.06:
            return rng.choice(["^", "$", "\\b", "\\B", "\\A", "\\Z"])
        if kind < 0.16 and depth < 3:
            body = self.expression(depth + 1)
            return rng.choice(["(?=", "(?!"]) + body + ")"
        if kind < 0.22 and depth < 3:
            return rng.choice(["(?<=", "(?<!"]) + fixed_sequence() + ")"
        if kind < 0.40 and depth < 3:
            self.groups += 1
            opener = "(" if rng.random() < 0.6 else "(?:"
            if opener == "(":
                inner = self.expression(depth + 1)
                return opener + inner + ")" + self.quantifier()
            return opener + self.expression(depth + 1) + ")" + self.quantifier()
        if kind < 0.44 and self.groups:
            return "\\" + str(rng.randint(1, min(self.groups, 3)))
        return fixed_atom() + self.quantifier()


def text_pool(pattern):
    pieces = [char for char in re.sub(r"[\\\[\](){}|*+?^$]", "", pattern)] or list("ab")
    texts = set()
    for _ in range(9):
        pool = pieces if rng.random() < 0.6 else ALPHABET
        texts.add("".join(rng.choice(pool) for _ in range(rng.randint(0, 11))))
    texts.add("")
    return sorted(texts)


def pack(found):
    if found is None:
        return None
    return [found.start(), found.end(), [None if group is None else [found.start(index + 1), found.end(index + 1)] for index, group in enumerate(found.groups())]]


def main():
    records = []
    attempts = 0
    while len(records) < 6000 and attempts < 40000:
        attempts += 1
        builder = Builder()
        pattern = builder.expression(0)
        prefix = rng.choice(["", "", "", "", "(?i)", "(?s)", "(?m)", "(?is)", "(?im)", "(?x)"])
        source = prefix + pattern
        try:
            compiled = re.compile(source)
        except (re.error, RecursionError, OverflowError):
            continue
        cases = []
        for text in text_pool(pattern):
            try:
                cases.append({"text": text, "search": pack(compiled.search(text)), "match": pack(compiled.match(text)), "fullmatch": pack(compiled.fullmatch(text)), "finditer": [pack(item) for item in compiled.finditer(text)]})
            except RecursionError:
                continue
        records.append({"pattern": source, "cases": cases})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(records, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    print("pyengine patterns", len(records), "cases", sum(len(item["cases"]) for item in records))


if __name__ == "__main__":
    main()
