#!/usr/bin/env python3
import json
from pathlib import Path
import re
import unicodedata

OUT = Path(__file__).resolve().parent / "vectors"
OUT.mkdir(parents=True, exist_ok=True)


def ranges(pattern):
    compiled = re.compile(pattern)
    return ranges_where(lambda code: compiled.fullmatch(chr(code)) is not None)


def ranges_where(test):
    found = []
    start = None
    for code in range(0x110000):
        if 0xD800 <= code <= 0xDFFF:
            hit = False
        else:
            hit = test(code)
        if hit and start is None:
            start = code
        if not hit and start is not None:
            found.append([start, code - 1])
            start = None
    if start is not None:
        found.append([start, 0x10FFFF])
    return found


document = {name: ranges(pattern) for name, pattern in (("s", r"\s"), ("w", r"\w"), ("d", r"\d"))}
document["unassigned"] = ranges_where(lambda code: unicodedata.category(chr(code)) == "Cn")
(OUT / "pyre_classes.json").write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
print({name: len(value) for name, value in document.items()})
