"""Build message() oracle vectors. Prints counts only."""

import itertools
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
os.environ.pop("AGENT_SAFEGUARDS_LOCALE", None)

from agent_safeguards.common import message

OUT = Path(__file__).resolve().parent / "vectors" / "locale.json"
CATALOG = json.loads((ROOT / "locales" / "en.json").read_text())


def fields_of(template):
    found = []
    index = 0
    while index < len(template):
        if template.startswith("{{", index) or template.startswith("}}", index):
            index += 2
            continue
        if template[index] == "{":
            end = template.find("}", index)
            if end < 0:
                break
            found.append(template[index + 1 : end])
            index = end + 1
            continue
        index += 1
    return found


def encode(value):
    if isinstance(value, str):
        return ["s", value]
    if isinstance(value, bool):
        return ["i", int(value)]
    if isinstance(value, int):
        return ["i", value]
    return ["f", value]


def call(key, values):
    try:
        return {"fn": "message", "args": [key, {name: encode(value) for name, value in values.items()}], "ret": message(key, **values), "exc": None}
    except Exception as exc:
        return {"fn": "message", "args": [key, {name: encode(value) for name, value in values.items()}], "ret": None, "exc": type(exc).__name__}


def variants(field):
    return [
        None,
        (field, "v"),
        (field, 7),
        (field, 1.5),
    ]


def main():
    rows = []
    for key, template in CATALOG.items():
        names = []
        for field in fields_of(template):
            if field not in names and field.isidentifier():
                names.append(field)
        choices = [variants(field) for field in names] or [[None]]
        for combo in itertools.product(*choices):
            values = {}
            for item in combo:
                if item is not None:
                    values[item[0]] = item[1]
            rows.append(call(key, values))
        extra = dict(values)
        extra["unused"] = "extra"
        rows.append(call(key, extra))
    probes = [
        ("{n}", {"n": 3}),
        ("{n:d}", {"n": 42}),
        ("{n:05d}", {"n": 42}),
        ("{n:05d}", {"n": -42}),
        ("{n:+05d}", {"n": -3}),
        ("{n: 05d}", {"n": 42}),
        ("{n:*=8d}", {"n": -42}),
        ("{n:0>5d}", {"n": -42}),
        ("{n:=5d}", {"n": -42}),
        ("{s:>10}", {"s": "hi"}),
        ("{s:*^10}", {"s": "hi"}),
        ("{s:*^5}", {"s": "xy"}),
        ("{s:.1s}", {"s": "hi"}),
        ("{s:05s}", {"s": "ab"}),
        ("{s!r}", {"s": "hi"}),
        ("{s!r}", {"s": "a'b"}),
        ("{s!a}", {"s": "héllo"}),
        ("{s!r}", {"s": "é"}),
        ("{s!s:>8}", {"s": "ab"}),
        ("{{ok}} {n}", {"n": 1}),
        ("{s[1]}", {"s": "ab"}),
        ("{s[0]}", {"s": "ab"}),
        ("{s[5]}", {"s": "ab"}),
        ("{}", {}),
        ("{0}", {}),
        ("{missing}", {}),
        ("a {", {}),
        ("a }", {}),
        ("{n:s}", {"n": 3}),
        ("{n!r:d}", {"n": 3}),
        ("{f}", {"f": 1.5}),
        ("{f}", {"f": -0.0}),
        ("{f:10}", {"f": 1.5}),
        ("{f:010}", {"f": -1.5}),
        ("{f:+10}", {"f": 1.5}),
    ]
    for key, values in probes:
        rows.append(call(key, values))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")))
    print("message", len(rows), "bytes", OUT.stat().st_size)


if __name__ == "__main__":
    main()
