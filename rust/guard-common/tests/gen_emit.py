"""Build JSON dumps oracle vectors. Prints counts only."""

import json
import math
from pathlib import Path

OUT = Path(__file__).resolve().parent / "vectors" / "emit.json"


def dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main():
    values = [
        None,
        True,
        False,
        0,
        1,
        -1,
        2**31,
        -2**31,
        2**53,
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.1,
        0.3,
        1.5,
        10.0,
        1e15,
        1e16,
        1e20,
        1e-4,
        1e-5,
        1e-7,
        1.2345e-10,
        "",
        "a",
        " ",
        "quote\"\\",
        "line\n\r\t",
        "\b\f",
        "\u0000\u001f\u007f",
        "café",
        "é",
        "😀",
        "\u2028",
        [],
        {},
        [1, 1.0, True, None, "é"],
        {"b": 1, "a": {"d": [False], "c": "x"}},
        {"ü": "ü", "a": "b"},
        {"nested": {"z": [], "m": {}}},
        {"long": "x" * 200, "empty": ""},
        [{"k": i, "v": float(i) + 0.5} for i in range(5)],
    ]
    rows = [{"fn": "dumps", "args": [value], "ret": dumps(value), "exc": None} for value in values]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")))
    print("dumps", len(rows), "bytes", OUT.stat().st_size)


if __name__ == "__main__":
    main()
