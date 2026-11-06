import itertools
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lib"))
from agent_safeguards import common

FORBIDDEN_ALPHABET = list("${}()[]'\"`<>a_1\n ")
ASSIGN_ALPHABET = list("A_1=a-\n.")
DURATION_ALPHABET = list("1.9smhdx\n")


def hexed(text):
    return text.encode("utf-8").hex()


out = open(sys.argv[1] if len(sys.argv) > 1 else __import__("os").path.dirname(__import__("os").path.abspath(__file__)) + "/vectors/exhaustive_shell.txt", "w")
count = 0
for length in range(0, 6):
    for chars in itertools.product(FORBIDDEN_ALPHABET, repeat=length):
        text = "".join(chars)
        out.write("F\t%s\t%d\n" % (hexed(text), 1 if common.HEREDOC_FORBIDDEN.search(text) else 0))
        count += 1
for length in range(0, 7):
    for chars in itertools.product(ASSIGN_ALPHABET, repeat=length):
        text = "".join(chars)
        out.write("A\t%s\t%d\n" % (hexed(text), 1 if common.ASSIGNMENT.fullmatch(text) else 0))
        count += 1
for length in range(0, 7):
    for chars in itertools.product(DURATION_ALPHABET, repeat=length):
        text = "".join(chars)
        out.write("D\t%s\t%d\n" % (hexed(text), 1 if common.DURATION.fullmatch(text) else 0))
        count += 1
out.close()
print("rows", count)
