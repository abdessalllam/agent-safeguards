import json
import random
import sys

TESTS = str(__import__("pathlib").Path(__file__).resolve().parent)
sys.path.insert(0, TESTS)
import gen_shell

WORDS = ["echo", "cat", "env", "rm", "git", "ls", "timeout", "sudo", "time", "nice", "command", "exec", "a", "b", "c", "x=1", "FOO=bar", "-C", "/tmp", "-rf", "--chdir=/w", "-n5", "5s", "*.py", "~/x", "é", "你", "'", '"']
METAS = [" ", " ", " ", "\t", "\n", ";", "&&", "||", "|", ">", ">>", "<", "2>", "&>", ">&", ">|", ">!", "<<EOF", "<<-EOF", "<<'EOF'", '<<"EOF"', "<<\\EOF", "EOF", "\nEOF\n", "$(", ")", "`", "'", '"', "\\", "\\\n", "{a,b}", "{1..3}", "{01..03}", "{c..a}", "$((", "))", "((", "[[", "]]", "#", "$", "${x}", "$'", "<(", ">(", "!", "{", "}", "(", "&", "=", "-", "1", "0"]

REDIRECTS = [">", ">>", ">|", ">&", "&>", "2>", "<", "<<", "<<<", "<&", ">!"]
CONSTRUCTS = [
    "((",
    "((x))",
    "((1+2))",
    "((\n2>))",
    "((x>1))",
    "((rm--chdir=/w{1..3}<<'EOF'cat\t&>time\t))",
    "((\\\n))",
    "$((1))",
    "$((2>>1))",
    "[[ 2 > 1 ]]",
    "[[\n2 > 1 ]]",
    "(echo)",
    "(ls > out)",
    "{ echo; }",
    "{a,b}",
    "$(ls)",
    "$(echo hi)",
    "`ls`",
    "`echo hi`",
    "'a > b'",
    '"a > b"',
    "<<EOF\nbody\nEOF\n",
    "<<'EOF'\nbody\nEOF\n",
    '<<"EOF"\nbody\nEOF\n',
    "<<-EOF\n\tbody\nEOF\n",
    "<<\\EOF\nEOF\n",
    "{1..3}",
    "{01..03}",
    "{c..a}",
    "{a,b,c}",
]
KNOWN = [
    ">|((\n2>))",
    ">>((rm--chdir=/w{1..3}<<'EOF'cat\t&>time\t))",
    ">&--chdir=/wcommand((\\\n))\t5s-rf*.py'-rf\\\nenvbcat~/xcommand",
    ">\x1ffile\x1f",
    ">\x1cfile\x1d",
    "<\x1ename\x1f",
    ">>\x1f((x))",
]


def build(rng):
    parts = []
    for _ in range(rng.randint(1, 26)):
        parts.append(rng.choice(WORDS) if rng.random() < 0.45 else rng.choice(METAS))
    text = "".join(parts)
    if rng.random() < 0.08:
        text = rng.choice(["cat <<EOF\n", "cat <<'EOF'\n", "cat <<-EOF\n\t"]) + text + rng.choice(["\nEOF\n", "\nEOF", "\n"]) + rng.choice(["", "env", "echo ok\n"])
    return text


def redirect_family():
    commands = list(KNOWN)
    for operator in REDIRECTS:
        for body in CONSTRUCTS:
            commands.append(operator + body)
            commands.append(operator + " " + body)
            commands.append("echo " + operator + body)
            commands.append("echo" + operator + body)
    for length in (0, 1, 23, 24, 25, 40):
        for operator in (">", ">>", ">|", "2>"):
            for body in ("((2>1))", "((\\\n))", "((\n2>))"):
                commands.append(("a" * length) + operator + body)
                commands.append((" " * length) + operator + body)
    return commands


def main():
    rows = []
    commands = []
    for seed in (20261106, 20261107, 20261108, 20261109, 20261110):
        rng = random.Random(seed)
        commands.extend(build(rng) for _ in range(3500))
    commands.extend(redirect_family())
    commands = [c for c in commands if len(c) <= 600]
    gen_shell.heart(rows, commands)
    gen_shell.small(rows, commands[:900])
    out = sys.argv[1] if len(sys.argv) > 1 else TESTS + "/vectors/fuzz_shell.json"
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=True)
    print("rows", len(rows), "commands", len(commands))


main()
