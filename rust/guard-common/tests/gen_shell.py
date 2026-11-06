"""Generate shell vectors by calling the Python guards."""

import ast
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
from agent_safeguards import common

OUT = Path(__file__).resolve().parent / "vectors" / "shell.json"


def record(rows, name, args, call):
    try:
        ret = pack(call())
        exc = None
    except Exception as error:
        ret = None
        exc = type(error).__name__
        if exc == "_Unplaceable":
            exc = "Unplaceable"
    rows.append({"fn": name, "args": pack(args), "ret": ret, "exc": exc})


def pack(value):
    if isinstance(value, common.HereDocument):
        return {
            "line_start": value.line_start,
            "marker_start": value.marker_start,
            "delimiter_end": value.delimiter_end,
            "line_end": value.line_end,
            "body_start": value.body_start,
            "body_end": value.body_end,
            "end": value.end,
            "quoted": value.quoted,
            "outer": list(value.outer) if value.outer is not None else None,
        }
    if isinstance(value, tuple):
        return [pack(part) for part in value]
    if isinstance(value, list):
        return [pack(part) for part in value]
    if isinstance(value, dict):
        return {key: pack(part) for key, part in value.items()}
    return value


def command_strings():
    found = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if 0 < len(text) <= 600 and any(ch in text for ch in " \t\n'\"\\$|&;<>#`{}()"):
                    found.append(text)
    return found


def mutations(base, rng):
    alphabet = list(" abc\t\n'\"\\$|&;<>#`()[]{}=-") + ["é", "你", "\t"]
    out = []
    for text in base:
        chars = list(text)
        for _ in range(2):
            if not chars:
                chars = ["a"]
            kind = rng.randrange(3)
            at = rng.randrange(len(chars) + (1 if kind == 0 else 0))
            if kind == 0:
                chars.insert(min(at, len(chars)), rng.choice(alphabet))
            elif kind == 1:
                del chars[min(at, len(chars) - 1)]
            elif len(chars) >= 2:
                left = rng.randrange(len(chars))
                right = rng.randrange(len(chars))
                chars[left], chars[right] = chars[right], chars[left]
            out.append("".join(chars))
    return out


def edges():
    return [
        "",
        " ",
        "echo",
        "echo a",
        "[[ 2 > 1 ]]",
        "echo $((2 >> 1))",
        "(( x > 1 ))",
        "echo $((1+1)) > /dev/review-disk",
        "((echo hi) > /dev/review-disk)",
        "printf x >! /dev/review-disk",
        "printf x >&! /dev/review-disk",
        "printf x &>! /dev/review-disk",
        "printf x >!/dev/review-disk",
        "printf x >>! /dev/review-disk",
        "cat <<EOF\nhello\nEOF\n",
        "cat <<'EOF'\nhello\nEOF\n",
        'cat <<"E\\$D"\nDATA\nE$D\n',
        "cat > /tmp/x.txt <<''\nit's harmless text\n\n",
        "cat > /tmp/x.txt <<\"\"\nit's harmless text\n\n",
        "echo 'a > b' > out",
        "echo $(ls)",
        "echo '$(ls)'",
        'echo "$(ls)"',
        "echo $(a $(b))",
        "echo $((1+$(ls)))",
        "echo <(ls)",
        "echo >(ls)",
        "cat <<EOF\nit's text\nEOF\nenv\n",
        "echo a\\\nb\n'c'\n",
        "echo 'a > b' # comment\nnext",
        "FOO=1 env -C /tmp cmd",
        "a=b echo hi",
        "2>out",
        "echo 2> out",
        "cmd <<EOF",
        "cmd <<EOF\n",
        "cmd <<-EOF\n\thello\nEOF\n",
        "cmd <<'E O F'\nE O F\n",
        "cmd <<\\E\\O\\F\nEOF\n",
        "# <<EOF\nnot\n",
        "echo '<<EOF'\n",
        'echo "<<EOF"\n',
        "x=$((a>b ? 1 : 2))",
        "[[ a > b ]] && echo yes",
        "echo $(( (1 > 0) + 2 ))",
        "printf x > /dev/null; printf %s $'can\\'t'",
        "time 5s cmd",
        "timeout --signal=KILL 1 cmd",
        "{1..3}",
        "{8..10}",
        "{01..03}",
        "{1..10..2}",
        "{8..10..08}",
        "{a..c}",
        "{c..a}",
        "{a..1}",
        "pre{1..2}post",
        "{a,b}{1..2}",
        "{c,a,b}",
        "{1..3..0}",
        "{1..300}",
        "a{b,c}d",
        "{01..03..02}",
        "{-2..2}",
        "{2..0..2}",
        "{00..02}",
        "plain",
        "café <<EOF\nü\nEOF\n",
        "echo 你 > out",
        "$((1))",
        "$(())",
        "$((",
        "''",
        '""',
        "\\",
        "\\\n",
        "# only",
        "echo # hi\nnext",
        "a'b",
        "a'b'",
        '"a\\"b"',
        "cmd <<EOF\n$(ls)\nEOF\n",
        "echo `ls`",
        "echo '`ls`'",
        'echo "`ls`"',
        "if cmd; then echo; fi",
        "{ echo hi; }",
        "! cmd",
        "sudo -D /tmp -u root cmd",
        "env -C /tmp -S 'echo hi' extra",
        "/bin/env --chdir=/work cmd",
        "command -v ls",
        "command ls",
        "rtk proxy git status",
        "nice -n5 cmd",
        "stdbuf -o0 cmd",
        "timeout 1s cmd",
        "gtimeout -k 1 2 cmd",
        "FOO=bar\\nbaz echo",
        "A=\nB",
        "echo ${name}",
        "echo ${1}",
        "echo $(())",
        "cat <<EOF\n1\nEOF\ncat <<END\n2\nEND\n",
        "((echo) > file)",
        "echo \\> file",
        "echo '>' file",
        "2>&1",
        "&>out",
        ">&!",
        "cat <<EOF\nhello\nEOF\ncat <<EOF\nsecond\nEOF\n",
    ]


def heart(rows, commands):
    for command in commands:
        record(rows, "normalize_command", [command, None], lambda command=command: common.normalize_command(command, None))
        def with_redirects(command=command):
            redirects = []
            text = common.normalize_command(command, redirects)
            return {"text": text, "redirects": redirects}
        record(rows, "normalize_command", [command, []], with_redirects)
        record(rows, "unquoted_text", [command], lambda command=command: common.unquoted_text(command))
        record(rows, "unquoted_lines", [command], lambda command=command: common.unquoted_lines(command))
        record(rows, "mark_opening_quotes", [command], lambda command=command: common.mark_opening_quotes(command))
        record(rows, "heredocs", [command], lambda command=command: common.heredocs(command))
        record(rows, "command_substitutions", [command], lambda command=command: common.command_substitutions(command))


def small(rows, commands):
    samples = commands[:240]
    for command in samples:
        length = len(command)
        for index in {0, 1, min(2, length), max(length - 1, 0)}:
            if length == 0:
                record(rows, "closing_quote", [command, 0], lambda command=command: common._closing_quote(command, 0))
                break
            record(rows, "closing_quote", [command, index], lambda command=command, index=index: common._closing_quote(command, index))
            record(rows, "skip_quoted", [command, index], lambda command=command, index=index: common._skip_quoted(command, index))
            record(rows, "skip_operand", [command, index], lambda command=command, index=index: common._skip_operand(command, index))
            record(rows, "test_end", [command, index], lambda command=command, index=index: common._test_end(command, index))
            record(rows, "double_parenthesis_end", [command, index], lambda command=command, index=index: common._double_parenthesis_end(command, index))
            record(rows, "closing_parenthesis", [command, index], lambda command=command, index=index: common._closing_parenthesis(command, index))
            record(rows, "closing_backtick", [command, index], lambda command=command, index=index: common._closing_backtick(command, index))
            record(rows, "read_delimiter", [command, index], lambda command=command, index=index: common._read_delimiter(command, index))
            record(rows, "expression_end", [command, index, True, []], lambda command=command, index=index: common._expression_end(command, index, True, []))
            record(rows, "expression_end", [command, index, False, ["e", "c", "h", "o"]], lambda command=command, index=index: common._expression_end(command, index, False, ["e", "c", "h", "o"]))
        kept_sets = [[], ["e", "c", "h", "o"], ["2"], [" ", "2"], ["echo", "2"], list(command[:8])]
        for kept in kept_sets:
            record(rows, "at_command_start", [kept], lambda kept=list(kept): common._at_command_start(kept))
            def dropped(kept=list(kept)):
                live = list(kept)
                value = common._drop_descriptor(live)
                return {"dropped": value, "kept": live}
            record(rows, "drop_descriptor", [kept], dropped)
        record(rows, "find_terminator", [command, 0, "EOF", False], lambda command=command: common._find_terminator(command, 0, "EOF", False))
        record(rows, "find_terminator", [command, 0, "EOF", True], lambda command=command: common._find_terminator(command, 0, "EOF", True))
        if common.BRACE_PATTERN.search(command):
            record(rows, "brace_options", [command], lambda command=command: common.brace_options(common.BRACE_PATTERN.search(command)))
        record(rows, "expand_braces", [command], lambda command=command: common.expand_braces(command))
    letters = ["", "t", "nS", "tS"]
    options = [[], ["--target-directory"], ["-C", "--chdir"], ["-u", "--unset"]]
    word_sets = [
        [],
        ["cmd"],
        ["-n", "5", "file"],
        ["-t", "dest", "src"],
        ["--", "-n"],
        ["--chdir", "/tmp", "cmd"],
        ["--chdir=/tmp", "cmd"],
        ["file", "-x"],
        ["-"],
        ["--"],
    ]
    for words in word_sets:
        for letter in letters:
            for option in options:
                record(
                    rows,
                    "first_operand",
                    [words, letter, option],
                    lambda words=list(words), letter=letter, option=set(option): common.first_operand(words, letter, option),
                )
                record(
                    rows,
                    "split_options",
                    [words, letter, option],
                    lambda words=list(words), letter=letter, option=set(option): common.split_options(words, letter, option),
                )
    option_words = ["-n", "-ufile", "--chdir", "--chdir=/tmp", "-Eu", "-n5", "--", "file", "-S", "--split-string=a b"]
    value_sets = [[], ["-u", "--chdir"], ["-n", "-S", "--split-string"], ["-E", "-u"]]
    for option in option_words:
        for values in value_sets:
            record(
                rows,
                "option_names",
                [option, values],
                lambda option=option, values=set(values): common.option_names(option, values),
            )
            record(
                rows,
                "option_value",
                [option, values[0] if values else "-n", ["cmd", "next"], 0],
                lambda option=option, values=list(values): common._option_value(option, values[0] if values else "-n", ["cmd", "next"], 0),
            )
    wrappers = [
        ["cmd"],
        ["env", "-C", "/tmp", "cmd"],
        ["/usr/bin/sudo", "-R", "/chroot", "cmd"],
        ["FOO=1", "cmd"],
        ["command", "-v", "ls"],
        ["command", "ls"],
        ["env", "-S", "echo hi"],
        ["nice", "-n", "5", "cmd"],
        ["rtk", "proxy", "git", "status"],
        ["timeout", "1s", "cmd"],
        ["if", "echo", "hi"],
        ["env", "sudo", "-D", "/work", "cmd"],
        ["stdbuf", "-o", "0", "cmd"],
        ["env", "-S"],
        ["busybox", "env", "cmd"],
        ["time", "-p", "cmd"],
    ]
    keeps = [[], ["sudo"], ["env"]]
    for words in wrappers:
        for keep in keeps:
            record(
                rows,
                "strip_wrappers_with_directory",
                [words, keep],
                lambda words=list(words), keep=set(keep): common.strip_wrappers_with_directory(words, keep),
            )
            record(
                rows,
                "strip_wrappers",
                [words, keep],
                lambda words=list(words), keep=set(keep): common.strip_wrappers(words, keep),
            )
    for command in samples[:40]:
        record(rows, "scan_code", [command, 0, False, 0, None], lambda command=command: scan(command))
        record(rows, "scan_double_quoted", [command, 0, 0, 0], lambda command=command: scan_double(command))
        newline = command.find("\n")
        if newline < 0:
            newline = 0
        pending_arg = [{
            "line_start": 0,
            "marker_start": 0,
            "delimiter_end": 0,
            "delimiter": "EOF",
            "strip_tabs": False,
            "quoted": False,
            "outer": None,
        }]
        record(
            rows,
            "read_bodies",
            [command, newline, pending_arg],
            lambda command=command, newline=newline: run_bodies(command, newline),
        )
        record(rows, "heredoc_forbidden", [command], lambda command=command: common.HEREDOC_FORBIDDEN.search(command) is not None)
        record(rows, "assignment_matches", [command], lambda command=command: common.ASSIGNMENT.fullmatch(command) is not None)
        record(rows, "duration_matches", [command], lambda command=command: common.DURATION.fullmatch(command) is not None)


def scan(command):
    found = []
    index = common._scan_code(command, 0, False, found, 0, None)
    return {"index": index, "found": found}


def scan_double(command):
    found = []
    index = common._scan_double_quoted(command, 0, found, 0, 0)
    return {"index": index, "found": found}


def run_bodies(command, newline):
    pending = [(0, 0, 0, "EOF", False, False, None)]
    found = []
    index = common._read_bodies(command, newline, pending, found)
    return {"index": index, "found": found}


def main():
    rows = []
    seen = []
    have = set()
    for text in edges() + command_strings():
        if text not in have:
            have.add(text)
            seen.append(text)
    rng = random.Random(20261105)
    for text in mutations(seen[:400], rng):
        if text not in have and len(text) <= 600:
            have.add(text)
            seen.append(text)
        if len(seen) >= 1600:
            break
    heart(rows, seen)
    small(rows, seen)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"shell rows {len(rows)} commands {len(seen)}")


if __name__ == "__main__":
    main()
