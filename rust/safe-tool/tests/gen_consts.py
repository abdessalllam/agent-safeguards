"""Record Python safe-tool constants for the Rust vector replay."""

import ast
import importlib.machinery
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("safe_tool_mod", str(ROOT / "bin/safe-tool"))
mod = loader.load_module()

NAMES = """TOOL_NAME SELF_PATH GIT_PATH RTK_PATH CODERABBIT_PATH MAX_OUTPUT_BYTES STATUS_TIMEOUT_SECONDS GIT_TIMEOUT_SECONDS RTK_REWRITE_TIMEOUT_SECONDS OBJECT_ID_PATTERN ATTRIBUTION_PATTERN EMAIL_PATTERN NON_EMAIL_IDENTITY_FIELD_PATTERN HOOK_EVENTS HOOK_BUDGET_SECONDS PROXY_PREFIX EVENT_PATTERN EVENT_SEARCH_BYTES RESERVED_EMAIL_DOMAINS RESERVED_EMAIL_SUFFIXES FIXTURE_EMAIL_DOMAINS SHARED_EMAIL_LOCALS SHELL_PUNCTUATION CLI_GLOBAL_VALUE_OPTIONS SAFE_PROXY_COMMANDS DIRECT_IDENTITY_COMMANDS DEFINITION_PRINTERS DEFINITION_OUTPUT_PATTERN DEFINITION_PARAMETER_PATTERN SHELL_COMMAND_OPTION STARTUP_RC_NAMES STARTUP_HISTORY_NAMES STARTUP_FOLDER_PATHS STARTUP_HISTORY_FOLDER_PATHS STARTUP_FOLDERS STARTUP_HISTORY_FOLDERS STARTUP_SYSTEM_FILES STARTUP_SOURCEABLE STARTUP_NAME_END STARTUP_HISTORY STARTUP_NAME STARTUP_BOUNDARY STARTUP_FILE_PATTERN STARTUP_HISTORY_PATTERN STARTUP_SAMPLE_NAMES GLOB_SYNTAX_PATTERN DOTGLOB_PATTERN FIND_NAME_PATTERN FIND_ROOTS FIND_UNCHECKABLE PIPELINE_OPERATOR_PATTERN PIPELINE_WORD_PATTERN HISTORY_VARIABLE_PATTERN PROCESS_ENVIRONMENT_PATTERN GIT_BLOB_SPEC HEREDOC_DATA_COMMANDS MAX_HEREDOC_LINE_CHARS SYSTEM_COMMAND_PATH JQ_PROGRAM_FILE HEREDOC_ARGUMENT_COMMANDS GH_TEXT_OPTIONS REMOTE_MAX_CHARS REMOTE_READ_COMMANDS REMOTE_FORBIDDEN_OPTIONS REMOTE_FORBIDDEN_LONG REMOTE_FORBIDDEN_LETTERS REMOTE_EXACT_LONG REMOTE_VALUE_LETTERS REMOTE_ATTACHED_LETTERS REMOTE_FLAG_LONG DOCKER_STATS_VALUE_OPTIONS BOOLEAN_TRUE BOOLEAN_FALSE PS_PROFILES _PS_TARGET PS_LONG_VALUE_OPTIONS DOCKER_VALUE_LETTERS DOCKER_VALUE_OPTIONS COMPOSE_VALUE_LETTERS COMPOSE_VALUE_OPTIONS SYSTEMCTL_VALUE_LETTERS SYSTEMCTL_VALUE_OPTIONS DATE_VALUE_LETTERS DATE_VALUE_OPTIONS UNIQ_VALUE_LETTERS UNIQ_VALUE_OPTIONS REMOTE_SUBCOMMANDS REMOTE_COMPOSE_SUBCOMMANDS REMOTE_SECRET_PATHS REDACT_URL REDACT_USER_IPV6 REDACT_USER_HOST REDACT_IPV4 REDACT_IPV6 _STARTUP_RULES MAX_GLOB_WORDS MAX_GLOB_WORD_CHARS SECRET_VARIABLE_PATTERN PRINTING_COMMANDS PLAIN_UTILITIES CREDENTIAL_COMMANDS ENVIRONMENT_SERVICE_ACTIONS STARTUP_KEYWORDS STARTUP_COMMAND_POSITION STARTUP_QUOTED_POSITION SOURCE_STARTUP_PATTERN METADATA_STARTUP_PATTERN HAS_KEY_STARTUP_PATTERN TRACE_OPTION TRACE_OPTION_NAMES TRACE_COMMANDS TRACE_ENVIRONMENT_PATTERN SHADOWING_PATTERN JQ_PROGRAM JQ_ENVIRONMENT HERE_STRING_SECRET HEREDOC_EXPANSION COMPOUND_WORDS HEREDOC_START STARTUP_KEY_FILES KEY_NAME_PATTERN KEY_ASSIGNMENT_PATTERN MAX_KEY_NAMES MAX_STARTUP_FILE_LINES MAX_STARTUP_LINE_CHARS PRIVATE_ADDRESS_V4 PRIVATE_ADDRESS_V6 LOGIN_BANNER_PATTERN LABELLED_ADDRESS ADDRESS_LOOKUP_COMMAND BARE_ADDRESS EMULATOR_ADDRESS SENSITIVE_FLAGS SENSITIVE_PATH_FRAGMENTS TEMPLATE_SUFFIX SAFE_CONFIG_KEYS SAFE_CONFIG_WORDS CONFIG_SCOPES CONFIG_ENVIRONMENT SEPARATORS_AFTER_QUIET UNRESOLVED_WORD GREP_ENVIRONMENT NEIGHBOR_COMMANDS GIT_CONFIG_FRAGMENTS METADATA_COMMANDS GREP_COMMANDS GREP_COUNTING_FLAGS GREP_VALUE_FLAGS GREP_PLAIN_FLAGS GREP_COUNTING_OPTIONS GREP_PLAIN_OPTIONS SECRET_FILE_EXEMPT SECRET_FILE_NAME SENSITIVE_FILE_PATTERN GIT_CONFIG_PATH_PATTERN SENSITIVE_PATH_PATTERN GENERIC_PRIVATE_SUBCOMMANDS GENERIC_PRIVATE_ACTIONS SAFE_LOG_PLACEHOLDERS SAFE_LOG_DATE_LETTERS SAFE_PRETTY_NAMES SAFE_FOR_EACH_REF_FIELDS SAFE_ENV_KEYS DEFAULT_LOCAL_ONLY LOCAL_ONLY_ENTRY""".split()

COMPUTED = {"SELF_PATH", "GIT_PATH", "RTK_PATH", "CODERABBIT_PATH", "_PS_TARGET", "_STARTUP_RULES"}
TUPLES = {
    "RESERVED_EMAIL_SUFFIXES", "STARTUP_FOLDER_PATHS", "STARTUP_HISTORY_FOLDER_PATHS", "STARTUP_SAMPLE_NAMES",
    "STARTUP_KEY_FILES", "SENSITIVE_PATH_FRAGMENTS", "GIT_CONFIG_FRAGMENTS", "SAFE_ENV_KEYS", "DEFAULT_LOCAL_ONLY",
}


def byte_span(text, span):
    start, end = span
    return [len(text[:start].encode()), len(text[:end].encode())]


def pack_match(found, text, binary):
    if found is None:
        return None
    if binary:
        groups = []
        for group in found.groups():
            if group is None:
                groups.append(None)
            else:
                groups.append(group.decode("utf-8", "replace"))
        return {"span": list(found.span()), "groups": groups}
    return {"span": byte_span(text, found.span()), "groups": list(found.groups())}


def cases_for(compiled, text):
    binary = isinstance(compiled.pattern, bytes)
    haystack = text.encode() if binary else text
    search = pack_match(compiled.search(haystack), text, binary)
    matched = pack_match(compiled.match(haystack), text, binary)
    full = pack_match(compiled.fullmatch(haystack), text, binary)
    found = [pack_match(item, text, binary) for item in compiled.finditer(haystack)]
    return {"search": search, "match": matched, "fullmatch": full, "finditer": found}


def literal_strings():
    found = set()
    tests = ROOT / "tests"
    for path in tests.glob("test_*.py"):
        source = path.read_text(errors="replace")
        if "_sensitive_command" not in source and "_sensitive_output" not in source:
            continue
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                found.add(node.value)
    corpus = tests / "secret_corpus.py"
    tree = ast.parse(corpus.read_text(errors="replace"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.add(node.value)
    return found


def boundaries():
    return [
        "", " ", "\n", "\t", ".", "/", "@", ":", "a", "A" * 40,
        "0123456789abcdef0123456789abcdef01234567",
        "0123456789abcdef0123456789abcdef01234567\n",
        "abc\n", "alias foo=", " is an alias for ", "foo () {",
        "user@example.com", "git@github.com", "noreply@example.com",
        "http://example.com/a", "ahttp://example.com", "HTTPS://Example.COM/x",
        "10.0.0.1", "10.0.2.15", "10.0.3.2", "8.8.8.8", "192.168.0.1",
        "172.16.5.1", "169.254.1.1", "100.64.1.1", "1.2.3.4", "1.2.3.4:80",
        "1.2.3.4abc", "x1.2.3.4", "1.2.3.4.", "1.2.3.4\n",
        "fe80::1", "FE80::1", "2001:db8::1", "fc00::1", "::1",
        "user@::1", "user@[::1]", "user@fe80::1%eth0",
        "cat id_rsa", "cat id_rsa.pub", "cat file.pem", "cat file.pem.example",
        "cat .gitconfig", "cat /.gitconfig", "cat .gitconfig.example",
        "cat .git/config", "/etc/profile", "/etc/profile.d/", "/etc/profileX",
        "/etc/zshrc", "source .bashrc", "source .bashrc2", ". .zshrc && ls",
        ".bash_history", ".bash_history\n", " -or\n", " -or ", " -o\n", "-regex ",
        "foo | bar", "foo || bar", "$(cmd)", "`cmd`", "<(x)", "<<EOF", "<<<EOF",
        "HEAD:file", "HEAD:/file", "jq env .", "strenv:", ".env",
        "~root", "~rootx", "~root/", "/root", "/proc/1/environ",
        "Welcome to Ubuntu", "Connection to example.com port 22",
        "Connection to localhost port 22", "Connected to example.com.",
        "inet 10.1.2.3", "ip address: 8.8.8.8",
        "ping 10.0.2.2 now", "\u2603.bashrc", "caf\u00e9.pem", "10.1.2.3\u00a04",
        "safe-tool has-key TOKEN", "echo $SECRET", "<<<$TOKEN",
    ]


def mutated(seeds):
    rng = random.Random(7)
    alphabet = list("abcdefghijklmnopqrstuvwxyzABCDEF0123456789./:_@- \n\t'\"|&;$`()[]{}<>\\")
    extra = []
    for seed in seeds:
        chars = list(seed)
        for _ in range(2):
            if not chars:
                chars.append("a")
            else:
                index = rng.randrange(len(chars))
                op = rng.randrange(3)
                if op == 0:
                    chars.insert(index, rng.choice(alphabet))
                elif op == 1:
                    del chars[index]
                else:
                    chars[index] = rng.choice(alphabet)
            extra.append("".join(chars))
    return extra


def constant_value(name, value):
    if isinstance(value, frozenset):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, dict):
        rows = []
        for key, item in value.items():
            if isinstance(item, frozenset):
                rows.append([key, sorted(item)])
            elif isinstance(item, tuple) and item and isinstance(item[0], frozenset):
                rows.append([key, sorted(item[0]), sorted(item[1])])
            elif isinstance(item, tuple):
                rows.append([key, list(item)])
            else:
                rows.append([key, item])
        return rows
    raise TypeError(name)


def main():
    corpus = set(literal_strings())
    corpus.update(boundaries())
    corpus.update(mutated(list(boundaries()) + list(sorted(corpus))[:80]))
    ordered = sorted(corpus, key=lambda item: (len(item), item))
    records = []
    for name in NAMES:
        if name in COMPUTED:
            continue
        value = getattr(mod, name)
        if isinstance(value, re.Pattern):
            for text in ordered:
                records.append({
                    "fn": name + ".cases",
                    "args": [text],
                    "ret": cases_for(value, text),
                    "exc": None,
                })
            continue
        records.append({"fn": name, "args": [], "ret": constant_value(name, value), "exc": None})
    destination = Path(__file__).resolve().parent / "vectors" / "consts.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(records, ensure_ascii=False, separators=(",", ":")))
    print("records", len(records), "bytes", destination.stat().st_size)


if __name__ == "__main__":
    main()
