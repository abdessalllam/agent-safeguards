"""Build secret_scan oracle vectors from the Python scanner. Prints counts only."""

import ast
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import secret_corpus
from agent_safeguards import secret_scan as scan

OUT = Path(__file__).resolve().parent / "vectors" / "secret_scan.json"
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:= \"'${}<>()[]&?#@%*\n\té"


def record(name, args, fn):
    try:
        return {"fn": name, "args": args, "ret": fn(), "exc": None}
    except Exception as exc:
        return {"fn": name, "args": args, "ret": None, "exc": type(exc).__name__}


def literals_from(path):
    tree = ast.parse(path.read_text())
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append(node.value)
    return found


def mutate(rng, text):
    if not text:
        return ALPHABET[rng.randrange(len(ALPHABET))]
    chars = list(text)
    kind = rng.randrange(6)
    if kind == 0:
        del chars[rng.randrange(len(chars))]
    elif kind == 1:
        chars.insert(rng.randrange(len(chars) + 1), ALPHABET[rng.randrange(len(ALPHABET))])
    elif kind == 2 and len(chars) >= 2:
        index = rng.randrange(len(chars) - 1)
        chars[index], chars[index + 1] = chars[index + 1], chars[index]
    elif kind == 3:
        return text.swapcase()
    elif kind == 4:
        return (text + text)[:500]
    else:
        return text[: max(0, len(text) // 2)]
    return "".join(chars)[:500]


def corpus():
    texts = ["", "a", " ", "é", "a" * 80, "A" * 40, "." * 20, "added 3 packages in 1s"]
    texts.extend(literals_from(ROOT / "tests" / "test_secret_scan.py"))
    texts.extend(literals_from(ROOT / "tests" / "test_false_positives.py"))
    for seed in range(1, 5):
        rng = random.Random(seed)
        for _name, text in secret_corpus.benign(rng):
            texts.append(text[:800])
        tokens = secret_corpus.tokens(random.Random(seed))
        for _name, (token, _category) in tokens.items():
            texts.append(token)
            for template in list(secret_corpus.CONTEXTS.values())[:8]:
                texts.append(template.format(s=token)[:800])
    for _name, _category, _context, text in secret_corpus.embedded(random.Random(1)):
        texts.append(text[:800])
        if len(texts) > 1800:
            break
    rng = random.Random(20261105)
    base = [text for text in texts if text][:400]
    for text in base:
        for _ in range(4):
            texts.append(mutate(rng, text[:240]))
    texts.append("eyJ" + "a" * 40 + ".bbbbbbbb.cccccccc")
    texts.append("eyJ" + "a" * 40)
    texts.append("eyJ" + "a" * 40 + ".short")
    texts.append("password=" + "4815162342")
    texts.append("\n".join(["-----BEGIN CERTIFICATE-----", "AAAA" * 20, "-----END CERTIFICATE-----"]))
    texts.append("h1:" + "Aa1" * 20)
    deduped = []
    seen = set()
    for text in texts:
        if text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return deduped


def main():
    texts = corpus()
    rows = []
    deadline_open = time.monotonic() + 3600
    names = [pattern.pattern for pattern in scan.FORMAT_PATTERNS]
    del names
    pattern_names = [
        "private_key", "pem_header", "aws_access_key", "github", "gitlab", "npm", "prefixed",
        "xapp", "whsec", "google", "ya29", "sk_hex", "sendgrid", "mailgun", "vendor",
        "authorization", "bearer", "login", "auth_field", "signed_url", "query", "url_credentials",
    ]
    for text in texts:
        rows.append(record("contains_secret", [text], lambda text=text: scan.contains_secret(text)))
        rows.append(record("contains_key", [text], lambda text=text: scan.contains_key(text)))
    sample = texts[:2100]
    for text in sample:
        rows.append(record("jwt_secret", [text], lambda text=text: scan._jwt_secret(text)))
        rows.append(record("without_public_material", [text], lambda text=text: scan._without_public_material(text)))
        for mode, deadline in (("open", deadline_open), ("expired", 0)):
            rows.append(record("labeled_secret", [text, mode], lambda text=text, deadline=deadline: scan._labeled_secret(text, deadline)))
            rows.append(record("bare_secret", [text, mode], lambda text=text, deadline=deadline: scan._bare_secret(text, deadline)))
    for text in texts[:400]:
        for index, pattern in enumerate(scan.FORMAT_PATTERNS):
            name = pattern_names[index]
            rows.append(record("format_secret", [name, text, "open"], lambda pattern=pattern, text=text: scan._format_secret(pattern, text, deadline_open)))
            if index % 4 == 0:
                rows.append(record("format_secret", [name, text, "expired"], lambda pattern=pattern, text=text: scan._format_secret(pattern, text, 0)))
    edges = ["", "a", "ab", "abcdef", "changeme", "xxxxxxxx", "example.com", "Aa1", "éé", "%s", "%2F", "%(name)s", "/", "/tmp/a", "UserAPIKeyAuth", "password", "hunter2", "123.456.789", "self.config.value", "OPENAI_API_KEY", "Red.Bicycle.Sample", "^1.2.3", "v2.31.0", "1.5e-06", "user@host.test", "&TypeName", "secretName:", "your-key-here", "test-value", "Aa1Bb2Cc3Dd4"]
    edges.extend(texts)
    for text in edges:
        rows.append(record("entropy", [text], lambda text=text: scan._entropy(text)))
        rows.append(record("placeholder_shaped", [text], lambda text=text: scan._placeholder_shaped(text)))
        rows.append(record("is_slug", [text], lambda text=text: scan._is_slug(text)))
        rows.append(record("annotation", [text], lambda text=text: scan._annotation(text)))
        rows.append(record("template_percent", [text], lambda text=text: scan._template_percent(text)))
        rows.append(record("type_name", [text], lambda text=text: scan._type_name(text)))
        rows.append(record("looks_like_path", [text], lambda text=text: scan._looks_like_path(text)))
        rows.append(record("token_looks_real", [text], lambda text=text: scan._token_looks_real(text)))
        rows.append(record("real_aws_key", [text], lambda text=text: scan._real_aws_key(scan.re.fullmatch(r"(?s).*", text))))
        rows.append(record("real_authorization", [text], lambda text=text: scan._real_authorization(fake(text))))
        rows.append(record("real_prefixed_key", [text], lambda text=text: scan._real_prefixed_key(fake(text))))
        rows.append(record("real_credentials", [text], lambda text=text: scan._real_credentials(fake(text))))
        rows.append(record("real_query_value", [text], lambda text=text: scan._real_query_value(fake(text))))
        for length in (0, 1, 6, 8):
            rows.append(record("ascending_run", [text, length], lambda text=text, length=length: scan._ascending_run(text, length)))
    labels = ["password", "passwd", "pwd", "secret", "token", "api_key", "api-key", "name", "db_passwd"]
    for label in labels:
        for text in edges[:350]:
            rows.append(record("plausible_value", [label, text], lambda label=label, text=text: scan._plausible_value(label, text)))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")))
    counts = {}
    for row in rows:
        counts[row["fn"]] = counts.get(row["fn"], 0) + 1
    for name in sorted(counts):
        print(f"{name} {counts[name]}")
    print("total", len(rows), "bytes", OUT.stat().st_size)


def fake(text):
    return scan.re.fullmatch(r"(?s)(?P<value>.*)", text)


if __name__ == "__main__":
    main()
