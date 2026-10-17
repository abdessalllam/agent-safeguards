"""Finds secret-shaped values in text before an agent can read it. Leans toward false positives."""

from __future__ import annotations

import math
import re
import time
from collections import Counter

# The hook is killed after 5 seconds and a killed hook lets the output through, so a scan that
# cannot finish in time reports a secret instead (withholding is the safe failure).
SCAN_BUDGET_SECONDS = 3.0

# Patterns whose match is only a secret when what follows the prefix is not a placeholder, a slug or a documented example.
AWS_ACCESS_KEY = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}")
PREFIXED_KEY = re.compile(
    r"(?:(?<![A-Za-z])sk-(?:ant-|proj-)?|xox[baprs]-|sk_live_|rk_live_|sk_test_|rk_test_)(?P<value>[A-Za-z0-9_-]{12,})"
)
AUTHORIZATION_HEADER = re.compile(
    r"(?i)authorization\s*[:=]\s*[\"']?(?P<scheme>bearer|basic|token|digest)\s+(?![$<{])(?P<value>[A-Za-z0-9._~+/=-]{8,})"
)
BEARER_VALUE = re.compile(r"(?i)bearer\s+(?![$<{])(?P<value>[A-Za-z0-9._~+/=-]{24,})")
QUERY_SECRET = re.compile(r"(?i)[?&](?:[a-z0-9.-]{0,30}_)?(?P<name>token|key|secret|password|passwd|apikey)=(?P<value>[^\s&#]+)")
URL_CREDENTIALS = re.compile(r"(?i)[a-z][a-z0-9+.-]{0,30}://[^\s/:@]*:(?P<value>[^\s/@]+)@")

FORMAT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY[A-Z ]{0,40}-----"),
    re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}"),
    AWS_ACCESS_KEY,
    re.compile(r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"),
    re.compile(r"gl(?:pat|dt|ptt|rt|soat|imt|agent|cbt|ft)-[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?:(?<![A-Za-z_])npm_[A-Za-z0-9]{30,}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{12,})"),
    PREFIXED_KEY,
    re.compile(r"xapp-\d-[A-Za-z0-9-]{20,}"),
    re.compile(r"whsec_[A-Za-z0-9]{24,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"),
    re.compile(r"(?<![A-Za-z])SK[0-9a-f]{32}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?<![A-Za-z])key-[0-9a-f]{32}"),
    re.compile(
        r"(?:(?<![A-Za-z])(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|pplx-[A-Za-z0-9]{40,}"
        r"|sbp_[a-f0-9]{40}|shp(?:at|ca|pa|ss)_[a-f0-9]{32})|dop_v1_[a-f0-9]{64}|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})"
    ),
    AUTHORIZATION_HEADER,
    BEARER_VALUE,
    re.compile(r"(?i)\blogin\s+\S+\s+password\s+\S{4,}"),
    re.compile(r"(?i)\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{16,}\""),
    re.compile(r"(?i)[?&](?:sig|signature|x-amz-signature)=[A-Za-z0-9%+/=_-]{20,}"),
    QUERY_SECRET,
    # Repeats are bounded where several match starts can share one run of characters (here the scheme),
    # which keeps every pattern linear: a hook that overruns its timeout lets the output through.
    URL_CREDENTIALS,
)

LABELED_VALUE = re.compile(
    r"""(?ix)
    (?P<label>pass(?:word|wd)|pwd|secret|token|credential|api[_-]?key|apikey|access[_-]?key|private[_-]?key
        |auth[_-]?(?:key|token)|account[_-]?key|shared[_-]?access[_-]?key|signing[_-]?key|encryption[_-]?key
        |session[_-]?key|master[_-]?key|_auth(?![a-z]))
    [a-z0-9_.-]{0,40}
    ["']?\s*[:=]\s*["']?
    (?P<value>[^\s"'<>{}()\[\],;`]{6,})
    (?=[\s"'<>{}()\[\],;`]|\Z)
    """
)
PLACEHOLDER = re.compile(
    r"(?i)(?:x+|\*+|\.+|-+|_+|changeme|change-me|redacted|your[-_].*|example.*|placeholder|todo|null|none|nil|undefined|true|false|yes|no|"
    r"required|optional|enabled|disabled|password|secret|token)"
)
PASSWORD_LABEL = re.compile(r"(?i)pass|pwd")
# A value made only of lowercase words (`access_token`, `my-secret-name`), a camelCase or PascalCase name (`clientSecret`) or an
# environment variable name (`OPENAI_API_KEY`) is code that refers to a secret, not one; a password may be a passphrase, so for a
# password label only the forms code uses (not hyphenated words) are skipped.
IDENTIFIER_WORDS = re.compile(r"_*[A-Za-z]{2,}(?:[_:-][A-Za-z]+)+(?:[-_][0-9]{1,4})?|_+[A-Za-z][A-Za-z_]{2,}|[a-z]{2,}[-_][0-9]{1,6}")
# A number or a float (`1.5e-06`), an email address and a reference to an environment variable (`os.environ/OPENAI_API_KEY`, the
# way a config file names a secret without holding it) are not secrets either.
NON_SECRET_VALUE = re.compile(
    r"[0-9][0-9_]*(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?|[^@\s]+@[^@\s]+\.[A-Za-z]{2,}|[A-Za-z_.]+/[A-Z][A-Z0-9_]+|[a-z]{2,10}[0-9]{1,6}"
)
# Words that a password in a test or a template is made of: `redis-secret`, `admin-password`, `mypassword`.
PASSWORD_FIXTURE = re.compile(r"[a-z_-]*(?:password|passwd|secret|token)[a-z_-]*")
# `settings.Key`, `claim.existing!.token`, `Mode::File` and `&Self::Token`: a path through code, with optional chaining or `::`.
CODE_REFERENCE = re.compile(r"&?[A-Za-z_]\w*(?:(?:[!?]?\.|::)[A-Za-z_]\w*)+[!?]?(?:\(\))?")
TITLE_WORD = re.compile(r"[A-Z][a-z]{5,}")
CAMEL_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
SNAKE_WORDS = re.compile(r"_*[a-z]+(?:_[a-z]+)+")
CODE_NAME = re.compile(r"[a-z]+(?:[A-Z][a-z]+)+|(?:[A-Z][a-z]+){2,}|[A-Z]{2,}(?:_[A-Z]{2,})+")
# Values a test, a template or documentation uses in place of a secret.
FIXTURE_VALUE = re.compile(r"(?i)(?:test|testing|dummy|fake|sample|example|demo|mock|placeholder|changeme|insert|replace)(?:[-_.][A-Za-z0-9._-]*|[0-9]*)")
SLUG_SEGMENT = re.compile(r"[a-z]+|[A-Z]+|(?:[A-Z][a-z]+)+|[0-9]+|[0-9a-f]{3,12}")
SLUG_WORD = re.compile(r"[a-z]{4,}|[A-Z][a-z]{3,}(?:[A-Z][a-z]+)*")
SEPARATORS = re.compile(r"[-_/.+:]+")
RANGE_VERSION = re.compile(r"[\^~<>=v]+\d+(?:\.\d+)*(?:[-+][\w.+-]*)?")
VERSION = re.compile(r"(?:[\^~<>=v]+\d+(?:\.\d+)*|\d+(?:\.\d+)+)(?:[-+][\w.+-]*)?")
DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
BARE_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_.-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/=_.-])")
PUBLIC_BLOCK_LABELS = (
    "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE", "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST",
    "X509 CRL", "PUBLIC KEY", "RSA PUBLIC KEY", "EC PUBLIC KEY", "PGP PUBLIC KEY BLOCK",
)
PUBLIC_BLOCK_START = re.compile(r"-----BEGIN (" + "|".join(PUBLIC_BLOCK_LABELS) + r")-----")
JWT_FIRST = re.compile(r"eyJ[A-Za-z0-9_-]{8,}")
BASE64URL_RUN = re.compile(r"[A-Za-z0-9_-]{5,}")
PUBLIC_INLINE = re.compile(
    r"(?:ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+)\s+AAAA[A-Za-z0-9+/=]+|data:[a-z0-9/+.-]+;base64,[A-Za-z0-9+/=]+"
)
INTEGRITY_PREFIXES = ("sha1-", "sha256-", "sha384-", "sha512-", "md5-")


def _real_aws_key(found: re.Match) -> bool:
    return not found.group(0).endswith("EXAMPLE")


# What follows a token prefix is a key when it is long and random-looking, or mixes letter cases and digits; `your-key-here`,
# `sk-ant-api03-xxxxxxxx`, `abcdef123456` and `...` are what documentation and tests put there.
def _token_looks_real(value: str) -> bool:
    if _placeholder_shaped(value) or "..." in value or "\u2026" in value or "EXAMPLE" in value:
        return False
    mixed = any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value)
    return mixed or (len(value) >= 24 and _entropy(value) >= 3.3)


def _real_prefixed_key(found: re.Match) -> bool:
    return _token_looks_real(found.group("value"))


# `Basic` carries `user:password` in base64, which is short and has no tell-tale shape, so only a placeholder is let through.
def _real_authorization(found: re.Match) -> bool:
    value = found.group("value")
    if found.group("scheme").lower() == "basic":
        return not (_placeholder_shaped(value) or "..." in value or "\u2026" in value)
    return _token_looks_real(value)


def _real_credentials(found: re.Match) -> bool:
    value = found.group("value")
    return not (
        value[0] in "$%<{*:[" or _placeholder_shaped(value) or CODE_NAME.fullmatch(value) or NON_SECRET_VALUE.fullmatch(value)
    )


# A value in a query string is cut at the end of the string or the call it sits in (`'`, `"`, `,`, `)`). Any value of a credential
# parameter counts, however short, except a template (`${TOKEN}`, `{token}`, `<token>`, `[TOKEN]`), a reference to code and a
# placeholder word.
def _real_query_value(found: re.Match) -> bool:
    value = found.group("value").strip("'\"`,;)]}>")
    if not value or value[0] in "$%<{*[:@(":
        return False
    return not (CODE_NAME.fullmatch(value) or CODE_REFERENCE.fullmatch(value) or IDENTIFIER_WORDS.fullmatch(value) or PLACEHOLDER.fullmatch(value))


# What a match of one of these patterns must also be before it counts.
FORMAT_CHECKS = {
    AWS_ACCESS_KEY: _real_aws_key,
    PREFIXED_KEY: _real_prefixed_key,
    AUTHORIZATION_HEADER: _real_authorization,
    BEARER_VALUE: _real_prefixed_key,
    URL_CREDENTIALS: _real_credentials,
    QUERY_SECRET: _real_query_value,
}


def _format_secret(pattern: re.Pattern, text: str, deadline: float) -> bool:
    check = FORMAT_CHECKS.get(pattern)
    if check is None:
        return pattern.search(text) is not None
    for found in pattern.finditer(text):
        if check(found) or time.monotonic() > deadline:
            return True
    return False


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _ascending_run(value: str, length: int = 6) -> bool:
    run = 1
    for previous, current in zip(value, value[1:]):
        run = run + 1 if ord(current) == ord(previous) + 1 and current.isalnum() else 1
        if run >= length:
            return True
    return False


# 1234567890abcdef, xxxxxxxx, aaaaaaaaaa and `your-key-here` are what people write where a key goes; a random key has none of these.
def _placeholder_shaped(value: str) -> bool:
    return (
        re.fullmatch(r"[a-z]+(?:[-_][a-z]+)*", value) is not None
        or FIXTURE_VALUE.fullmatch(value) is not None
        or re.search(r"(.)\1{4,}", value) is not None
        or _ascending_run(value)
        # two lowercase words of four letters or more joined by dashes or underscores (`base64-encoded-credentials-here`)
        or sum(1 for part in re.split(r"[-_]", value) if re.fullmatch(r"[a-z]{4,}", part)) >= 2
    )


# A long run of words, hex groups and numbers joined by dashes, slashes or underscores is a path or a slug, not a key
# (`/tmp/claude-501/-Users-me--claude-worktrees-Project-name-4ddd85/...`); random keys have few separators and no such words.
def _is_slug(value: str) -> bool:
    parts = [part for part in SEPARATORS.split(value) if part]
    if len(parts) < 4:
        return False
    total = sum(len(part) for part in parts)
    covered = sum(len(part) for part in parts if SLUG_SEGMENT.fullmatch(part))
    return covered >= 0.8 * total and sum(1 for part in parts if SLUG_WORD.fullmatch(part)) >= 2


# A name made of letters only, in mixed case, whose words are about three letters or more (`UserAPIKeyAuth`, `StoredOAuthTokens`):
# a type or a class that a typed language puts after the label (`api_key: UserAPIKeyAuth`). A random key has digits, or
# words of one or two letters.
def _type_name(value: str) -> bool:
    if not re.fullmatch(r"[A-Za-z]{8,}", value) or value.islower() or value.isupper():
        return False
    return len(value) >= 3 * len(CAMEL_WORD.findall(value))


def _looks_like_path(value: str) -> bool:
    return value[0] == "/" and (len(value) < 24 or "." in value or sum(c.isupper() for c in value) < 3)


def _plausible_value(label: str, value: str) -> bool:
    # `:Type` and `&Type` are annotations, `key:` is a mapping key and a PEM header has its own rule.
    if PLACEHOLDER.fullmatch(value) or value[0] in "$%<{*~.:&" or value.endswith(":") or value.startswith("-----") or "://" in value[:12] or _looks_like_path(value):
        return False
    password = bool(PASSWORD_LABEL.search(label))
    if CODE_NAME.fullmatch(value) or TITLE_WORD.fullmatch(value) or (len(value) <= 48 and (FIXTURE_VALUE.fullmatch(value) or "EXAMPLE" in value)):
        return False
    if password:
        if SNAKE_WORDS.fullmatch(value) or (len(value) <= 40 and PASSWORD_FIXTURE.fullmatch(value)):
            return False
    elif (
        IDENTIFIER_WORDS.fullmatch(value)
        or CODE_REFERENCE.fullmatch(value)
        or NON_SECRET_VALUE.fullmatch(value)
        or _type_name(value)
        or _placeholder_shaped(value)
    ):
        return False
    # A password label keeps plain versions and Title.Case words: only range versions and
    # lowercase code references (self.config.x) are treated as non-secrets there.
    if password:
        if RANGE_VERSION.fullmatch(value) or (DOTTED_NAME.fullmatch(value) and value[0].islower() and not any(c.isdigit() for c in value)):
            return False
    elif VERSION.fullmatch(value) or DOTTED_NAME.fullmatch(value):
        return False
    if len(value) < (6 if password else 8):
        return False
    if any(character.isdigit() or character.isupper() or not character.isalnum() for character in value):
        return True
    return password and len(value) >= 10


def _labeled_secret(text: str, deadline: float) -> bool:
    for match in LABELED_VALUE.finditer(text):
        if time.monotonic() > deadline:
            return True
        if text[match.end("value") : match.end("value") + 1] in ("(", "["):
            continue
        if _plausible_value(match.group("label"), match.group("value")):
            return True
    return False


def _without_public_material(text: str) -> str:
    # str.find instead of a lazy regex: stray BEGIN markers with no END must not rescan the rest of the text.
    kept: list[str] = []
    position = 0
    ends: dict[str, int] = {}
    for start in PUBLIC_BLOCK_START.finditer(text):
        if start.start() < position:
            continue
        label = start.group(1)
        marker = "-----END " + label + "-----"
        end = ends.get(label, -2)
        if end != -1 and end < start.end():
            end = ends[label] = text.find(marker, start.end())
        if end < 0:
            continue
        kept.append(text[position : start.start()])
        position = end + len(marker)
    kept.append(text[position:])
    return PUBLIC_INLINE.sub(" ", " ".join(kept))


def _jwt_secret(text: str) -> bool:
    # Each match consumes its whole run, so the scan stays linear without a length cap on the segments.
    for first in JWT_FIRST.finditer(text):
        if text[first.end() : first.end() + 1] != ".":
            continue
        second = BASE64URL_RUN.match(text, first.end() + 1)
        if second is not None and text[second.end() : second.end() + 1] == "." and BASE64URL_RUN.match(text, second.end() + 1):
            return True
    return False


def _bare_secret(text: str, deadline: float) -> bool:
    cleaned = _without_public_material(text)
    for found in BARE_CANDIDATE.finditer(cleaned):
        if time.monotonic() > deadline:
            return True
        candidate = found.group(0)
        if candidate.lower().startswith(INTEGRITY_PREFIXES) or candidate.count("/") > len(candidate) * 0.08 or _is_slug(candidate):
            continue
        if cleaned[max(0, found.start() - 3) : found.start()] == "h1:":
            continue
        has_classes = any(c.isupper() for c in candidate) and any(c.islower() for c in candidate) and any(c.isdigit() for c in candidate)
        if has_classes and _entropy(candidate) >= 4.2:
            return True
    return False


def contains_secret(text: str) -> bool:
    deadline = time.monotonic() + SCAN_BUDGET_SECONDS
    for pattern in FORMAT_PATTERNS:
        if _format_secret(pattern, text, deadline) or time.monotonic() > deadline:
            return True
    found = _jwt_secret(text) or _labeled_secret(text, deadline) or _bare_secret(text, deadline)
    return found or time.monotonic() > deadline
