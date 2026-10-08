"""Finds secret-shaped values in text before an agent can read it. Leans toward false positives."""

from __future__ import annotations

import math
import re
import time
from collections import Counter

# The hook is killed after 5 seconds and a killed hook lets the output through, so a scan that
# cannot finish in time reports a secret instead (withholding is the safe failure).
SCAN_BUDGET_SECONDS = 3.0

FORMAT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY[A-Z ]{0,40}-----"),
    re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}"),
    re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}"),
    re.compile(r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"),
    re.compile(r"gl(?:pat|dt|ptt|rt|soat|imt|agent|cbt|ft)-[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?:(?<![A-Za-z_])npm_[A-Za-z0-9]{30,}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{12,})"),
    re.compile(r"(?:(?<![A-Za-z])sk-(?:ant-|proj-)?|xox[baprs]-|sk_live_|rk_live_|sk_test_|rk_test_)[A-Za-z0-9_-]{12,}"),
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
    re.compile(r"(?i)authorization\s*[:=]\s*[\"']?(?:bearer|basic|token|digest)\s+(?![$<{])[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)bearer\s+(?![$<{])[A-Za-z0-9._~+/=-]{24,}"),
    re.compile(r"(?i)\blogin\s+\S+\s+password\s+\S{4,}"),
    re.compile(r"(?i)\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{16,}\""),
    re.compile(r"(?i)[?&](?:sig|signature|x-amz-signature)=[A-Za-z0-9%+/=_-]{20,}"),
    re.compile(r"(?i)[?&](?:[a-z0-9.-]{0,30}_)?(?:token|key|secret|password|passwd|apikey)=[^\s&#]"),
    # Repeats are bounded where several match starts can share one run of characters (here the scheme),
    # which keeps every pattern linear: a hook that overruns its timeout lets the output through.
    re.compile(r"(?i)[a-z][a-z0-9+.-]{0,30}://[^\s/:@]*:[^\s/@]+@"),
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


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _looks_like_path(value: str) -> bool:
    return value[0] == "/" and (len(value) < 24 or "." in value or sum(c.isupper() for c in value) < 3)


def _plausible_value(label: str, value: str) -> bool:
    if PLACEHOLDER.fullmatch(value) or value[0] in "$%<{*~." or "://" in value[:12] or _looks_like_path(value):
        return False
    password = bool(PASSWORD_LABEL.search(label))
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
        if candidate.lower().startswith(INTEGRITY_PREFIXES) or candidate.count("/") > len(candidate) * 0.08:
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
        if pattern.search(text) or time.monotonic() > deadline:
            return True
    found = _jwt_secret(text) or _labeled_secret(text, deadline) or _bare_secret(text, deadline)
    return found or time.monotonic() > deadline
