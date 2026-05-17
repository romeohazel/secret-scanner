"""Shannon entropy and a heuristic for generic high-entropy secrets.

Flags string assignments whose variable name looks secret-related
(`password`, `api_key`, `token`, ...) and whose value is both long
enough and high-entropy enough to plausibly be a real secret.
"""

import math
import re

ENTROPY_THRESHOLD = 4.0
MIN_SECRET_LENGTH = 12

SECRET_KEYWORDS = (
    "secret",
    "token",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "auth",
    "credential",
)

# Matches assignments like `password = "xyz"` or `API_KEY: 'xyz'`.
# Group 1 captures the variable name; group 2 captures the quoted value.
_ASSIGNMENT_RE = re.compile(
    r"(\w*(?:" + "|".join(SECRET_KEYWORDS) + r")\w*)"
    r"\s*[:=]\s*"
    r"['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


def shannon_entropy(s):
    """Return the Shannon entropy (bits per character) of string `s`."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def scan_line(line):
    """Return (rule_name, matched_text) tuples for any generic secrets on `line`."""
    findings = []
    for match in _ASSIGNMENT_RE.finditer(line):
        value = match.group(2)
        if len(value) >= MIN_SECRET_LENGTH and shannon_entropy(value) > ENTROPY_THRESHOLD:
            findings.append(("Generic High-Entropy Secret", value))
    return findings
