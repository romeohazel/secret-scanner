"""Regex patterns for well-known secret formats.

Each pattern is paired with a human-readable rule name. `scan_line` runs
all patterns against a single line of text and returns every match.
"""

import re

PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token (classic)", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub Token (fine-grained)", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("Stripe Live Key", re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    ("Google API Key", re.compile(r"AIza[A-Za-z0-9_\-]{35}")),
    ("JWT / Supabase Token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("Private Key Block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]


def scan_line(line):
    """Return a list of (rule_name, matched_text) tuples for every pattern hit in `line`."""
    findings = []
    for name, pattern in PATTERNS:
        for match in pattern.finditer(line):
            findings.append((name, match.group(0)))
    return findings
