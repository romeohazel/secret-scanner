"""Format and print scanner findings without ever revealing a raw secret."""

from collections import defaultdict


def redact(secret):
    """Return a masked version of `secret`, keeping only the first/last 4 chars.

    Secrets of 8 chars or fewer are masked entirely.
    """
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def _deduplicate(findings):
    """Collapse findings sharing the same (file, line, match) — first one wins.

    Different rules sometimes fire on the same secret at the same location
    (e.g. a regex rule and the generic entropy heuristic both flag a token
    assignment). The composite key preserves real signal: the same secret
    in two different files, or on two different lines, is still reported.
    """
    seen = set()
    unique = []
    for finding in findings:
        key = (finding["file"], finding["line"], finding["match"])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def print_report(findings):
    """Group findings by file and print a human-readable report to stdout."""
    findings = _deduplicate(findings)

    if not findings:
        print("No secrets found.")
        return

    by_file = defaultdict(list)
    for finding in findings:
        by_file[finding["file"]].append(finding)

    for file_path in sorted(by_file):
        print(file_path)
        for finding in sorted(by_file[file_path], key=lambda f: f["line"]):
            line_no = finding["line"]
            rule = finding["rule"]
            redacted = redact(finding["match"])
            print(f"  line {line_no}: [{rule}] {redacted}")
        print()

    n = len(findings)
    m = len(by_file)
    print(
        f"{n} secret{'s' if n != 1 else ''} found "
        f"across {m} file{'s' if m != 1 else ''}."
    )
