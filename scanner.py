"""CLI entry point: walk a directory, scan every text file, print a report.

Exits with status 1 if any findings are reported, 0 otherwise.
"""

import argparse
import os
import sys

import entropy
import patterns
import report

SKIP_DIRS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    ".next",
    "__pycache__",
    "venv",
    ".venv",
}

SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".zip",
    ".lock",
    ".woff",
    ".woff2",
    ".ttf",
    ".ico",
}

BINARY_SNIFF_BYTES = 4096


def is_binary(path):
    """Heuristic: a file is treated as binary if its first chunk contains a NUL byte."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def should_skip_file(path):
    """Return True for files we don't want to scan (binary or known non-text extension)."""
    _, ext = os.path.splitext(path)
    if ext.lower() in SKIP_EXTENSIONS:
        return True
    return is_binary(path)


def scan_file(path):
    """Yield finding dicts for every regex or entropy hit in `path`."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                for rule, match in patterns.scan_line(line):
                    yield {"file": path, "line": lineno, "rule": rule, "match": match}
                for rule, match in entropy.scan_line(line):
                    yield {"file": path, "line": lineno, "rule": rule, "match": match}
    except OSError as e:
        print(f"warning: could not read {path}: {e}", file=sys.stderr)


def walk(target, verbose=False):
    """Walk `target` recursively, yielding findings from every scannable file."""
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            if should_skip_file(path):
                if verbose:
                    print(f"skip {path}", file=sys.stderr)
                continue
            if verbose:
                print(f"scan {path}", file=sys.stderr)
            yield from scan_file(path)


def main():
    parser = argparse.ArgumentParser(
        description="Recursively scan a directory for leaked secrets.",
    )
    parser.add_argument("target", help="Directory to scan")
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print every file as it is scanned or skipped",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        sys.exit(2)

    findings = list(walk(args.target, verbose=args.verbose))
    report.print_report(findings)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
