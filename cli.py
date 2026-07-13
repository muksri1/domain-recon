"""Command-line runner for domain-recon.

Examples:
    python cli.py example.com
    python cli.py example.com --csv out.csv
    python cli.py example.com --json report.json
"""

from __future__ import annotations

import argparse
import json
import sys

from reconlib import InvalidDomain, findings_to_csv, scan_domain

# Windows consoles default to a legacy code page; force UTF-8 so em-dashes and
# check marks render instead of mojibake.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# ANSI colors (disabled automatically when output is not a TTY).
_C = {"PASS": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m",
      "INFO": "\033[36m", "ERROR": "\033[35m", "reset": "\033[0m", "bold": "\033[1m"}


def _color(text, key):
    if not sys.stdout.isatty():
        return text
    return f"{_C.get(key, '')}{text}{_C['reset']}"


def _print_report(report: dict):
    print()
    print(_color(f"  Domain: {report['domain']}", "bold"))
    print(f"  Scanned: {report['scanned_at']}  ({report['elapsed_seconds']}s)")
    grade = report["grade"]
    grade_key = "PASS" if grade in ("A", "B") else "WARN" if grade == "C" else "FAIL"
    print(f"  Score: {_color(str(report['score']) + '/100  grade ' + grade, grade_key)}")
    c = report["counts"]
    print(f"  {_color('PASS ' + str(c['PASS']), 'PASS')}  "
          f"{_color('WARN ' + str(c['WARN']), 'WARN')}  "
          f"{_color('FAIL ' + str(c['FAIL']), 'FAIL')}  "
          f"{_color('INFO ' + str(c['INFO']), 'INFO')}")
    print()

    current = None
    for f in report["findings"]:
        if f["category"] != current:
            current = f["category"]
            print(_color(f"  {current}", "bold"))
        tag = _color(f"{f['status']:<5}", f["status"])
        print(f"    [{tag}] {f['check']}: {f['detail']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Passive domain security-controls review.")
    parser.add_argument("domain", help="Domain name to assess (e.g. example.com)")
    parser.add_argument("--csv", metavar="PATH", help="Write findings to a CSV file")
    parser.add_argument("--json", metavar="PATH", help="Write the full report as JSON")
    parser.add_argument("--quiet", action="store_true", help="Suppress the console table")
    args = parser.parse_args()

    try:
        report = scan_domain(args.domain)
    except InvalidDomain as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    if not args.quiet:
        _print_report(report)

    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as fh:
            fh.write(findings_to_csv(report))
        print(f"  CSV written to {args.csv}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"  JSON written to {args.json}")

    # Non-zero exit if any control failed — useful in CI pipelines.
    sys.exit(1 if report["counts"]["FAIL"] else 0)


if __name__ == "__main__":
    main()
