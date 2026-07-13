"""Serialize a scan report to CSV for spreadsheets / downstream analysis."""

from __future__ import annotations

import csv
import io

_COLUMNS = ["domain", "scanned_at", "category", "check", "status",
            "severity", "detail", "recommendation", "evidence"]


def findings_to_csv(report: dict) -> str:
    """Return the report's findings as a CSV string (one row per finding)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for row in report.get("findings", []):
        writer.writerow({
            "domain": report.get("domain", ""),
            "scanned_at": report.get("scanned_at", ""),
            **row,
        })
    return buffer.getvalue()
