"""Data models for reconnaissance findings.

A *Finding* is the atomic unit of the report: one observation about one
security control, with a status, an optional severity, human-readable detail,
and a remediation recommendation. Everything the dashboard renders and the CSV
exports is a list of Findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Outcome of a single check."""

    PASS = "PASS"      # control present and correctly configured
    WARN = "WARN"      # present but weak, or best-practice gap
    FAIL = "FAIL"      # control missing or misconfigured
    INFO = "INFO"      # neutral observation / attack-surface data
    ERROR = "ERROR"    # the check itself could not complete


class Severity(str, Enum):
    """How much a non-passing finding matters."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Penalty applied to the 0-100 score for each (status, severity) combination.
# INFO/PASS never subtract. ERROR is neutral (we could not measure it).
_PENALTY = {
    (Status.FAIL, Severity.HIGH): 18,
    (Status.FAIL, Severity.MEDIUM): 11,
    (Status.FAIL, Severity.LOW): 5,
    (Status.WARN, Severity.HIGH): 9,
    (Status.WARN, Severity.MEDIUM): 5,
    (Status.WARN, Severity.LOW): 2,
}


@dataclass
class Finding:
    category: str          # e.g. "Email Authentication"
    check: str             # e.g. "DMARC policy"
    status: Status
    detail: str            # what we observed
    recommendation: str = ""
    severity: Severity = Severity.NONE
    evidence: str = ""     # raw record / header value backing the finding

    def penalty(self) -> int:
        return _PENALTY.get((self.status, self.severity), 0)

    def to_row(self) -> dict[str, Any]:
        """Flat dict used for both JSON and CSV serialization."""
        return {
            "category": self.category,
            "check": self.check,
            "status": self.status.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


def score_findings(findings: list[Finding]) -> dict[str, Any]:
    """Compute an overall 0-100 score and letter grade from findings."""
    score = 100 - sum(f.penalty() for f in findings)
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1

    return {"score": score, "grade": grade, "counts": counts}
