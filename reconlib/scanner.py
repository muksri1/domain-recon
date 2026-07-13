"""Scan orchestrator.

Runs every registered check against a domain, in parallel, and assembles a
single report dict that the web dashboard and CSV exporter both consume.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone

from .models import Finding, Status, Severity, score_findings
from .utils import normalize_domain, make_resolver, InvalidDomain
from .checks import (
    dns_records,
    email_auth,
    dnssec_caa,
    tls_cert,
    http_headers,
    registration,
    attack_surface,
)

# Ordered so the dashboard shows controls before informational surface data.
CHECKS = [
    ("DNS Footprint", dns_records),
    ("Email Authentication", email_auth),
    ("DNS Integrity", dnssec_caa),
    ("TLS / Certificate", tls_cert),
    ("HTTP Security Headers", http_headers),
    ("Domain Registration", registration),
    ("Attack Surface", attack_surface),
]


def _run_one(name, module, domain, resolver) -> list[Finding]:
    """Execute a single check, converting any unexpected crash into an ERROR finding."""
    try:
        return module.run(domain, resolver=resolver)
    except Exception as exc:  # defensive: a bug in one check must not kill the scan
        return [Finding(
            name, "check execution", Status.ERROR,
            f"The '{name}' check raised an unexpected error: {exc.__class__.__name__}: {exc}.",
            severity=Severity.NONE, evidence=str(exc),
        )]


# Overall wall-clock budget for a scan. A single slow/streaming external service
# (notably crt.sh on large domains) must not hang the whole request, so any check
# still running past this deadline is abandoned with a TIMEOUT finding.
SCAN_BUDGET_SECONDS = 25.0


def scan_domain(raw_domain: str, max_workers: int = 7,
                budget: float = SCAN_BUDGET_SECONDS) -> dict:
    """Run all checks and return a structured report.

    Raises InvalidDomain if the input cannot be parsed as a domain.
    """
    domain = normalize_domain(raw_domain)
    resolver = make_resolver()
    started = time.perf_counter()

    findings: list[Finding] = []
    # Not using the context manager: its __exit__ calls shutdown(wait=True), which
    # would block on a straggler thread and defeat the deadline. We shut down with
    # wait=False and let any orphaned check thread finish and die on its own.
    pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = {
            pool.submit(_run_one, name, module, domain, resolver): name
            for name, module in CHECKS
        }
        deadline = time.monotonic() + budget
        for future, name in futures.items():
            remaining = deadline - time.monotonic()
            try:
                findings.extend(future.result(timeout=max(0.0, remaining)))
            except FuturesTimeout:
                findings.append(Finding(
                    name, "check execution", Status.ERROR,
                    f"The '{name}' check did not finish within the {budget:.0f}s scan "
                    "budget and was skipped.",
                    "Re-run the scan; if it persists the underlying service may be slow.",
                    Severity.NONE,
                ))
    finally:
        pool.shutdown(wait=False)

    # Stable ordering: by category (in CHECKS order), then worst status first.
    category_order = {name: i for i, (name, _) in enumerate(CHECKS)}
    status_rank = {Status.FAIL: 0, Status.WARN: 1, Status.ERROR: 2,
                   Status.INFO: 3, Status.PASS: 4}
    findings.sort(key=lambda f: (category_order.get(f.category, 99),
                                 status_rank.get(f.status, 9), f.check))

    summary = score_findings(findings)
    elapsed = round(time.perf_counter() - started, 2)

    # Per-category rollup for the dashboard.
    categories: dict[str, dict] = {}
    for name, _ in CHECKS:
        categories[name] = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0, "ERROR": 0}
    for f in findings:
        categories.setdefault(f.category,
                              {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0, "ERROR": 0})
        categories[f.category][f.status.value] += 1

    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_seconds": elapsed,
        "score": summary["score"],
        "grade": summary["grade"],
        "counts": summary["counts"],
        "categories": categories,
        "findings": [f.to_row() for f in findings],
    }
