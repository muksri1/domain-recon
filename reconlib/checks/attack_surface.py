"""Attack-surface awareness from public Certificate Transparency logs (crt.sh).

Every publicly trusted TLS certificate is logged to CT. Querying crt.sh reveals
subdomains that have had certificates issued — a passive way to understand how
much surface a domain exposes, without any scanning of the target itself.
"""

from __future__ import annotations

import time

import requests

from ..models import Finding, Status, Severity

CATEGORY = "Attack Surface"
# crt.sh is frequently overloaded and either fast-fails with 502 or hangs. Keep
# the total budget bounded (worst case ~ _RETRIES * _TIMEOUT + backoff) so this
# one external dependency never dominates the scan; it degrades to ERROR if slow.
_TIMEOUT = 8.0
_RETRIES = 2


def _query_crtsh(domain: str):
    """Query crt.sh with retries on transient errors. Returns parsed JSON rows.

    Raises the last exception if every attempt fails.
    """
    last_exc: Exception = RuntimeError("no attempt made")
    for attempt in range(_RETRIES):
        try:
            resp = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=_TIMEOUT,
                headers={"User-Agent": "domain-recon/1.0"},
            )
            if resp.status_code in (502, 503, 504, 429):
                last_exc = requests.HTTPError(f"crt.sh returned {resp.status_code}")
                if attempt < _RETRIES - 1:
                    time.sleep(1.0)
                continue
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < _RETRIES - 1:
                time.sleep(1.0)
    raise last_exc


def run(domain: str, resolver=None) -> list[Finding]:
    findings: list[Finding] = []
    try:
        rows = _query_crtsh(domain)
    except (requests.RequestException, ValueError) as exc:
        findings.append(Finding(
            CATEGORY, "Certificate Transparency (crt.sh)", Status.ERROR,
            "Could not query crt.sh after retries (the public service is often rate-limited "
            "or temporarily down); subdomain discovery skipped.",
            "Re-run later, or query crt.sh / another CT source manually.",
            Severity.NONE, str(exc),
        ))
        return findings

    names: set[str] = set()
    for row in rows:
        value = row.get("name_value", "")
        for name in value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain:
                names.add(name)

    if not names:
        findings.append(Finding(
            CATEGORY, "Subdomains (CT logs)", Status.INFO,
            "No subdomains found in public Certificate Transparency logs.",
        ))
        return findings

    sample = sorted(names)
    findings.append(Finding(
        CATEGORY, "Subdomains (CT logs)", Status.INFO,
        f"{len(names)} distinct subdomain(s) appear in public CT logs. Each is potential "
        "attack surface worth confirming is intended and maintained.",
        "Review this list for forgotten or staging hosts that should be decommissioned.",
        Severity.NONE,
        ", ".join(sample[:40]) + (f" … (+{len(sample) - 40} more)" if len(sample) > 40 else ""),
    ))

    # Flag names that often indicate non-production / higher-risk hosts.
    interesting_markers = ("dev", "test", "staging", "stage", "uat", "qa", "admin",
                           "internal", "vpn", "jenkins", "gitlab", "grafana", "kibana")
    flagged = sorted({n for n in names if any(m in n for m in interesting_markers)})
    if flagged:
        findings.append(Finding(
            CATEGORY, "Sensitive-looking hostnames", Status.WARN,
            f"{len(flagged)} subdomain(s) have names suggesting non-production or "
            "administrative services exposed publicly.",
            "Verify these hosts should be internet-facing; restrict or remove if not.",
            Severity.LOW,
            ", ".join(flagged[:30]) + (f" … (+{len(flagged) - 30} more)" if len(flagged) > 30 else ""),
        ))

    return findings
