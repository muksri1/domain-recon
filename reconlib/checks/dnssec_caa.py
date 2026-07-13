"""Zone-integrity controls: DNSSEC signing and CAA issuance restriction."""

from __future__ import annotations

import dns.flags
import dns.resolver
import dns.message
import dns.query

from ..models import Finding, Status, Severity
from ..utils import make_resolver

CATEGORY = "DNS Integrity"


def _has_dnssec(resolver, domain: str) -> tuple[bool, str]:
    """Return (signed, evidence). Presence of DNSKEY indicates the zone is signed."""
    try:
        answer = resolver.resolve(domain, "DNSKEY")
        return True, f"{len(answer)} DNSKEY record(s) present"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        return False, ""


def run(domain: str, resolver=None) -> list[Finding]:
    resolver = resolver or make_resolver()
    findings: list[Finding] = []

    signed, evidence = _has_dnssec(resolver, domain)
    if signed:
        findings.append(Finding(
            CATEGORY, "DNSSEC", Status.PASS,
            "Zone is DNSSEC-signed (DNSKEY present), protecting against DNS response "
            "tampering and cache poisoning.",
            evidence=evidence,
        ))
    else:
        findings.append(Finding(
            CATEGORY, "DNSSEC", Status.WARN,
            "No DNSSEC signing detected. DNS answers for this domain cannot be "
            "cryptographically validated by resolvers.",
            "Enable DNSSEC at your DNS provider and publish the DS record at the registrar.",
            Severity.MEDIUM,
        ))

    # ---- CAA -------------------------------------------------------------
    try:
        caa = list(resolver.resolve(domain, "CAA"))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        caa = []

    if caa:
        issuers = [str(r) for r in caa]
        findings.append(Finding(
            CATEGORY, "CAA", Status.PASS,
            "CAA record restricts which certificate authorities may issue certificates "
            "for this domain.",
            evidence="; ".join(issuers),
        ))
    else:
        findings.append(Finding(
            CATEGORY, "CAA", Status.WARN,
            "No CAA record. Any public CA may issue a certificate for this domain, "
            "widening the mis-issuance risk.",
            "Publish a CAA record naming only your intended CA(s), e.g. "
            "'0 issue \"letsencrypt.org\"'.",
            Severity.LOW,
        ))

    return findings
