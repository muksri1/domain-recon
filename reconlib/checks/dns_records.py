"""Baseline DNS footprint: A/AAAA/MX/NS/TXT/SOA and nameserver redundancy.

These are mostly INFO findings that describe the domain's public footprint, plus
a couple of resilience best-practice checks (redundant nameservers, IPv6).
"""

from __future__ import annotations

import dns.resolver

from ..models import Finding, Status, Severity
from ..utils import make_resolver

CATEGORY = "DNS Footprint"


def _resolve(resolver, name, rtype):
    try:
        return list(resolver.resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        return []


def run(domain: str, resolver=None) -> list[Finding]:
    resolver = resolver or make_resolver()
    findings: list[Finding] = []

    a = [str(r) for r in _resolve(resolver, domain, "A")]
    aaaa = [str(r) for r in _resolve(resolver, domain, "AAAA")]
    mx = [(r.preference, str(r.exchange).rstrip(".")) for r in _resolve(resolver, domain, "MX")]
    ns = [str(r).rstrip(".") for r in _resolve(resolver, domain, "NS")]

    if a:
        findings.append(Finding(
            CATEGORY, "A records", Status.INFO,
            f"Resolves to {len(a)} IPv4 address(es).",
            evidence=", ".join(a),
        ))
    else:
        findings.append(Finding(
            CATEGORY, "A records", Status.WARN,
            "No A record found; the apex domain does not resolve to IPv4.",
            "Confirm this is intentional (e.g. a redirect-only or MX-only domain).",
            Severity.LOW,
        ))

    findings.append(Finding(
        CATEGORY, "IPv6 (AAAA)",
        Status.PASS if aaaa else Status.INFO,
        f"{len(aaaa)} IPv6 address(es) published." if aaaa
        else "No AAAA record; the domain is IPv4-only.",
        "" if aaaa else "Consider publishing AAAA records to support IPv6 clients.",
        evidence=", ".join(str(x) for x in aaaa),
    ))

    if ns:
        distinct_domains = {".".join(host.split(".")[-2:]) for host in ns}
        if len(ns) >= 2:
            findings.append(Finding(
                CATEGORY, "Nameserver redundancy", Status.PASS,
                f"{len(ns)} nameservers configured.",
                evidence=", ".join(ns),
            ))
        else:
            findings.append(Finding(
                CATEGORY, "Nameserver redundancy", Status.WARN,
                "Only one nameserver is published — a single point of failure.",
                "Publish at least two nameservers, ideally on separate networks.",
                Severity.MEDIUM, ", ".join(ns),
            ))
        if len(distinct_domains) < 2 and len(ns) >= 2:
            findings.append(Finding(
                CATEGORY, "Nameserver diversity", Status.INFO,
                "All nameservers appear to sit under a single parent domain/provider.",
                "For higher resilience, consider a secondary DNS provider.",
                evidence=", ".join(sorted(distinct_domains)),
            ))
    else:
        findings.append(Finding(
            CATEGORY, "Nameservers", Status.ERROR,
            "Could not retrieve NS records.",
        ))

    real_mx = [(p, h) for p, h in mx if h]  # null MX (RFC 7505) has an empty exchange
    if mx and not real_mx:
        findings.append(Finding(
            CATEGORY, "Mail exchangers (MX)", Status.INFO,
            "Null MX record (RFC 7505) published — the domain explicitly does not send or "
            "receive email.",
            evidence="; ".join(f"{p} ." for p, _ in mx),
        ))
    elif real_mx:
        findings.append(Finding(
            CATEGORY, "Mail exchangers (MX)", Status.INFO,
            f"{len(real_mx)} MX host(s) configured — the domain can receive email.",
            evidence=", ".join(f"{p} {h}" for p, h in sorted(real_mx)),
        ))
    else:
        findings.append(Finding(
            CATEGORY, "Mail exchangers (MX)", Status.INFO,
            "No MX records; the domain does not advertise mail servers.",
        ))

    return findings
