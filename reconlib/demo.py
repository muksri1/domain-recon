"""A canned, offline sample report used by the dashboard's demo mode (?demo=1).

Built from real Finding objects and scored with the production scoring logic, so
the demo always matches the shape the live scanner produces. The data is
illustrative (a fictional example-corp.com) and performs no network calls.
"""

from __future__ import annotations

from .models import Finding, Severity, Status, score_findings

_F = Finding
_DEMO_FINDINGS = [
    # DNS Footprint
    _F("DNS Footprint", "A records", Status.INFO, "Resolves to 2 IPv4 address(es).",
       evidence="203.0.113.10, 203.0.113.11"),
    _F("DNS Footprint", "IPv6 (AAAA)", Status.PASS, "2 IPv6 address(es) published.",
       evidence="2001:db8::10, 2001:db8::11"),
    _F("DNS Footprint", "Nameserver redundancy", Status.PASS, "4 nameservers configured.",
       evidence="ns1.example-dns.net, ns2.example-dns.net, ns3.example-dns.org, ns4.example-dns.org"),
    _F("DNS Footprint", "Mail exchangers (MX)", Status.INFO,
       "2 MX host(s) configured — the domain can receive email.",
       evidence="10 mx1.example-corp.com, 20 mx2.example-corp.com"),

    # Email Authentication
    _F("Email Authentication", "SPF", Status.PASS,
       "SPF record present with a hard-fail (-all) policy.",
       evidence="v=spf1 include:_spf.example-corp.com -all"),
    _F("Email Authentication", "DMARC", Status.WARN,
       "DMARC set to p=quarantine; failing mail is sent to spam rather than rejected.",
       "Advance to p=reject once aggregate reports show no legitimate senders failing.",
       Severity.LOW, "v=DMARC1; p=quarantine; rua=mailto:dmarc@example-corp.com"),
    _F("Email Authentication", "DKIM", Status.PASS,
       "DKIM key(s) found for selector(s): selector1, selector2.",
       evidence="selector1, selector2"),

    # DNS Integrity
    _F("DNS Integrity", "DNSSEC", Status.WARN,
       "No DNSSEC signing detected. DNS answers for this domain cannot be "
       "cryptographically validated by resolvers.",
       "Enable DNSSEC at your DNS provider and publish the DS record at the registrar.",
       Severity.MEDIUM),
    _F("DNS Integrity", "CAA", Status.PASS,
       "CAA record restricts which certificate authorities may issue certificates for this domain.",
       evidence='0 issue "letsencrypt.org"'),

    # TLS / Certificate
    _F("TLS / Certificate", "Certificate expiry", Status.PASS,
       "Certificate valid for 74 more day(s).", evidence="Sep 25 12:00:00 2026 GMT"),
    _F("TLS / Certificate", "Certificate issuer", Status.INFO,
       "Issued to 'example-corp.com' by 'Let's Encrypt'.",
       evidence="{'commonName': 'R11', 'organizationName': \"Let's Encrypt\"}"),
    _F("TLS / Certificate", "Negotiated protocol", Status.PASS,
       "Connection negotiated TLSv1.3.", evidence="TLSv1.3; TLS_AES_256_GCM_SHA384"),
    _F("TLS / Certificate", "Legacy TLS protocols", Status.PASS,
       "TLS 1.0 and TLS 1.1 are not accepted."),

    # HTTP Security Headers
    _F("HTTP Security Headers", "HTTPS redirect", Status.PASS,
       "Plain HTTP requests are redirected to HTTPS.",
       evidence="http://example-corp.com/ -> https://example-corp.com/"),
    _F("HTTP Security Headers", "HSTS (Strict-Transport-Security)", Status.PASS,
       "Header is present.", evidence="max-age=31536000; includeSubDomains"),
    _F("HTTP Security Headers", "Content-Security-Policy", Status.PASS, "Header is present.",
       evidence="default-src 'self'; ..."),
    _F("HTTP Security Headers", "X-Content-Type-Options", Status.PASS, "Header is present.",
       evidence="nosniff"),
    _F("HTTP Security Headers", "X-Frame-Options", Status.PASS, "Header is present.",
       evidence="DENY"),
    _F("HTTP Security Headers", "Referrer-Policy", Status.FAIL, "Header is not set.",
       "Add a 'Referrer-Policy' such as 'strict-origin-when-cross-origin'.", Severity.LOW),
    _F("HTTP Security Headers", "Permissions-Policy", Status.FAIL, "Header is not set.",
       "Add a 'Permissions-Policy' to restrict access to browser features.", Severity.LOW),
    _F("HTTP Security Headers", "Info disclosure: server", Status.WARN,
       "Response advertises 'server: nginx/1.21.0', revealing software details.",
       "Suppress or genericize the 'server' header to reduce fingerprinting.",
       Severity.LOW, "nginx/1.21.0"),

    # Domain Registration
    _F("Domain Registration", "Registrar", Status.INFO, "Registered through Example Registrar, Inc.",
       evidence="Example Registrar, Inc."),
    _F("Domain Registration", "Registration expiry", Status.PASS,
       "Registration valid for 268 more day(s).", evidence="2027-04-07T00:00:00+00:00"),
    _F("Domain Registration", "Registrar lock", Status.PASS,
       "Protective status codes are set (transfer/delete/update prohibited).",
       evidence="clienttransferprohibited, clientdeleteprohibited"),

    # Attack Surface
    _F("Attack Surface", "Subdomains (CT logs)", Status.INFO,
       "18 distinct subdomain(s) appear in public CT logs. Each is potential attack surface "
       "worth confirming is intended and maintained.",
       "Review this list for forgotten or staging hosts that should be decommissioned.",
       evidence="api.example-corp.com, blog.example-corp.com, cdn.example-corp.com, "
                "mail.example-corp.com, shop.example-corp.com, www.example-corp.com … (+12 more)"),
    _F("Attack Surface", "Sensitive-looking hostnames", Status.WARN,
       "2 subdomain(s) have names suggesting non-production or administrative services "
       "exposed publicly.",
       "Verify these hosts should be internet-facing; restrict or remove if not.",
       Severity.LOW, "admin.example-corp.com, staging.example-corp.com"),
]

_CATEGORY_ORDER = [
    "DNS Footprint", "Email Authentication", "DNS Integrity", "TLS / Certificate",
    "HTTP Security Headers", "Domain Registration", "Attack Surface",
]


def _build() -> dict:
    summary = score_findings(_DEMO_FINDINGS)
    categories = {name: {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0, "ERROR": 0}
                  for name in _CATEGORY_ORDER}
    for f in _DEMO_FINDINGS:
        categories[f.category][f.status.value] += 1
    return {
        "domain": "example-corp.com",
        "scanned_at": "2026-07-13T09:00:00+00:00",
        "elapsed_seconds": 6.2,
        "score": summary["score"],
        "grade": summary["grade"],
        "counts": summary["counts"],
        "categories": categories,
        "findings": [f.to_row() for f in _DEMO_FINDINGS],
        "demo": True,
    }


DEMO_REPORT = _build()
