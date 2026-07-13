"""Email authentication controls: SPF, DMARC, and best-effort DKIM discovery.

These records tell receiving mail servers how to detect spoofed mail claiming to
be from this domain. A domain with MX but no SPF/DMARC is trivially spoofable.
"""

from __future__ import annotations

import dns.resolver

from ..models import Finding, Severity, Status
from ..utils import make_resolver

CATEGORY = "Email Authentication"

# Selectors commonly used by mainstream mail providers, probed to give the user
# a hint about DKIM. Absence here does NOT prove DKIM is unconfigured.
_COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "default", "mail", "dkim", "smtp", "mandrill", "mxvault", "everlytickey1",
]


def _is_valid_dkim(record: str) -> bool:
    """A usable DKIM key must publish a non-empty public key (p=...).

    'v=DKIM1; p=' with an empty value is a *revoked* key (common on wildcard
    _domainkey records used by example/anti-abuse domains) and must not count.
    """
    low = record.lower()
    if "v=dkim1" not in low and "p=" not in low:
        return False
    for token in record.split(";"):
        token = token.strip()
        if token.lower().startswith("p="):
            return len(token[2:].strip().strip('"')) > 0
    return False


def _txt(resolver, name) -> list[str]:
    out = []
    try:
        for r in resolver.resolve(name, "TXT"):
            # dnspython returns quoted, possibly multi-string TXT records.
            out.append("".join(s.decode() if isinstance(s, bytes) else s for s in r.strings))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        pass
    return out


def run(domain: str, resolver=None) -> list[Finding]:
    resolver = resolver or make_resolver()
    findings: list[Finding] = []

    # ---- SPF -------------------------------------------------------------
    spf_records = [t for t in _txt(resolver, domain) if t.lower().startswith("v=spf1")]
    if not spf_records:
        findings.append(Finding(
            CATEGORY, "SPF", Status.FAIL,
            "No SPF record found. Anyone can send mail claiming to be from this domain "
            "without failing an SPF check.",
            "Publish a TXT record starting with 'v=spf1' that lists authorized senders "
            "and ends with '-all'.",
            Severity.HIGH,
        ))
    elif len(spf_records) > 1:
        findings.append(Finding(
            CATEGORY, "SPF", Status.FAIL,
            "Multiple SPF records published — RFC 7208 requires exactly one; receivers "
            "will treat this as a permerror.",
            "Consolidate into a single 'v=spf1' TXT record.",
            Severity.MEDIUM, " | ".join(spf_records),
        ))
    else:
        spf = spf_records[0]
        low = spf.lower()
        if "-all" in low:
            findings.append(Finding(
                CATEGORY, "SPF", Status.PASS,
                "SPF record present with a hard-fail (-all) policy.",
                evidence=spf,
            ))
        elif "~all" in low:
            findings.append(Finding(
                CATEGORY, "SPF", Status.WARN,
                "SPF present but ends with soft-fail (~all); unauthorized mail is marked, "
                "not rejected.",
                "Move to '-all' once you are confident all legitimate senders are listed.",
                Severity.LOW, spf,
            ))
        elif "+all" in low or "?all" in low:
            findings.append(Finding(
                CATEGORY, "SPF", Status.FAIL,
                "SPF ends with '+all' or '?all', which authorizes any sender — effectively "
                "no protection.",
                "Replace the trailing mechanism with '-all'.",
                Severity.HIGH, spf,
            ))
        else:
            findings.append(Finding(
                CATEGORY, "SPF", Status.WARN,
                "SPF present but has no explicit 'all' mechanism; behavior for unlisted "
                "senders is undefined.",
                "Append '-all' (hard fail) to the record.",
                Severity.MEDIUM, spf,
            ))

    # ---- DMARC -----------------------------------------------------------
    dmarc_records = [t for t in _txt(resolver, f"_dmarc.{domain}")
                     if t.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        findings.append(Finding(
            CATEGORY, "DMARC", Status.FAIL,
            "No DMARC record. Without DMARC there is no policy telling receivers what to do "
            "with mail that fails SPF/DKIM, and no reporting.",
            "Publish a TXT record at _dmarc.<domain> such as "
            "'v=DMARC1; p=none; rua=mailto:dmarc@<domain>' and tighten to p=reject over time.",
            Severity.HIGH,
        ))
    else:
        dmarc = dmarc_records[0]
        low = dmarc.lower()
        policy = "none"
        for token in low.replace(" ", "").split(";"):
            if token.startswith("p="):
                policy = token[2:]
        has_rua = "rua=" in low
        if policy == "reject":
            findings.append(Finding(
                CATEGORY, "DMARC", Status.PASS,
                "DMARC published with an enforcing policy (p=reject).",
                "" if has_rua else "Add an 'rua=' aggregate-report address to gain visibility.",
                evidence=dmarc,
            ))
        elif policy == "quarantine":
            findings.append(Finding(
                CATEGORY, "DMARC", Status.WARN,
                "DMARC set to p=quarantine; failing mail is sent to spam rather than rejected.",
                "Advance to p=reject once aggregate reports show no legitimate senders failing.",
                Severity.LOW, dmarc,
            ))
        else:
            findings.append(Finding(
                CATEGORY, "DMARC", Status.WARN,
                "DMARC set to p=none (monitor only); spoofed mail is not blocked.",
                "Use p=none to collect reports, then move to quarantine and reject.",
                Severity.MEDIUM, dmarc,
            ))

    # ---- DKIM (best-effort discovery) -----------------------------------
    # Guard against wildcard *._domainkey records: if an improbable random
    # selector also "resolves", the domain answers every selector and per-selector
    # discovery is meaningless, so we don't claim DKIM is configured.
    wildcard = any(_is_valid_dkim(r)
                   for r in _txt(resolver, f"zz9-recon-probe._domainkey.{domain}"))
    found_selectors = []
    if not wildcard:
        for selector in _COMMON_DKIM_SELECTORS:
            recs = _txt(resolver, f"{selector}._domainkey.{domain}")
            if any(_is_valid_dkim(r) for r in recs):
                found_selectors.append(selector)
    if found_selectors:
        findings.append(Finding(
            CATEGORY, "DKIM", Status.PASS,
            f"DKIM key(s) found for selector(s): {', '.join(found_selectors)}.",
            evidence=", ".join(found_selectors),
        ))
    else:
        findings.append(Finding(
            CATEGORY, "DKIM", Status.INFO,
            "No DKIM key found among common selectors. DKIM uses provider-specific "
            "selector names, so it may still be configured under a name not probed here.",
            "Confirm DKIM signing is enabled with your mail provider.",
        ))

    return findings
