"""Domain registration intelligence via RDAP (the modern, JSON WHOIS successor).

Uses rdap.org, which redirects to the authoritative registry for the TLD. This
is public registration data; no credentials are required.
"""

from __future__ import annotations

from datetime import datetime, timezone

import requests

from ..models import Finding, Status, Severity

CATEGORY = "Domain Registration"
_TIMEOUT = 10.0


def _event(events, action):
    for e in events or []:
        if e.get("eventAction") == action:
            return e.get("eventDate")
    return None


def _parse_iso(value: str):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def run(domain: str, resolver=None) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=_TIMEOUT,
                            headers={"Accept": "application/rdap+json"})
        if resp.status_code == 404:
            findings.append(Finding(
                CATEGORY, "RDAP lookup", Status.INFO,
                "Registry returned no RDAP record for this domain.",
            ))
            return findings
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        findings.append(Finding(
            CATEGORY, "RDAP lookup", Status.ERROR,
            f"RDAP lookup failed ({exc.__class__.__name__}); registration data unavailable.",
            evidence=str(exc),
        ))
        return findings

    events = data.get("events", [])
    registered = _parse_iso(_event(events, "registration"))
    expires = _parse_iso(_event(events, "expiration"))

    # Registrar name from the entities block.
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        registrar = item[3]
    if registrar:
        findings.append(Finding(
            CATEGORY, "Registrar", Status.INFO,
            f"Registered through {registrar}.",
            evidence=registrar,
        ))

    if registered:
        findings.append(Finding(
            CATEGORY, "Registration date", Status.INFO,
            f"Domain first registered on {registered.date().isoformat()}.",
            evidence=registered.isoformat(),
        ))

    if expires:
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            findings.append(Finding(
                CATEGORY, "Registration expiry", Status.FAIL,
                f"Domain registration expired {abs(days)} day(s) ago.",
                "Renew the domain immediately to avoid loss and takeover risk.",
                Severity.HIGH, expires.isoformat(),
            ))
        elif days <= 30:
            findings.append(Finding(
                CATEGORY, "Registration expiry", Status.WARN,
                f"Domain registration expires in {days} day(s).",
                "Renew the domain and consider enabling auto-renew.",
                Severity.MEDIUM, expires.isoformat(),
            ))
        else:
            findings.append(Finding(
                CATEGORY, "Registration expiry", Status.PASS,
                f"Registration valid for {days} more day(s).",
                evidence=expires.isoformat(),
            ))

    # Registry lock / protective status codes.
    statuses = [s.lower() for s in data.get("status", [])]
    locks = [s for s in statuses if "transferprohibited" in s.replace(" ", "")
             or "deleteprohibited" in s.replace(" ", "")
             or "updateprohibited" in s.replace(" ", "")]
    if locks:
        findings.append(Finding(
            CATEGORY, "Registrar lock", Status.PASS,
            "Protective status codes are set (transfer/delete/update prohibited).",
            evidence=", ".join(locks),
        ))
    else:
        findings.append(Finding(
            CATEGORY, "Registrar lock", Status.WARN,
            "No protective 'clientTransferProhibited'-style status codes detected.",
            "Enable registrar lock to guard against unauthorized transfers.",
            Severity.LOW, ", ".join(statuses) or "none",
        ))

    # DNSSEC delegation as recorded at the registry.
    secure_dns = data.get("secureDNS") or {}
    if secure_dns.get("delegationSigned"):
        findings.append(Finding(
            CATEGORY, "DNSSEC delegation (registry)", Status.PASS,
            "Registry records a signed delegation (DS record present at the parent).",
        ))

    return findings
