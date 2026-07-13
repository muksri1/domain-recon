"""TLS certificate and protocol posture on port 443.

Passive checks only: we open a normal TLS connection (as any browser would),
read the presented certificate, and separately test whether the server still
negotiates the deprecated TLS 1.0/1.1 protocols.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..models import Finding, Severity, Status

CATEGORY = "TLS / Certificate"

_PORT = 443
_TIMEOUT = 8.0


def _parse_cert_time(value: str) -> datetime:
    # OpenSSL format, e.g. 'Jun  1 12:00:00 2025 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _connect(domain: str):
    """Return (cert_dict, negotiated_protocol, cipher_tuple) or raise."""
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, _PORT), timeout=_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert(), ssock.version(), ssock.cipher()


def _supports_legacy(domain: str, max_version) -> bool:
    """Try to negotiate a specific (deprecated) TLS version. True if it connects."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = max_version
        ctx.maximum_version = max_version
    except (ValueError, OSError):
        # This Python/OpenSSL build refuses to even offer the version.
        return False
    try:
        with socket.create_connection((domain, _PORT), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except (ssl.SSLError, OSError):
        return False


def run(domain: str, resolver=None) -> list[Finding]:
    findings: list[Finding] = []

    try:
        cert, protocol, cipher = _connect(domain)
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        # Distinguish "no HTTPS at all" from "cert invalid".
        if isinstance(exc, ssl.SSLCertVerificationError):
            findings.append(Finding(
                CATEGORY, "Certificate validation", Status.FAIL,
                f"TLS certificate failed validation: {exc.verify_message or exc}.",
                "Install a certificate that is trusted, unexpired, and matches the hostname.",
                Severity.HIGH, str(exc),
            ))
        else:
            findings.append(Finding(
                CATEGORY, "HTTPS availability", Status.WARN,
                f"Could not establish an HTTPS connection on port 443 ({exc.__class__.__name__}).",
                "Confirm the site serves HTTPS; sites without TLS expose all traffic in cleartext.",
                Severity.MEDIUM, str(exc),
            ))
        return findings

    # ---- Expiry ----------------------------------------------------------
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = _parse_cert_time(not_after)
            days = (expires - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(Finding(
                    CATEGORY, "Certificate expiry", Status.FAIL,
                    f"Certificate expired {abs(days)} day(s) ago.",
                    "Renew and deploy a current certificate immediately.",
                    Severity.HIGH, not_after,
                ))
            elif days <= 14:
                findings.append(Finding(
                    CATEGORY, "Certificate expiry", Status.WARN,
                    f"Certificate expires in {days} day(s).",
                    "Renew soon and verify automated renewal is working.",
                    Severity.MEDIUM, not_after,
                ))
            else:
                findings.append(Finding(
                    CATEGORY, "Certificate expiry", Status.PASS,
                    f"Certificate valid for {days} more day(s).",
                    evidence=not_after,
                ))
        except ValueError:
            findings.append(Finding(
                CATEGORY, "Certificate expiry", Status.INFO,
                f"Certificate notAfter present but unparseable: {not_after}.",
            ))

    # ---- Issuer / subject ------------------------------------------------
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    findings.append(Finding(
        CATEGORY, "Certificate issuer", Status.INFO,
        f"Issued to '{subject.get('commonName', '?')}' by "
        f"'{issuer.get('organizationName') or issuer.get('commonName', '?')}'.",
        evidence=str(issuer),
    ))

    sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
    if sans:
        findings.append(Finding(
            CATEGORY, "Subject Alternative Names", Status.INFO,
            f"Certificate covers {len(sans)} hostname(s).",
            evidence=", ".join(sans[:25]) + (" …" if len(sans) > 25 else ""),
        ))

    # ---- Negotiated protocol / cipher -----------------------------------
    if protocol in ("TLSv1.3", "TLSv1.2"):
        findings.append(Finding(
            CATEGORY, "Negotiated protocol", Status.PASS,
            f"Connection negotiated {protocol}.",
            evidence=f"{protocol}; {cipher[0] if cipher else '?'}",
        ))
    else:
        findings.append(Finding(
            CATEGORY, "Negotiated protocol", Status.WARN,
            f"Connection negotiated {protocol}, which is deprecated.",
            "Prefer TLS 1.2+ and disable older protocols.",
            Severity.MEDIUM, str(protocol),
        ))

    # ---- Legacy protocol support ----------------------------------------
    legacy_supported = []
    for label, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        if _supports_legacy(domain, ver):
            legacy_supported.append(label)
    if legacy_supported:
        findings.append(Finding(
            CATEGORY, "Legacy TLS protocols", Status.FAIL,
            f"Server still accepts deprecated protocol(s): {', '.join(legacy_supported)}.",
            "Disable TLS 1.0 and TLS 1.1 at the server/load balancer.",
            Severity.MEDIUM, ", ".join(legacy_supported),
        ))
    else:
        findings.append(Finding(
            CATEGORY, "Legacy TLS protocols", Status.PASS,
            "TLS 1.0 and TLS 1.1 are not accepted.",
        ))

    return findings
