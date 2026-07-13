"""HTTP response security controls: security headers, HTTPS upgrade, cookie flags.

We make one plain-HTTP request (to check for an HTTPS upgrade) and one HTTPS
request (to inspect headers and cookies). Everything here is a normal GET that
any browser would perform.
"""

from __future__ import annotations

import requests

from ..models import Finding, Severity, Status

CATEGORY = "HTTP Security Headers"
_TIMEOUT = 10.0
_HEADERS = {"User-Agent": "domain-recon/1.0 (+security-posture-check)"}

# header -> (friendly name, severity if missing, recommendation)
_SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS (Strict-Transport-Security)", Severity.HIGH,
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to force HTTPS.",
    ),
    "content-security-policy": (
        "Content-Security-Policy", Severity.MEDIUM,
        "Define a Content-Security-Policy to mitigate XSS and data-injection.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options", Severity.LOW,
        "Add 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    ),
    "x-frame-options": (
        "X-Frame-Options", Severity.MEDIUM,
        "Add 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive) to prevent clickjacking.",
    ),
    "referrer-policy": (
        "Referrer-Policy", Severity.LOW,
        "Add a 'Referrer-Policy' such as 'strict-origin-when-cross-origin'.",
    ),
    "permissions-policy": (
        "Permissions-Policy", Severity.LOW,
        "Add a 'Permissions-Policy' to restrict access to browser features (camera, geolocation, …).",
    ),
}


def _get(url: str, allow_redirects: bool = True):
    return requests.get(url, headers=_HEADERS, timeout=_TIMEOUT,
                        allow_redirects=allow_redirects, verify=True)


def run(domain: str, resolver=None) -> list[Finding]:
    findings: list[Finding] = []

    # ---- HTTP -> HTTPS upgrade ------------------------------------------
    try:
        http_resp = _get(f"http://{domain}/")
        final = http_resp.url
        if final.startswith("https://"):
            findings.append(Finding(
                CATEGORY, "HTTPS redirect", Status.PASS,
                "Plain HTTP requests are redirected to HTTPS.",
                evidence=f"http://{domain}/ -> {final}",
            ))
        else:
            findings.append(Finding(
                CATEGORY, "HTTPS redirect", Status.FAIL,
                "Plain HTTP is served without redirecting to HTTPS; traffic can be intercepted.",
                "Redirect all HTTP traffic to HTTPS with a 301 and enable HSTS.",
                Severity.MEDIUM, f"final URL: {final}",
            ))
    except requests.RequestException:
        # No HTTP listener is fine (some sites are HTTPS-only); note it neutrally.
        findings.append(Finding(
            CATEGORY, "HTTPS redirect", Status.INFO,
            "No response on plain HTTP (port 80). The site may be HTTPS-only.",
        ))

    # ---- Fetch over HTTPS for header/cookie inspection ------------------
    try:
        resp = _get(f"https://{domain}/")
    except requests.exceptions.SSLError as exc:
        findings.append(Finding(
            CATEGORY, "HTTPS request", Status.FAIL,
            f"HTTPS request failed TLS verification: {exc}.",
            "Fix the TLS certificate so browsers can connect securely.",
            Severity.HIGH, str(exc),
        ))
        return findings
    except requests.RequestException as exc:
        findings.append(Finding(
            CATEGORY, "HTTPS request", Status.WARN,
            f"Could not fetch the site over HTTPS ({exc.__class__.__name__}); header checks skipped.",
            evidence=str(exc),
        ))
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # ---- Security headers -----------------------------------------------
    for key, (name, severity, rec) in _SECURITY_HEADERS.items():
        if key in headers:
            findings.append(Finding(
                CATEGORY, name, Status.PASS,
                "Header is present.",
                evidence=headers[key][:300],
            ))
        else:
            findings.append(Finding(
                CATEGORY, name, Status.FAIL,
                "Header is not set.",
                rec, severity,
            ))

    # ---- Information-disclosure headers ---------------------------------
    for key in ("server", "x-powered-by"):
        if key in headers and headers[key].strip():
            findings.append(Finding(
                CATEGORY, f"Info disclosure: {key}", Status.WARN,
                f"Response advertises '{key}: {headers[key]}', revealing software details.",
                f"Suppress or genericize the '{key}' header to reduce fingerprinting.",
                Severity.LOW, headers[key],
            ))

    # ---- Cookie flags ----------------------------------------------------
    cookies = resp.cookies
    if not cookies:
        findings.append(Finding(
            CATEGORY, "Cookie flags", Status.INFO,
            "No cookies were set on the landing page.",
        ))
    else:
        insecure = []
        for c in cookies:
            problems = []
            if not c.secure:
                problems.append("missing Secure")
            if not c.has_nonstandard_attr("HttpOnly"):
                problems.append("missing HttpOnly")
            samesite = c.get_nonstandard_attr("SameSite") if hasattr(c, "get_nonstandard_attr") else None
            if not samesite:
                problems.append("missing SameSite")
            if problems:
                insecure.append(f"{c.name} ({', '.join(problems)})")
        if insecure:
            findings.append(Finding(
                CATEGORY, "Cookie flags", Status.WARN,
                f"{len(insecure)} cookie(s) missing recommended security attributes.",
                "Set Secure, HttpOnly, and SameSite on session/auth cookies.",
                Severity.MEDIUM, "; ".join(insecure[:15]),
            ))
        else:
            findings.append(Finding(
                CATEGORY, "Cookie flags", Status.PASS,
                f"All {len(cookies)} cookie(s) set Secure, HttpOnly, and SameSite.",
            ))

    return findings
