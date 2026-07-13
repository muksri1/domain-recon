"""Shared helpers: domain validation/normalization and a DNS resolver factory."""

from __future__ import annotations

import re
import dns.resolver

# Permissive but strict enough to reject URLs, paths, and obvious junk.
# Accepts internationalized domains after they are punycode-encoded by the caller.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class InvalidDomain(ValueError):
    """Raised when user input cannot be parsed as a bare domain name."""


def normalize_domain(raw: str) -> str:
    """Turn user input into a bare, lowercase, punycode domain.

    Strips scheme, path, port, leading 'www.' and surrounding whitespace so
    that pasting a full URL still works. Raises InvalidDomain on bad input.
    """
    if not raw or not raw.strip():
        raise InvalidDomain("No domain provided.")

    value = raw.strip().lower()

    # Drop scheme and anything after the first slash, ? or #.
    value = re.sub(r"^[a-z]+://", "", value)
    value = re.split(r"[/?#]", value, 1)[0]

    # Drop credentials and port.
    value = value.split("@")[-1]
    value = value.split(":")[0]

    if value.startswith("www."):
        value = value[4:]

    # Internationalized domain names -> punycode (ASCII).
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass

    if not _DOMAIN_RE.match(value):
        raise InvalidDomain(f"'{raw}' is not a valid domain name.")

    return value


def make_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    """A DNS resolver with sane timeouts, using public resolvers as a fallback."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    # Fall back to well-known public resolvers if the system ones are empty
    # (common on locked-down or containerized hosts).
    if not resolver.nameservers:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    return resolver
