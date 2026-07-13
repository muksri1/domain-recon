"""domain-recon: passive security-controls posture review for a domain.

Public entry points:
    scan_domain(domain)            -> report dict
    findings_to_csv(report)        -> CSV string
"""

from .scanner import scan_domain
from .export import findings_to_csv
from .utils import InvalidDomain

__all__ = ["scan_domain", "findings_to_csv", "InvalidDomain"]
__version__ = "1.0.0"
