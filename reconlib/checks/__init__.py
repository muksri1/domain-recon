"""Individual security-control checks. Each module exposes:

    run(domain: str, resolver=None) -> list[Finding]

and must never raise on ordinary network/lookup failures — a check that cannot
complete should return an ERROR-status Finding instead, so one failing control
never aborts the whole scan.
"""
