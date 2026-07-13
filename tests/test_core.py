"""Offline unit tests — no network required, safe to run in CI."""

import csv
import io

import pytest

from reconlib.checks.email_auth import _is_valid_dkim
from reconlib.demo import DEMO_REPORT
from reconlib.export import findings_to_csv
from reconlib.models import Finding, Severity, Status, score_findings
from reconlib.utils import InvalidDomain, normalize_domain

# ---- domain normalization -------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("https://www.example.com/path?q=1", "example.com"),
    ("http://user:pass@example.com:8443/x", "example.com"),
    ("  sub.example.co.uk  ", "sub.example.co.uk"),
])
def test_normalize_domain_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", "not a domain", "no_tld", "http://", "..."])
def test_normalize_domain_rejects(bad):
    with pytest.raises(InvalidDomain):
        normalize_domain(bad)


# ---- scoring --------------------------------------------------------------

def test_score_all_pass_is_100():
    findings = [Finding("c", "x", Status.PASS, "ok")]
    assert score_findings(findings)["score"] == 100
    assert score_findings(findings)["grade"] == "A"


def test_high_fail_penalizes_and_clamps():
    findings = [Finding("c", "x", Status.FAIL, "bad", severity=Severity.HIGH)] * 10
    summary = score_findings(findings)
    assert summary["score"] == 0          # clamped, never negative
    assert summary["grade"] == "F"


def test_info_does_not_affect_score():
    findings = [Finding("c", "x", Status.INFO, "note")] * 5
    assert score_findings(findings)["score"] == 100


# ---- DKIM validity --------------------------------------------------------

def test_dkim_empty_p_is_invalid():
    assert _is_valid_dkim("v=DKIM1; p=") is False


def test_dkim_with_key_is_valid():
    assert _is_valid_dkim("v=DKIM1; k=rsa; p=MIIBIjANBgkq...") is True


def test_dkim_unrelated_txt_is_invalid():
    assert _is_valid_dkim("some other txt record") is False


# ---- CSV export -----------------------------------------------------------

def test_csv_roundtrips_findings():
    report = {
        "domain": "example.com",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "findings": [Finding("Cat", "Check", Status.FAIL, "detail, with comma",
                             "do x", Severity.HIGH, 'ev "quoted"').to_row()],
    }
    text = findings_to_csv(report)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 1
    assert rows[0]["domain"] == "example.com"
    assert rows[0]["status"] == "FAIL"
    assert rows[0]["detail"] == "detail, with comma"   # comma survived quoting
    assert rows[0]["evidence"] == 'ev "quoted"'         # quotes survived


# ---- demo report consistency ---------------------------------------------

def test_demo_report_counts_match_findings():
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0, "ERROR": 0}
    for f in DEMO_REPORT["findings"]:
        counts[f["status"]] += 1
    assert counts == DEMO_REPORT["counts"]
    assert 0 <= DEMO_REPORT["score"] <= 100
    assert DEMO_REPORT["grade"] in {"A", "B", "C", "D", "F"}
