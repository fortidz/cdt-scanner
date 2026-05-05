"""CsvOutputWriter tests — column order, formatting, BOM, LF, RFC 4180 quoting."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cdt.io import (
    ACCOUNTS_ENRICHED_HEADERS,
    FINDINGS_HEADERS,
    SITES_HEADERS,
    VALIDATION_ISSUES_HEADERS,
    AccountInMetadata,
    CsvOutputWriter,
    Site,
    TopCandidate,
    ValidationIssue,
)
from cdt.scoring import (
    Finding,
    FindingCode,
    OpportunityFlags,
    RiskBand,
    RiskScore,
    ScoringResult,
    Severity,
)

NOW = datetime(2026, 5, 5, 12, 0, 0, tzinfo=UTC)


def _result(
    *,
    rationale: str = "Sitio vivo sin WAF + infra en AWS → FortiAppSec.",
    has_aws: bool = True,
    appsec: bool = True,
    band: RiskBand = RiskBand.MEDIUM,
    score: int = 7,
) -> ScoringResult:
    return ScoringResult(
        risk=RiskScore(score=score, band=band, breakdown=[]),
        opportunity=OpportunityFlags(appsec=appsec),
        rationale=rationale,
        findings=[],
        waf_decision="No",
        waf_vendor="-",
        waf_tool="",
        public_cloud="Yes",
        complexity="One CSP",
        primary_hyperscaler="AWS",
        has_aws=has_aws,
        has_azure=False,
        has_gcp=False,
        has_oci=False,
    )


def _meta(*, rationale_extras: dict[str, str | None] | None = None) -> AccountInMetadata:
    extras = rationale_extras or {}
    return AccountInMetadata(
        title="Acme",
        country="Ecuador",
        website01="https://acme.example/",
        cms_framework=extras.get("cms"),
        web_server=extras.get("web_server"),
        cdn=extras.get("cdn"),
        scanned_at=NOW,
    )


# ---------- accounts_enriched.csv ----------


def test_write_accounts_enriched__column_order_matches_spec(tmp_path: Path) -> None:
    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched([_result()], {"k": _meta()})

    header_line = (tmp_path / "accounts_enriched.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header_line == ",".join(ACCOUNTS_ENRICHED_HEADERS)
    assert len(header_line.split(",")) == 26


def test_write_accounts_enriched__formats_risk_score_correctly(
    tmp_path: Path,
) -> None:
    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched([_result(score=7, band=RiskBand.MEDIUM)],
                                   {"k": _meta()})

    rows = (tmp_path / "accounts_enriched.csv").read_text(encoding="utf-8").splitlines()
    assert "MEDIUM (7/15)" in rows[1]


def test_write_accounts_enriched__bool_to_yes_no_conversion(tmp_path: Path) -> None:
    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched([_result(has_aws=True, appsec=True)],
                                   {"k": _meta()})
    body = (tmp_path / "accounts_enriched.csv").read_text(encoding="utf-8")

    headers = body.splitlines()[0].split(",")
    fields = body.splitlines()[1].split(",")
    cols = dict(zip(headers, fields, strict=False))

    assert cols["HasAWS"] == "Yes"
    assert cols["HasAzure"] == "No"
    assert cols["RecommendsFortiAppSec"] == "Yes"


def test_write_accounts_enriched__none_renders_as_dash(tmp_path: Path) -> None:
    """Empty CMS / WebServer / CDN render as ``"-"``."""

    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched([_result()], {"k": _meta()})
    body = (tmp_path / "accounts_enriched.csv").read_text(encoding="utf-8")

    headers = body.splitlines()[0].split(",")
    fields = body.splitlines()[1].split(",")
    cols = dict(zip(headers, fields, strict=False))

    assert cols["CMSFramework"] == "-"
    assert cols["WebServer"] == "-"
    assert cols["CDN"] == "-"


def test_write_accounts_enriched__rationale_truncated_at_200_chars(
    tmp_path: Path,
) -> None:
    long_rationale = "x" * 250
    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched(
        [_result(rationale=long_rationale)], {"k": _meta()}
    )
    body = (tmp_path / "accounts_enriched.csv").read_text(encoding="utf-8")
    # CSV may quote the field if needed; still substring-search the truncated form.
    truncated = "x" * 197 + "..."
    assert truncated in body
    # And the original 250-char string must not appear in full.
    assert "x" * 250 not in body


def test_write_accounts_enriched__quoted_minimal_for_comma_in_field(
    tmp_path: Path,
) -> None:
    """A rationale with a comma triggers quoting per RFC 4180."""

    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched(
        [_result(rationale="Multi-CSP, sin WAF, displacement.")], {"k": _meta()}
    )
    body = (tmp_path / "accounts_enriched.csv").read_text(encoding="utf-8")
    # The rationale field must be wrapped in double quotes.
    assert '"Multi-CSP, sin WAF, displacement."' in body


def test_write_accounts_enriched__no_bom_in_output(tmp_path: Path) -> None:
    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched([_result()], {"k": _meta()})

    raw = (tmp_path / "accounts_enriched.csv").read_bytes()
    # First byte must be the literal "T" of "Title", not the BOM (0xEF 0xBB 0xBF).
    assert raw[0:3] != b"\xef\xbb\xbf"
    assert raw[0:1] == b"T"


def test_write_accounts_enriched__lf_line_terminator(tmp_path: Path) -> None:
    writer = CsvOutputWriter(tmp_path)
    writer.write_accounts_enriched([_result()], {"k": _meta()})

    raw = (tmp_path / "accounts_enriched.csv").read_bytes()
    assert b"\r\n" not in raw
    assert raw.count(b"\n") == 2  # header + 1 data row


def test_write_accounts_enriched__metadata_extras_applied(tmp_path: Path) -> None:
    writer = CsvOutputWriter(tmp_path)
    meta = _meta(rationale_extras={"cms": "WordPress", "web_server": "nginx/1.27.1",
                                   "cdn": "Cloudflare"})
    writer.write_accounts_enriched([_result()], {"k": meta})
    body = (tmp_path / "accounts_enriched.csv").read_text(encoding="utf-8")

    headers = body.splitlines()[0].split(",")
    fields = body.splitlines()[1].split(",")
    cols = dict(zip(headers, fields, strict=False))

    assert cols["CMSFramework"] == "WordPress"
    assert cols["WebServer"] == "nginx/1.27.1"
    assert cols["CDN"] == "Cloudflare"


# ---------- sites.csv ----------


def test_write_sites__includes_primary_and_secondary(tmp_path: Path) -> None:
    writer = CsvOutputWriter(tmp_path)
    sites = [
        Site(title="Acme", country="Ecuador", site_url="https://acme.example/",
             is_primary=True, alive=True, status_code=200, scanned_at=NOW),
        Site(title="Acme", country="Ecuador", site_url="https://app.acme.example/",
             is_primary=False, alive=True, status_code=200, scanned_at=NOW),
    ]
    writer.write_sites(sites)
    rows = (tmp_path / "sites.csv").read_text(encoding="utf-8").splitlines()

    assert rows[0].split(",") == list(SITES_HEADERS)
    assert "1," in rows[1]  # IsPrimary=1
    assert "0," in rows[2]


def test_write_sites__cert_expires_iso_format(tmp_path: Path) -> None:
    expiry = datetime(2027, 6, 30, 9, 0, 0, tzinfo=UTC)
    sites = [
        Site(title="Acme", country="Ecuador", site_url="https://acme.example/",
             is_primary=True, alive=True, cert_expires_at=expiry, scanned_at=NOW),
    ]
    writer = CsvOutputWriter(tmp_path)
    writer.write_sites(sites)
    body = (tmp_path / "sites.csv").read_text(encoding="utf-8")
    assert "2027-06-30T09:00:00Z" in body


# ---------- findings.csv ----------


def test_write_findings__includes_all_severity_levels(tmp_path: Path) -> None:
    findings = [
        Finding(title="Acme", country="Ecuador", site_url="https://acme.example/",
                finding_code=FindingCode.MISSING_WAF, severity=Severity.HIGH,
                message="No WAF detected."),
        Finding(title="Acme", country="Ecuador", site_url="https://acme.example/",
                finding_code=FindingCode.MISSING_HSTS, severity=Severity.MEDIUM,
                message="HSTS missing."),
        Finding(title="Acme", country="Ecuador", site_url="https://acme.example/",
                finding_code=FindingCode.MISSING_XFO, severity=Severity.LOW,
                message="XFO missing."),
    ]
    writer = CsvOutputWriter(tmp_path)
    writer.write_findings(findings)

    body = (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert "MISSING_WAF" in body
    assert "MISSING_HSTS" in body
    assert "MISSING_XFO" in body
    assert "High" in body
    assert "Medium" in body
    assert "Low" in body


def test_write_findings__evidence_truncated_at_500_chars(tmp_path: Path) -> None:
    findings = [
        Finding(
            title="Acme",
            country="Ecuador",
            site_url="https://acme.example/",
            finding_code=FindingCode.MISSING_WAF,
            severity=Severity.HIGH,
            message="No WAF detected.",
            evidence="x" * 600,
        )
    ]
    writer = CsvOutputWriter(tmp_path)
    writer.write_findings(findings)

    body = (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert "x" * 600 not in body
    assert "x" * 497 + "..." in body


# ---------- validation_issues.csv ----------


def test_write_validation_issues__top_candidates_serialized(tmp_path: Path) -> None:
    issues = [
        ValidationIssue(
            title="Acme",
            country="Ecuador",
            provided_website="acme.example",
            issue="POSSIBLE_MISMATCH",
            suggestion="https://acme-real.example/",
            top_candidates=[
                TopCandidate(url="https://acme-real.example/", score=8.5),
                TopCandidate(url="https://other.example/", score=3.2),
            ],
        ),
    ]
    writer = CsvOutputWriter(tmp_path)
    writer.write_validation_issues(issues)

    body = (tmp_path / "validation_issues.csv").read_text(encoding="utf-8")
    headers = body.splitlines()[0].split(",")
    assert headers == list(VALIDATION_ISSUES_HEADERS)
    # Quoting wraps the candidates field because of commas.
    assert '"https://acme-real.example/ (8.5), https://other.example/ (3.2)"' in body


def test_write_validation_issues__suggestion_optional_renders_dash(
    tmp_path: Path,
) -> None:
    issues = [
        ValidationIssue(
            title="Acme",
            country="Ecuador",
            provided_website="acme.example",
            issue="DEAD_DOMAIN",
            suggestion="",
            top_candidates=[],
        ),
    ]
    writer = CsvOutputWriter(tmp_path)
    writer.write_validation_issues(issues)

    body = (tmp_path / "validation_issues.csv").read_text(encoding="utf-8")
    line = body.splitlines()[1].split(",")
    suggestion_idx = list(VALIDATION_ISSUES_HEADERS).index("Suggestion")
    assert line[suggestion_idx] == "-"


# ---------- empty input ----------


def test_write_findings__empty_iterable_produces_header_only(tmp_path: Path) -> None:
    writer = CsvOutputWriter(tmp_path)
    count = writer.write_findings([])
    assert count == 0
    body = (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert body.strip().split("\n") == [",".join(FINDINGS_HEADERS)]


def test_writer__creates_out_dir_if_missing(tmp_path: Path) -> None:
    nested = tmp_path / "nested" / "out"
    writer = CsvOutputWriter(nested)
    writer.write_findings([])
    assert (nested / "findings.csv").exists()
