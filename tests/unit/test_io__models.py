"""IO model contract tests."""

from __future__ import annotations

from datetime import UTC, datetime

from cdt.io import AccountInMetadata, Site, TopCandidate, ValidationIssue


def test_site__pydantic_validates_all_fields() -> None:
    site = Site(
        title="Acme",
        country="Ecuador",
        site_url="https://acme.example/",
        is_primary=True,
        alive=True,
        status_code=200,
        ip="1.2.3.4",
        asn=15169,
        asn_org="GOOGLE",
        cloud_provider="GCP",
        cdn="-",
        waf_detected=False,
        waf_vendor="-",
        cms_framework="WordPress",
        web_server="nginx/1.27.1",
        tls_version="TLSv1.3",
        scan_tier="browser",
        scanned_at=datetime(2026, 5, 5, tzinfo=UTC),
    )
    assert site.title == "Acme"
    assert site.is_primary is True
    assert site.asn == 15169


def test_site__optional_fields_default_correctly() -> None:
    """Building a Site with only required fields fills sensible defaults."""

    site = Site(
        title="Acme",
        country="Ecuador",
        site_url="https://acme.example/",
        scanned_at=datetime(2026, 5, 5, tzinfo=UTC),
    )
    assert site.is_primary is False
    assert site.alive is False
    assert site.status_code == 0
    assert site.cloud_provider == "-"
    assert site.cert_expires_at is None


def test_validation_issue__top_candidates_serialization() -> None:
    issue = ValidationIssue(
        title="Acme",
        country="Ecuador",
        provided_website="acme.example",
        issue="POSSIBLE_MISMATCH",
        suggestion="https://acme-real.example/",
        top_candidates=[
            TopCandidate(url="https://acme-real.example/", score=8.5),
            TopCandidate(url="https://acme-other.example/", score=3.1),
        ],
    )
    payload = issue.model_dump()
    assert payload["top_candidates"][0]["url"].startswith("https://acme-real")
    assert payload["top_candidates"][0]["score"] == 8.5


def test_models__round_trip_pydantic() -> None:
    """Site + ValidationIssue + AccountInMetadata serialise + parse cleanly."""

    meta = AccountInMetadata(
        title="Acme",
        country="Ecuador",
        website01="https://acme.example/",
        scanned_at=datetime(2026, 5, 5, tzinfo=UTC),
    )
    again = AccountInMetadata.model_validate(meta.model_dump(mode="json"))
    assert again.title == meta.title
    assert again.scanned_at == meta.scanned_at
