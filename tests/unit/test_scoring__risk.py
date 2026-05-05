"""RiskScorer tests — one per rubric item + band/cap/format edges."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cdt.detect.models import (
    CdnDetection,
    CloudDetection,
    Confidence,
    StackDetection,
    WafDetection,
)
from cdt.scan.models import TLSInfo
from cdt.scoring import (
    FindingCode,
    RiskBand,
    RiskScorer,
    ScoringInput,
)

NOW = datetime(2026, 5, 5, 12, 0, 0, tzinfo=UTC)


def _waf(vendor: str | None = None, active: bool = False, conf: Confidence = Confidence.LOW,
         cdn_capable: bool = False) -> WafDetection:
    return WafDetection(
        vendor=vendor, confidence=conf, waf_active=active, cdn_capable=cdn_capable
    )


def _input(
    *,
    is_alive: bool = True,
    headers: dict[str, str] | None = None,
    tls: TLSInfo | None = None,
    waf: WafDetection | None = None,
    cdn_vendor: str | None = None,
    tier: str = "browser",
    secondary_protected: list[bool] | None = None,
    server_header_cve_known: bool = False,
    admin_panel_exposed: bool = False,
    cms_outdated_with_cve: bool = False,
) -> ScoringInput:
    return ScoringInput(
        url="https://acme.example/",
        title="Acme",
        country="Ecuador",
        tier=tier,
        is_alive=is_alive,
        waf=waf or _waf(),
        cdn=CdnDetection(vendor=cdn_vendor),
        cloud=CloudDetection(),
        stack=StackDetection(),
        headers=headers or {},
        tls=tls,
        secondary_sites_protected=secondary_protected or [],
        server_header_cve_known=server_header_cve_known,
        admin_panel_exposed=admin_panel_exposed,
        cms_outdated_with_cve=cms_outdated_with_cve,
    )


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer()


# ---------- §6 rubric items ----------


def test_risk__dead_site_returns_zero(scorer: RiskScorer) -> None:
    risk, findings = scorer.score(_input(is_alive=False), now=NOW)
    assert risk.score == 0
    assert risk.band == RiskBand.LOW
    assert findings == []


def test_risk__alive_baseline_one_point(scorer: RiskScorer) -> None:
    """Alive + everything else perfect (no missing headers, valid TLS, WAF active)."""

    waf = _waf(vendor="Cloudflare", active=True, conf=Confidence.HIGH, cdn_capable=True)
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
    }
    tls = TLSInfo(version="TLSv1.3", not_after=NOW + timedelta(days=90))
    risk, _ = scorer.score(_input(waf=waf, headers=headers, tls=tls), now=NOW)
    assert risk.score == 1
    assert risk.band == RiskBand.LOW


def test_risk__missing_waf_three_points_high_finding(scorer: RiskScorer) -> None:
    """No WAF detected and no WAF-capable CDN → +3 + High finding."""

    risk, findings = scorer.score(_input(), now=NOW)
    assert any(item.rubric_item == "missing_waf" and item.points == 3 for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.MISSING_WAF for f in findings)


def test_risk__cdn_with_waf_function_no_missing_waf(scorer: RiskScorer) -> None:
    """A WAF-capable vendor wins WAF → no MISSING_WAF finding."""

    waf = _waf(vendor="Cloudflare", active=True, conf=Confidence.HIGH, cdn_capable=True)
    risk, findings = scorer.score(_input(waf=waf), now=NOW)
    assert not any(f.finding_code == FindingCode.MISSING_WAF for f in findings)


def test_risk__cert_expired_two_points(scorer: RiskScorer) -> None:
    tls = TLSInfo(version="TLSv1.3", not_after=NOW - timedelta(days=1))
    risk, findings = scorer.score(_input(tls=tls), now=NOW)
    assert any(item.rubric_item == "cert_expired_or_near" for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.EXPIRED_CERT for f in findings)


def test_risk__cert_expires_in_29_days_two_points(scorer: RiskScorer) -> None:
    tls = TLSInfo(version="TLSv1.3", not_after=NOW + timedelta(days=29))
    risk, _ = scorer.score(_input(tls=tls), now=NOW)
    assert any(item.rubric_item == "cert_expired_or_near" for item in risk.breakdown)


def test_risk__cert_expires_in_31_days_zero_points(scorer: RiskScorer) -> None:
    tls = TLSInfo(version="TLSv1.3", not_after=NOW + timedelta(days=31))
    risk, _ = scorer.score(_input(tls=tls), now=NOW)
    assert not any(item.rubric_item == "cert_expired_or_near" for item in risk.breakdown)


def test_risk__tls_11_two_points(scorer: RiskScorer) -> None:
    tls = TLSInfo(version="TLSv1.1", not_after=NOW + timedelta(days=90))
    risk, findings = scorer.score(_input(tls=tls), now=NOW)
    assert any(item.rubric_item == "weak_tls" for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.WEAK_TLS for f in findings)


def test_risk__tls_12_zero_points(scorer: RiskScorer) -> None:
    tls = TLSInfo(version="TLSv1.2", not_after=NOW + timedelta(days=90))
    risk, _ = scorer.score(_input(tls=tls), now=NOW)
    assert not any(item.rubric_item == "weak_tls" for item in risk.breakdown)


def test_risk__missing_hsts_one_point(scorer: RiskScorer) -> None:
    risk, findings = scorer.score(_input(), now=NOW)
    assert any(item.rubric_item == "missing_hsts" for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.MISSING_HSTS for f in findings)


def test_risk__missing_csp_one_point(scorer: RiskScorer) -> None:
    risk, findings = scorer.score(_input(), now=NOW)
    assert any(item.rubric_item == "missing_csp" for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.MISSING_CSP for f in findings)


def test_risk__missing_xfo_when_no_csp_one_point(scorer: RiskScorer) -> None:
    risk, _ = scorer.score(_input(), now=NOW)
    assert any(item.rubric_item == "missing_xfo" for item in risk.breakdown)


def test_risk__missing_xfo_when_csp_has_frame_ancestors_zero_points(
    scorer: RiskScorer,
) -> None:
    headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
    risk, findings = scorer.score(_input(headers=headers), now=NOW)
    assert not any(item.rubric_item == "missing_xfo" for item in risk.breakdown)
    assert not any(f.finding_code == FindingCode.MISSING_XFO for f in findings)


# ---------- Tier 3 (dast) gating ----------


def test_risk__tier_dast_cve_known_two_points(scorer: RiskScorer) -> None:
    risk, findings = scorer.score(
        _input(tier="dast", server_header_cve_known=True), now=NOW
    )
    assert any(item.rubric_item == "cve_known_version" for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.CVE_KNOWN_VERSION for f in findings)


def test_risk__tier_dast_admin_exposed_one_point(scorer: RiskScorer) -> None:
    risk, findings = scorer.score(
        _input(tier="dast", admin_panel_exposed=True), now=NOW
    )
    assert any(item.rubric_item == "admin_exposed" for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.EXPOSED_ADMIN for f in findings)


def test_risk__tier_browser_ignores_dast_inputs(scorer: RiskScorer) -> None:
    """dast-only signals must not contribute when ``tier != "dast"``."""

    risk, findings = scorer.score(
        _input(
            tier="browser",
            server_header_cve_known=True,
            admin_panel_exposed=True,
            cms_outdated_with_cve=True,
        ),
        now=NOW,
    )
    assert not any(item.rubric_item == "cve_known_version" for item in risk.breakdown)
    assert not any(item.rubric_item == "admin_exposed" for item in risk.breakdown)
    assert not any(f.finding_code == FindingCode.CVE_KNOWN_VERSION for f in findings)


# ---------- §6.1 secondary modifier ----------


def test_risk__secondary_unprotected_one_point_modifier(scorer: RiskScorer) -> None:
    waf_protected = _waf(vendor="Cloudflare", active=True, conf=Confidence.HIGH, cdn_capable=True)
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
    }
    tls = TLSInfo(version="TLSv1.3", not_after=NOW + timedelta(days=90))
    risk, findings = scorer.score(
        _input(
            waf=waf_protected,
            headers=headers,
            tls=tls,
            secondary_protected=[True, False, True],
        ),
        now=NOW,
    )
    assert any(item.rubric_item == "secondary_unprotected" for item in risk.breakdown)
    assert any(f.finding_code == FindingCode.SECONDARY_SITE_EXPOSED for f in findings)


def test_risk__secondary_modifier_no_op_when_primary_unprotected(
    scorer: RiskScorer,
) -> None:
    """If primary is also unprotected, §6.1 modifier does NOT fire."""

    risk, _ = scorer.score(
        _input(secondary_protected=[False, False]), now=NOW
    )
    assert not any(item.rubric_item == "secondary_unprotected" for item in risk.breakdown)


# ---------- Cap + bands ----------


def test_risk__score_capped_at_15(scorer: RiskScorer) -> None:
    """All items max out → 15, not higher."""

    tls = TLSInfo(version="TLSv1.0", not_after=NOW - timedelta(days=1))
    risk, _ = scorer.score(
        _input(
            tier="dast",
            tls=tls,
            server_header_cve_known=True,
            admin_panel_exposed=True,
            cms_outdated_with_cve=True,
        ),
        now=NOW,
    )
    assert risk.score == 15


@pytest.mark.parametrize(
    "score,expected_band",
    [
        (1, RiskBand.LOW),
        (5, RiskBand.LOW),
        (6, RiskBand.MEDIUM),
        (9, RiskBand.MEDIUM),
        (10, RiskBand.HIGH),
        (12, RiskBand.HIGH),
        (13, RiskBand.CRITICAL),
        (15, RiskBand.CRITICAL),
    ],
)
def test_risk__band_boundaries(score: int, expected_band: RiskBand) -> None:
    """The band thresholds match v0.4 §6 exactly."""

    from cdt.scoring.risk import _band_for

    assert _band_for(score) == expected_band


def test_risk__display_format_correct() -> None:
    from cdt.scoring import RiskScore as RS

    rs = RS(score=7, band=RiskBand.MEDIUM, breakdown=[])
    assert rs.display == "MEDIUM (7/15)"
