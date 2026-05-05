"""ScoringEngine integration-flavor tests over the full pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

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
    RiskBand,
    ScoringEngine,
    ScoringInput,
)

TEMPLATES_PATH = (
    Path(__file__).parent.parent.parent / "config" / "rationale_templates.yaml"
)
NOW = datetime(2026, 5, 5, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def engine() -> ScoringEngine:
    return ScoringEngine(rationale_path=TEMPLATES_PATH)


def _build(
    *,
    waf: WafDetection | None = None,
    cloud: CloudDetection | None = None,
    headers: dict[str, str] | None = None,
    tls: TLSInfo | None = None,
    has_aws: bool = False,
    has_azure: bool = False,
    has_gcp: bool = False,
    has_oci: bool = False,
) -> ScoringInput:
    return ScoringInput(
        url="https://acme.example/",
        title="Acme",
        country="Ecuador",
        tier="browser",
        is_alive=True,
        waf=waf or WafDetection(),
        cdn=CdnDetection(),
        cloud=cloud or CloudDetection(),
        stack=StackDetection(),
        headers=headers or {},
        tls=tls,
        has_aws=has_aws,
        has_azure=has_azure,
        has_gcp=has_gcp,
        has_oci=has_oci,
    )


def test_engine__full_pipeline_no_waf_cloud_appsec_recommended(
    engine: ScoringEngine,
) -> None:
    cloud = CloudDetection(
        provider="AWS", confidence=Confidence.HIGH, role="hyperscaler"
    )
    result = engine.evaluate(_build(cloud=cloud, has_aws=True), now=NOW)

    assert result.opportunity.appsec is True
    assert result.opportunity.web is False
    assert "FortiAppSec" in result.rationale
    assert result.public_cloud == "Yes"
    assert result.primary_hyperscaler == "AWS"
    assert result.complexity == "One CSP"


def test_engine__full_pipeline_fortinet_low_risk_no_recommendation(
    engine: ScoringEngine,
) -> None:
    waf = WafDetection(
        vendor="Fortinet_FortiWeb",
        confidence=Confidence.HIGH,
        waf_active=True,
        cdn_capable=False,
    )
    cloud = CloudDetection(
        provider="AWS", confidence=Confidence.HIGH, role="hyperscaler"
    )
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
    }
    tls = TLSInfo(version="TLSv1.3", not_after=NOW + timedelta(days=90))

    result = engine.evaluate(
        _build(waf=waf, cloud=cloud, headers=headers, tls=tls, has_aws=True),
        now=NOW,
    )

    assert result.risk.band == RiskBand.LOW
    assert result.opportunity.appsec is False
    assert result.opportunity.web is False
    assert result.opportunity.cnapp is False
    assert result.rationale == ""


def test_engine__full_pipeline_multi_csp_cnapp_yes_with_displacement(
    engine: ScoringEngine,
) -> None:
    """Akamai-fronted multi-CSP at HIGH risk → AppSec displacement + CNAPP."""

    waf = WafDetection(
        vendor="Akamai",
        confidence=Confidence.HIGH,
        waf_active=True,
        cdn_capable=True,
    )
    cloud = CloudDetection(
        provider="AWS", confidence=Confidence.HIGH, role="hyperscaler"
    )
    # Bump risk to HIGH by leaving headers / TLS missing.
    result = engine.evaluate(
        _build(waf=waf, cloud=cloud, has_aws=True, has_azure=True, has_gcp=True),
        now=NOW,
    )

    assert result.opportunity.cnapp is True
    assert result.complexity == "Three CSP"
    assert "AWS+Azure+GCP" in result.rationale
    if result.opportunity.appsec:
        assert "displacement" in result.rationale


def test_engine__derived_fields_populated_correctly(engine: ScoringEngine) -> None:
    waf = WafDetection(
        vendor="Cloudflare",
        confidence=Confidence.HIGH,
        waf_active=True,
        cdn_capable=True,
    )
    result = engine.evaluate(_build(waf=waf), now=NOW)

    assert result.waf_decision == "Yes"
    assert result.waf_vendor == "Cloudflare"
    assert "Cloudflare" in result.waf_tool


def test_engine__findings_aggregated_from_risk(engine: ScoringEngine) -> None:
    """Findings from RiskScorer reach the ScoringResult unchanged."""

    result = engine.evaluate(_build(), now=NOW)
    codes = {f.finding_code.value for f in result.findings}
    assert "MISSING_WAF" in codes
    assert "MISSING_HSTS" in codes
    assert "MISSING_CSP" in codes


def test_engine__rationale_rendered_in_result(engine: ScoringEngine) -> None:
    """A non-empty rationale appears for any opportunity flag."""

    result = engine.evaluate(_build(), now=NOW)
    # Default is web=Yes (no WAF + no cloud) → fortiweb_onprem template.
    assert result.opportunity.web is True
    assert "FortiWeb" in result.rationale


def test_engine__waf_tool_for_fortinet_humanizes() -> None:
    from cdt.scoring.engine import _build_waf_tool

    assert _build_waf_tool("Fortinet_FortiWeb") == "FortiWeb (Fortinet) WAF"
    assert _build_waf_tool("Cloudflare") == "Cloudflare WAF"
    assert _build_waf_tool(None) == ""
