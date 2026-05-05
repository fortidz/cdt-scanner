"""OpportunityCalculator tests — every branch of v0.4 §7.3."""

from __future__ import annotations

import pytest

from cdt.detect.models import (
    CdnDetection,
    CloudDetection,
    Confidence,
    StackDetection,
    WafDetection,
)
from cdt.scoring import (
    OpportunityCalculator,
    RiskBand,
    RiskScore,
    ScoringInput,
    compute_complexity,
    compute_primary_hyperscaler,
    compute_public_cloud,
    compute_waf_decision,
)


def _input(
    *,
    waf: WafDetection | None = None,
    cloud: CloudDetection | None = None,
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
        waf=waf or WafDetection(),
        cdn=CdnDetection(),
        cloud=cloud or CloudDetection(),
        stack=StackDetection(),
        has_aws=has_aws,
        has_azure=has_azure,
        has_gcp=has_gcp,
        has_oci=has_oci,
    )


def _risk(band: RiskBand = RiskBand.LOW, score: int = 1) -> RiskScore:
    return RiskScore(score=score, band=band, breakdown=[])


@pytest.fixture
def calculator() -> OpportunityCalculator:
    return OpportunityCalculator()


# ---------- defaults ----------


def test_opp__default_no_signals_all_false() -> None:
    """Live site, no detected issues, no cloud → web=Yes (no WAF + no cloud)."""

    flags = OpportunityCalculator().calculate(
        _input(waf=WafDetection(confidence=Confidence.LOW)), _risk()
    )
    # Default WAF=No (no detection) AND public_cloud=No → Web=Yes
    assert flags.appsec is False
    assert flags.web is True
    assert flags.cnapp is False


# ---------- WAF=No branch ----------


def test_opp__no_waf_public_cloud_appsec_yes(calculator: OpportunityCalculator) -> None:
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = calculator.calculate(_input(cloud=cloud, has_aws=True), _risk())
    assert flags.appsec is True
    assert flags.web is False


def test_opp__no_waf_no_cloud_web_yes(calculator: OpportunityCalculator) -> None:
    flags = calculator.calculate(_input(), _risk())
    assert flags.web is True
    assert flags.appsec is False


# ---------- WAF=Yes (competitor) ----------


def test_opp__competitor_waf_high_risk_public_cloud_appsec_yes(
    calculator: OpportunityCalculator,
) -> None:
    waf = WafDetection(
        vendor="Cloudflare", confidence=Confidence.HIGH, waf_active=True, cdn_capable=True
    )
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = calculator.calculate(
        _input(waf=waf, cloud=cloud, has_aws=True), _risk(RiskBand.HIGH, 10)
    )
    assert flags.appsec is True


def test_opp__competitor_waf_low_risk_no_recommendation(
    calculator: OpportunityCalculator,
) -> None:
    """Akamai + LOW risk → no displacement (only HIGH+ triggers)."""

    waf = WafDetection(
        vendor="Akamai", confidence=Confidence.HIGH, waf_active=True, cdn_capable=True
    )
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = calculator.calculate(
        _input(waf=waf, cloud=cloud, has_aws=True), _risk(RiskBand.LOW, 1)
    )
    assert flags.appsec is False
    assert flags.web is False


# ---------- Fortinet exception ----------


def test_opp__fortinet_waf_low_risk_one_csp_no_recommendation(
    calculator: OpportunityCalculator,
) -> None:
    waf = WafDetection(
        vendor="Fortinet_FortiWeb",
        confidence=Confidence.HIGH,
        waf_active=True,
        cdn_capable=False,
    )
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = calculator.calculate(
        _input(waf=waf, cloud=cloud, has_aws=True), _risk(RiskBand.LOW, 1)
    )
    assert flags.appsec is False
    assert flags.web is False
    assert flags.cnapp is False


def test_opp__fortinet_waf_low_risk_two_csp_cnapp_yes(
    calculator: OpportunityCalculator,
) -> None:
    """Two-CSP overrides the One-CSP exception path; CNAPP fires."""

    waf = WafDetection(
        vendor="Fortinet_FortiWeb",
        confidence=Confidence.HIGH,
        waf_active=True,
        cdn_capable=False,
    )
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = calculator.calculate(
        _input(waf=waf, cloud=cloud, has_aws=True, has_gcp=True),
        _risk(RiskBand.LOW, 1),
    )
    assert flags.appsec is False
    assert flags.web is False
    assert flags.cnapp is True


# ---------- Multi-CSP CNAPP ----------


def test_opp__multi_csp_always_cnapp_yes(calculator: OpportunityCalculator) -> None:
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = calculator.calculate(
        _input(cloud=cloud, has_aws=True, has_azure=True, has_gcp=True), _risk()
    )
    assert flags.cnapp is True


def test_opp__one_csp_no_cnapp(calculator: OpportunityCalculator) -> None:
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = calculator.calculate(_input(cloud=cloud, has_aws=True), _risk())
    assert flags.cnapp is False


# ---------- compute_waf_decision ----------


@pytest.mark.parametrize(
    "conf,active,expected",
    [
        (Confidence.HIGH, True, "Yes"),
        (Confidence.HIGH, False, "Further investigation needed"),
        (Confidence.MEDIUM, True, "Further investigation needed"),
        (Confidence.LOW, False, "No"),
    ],
)
def test_opp__waf_decision_matrix(conf: Confidence, active: bool, expected: str) -> None:
    waf = WafDetection(vendor="Cloudflare" if conf != Confidence.LOW else None, confidence=conf,
                       waf_active=active)
    assert compute_waf_decision(waf) == expected


# ---------- compute_complexity ----------


def test_opp__complexity_calculation() -> None:
    def _cx(pc: str, n: int) -> str:
        flags = [True] * n + [False] * (4 - n)
        return compute_complexity(
            pc, has_aws=flags[0], has_azure=flags[1], has_gcp=flags[2], has_oci=flags[3]
        )

    assert _cx("No", 1) == "-"
    assert _cx("Yes", 1) == "One CSP"
    assert _cx("Yes", 2) == "Two CSP"
    assert _cx("Yes", 3) == "Three CSP"
    assert _cx("Yes", 4) == "Four CSP"
    assert _cx("Yes", 0) == "-"


def test_opp__primary_hyperscaler_priority() -> None:
    """Primary cloud detection wins; falls back to has_* priority order."""

    aws_cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    assert compute_primary_hyperscaler(aws_cloud, has_aws=True, has_azure=False,
                                       has_gcp=False, has_oci=False) == "AWS"

    edge = CloudDetection(provider="Cloudflare", confidence=Confidence.HIGH, role="edge_only")
    assert compute_primary_hyperscaler(edge, has_aws=False, has_azure=True,
                                       has_gcp=False, has_oci=False) == "Azure"

    unknown = CloudDetection()
    assert compute_primary_hyperscaler(unknown, has_aws=False, has_azure=False,
                                       has_gcp=False, has_oci=False) == "-"


# ---------- compute_public_cloud ----------


def test_opp__public_cloud_datacenter_returns_no() -> None:
    cloud = CloudDetection(
        provider="datacenter", confidence=Confidence.HIGH, role="datacenter"
    )
    assert compute_public_cloud(cloud) == "No"


def test_opp__public_cloud_low_unknown_returns_no() -> None:
    """Without any provider, cloud is treated as off-cloud."""

    cloud = CloudDetection()
    assert compute_public_cloud(cloud) == "No"
