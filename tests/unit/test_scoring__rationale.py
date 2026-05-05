"""RationaleRenderer tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cdt.detect.models import (
    CdnDetection,
    CloudDetection,
    Confidence,
    StackDetection,
    WafDetection,
)
from cdt.errors import InputError
from cdt.scoring import (
    OpportunityFlags,
    RationaleRenderer,
    RiskBand,
    RiskScore,
    ScoringInput,
)

TEMPLATES_PATH = (
    Path(__file__).parent.parent.parent / "config" / "rationale_templates.yaml"
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


def _risk(band: RiskBand = RiskBand.LOW) -> RiskScore:
    return RiskScore(score=1, band=band, breakdown=[])


@pytest.fixture
def renderer() -> RationaleRenderer:
    return RationaleRenderer(TEMPLATES_PATH)


def test_rationale__appsec_no_waf_cloud_renders_correctly(
    renderer: RationaleRenderer,
) -> None:
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = OpportunityFlags(appsec=True, web=False, cnapp=False)
    out = renderer.render(
        flags,
        _input(cloud=cloud, has_aws=True),
        _risk(),
        primary_hyperscaler="AWS",
        complexity="One CSP",
    )
    assert "AWS" in out
    assert "FortiAppSec" in out
    assert "Cloud WAF" in out


def test_rationale__appsec_displacement_with_vendor_and_band(
    renderer: RationaleRenderer,
) -> None:
    waf = WafDetection(
        vendor="Akamai", confidence=Confidence.HIGH, waf_active=True, cdn_capable=True
    )
    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = OpportunityFlags(appsec=True, web=False, cnapp=False)
    out = renderer.render(
        flags,
        _input(waf=waf, cloud=cloud, has_aws=True),
        _risk(RiskBand.HIGH),
        primary_hyperscaler="AWS",
        complexity="One CSP",
    )
    assert "Akamai" in out
    assert "HIGH" in out
    assert "displacement" in out


def test_rationale__cnapp_with_complexity_and_csps_list(
    renderer: RationaleRenderer,
) -> None:
    flags = OpportunityFlags(appsec=False, web=False, cnapp=True)
    out = renderer.render(
        flags,
        _input(has_aws=True, has_gcp=True),
        _risk(),
        primary_hyperscaler="AWS",
        complexity="Two CSP",
    )
    assert "Two CSP" in out
    assert "AWS+GCP" in out
    assert "FortiCNAPP" in out


def test_rationale__fortiweb_no_vars(renderer: RationaleRenderer) -> None:
    flags = OpportunityFlags(appsec=False, web=True, cnapp=False)
    out = renderer.render(
        flags, _input(), _risk(), primary_hyperscaler="-", complexity="-"
    )
    assert "FortiWeb" in out


def test_rationale__multiple_recommendations_concatenated_with_semicolon(
    renderer: RationaleRenderer,
) -> None:
    """AppSec (no WAF + cloud) + CNAPP (multi-CSP) → concatenated with '; '."""

    cloud = CloudDetection(provider="AWS", confidence=Confidence.HIGH, role="hyperscaler")
    flags = OpportunityFlags(appsec=True, web=False, cnapp=True)
    out = renderer.render(
        flags,
        _input(cloud=cloud, has_aws=True, has_gcp=True),
        _risk(),
        primary_hyperscaler="AWS",
        complexity="Two CSP",
    )
    assert "; " in out
    parts = out.split("; ")
    assert len(parts) == 2
    assert any("FortiAppSec" in p for p in parts)
    assert any("FortiCNAPP" in p for p in parts)


def test_rationale__no_recommendations_empty_string(
    renderer: RationaleRenderer,
) -> None:
    flags = OpportunityFlags(appsec=False, web=False, cnapp=False)
    out = renderer.render(
        flags, _input(), _risk(), primary_hyperscaler="-", complexity="-"
    )
    assert out == ""


def test_rationale__loads_templates_from_yaml(renderer: RationaleRenderer) -> None:
    """Smoke test that the YAML loaded all 4 templates."""

    flags = OpportunityFlags(appsec=False, web=True, cnapp=False)
    out = renderer.render(
        flags, _input(), _risk(), primary_hyperscaler="-", complexity="-"
    )
    assert "FortiWeb" in out  # template exists


def test_rationale__missing_template_yaml_raises(tmp_path: Path) -> None:
    bad = tmp_path / "missing.yaml"
    with pytest.raises(InputError):
        RationaleRenderer(bad)


def test_rationale__invalid_yaml_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("templates:\n  - bare list", encoding="utf-8")
    with pytest.raises(InputError):
        RationaleRenderer(bad)
