"""WAF detector — one parametrized test per vendor with HIGH-confidence fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cdt.detect import (
    Confidence,
    DetectionInput,
    DetectionRules,
    WafDetector,
)

RULES_PATH = Path(__file__).parent.parent.parent / "config" / "detection_rules.yaml"
FIXTURES = Path(__file__).parent.parent / "fixtures" / "http" / "waf"


def _load(rel: str) -> DetectionInput:
    payload = json.loads((FIXTURES / rel).read_text(encoding="utf-8"))
    return DetectionInput.model_validate(
        {
            "url": payload["url"],
            "status": payload["status"],
            "headers": {k.lower(): v for k, v in payload["headers"].items()},
            "cookies": payload.get("cookies", []),
            "body_snippet": payload.get("body", ""),
            "cnames": payload.get("cnames", []),
        }
    )


@pytest.fixture(scope="module")
def detector() -> WafDetector:
    return WafDetector(DetectionRules.load(RULES_PATH))


@pytest.mark.parametrize(
    "fixture,expected_vendor",
    [
        ("cloudflare_pro.json", "Cloudflare"),
        ("aws_cloudfront_waf.json", "AWS_CloudFront_WAF"),
        ("azure_frontdoor.json", "Azure_FrontDoor_WAF"),
        ("akamai_ghost.json", "Akamai"),
        ("fortinet_fortiweb.json", "Fortinet_FortiWeb"),
        ("fortinet_fortigate.json", "Fortinet_FortiGate"),
        ("imperva_incapsula.json", "Imperva"),
        ("f5_bigip.json", "F5_BIGIP_ASM"),
        ("sucuri.json", "Sucuri"),
        ("barracuda.json", "Barracuda"),
        ("stackpath.json", "StackPath"),
        ("wallarm.json", "Wallarm"),
    ],
)
def test_waf__vendor_high_confidence(
    detector: WafDetector, fixture: str, expected_vendor: str
) -> None:
    """Each canonical fixture clears threshold + gap for its vendor."""

    ctx = _load(fixture)
    result = detector.detect(ctx)
    assert result.vendor == expected_vendor
    assert result.confidence == Confidence.HIGH


def test_waf__citrix_netscaler_resolves(detector: WafDetector) -> None:
    """Citrix has only primary + secondary; threshold met but possibly MEDIUM."""

    ctx = _load("citrix_netscaler.json")
    result = detector.detect(ctx)
    assert result.vendor == "Citrix_NetScaler"
    assert result.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def test_waf__cloudflare_block_page_marks_active(detector: WafDetector) -> None:
    """A 403 with Cloudflare body sets ``waf_active=True``."""

    ctx = _load("cloudflare_block_page.json")
    result = detector.detect(ctx)
    assert result.vendor == "Cloudflare"
    assert result.waf_active is True


def test_waf__no_signals_returns_low_confidence_none(detector: WafDetector) -> None:
    ctx = _load("no_waf_clean.json")
    result = detector.detect(ctx)
    assert result.vendor is None
    assert result.confidence == Confidence.LOW


def test_waf__wafw00f_corroboration_boosts_confidence(detector: WafDetector) -> None:
    """A wafw00f vendor match adds primary-strength evidence."""

    ctx = _load("no_waf_clean.json")
    boosted = ctx.model_copy(
        update={"wafw00f_vendor": "Cloudflare", "wafw00f_generic": False}
    )
    result = detector.detect(boosted)
    assert result.vendor == "Cloudflare"
    assert result.waf_active is True
