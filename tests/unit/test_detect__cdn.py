"""CDN detector — parametrized vendor tests + WAF crossover."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cdt.detect import (
    CdnDetector,
    Confidence,
    DetectionInput,
    DetectionRules,
    WafDetector,
)

RULES_PATH = Path(__file__).parent.parent.parent / "config" / "detection_rules.yaml"
CDN_FIXTURES = Path(__file__).parent.parent / "fixtures" / "http" / "cdn"
WAF_FIXTURES = Path(__file__).parent.parent / "fixtures" / "http" / "waf"


def _load(path: Path) -> DetectionInput:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return DetectionInput.model_validate(
        {
            "url": payload["url"],
            "status": payload["status"],
            "headers": {k.lower(): v for k, v in payload["headers"].items()},
            "cookies": payload.get("cookies", []),
            "body_snippet": payload.get("body", ""),
            "cnames": payload.get("cnames", []),
            "asn": payload.get("asn"),
        }
    )


@pytest.fixture(scope="module")
def cdn_detector() -> CdnDetector:
    return CdnDetector(DetectionRules.load(RULES_PATH))


@pytest.fixture(scope="module")
def waf_detector() -> WafDetector:
    return WafDetector(DetectionRules.load(RULES_PATH))


@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("fastly_cache_hit.json", "Fastly"),
        ("keycdn.json", "KeyCDN"),
        ("bunnycdn.json", "BunnyCDN"),
        ("cdn77.json", "CDN77"),
        ("google_cloud_cdn.json", "Google_Cloud_CDN"),
    ],
)
def test_cdn__vendor_detected(
    cdn_detector: CdnDetector, fixture: str, expected: str
) -> None:
    ctx = _load(CDN_FIXTURES / fixture)
    result = cdn_detector.detect(ctx)
    assert result.vendor == expected
    assert result.confidence == Confidence.HIGH


def test_cdn__capable_waf_winner_propagates_to_cdn(
    cdn_detector: CdnDetector, waf_detector: WafDetector
) -> None:
    """A Cloudflare WAF result also reports as CDN=Cloudflare."""

    ctx = _load(WAF_FIXTURES / "cloudflare_pro.json")
    waf = waf_detector.detect(ctx)
    cdn = cdn_detector.detect(ctx, waf_detection=waf)
    assert cdn.vendor == "Cloudflare"


def test_cdn__no_match_returns_low_confidence(cdn_detector: CdnDetector) -> None:
    ctx = _load(WAF_FIXTURES / "no_waf_clean.json")
    cdn = cdn_detector.detect(ctx)
    assert cdn.vendor is None
    assert cdn.confidence == Confidence.LOW
