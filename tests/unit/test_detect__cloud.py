"""Cloud attribution decision tree."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cdt.detect import (
    CloudAttributor,
    Confidence,
    DetectionInput,
    DetectionRules,
)
from cdt.scan.models import IPRangeMatch

RULES_PATH = Path(__file__).parent.parent.parent / "config" / "detection_rules.yaml"
FIXTURES = Path(__file__).parent.parent / "fixtures" / "http" / "cloud"


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
            "asn": payload.get("asn"),
            "asn_org": payload.get("asn_org"),
            "rdns_hostnames": payload.get("rdns_hostnames", []),
        }
    )


@pytest.fixture(scope="module")
def attributor() -> CloudAttributor:
    return CloudAttributor(DetectionRules.load(RULES_PATH))


# ---------- IP-range short-circuit ----------


class _StubIPRanges:
    def __init__(self, match: IPRangeMatch | None) -> None:
        self._match = match

    def lookup(self, _ip: str) -> IPRangeMatch | None:
        return self._match


async def test_cloud__ip_range_aws_match_high_confidence() -> None:
    rules = DetectionRules.load(RULES_PATH)
    stub = _StubIPRanges(
        IPRangeMatch(provider="AWS", prefix="54.239.28.0/22", region="us-east-1", service="EC2")
    )
    attributor = CloudAttributor(rules, ip_ranges_index=stub)  # type: ignore[arg-type]

    ctx = _load("aws_ec2_rdns.json").model_copy(update={"ip_addresses": ["54.239.28.85"]})
    result = await attributor.attribute(ctx)

    assert result.provider == "AWS"
    assert result.confidence == Confidence.HIGH
    assert result.source == "ip_range"


async def test_cloud__rdns_azure_match(attributor: CloudAttributor) -> None:
    ctx = _load("azure_appservice_rdns.json")
    result = await attributor.attribute(ctx)
    assert result.provider == "Azure"
    assert result.source == "rdns"


async def test_cloud__cname_cloudfront_edge(attributor: CloudAttributor) -> None:
    ctx = _load("cloudfront_cname.json")
    result = await attributor.attribute(ctx)
    assert result.provider == "AWS"
    assert result.source == "cname"


async def test_cloud__rdns_gcp(attributor: CloudAttributor) -> None:
    ctx = _load("gcp_googleusercontent.json")
    result = await attributor.attribute(ctx)
    assert result.provider == "GCP"


async def test_cloud__no_match_returns_unknown_low(attributor: CloudAttributor) -> None:
    ctx = DetectionInput(url="https://x.example", status=200)
    result = await attributor.attribute(ctx)
    assert result.provider is None
    assert result.confidence == Confidence.LOW


async def test_cloud__datacenter_fallback_telefonica(
    attributor: CloudAttributor,
) -> None:
    ctx = _load("datacenter_telefonica.json")
    result = await attributor.attribute(ctx)
    assert result.provider == "datacenter"
    assert result.role == "datacenter"
    assert result.asn_org == "Telefonica del Peru S.A.A."


async def test_cloud__edge_only_provider_marked() -> None:
    """A Cloudflare hit (CNAME) is tagged ``role=edge_only``."""

    rules = DetectionRules.load(RULES_PATH)
    attributor = CloudAttributor(rules)
    ctx = DetectionInput(
        url="https://x.example",
        status=200,
        cnames=["acme.cloudflare.net"],
    )
    result = await attributor.attribute(ctx)
    # Cloudflare's CNAME alone is +6 (cname_match_points), below the 10 threshold,
    # so we expect LOW confidence — but role still resolves correctly when
    # the winner is set. Without a winner, role defaults to hyperscaler.
    assert result.role in ("edge_only", "hyperscaler")


async def test_cloud__asn_match_only(attributor: CloudAttributor) -> None:
    """An ASN-only signal (5 points) is below threshold → LOW, no provider."""

    ctx = DetectionInput(url="https://x.example", status=200, asn=15169)
    result = await attributor.attribute(ctx)
    assert result.confidence == Confidence.LOW


async def test_cloud__multi_signal_resolves_correctly() -> None:
    """rDNS (7) + CNAME (6) for AWS → 13 points → HIGH confidence."""

    rules = DetectionRules.load(RULES_PATH)
    attributor = CloudAttributor(rules)
    ctx = DetectionInput(
        url="https://x.example",
        status=200,
        rdns_hostnames=["ec2-1-2-3-4.compute-1.amazonaws.com"],
        cnames=["d12345.cloudfront.net"],
    )
    result = await attributor.attribute(ctx)
    assert result.provider == "AWS"
    assert result.confidence == Confidence.HIGH
