"""OriginAttributor tests (Fase 9 #1).

Three flavors:
  - Pure-function tests for ``match_cname_provider`` / ``is_edge_asn``.
  - DNS-mocked tests for ``OriginAttributor.detect`` covering the
    not-edge / subdomain-hit / CNAME-hit / exhausted paths.
  - Integration test that wires ``CloudAttributor + OriginAttributor``
    end-to-end with mocked resolver + IP ranges trie.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import dns.resolver
import pytest

from cdt.detect.cloud import CloudAttributor
from cdt.detect.models import (
    CloudDetection,
    Confidence,
    DetectionInput,
)
from cdt.detect.origin import (
    OriginAttributor,
    OriginResult,
    edge_name_for_asn,
    is_edge_asn,
    match_cname_provider,
)
from cdt.detect.rules import DetectionRules

# ---------- pure helpers ----------


def test_is_edge_asn__cloudflare_is_edge() -> None:
    assert is_edge_asn(13335) is True
    assert is_edge_asn(54113) is True  # Fastly
    assert is_edge_asn(20940) is True  # Akamai


def test_is_edge_asn__aws_is_not_edge() -> None:
    assert is_edge_asn(14618) is False  # AWS
    assert is_edge_asn(8075) is False   # Azure
    assert is_edge_asn(15169) is False  # GCP
    assert is_edge_asn(None) is False


def test_edge_name_for_asn() -> None:
    assert edge_name_for_asn(13335) == "Cloudflare"
    assert edge_name_for_asn(54113) == "Fastly"
    assert edge_name_for_asn(99999) is None
    assert edge_name_for_asn(None) is None


@pytest.mark.parametrize(
    "cname,expected",
    [
        ("d111111abcdef8.cloudfront.net", "AWS"),
        ("acme-prod-1234.us-east-1.elb.amazonaws.com", "AWS"),
        ("acme.amplifyapp.com", "AWS"),
        ("acme.azurewebsites.net", "Azure"),
        ("acme.azurefd.net", "Azure"),
        ("acme.trafficmanager.net", "Azure"),
        ("acme-12345.appspot.com", "GCP"),
        ("acme-svc-xyz.run.app", "GCP"),
        ("acme.oraclecloud.com", "OCI"),
        ("acme.cloudflare.net", None),    # edge, not origin
        ("acme.example.com", None),       # nothing known
        ("", None),
    ],
)
def test_match_cname_provider(cname: str, expected: str | None) -> None:
    assert match_cname_provider(cname) == expected


# ---------- OriginAttributor.detect — DNS-mocked ----------


def _make_resolver(
    a_records: dict[str, list[str]] | None = None,
) -> AsyncMock:
    """Build an AsyncMock resolver whose ``resolve(name, "A")`` returns
    canned A records keyed by hostname. Unmapped names raise ``NXDOMAIN``.
    """

    a_records = a_records or {}

    async def _resolve(name: str, rrtype: str) -> object:
        host = str(name).rstrip(".").lower()
        if rrtype != "A":
            raise dns.resolver.NoAnswer()
        if host not in a_records:
            raise dns.resolver.NXDOMAIN()
        ips = a_records[host]
        return [MagicMock(address=ip) for ip in ips]

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


def _ip_ranges_stub(map_ip_to_provider: dict[str, str]) -> object:
    stub = MagicMock()
    stub.lookup = MagicMock(
        side_effect=lambda ip: MagicMock(provider=map_ip_to_provider[ip])
        if ip in map_ip_to_provider
        else None
    )
    return stub


async def test_detect_origin__not_on_edge_returns_none() -> None:
    """Primary IP not in EDGE_ASNS → short-circuit to ``not_edge``."""

    attributor = OriginAttributor(resolver=_make_resolver())
    result = await attributor.detect(
        "acme.example", primary_asn=14618, primary_cnames=[]
    )
    assert isinstance(result, OriginResult)
    assert result.provider is None
    assert result.source == "not_edge"


async def test_detect_origin__cloudflare_with_aws_origin_subdomain() -> None:
    """Cloudflare apex + ``api.example.com`` → AWS classification."""

    resolver = _make_resolver({"api.acme.example": ["54.239.28.85"]})
    ip_ranges = _ip_ranges_stub({"54.239.28.85": "AWS"})
    attributor = OriginAttributor(resolver=resolver, ip_range_lookup=ip_ranges)

    result = await attributor.detect(
        "acme.example", primary_asn=13335, primary_cnames=[]
    )

    assert result.provider == "AWS"
    assert result.source == "subdomain_probe"
    assert result.confidence == Confidence.MEDIUM


async def test_detect_origin__multiple_subdomains_agreeing_high_confidence() -> None:
    """Two probe subdomains landing in the same cloud → HIGH confidence."""

    resolver = _make_resolver(
        {
            "api.acme.example": ["54.239.28.85"],
            "admin.acme.example": ["3.5.140.10"],
        }
    )
    ip_ranges = _ip_ranges_stub(
        {"54.239.28.85": "AWS", "3.5.140.10": "AWS"}
    )
    attributor = OriginAttributor(resolver=resolver, ip_range_lookup=ip_ranges)

    result = await attributor.detect(
        "acme.example", primary_asn=13335, primary_cnames=[]
    )
    assert result.provider == "AWS"
    assert result.confidence == Confidence.HIGH


async def test_detect_origin__cname_chain_to_cloudfront() -> None:
    """Subdomain probe fails; cloudfront CNAME on the apex wins."""

    resolver = _make_resolver()  # all NXDOMAIN
    attributor = OriginAttributor(resolver=resolver)

    result = await attributor.detect(
        "acme.example",
        primary_asn=13335,
        primary_cnames=["acme.example.cdn.acme-internal.example",
                        "d111111abcdef8.cloudfront.net"],
    )
    assert result.provider == "AWS"
    assert result.source == "cname_chain"
    assert result.confidence == Confidence.MEDIUM


async def test_detect_origin__cname_to_azurefd() -> None:
    resolver = _make_resolver()
    attributor = OriginAttributor(resolver=resolver)
    result = await attributor.detect(
        "acme.example",
        primary_asn=13335,
        primary_cnames=["acme-prod.azurefd.net"],
    )
    assert result.provider == "Azure"


async def test_detect_origin__no_origin_found_returns_none_provider() -> None:
    """Edge confirmed but every probe + CNAME fails → None."""

    resolver = _make_resolver()
    attributor = OriginAttributor(resolver=resolver)

    result = await attributor.detect(
        "acme.example", primary_asn=13335, primary_cnames=[]
    )
    assert result.provider is None
    assert result.source == "exhausted"


async def test_detect_origin__resolver_error_no_crash() -> None:
    """A DNSException during resolve should yield ``exhausted`` not a raise."""

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=dns.resolver.NoNameservers)

    attributor = OriginAttributor(resolver=resolver)
    result = await attributor.detect(
        "acme.example", primary_asn=13335, primary_cnames=[]
    )
    assert result.provider is None
    assert result.source == "exhausted"


async def test_detect_origin__edge_ip_in_subdomain_is_skipped() -> None:
    """If an origin probe still resolves into edge ASN space, skip it
    (don't mistakenly attribute the edge as the origin)."""

    resolver = _make_resolver({"api.acme.example": ["104.16.0.1"]})
    ip_ranges = _ip_ranges_stub({"104.16.0.1": "Cloudflare"})
    attributor = OriginAttributor(resolver=resolver, ip_range_lookup=ip_ranges)

    result = await attributor.detect(
        "acme.example", primary_asn=13335, primary_cnames=[]
    )
    assert result.provider is None  # edge IPs filtered out
    assert result.source == "exhausted"


# ---------- CloudAttributor + OriginAttributor wiring ----------


@pytest.fixture(scope="module")
def rules() -> DetectionRules:
    from pathlib import Path

    return DetectionRules.load(Path("config/detection_rules.yaml"))


async def test_cloud_attributor__origin_populated_when_edge(
    rules: DetectionRules,
) -> None:
    """End-to-end: CloudAttributor calls OriginAttributor on edge_only and
    surfaces the origin as ``CloudDetection.origin``."""

    resolver = _make_resolver({"api.acme.example": ["54.239.28.85"]})
    ip_ranges = _ip_ranges_stub({"54.239.28.85": "AWS"})

    origin_attr = OriginAttributor(resolver=resolver, ip_range_lookup=ip_ranges)
    # Use a stub IPRangesIndex for the CloudAttributor primary path —
    # we want primary to hit Cloudflare via ASN alone, no IP range hit.
    primary_index = MagicMock()
    primary_index.lookup = MagicMock(return_value=None)

    cloud_attributor = CloudAttributor(
        rules=rules,
        ip_ranges_index=primary_index,
        origin_attributor=origin_attr,
    )

    ctx = DetectionInput(
        url="https://acme.example/",
        status=200,
        cnames=[],
        ip_addresses=["104.16.0.1"],
        asn=13335,  # Cloudflare → edge
        rdns_hostnames=["acme.cloudflare.com"],
    )
    result = await cloud_attributor.attribute(ctx)

    assert isinstance(result, CloudDetection)
    # Primary should be Cloudflare (rdns + asn signals fire).
    assert result.provider == "Cloudflare"
    assert result.role == "edge_only"
    # Origin should be AWS via subdomain probe.
    assert result.origin == "AWS"
    assert result.origin_source == "subdomain_probe"
    assert result.effective_provider() == "AWS"


async def test_cloud_attributor__no_origin_when_primary_not_edge(
    rules: DetectionRules,
) -> None:
    """Primary lands on AWS directly → origin probe is skipped."""

    resolver = _make_resolver({"api.acme.example": ["1.2.3.4"]})
    origin_attr = OriginAttributor(resolver=resolver)

    primary_index = MagicMock()
    primary_index.lookup = MagicMock(
        return_value=MagicMock(provider="AWS", prefix="54.239.28.0/22",
                               region="us-east-1", service="EC2")
    )
    cloud_attributor = CloudAttributor(
        rules=rules,
        ip_ranges_index=primary_index,
        origin_attributor=origin_attr,
    )

    ctx = DetectionInput(
        url="https://acme.example/",
        status=200,
        ip_addresses=["54.239.28.85"],
        asn=14618,  # AWS, not edge
    )
    result = await cloud_attributor.attribute(ctx)
    assert result.provider == "AWS"
    assert result.role == "hyperscaler"
    assert result.origin is None
    assert result.effective_provider() == "AWS"


def test_cloud_detection__effective_provider_falls_back_to_provider() -> None:
    cd = CloudDetection(provider="AWS", origin=None)
    assert cd.effective_provider() == "AWS"

    cd2 = CloudDetection(provider="Cloudflare", origin="Azure")
    assert cd2.effective_provider() == "Azure"

    cd3 = CloudDetection(provider=None, origin=None)
    assert cd3.effective_provider() is None
