"""Tests for the passive scanner — DNS, WHOIS, ASN, cloud attribution."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from cdt.discovery.cache import DiscoveryCache
from cdt.scan.models import (
    ASNResult,
    CloudConfidence,
    CloudSource,
    DNSResult,
    IPRangeMatch,
)
from cdt.scan.passive import IPRangesIndex, PassiveScanner

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_json(rel: str) -> dict:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


def _load_text(rel: str) -> str:
    return (FIXTURES / rel).read_text(encoding="utf-8")


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


def _build_a_answer(addresses: list[str]) -> list:
    """A list of dnspython-shaped A records, mocked enough for our consumer."""

    return [MagicMock(address=ip) for ip in addresses]


def _resolver_with(responses: dict[tuple[str, str], list]) -> AsyncMock:
    """Async resolver mock keyed by (name, rrtype). Default → NoAnswer."""

    import dns.resolver

    async def _resolve(name, rrtype, *args, **kwargs):  # noqa: ANN001
        key = (str(name).rstrip("."), rrtype)
        if key not in responses:
            raise dns.resolver.NoAnswer()
        return responses[key]

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


@pytest.fixture
async def index(cache: DiscoveryCache) -> AsyncIterator[IPRangesIndex]:
    idx = IPRangesIndex(cache=cache, urls={"aws": "https://example.test/aws.json"})
    try:
        yield idx
    finally:
        await idx.aclose()


async def test_ip_ranges_index__loads_aws_json_fixture(
    index: IPRangesIndex,
) -> None:
    """A canned AWS dataset is ingested into the v4 trie and answers lookups."""

    with respx.mock:
        respx.get("https://example.test/aws.json").mock(
            return_value=httpx.Response(
                200,
                json=_load_json("ip_ranges/aws-mini.json"),
                headers={"content-type": "application/json"},
            )
        )
        await index.load_or_refresh()

    match = index.lookup("54.239.28.85")
    assert match is not None
    assert match.provider == "AWS"
    assert match.service == "EC2"
    assert match.region == "us-east-1"


async def test_dns__returns_a_aaaa_records(cache: DiscoveryCache) -> None:
    resolver = _resolver_with(
        {
            ("acme.example", "CNAME"): [],  # NoAnswer simulated below
            ("acme.example", "A"): _build_a_answer(["1.2.3.4"]),
            ("acme.example", "AAAA"): [MagicMock(address="2001:db8::1")],
        }
    )
    # CNAME resolution should produce NoAnswer; remove the empty entry so the
    # mock falls through to its default raise.
    resolver.resolve.side_effect = _resolver_with(
        {
            ("acme.example", "A"): _build_a_answer(["1.2.3.4"]),
            ("acme.example", "AAAA"): [MagicMock(address="2001:db8::1")],
        }
    ).resolve.side_effect

    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx, resolver=resolver)
        result = await scanner.resolve_dns("acme.example")
    finally:
        await idx.aclose()

    assert result.a_records == ["1.2.3.4"]
    assert result.aaaa_records == ["2001:db8::1"]
    assert result.cname_chain == []


async def test_whois__parses_registrar_and_dates(cache: DiscoveryCache) -> None:
    fake = _load_json("whois/tipti_market_whois.json")
    fake_entry = MagicMock()
    fake_entry.__iter__ = lambda self: iter(fake.items())
    fake_entry.__dict__ = fake

    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        with patch("cdt.scan.passive._run_whois", return_value=fake):
            result = await scanner.whois_lookup("tipti.market")
    finally:
        await idx.aclose()

    assert result.registrar == "GoDaddy.com, LLC"
    assert isinstance(result.created, datetime)
    assert result.created.year == 2018
    assert "NS1.TIPTI-EXAMPLE.NET" in result.name_servers


async def test_asn__lookup_via_ipwhois(cache: DiscoveryCache) -> None:
    fake = {
        "asn": "13335",
        "asn_description": "CLOUDFLARENET, US",
        "asn_country_code": "US",
    }

    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        with patch("cdt.scan.passive._run_ipwhois", return_value=fake):
            result = await scanner.asn_lookup("104.16.0.1")
    finally:
        await idx.aclose()

    assert result.asn == 13335
    assert result.asn_country == "US"
    assert "CLOUDFLARENET" in (result.asn_org or "")


async def test_attribute_cloud__ip_range_match_high_confidence(
    cache: DiscoveryCache,
) -> None:
    """A pytricia hit is the strongest signal — short-circuits the rest."""

    idx = IPRangesIndex(cache=cache)
    try:
        with respx.mock:
            respx.get("https://ip-ranges.amazonaws.com/ip-ranges.json").mock(
                return_value=httpx.Response(
                    200,
                    json=_load_json("ip_ranges/aws-mini.json"),
                    headers={"content-type": "application/json"},
                )
            )
            idx_loaded = IPRangesIndex(
                cache=cache,
                urls={"aws": "https://ip-ranges.amazonaws.com/ip-ranges.json"},
            )
            try:
                await idx_loaded.load_or_refresh()
                scanner = PassiveScanner(ip_ranges=idx_loaded)
                dns_result = DNSResult(apex="acme.example", a_records=["54.239.28.85"])
                attribution = await scanner.attribute_cloud(dns_result, asn=None)
            finally:
                await idx_loaded.aclose()
    finally:
        await idx.aclose()

    assert attribution.provider == "AWS"
    assert attribution.source == CloudSource.IP_RANGE
    assert attribution.confidence == CloudConfidence.HIGH


async def test_attribute_cloud__rdns_match_when_no_ip_range(
    cache: DiscoveryCache,
) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        with patch.object(
            scanner,
            "_reverse_dns",
            new=AsyncMock(return_value="ec2-1-2-3-4.compute.amazonaws.com"),
        ):
            dns_result = DNSResult(apex="acme.example", a_records=["1.2.3.4"])
            attribution = await scanner.attribute_cloud(dns_result, asn=None)
    finally:
        await idx.aclose()

    assert attribution.provider == "AWS"
    assert attribution.source == CloudSource.RDNS
    assert attribution.confidence == CloudConfidence.MEDIUM


async def test_attribute_cloud__cname_match_falls_through(
    cache: DiscoveryCache,
) -> None:
    """When IP range and rDNS produce nothing, CNAME suffix takes over."""

    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        with patch.object(scanner, "_reverse_dns", new=AsyncMock(return_value=None)):
            dns_result = DNSResult(
                apex="shop.acme.example",
                a_records=["13.224.50.10"],
                cname_chain=[
                    "shop.acme.example.cdn.acme-internal.example",
                    "d111111abcdef8.cloudfront.net",
                ],
            )
            attribution = await scanner.attribute_cloud(dns_result, asn=None)
    finally:
        await idx.aclose()

    assert attribution.provider == "AWS"
    assert attribution.source == CloudSource.CNAME
    assert attribution.matched_value == "d111111abcdef8.cloudfront.net"


async def test_attribute_cloud__asn_match_last_resort(
    cache: DiscoveryCache,
) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        with patch.object(scanner, "_reverse_dns", new=AsyncMock(return_value=None)):
            dns_result = DNSResult(apex="acme.example", a_records=["198.51.100.1"])
            asn = ASNResult(ip="198.51.100.1", asn=13335, asn_org="CLOUDFLARENET")
            attribution = await scanner.attribute_cloud(dns_result, asn=asn)
    finally:
        await idx.aclose()

    assert attribution.provider == "Cloudflare"
    assert attribution.source == CloudSource.ASN
    assert attribution.confidence == CloudConfidence.LOW


async def test_attribute_cloud__no_match_returns_unknown(
    cache: DiscoveryCache,
) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        with patch.object(scanner, "_reverse_dns", new=AsyncMock(return_value=None)):
            dns_result = DNSResult(apex="acme.example", a_records=["198.51.100.1"])
            asn = ASNResult(ip="198.51.100.1", asn=99999, asn_org="UNKNOWN-CORP")
            attribution = await scanner.attribute_cloud(dns_result, asn=asn)
    finally:
        await idx.aclose()

    assert attribution.provider is None
    assert attribution.source == CloudSource.UNKNOWN


async def test_ip_ranges_index__skips_provider_on_fetch_failure(
    cache: DiscoveryCache,
) -> None:
    """One bad URL must not poison the rest of the index."""

    idx = IPRangesIndex(
        cache=cache,
        urls={"aws": "https://example.test/aws.json"},
    )
    try:
        with respx.mock:
            respx.get("https://example.test/aws.json").mock(
                side_effect=httpx.ConnectError("nope")
            )
            await idx.load_or_refresh()
    finally:
        await idx.aclose()

    assert idx.lookup("54.239.28.85") is None


def test_ip_range_match__model_round_trip() -> None:
    m = IPRangeMatch(provider="AWS", prefix="54.239.28.0/22", service="EC2")
    payload = m.model_dump()
    again = IPRangeMatch.model_validate(payload)
    assert again == m
