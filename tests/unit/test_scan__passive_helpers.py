"""Coverage tests for passive.py helpers and ingest paths."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from cdt.discovery.cache import DiscoveryCache
from cdt.scan.models import CloudConfidence, CloudSource
from cdt.scan.passive import (
    IPRangesIndex,
    PassiveScanner,
    _first_dt,
    _first_str,
    _match_rdns,
    _str_list,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load(rel: str) -> dict:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


def test_first_str__handles_list_and_none() -> None:
    assert _first_str(["a", "b"]) == "a"
    assert _first_str([]) is None
    assert _first_str(None) is None
    assert _first_str("plain") == "plain"
    assert _first_str(42) == "42"


def test_first_dt__parses_iso_and_passes_through() -> None:
    dt = datetime(2026, 1, 2, 3, 4, 5)
    assert _first_dt([dt, "ignored"]) == dt
    assert _first_dt("2026-01-02T03:04:05") == dt
    assert _first_dt(None) is None
    assert _first_dt([]) is None
    assert _first_dt("not-a-date") is None
    assert _first_dt(42) is None


def test_str_list__normalises_input_shapes() -> None:
    assert _str_list(["a", "b"]) == ["a", "b"]
    assert _str_list("solo") == ["solo"]
    assert _str_list(None) == []
    assert _str_list([1, None, "x"]) == ["1", "x"]


def test_match_rdns__case_insensitive_glob() -> None:
    patterns = {"AWS": ["*.amazonaws.com"], "Cloudflare": ["*.cloudflare.com"]}
    assert _match_rdns("ec2-1.compute.amazonaws.com", patterns) == "AWS"
    assert _match_rdns("EDGE.CLOUDFLARE.COM", patterns) == "Cloudflare"
    assert _match_rdns("foo.example.com", patterns) is None


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


async def test_ingest_gcp__populates_v4_and_v6_tries(cache: DiscoveryCache) -> None:
    idx = IPRangesIndex(cache=cache, urls={"gcp": "https://example.test/gcp.json"})
    try:
        with respx.mock:
            respx.get("https://example.test/gcp.json").mock(
                return_value=httpx.Response(
                    200,
                    json=_load("ip_ranges/gcp-mini.json"),
                    headers={"content-type": "application/json"},
                )
            )
            await idx.load_or_refresh()
    finally:
        await idx.aclose()

    match = idx.lookup("34.65.0.1")
    assert match is not None
    assert match.provider == "GCP"


async def test_ingest_cloudflare_v4__plain_text_lines(cache: DiscoveryCache) -> None:
    body = (FIXTURES / "ip_ranges" / "cloudflare-v4-mini.txt").read_text(encoding="utf-8")
    idx = IPRangesIndex(
        cache=cache, urls={"cloudflare_v4": "https://example.test/cf-v4.txt"}
    )
    try:
        with respx.mock:
            respx.get("https://example.test/cf-v4.txt").mock(
                return_value=httpx.Response(
                    200,
                    text=body,
                    headers={"content-type": "text/plain"},
                )
            )
            await idx.load_or_refresh()
    finally:
        await idx.aclose()

    match = idx.lookup("104.16.10.10")
    assert match is not None
    assert match.provider == "Cloudflare"


async def test_ingest_oci__splits_v4_and_v6(cache: DiscoveryCache) -> None:
    payload = {
        "regions": [
            {
                "region": "us-ashburn-1",
                "cidrs": [
                    {"cidr": "129.146.0.0/16", "tags": ["OCI"]},
                    {"cidr": "2603:c020::/32", "tags": ["OCI"]},
                ],
            }
        ]
    }
    idx = IPRangesIndex(cache=cache, urls={"oci": "https://example.test/oci.json"})
    try:
        with respx.mock:
            respx.get("https://example.test/oci.json").mock(
                return_value=httpx.Response(
                    200, json=payload, headers={"content-type": "application/json"}
                )
            )
            await idx.load_or_refresh()
    finally:
        await idx.aclose()

    assert idx.lookup("129.146.5.5") is not None
    assert idx.lookup("129.146.5.5").provider == "OCI"  # type: ignore[union-attr]


async def test_ingest_fastly__addresses_and_ipv6(cache: DiscoveryCache) -> None:
    payload = {
        "addresses": ["151.101.0.0/16"],
        "ipv6_addresses": ["2a04:4e42::/32"],
    }
    idx = IPRangesIndex(
        cache=cache, urls={"fastly": "https://example.test/fastly.json"}
    )
    try:
        with respx.mock:
            respx.get("https://example.test/fastly.json").mock(
                return_value=httpx.Response(
                    200, json=payload, headers={"content-type": "application/json"}
                )
            )
            await idx.load_or_refresh()
    finally:
        await idx.aclose()

    assert idx.lookup("151.101.10.10") is not None


async def test_lookup__bad_input_returns_none(cache: DiscoveryCache) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        assert idx.lookup("") is None
        assert idx.lookup("not-an-ip") is None
    finally:
        await idx.aclose()


async def test_resolve_dns__follows_cname_chain(cache: DiscoveryCache) -> None:
    """``resolve_dns`` walks CNAMEs until terminal A/AAAA — capped at 10 hops."""

    import dns.resolver

    cname_targets = {"acme.example": "edge.acme.example", "edge.acme.example": None}

    async def fake_resolve(name, rrtype, *args, **kwargs):  # noqa: ANN001
        key = str(name).rstrip(".")
        if rrtype == "CNAME":
            target = cname_targets.get(key)
            if not target:
                raise dns.resolver.NoAnswer()
            ans = MagicMock()
            target_obj = MagicMock(target=MagicMock(__str__=lambda self: target))
            ans.__getitem__ = lambda self, idx: target_obj
            return ans
        if rrtype == "A" and key == "edge.acme.example":
            return [MagicMock(address="1.2.3.4")]
        raise dns.resolver.NoAnswer()

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=fake_resolve)
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx, resolver=resolver)
        result = await scanner.resolve_dns("acme.example")
    finally:
        await idx.aclose()

    assert "edge.acme.example" in result.cname_chain
    assert "1.2.3.4" in result.a_records


async def test_scan__pipeline_captures_step_errors(cache: DiscoveryCache) -> None:
    """Every step is wrapped — one failing step must not abort the others."""

    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)

        with patch.object(
            scanner, "resolve_dns", new=AsyncMock(side_effect=RuntimeError("dns boom"))
        ), patch.object(
            scanner,
            "whois_lookup",
            new=AsyncMock(side_effect=RuntimeError("whois boom")),
        ):
            result = await scanner.scan("https://acme.example/")
    finally:
        await idx.aclose()

    assert result.url == "https://acme.example/"
    assert any("dns" in e for e in result.errors)
    assert any("whois" in e for e in result.errors)
    assert result.cloud_attribution.source == CloudSource.UNKNOWN


async def test_scan__bad_url_short_circuits(cache: DiscoveryCache) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        result = await scanner.scan("not a url")
    finally:
        await idx.aclose()

    assert result.dns is None
    assert any("normalize" in e for e in result.errors)


async def test_attribute_cloud__ipv6_match(cache: DiscoveryCache) -> None:
    """An IPv6 record routes through the v6 trie and is attributed."""

    idx = IPRangesIndex(cache=cache, urls={"aws": "https://example.test/aws.json"})
    try:
        with respx.mock:
            respx.get("https://example.test/aws.json").mock(
                return_value=httpx.Response(
                    200,
                    json=_load("ip_ranges/aws-mini.json"),
                    headers={"content-type": "application/json"},
                )
            )
            await idx.load_or_refresh()
        scanner = PassiveScanner(ip_ranges=idx)
        from cdt.scan.models import DNSResult

        dns_result = DNSResult(
            apex="acme.example",
            a_records=[],
            aaaa_records=["2600:1f18::1"],
        )
        attribution = await scanner.attribute_cloud(dns_result, asn=None)
    finally:
        await idx.aclose()

    assert attribution.provider == "AWS"
    assert attribution.confidence == CloudConfidence.HIGH
