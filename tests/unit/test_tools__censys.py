"""Tests for the Censys wrapper (Hosts.view + Certs.search)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cdt.discovery.cache import DiscoveryCache
from cdt.tools import CensysCertResult, CensysHostResult, CensysWrapper

FIXTURES = Path(__file__).parent.parent / "fixtures" / "censys"


def _load(name: str) -> Any:  # noqa: F821
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


async def test_censys__disabled_when_no_credentials(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)

    wrapper = CensysWrapper(cache=cache)
    assert wrapper.enabled is False

    with patch("cdt.tools.censys_wrapper._run_censys_host") as host_spy, patch(
        "cdt.tools.censys_wrapper._run_censys_certs"
    ) as cert_spy:
        host_result = await wrapper.lookup_host("1.2.3.4")
        cert_result = await wrapper.search_certs("acme.example")

    assert host_result.enabled is False
    assert cert_result.enabled is False
    host_spy.assert_not_called()
    cert_spy.assert_not_called()


async def test_censys__host_lookup_returns_services(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")
    payload = _load("host_view_azure.json")

    wrapper = CensysWrapper(cache=cache)
    with patch("cdt.tools.censys_wrapper._run_censys_host", return_value=payload):
        result = await wrapper.lookup_host("20.62.146.1")

    assert isinstance(result, CensysHostResult)
    assert result.enabled is True
    assert len(result.services) == 2
    assert result.autonomous_system is not None
    assert result.autonomous_system["asn"] == 8075
    assert "acme-azure.example" in result.dns_names
    assert result.operating_system == "Windows Server"


async def test_censys__cert_search_returns_certs(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")
    payload = _load("cert_search_tipti.json")

    wrapper = CensysWrapper(cache=cache)
    with patch("cdt.tools.censys_wrapper._run_censys_certs", return_value=payload):
        result = await wrapper.search_certs("tipti.market")

    assert isinstance(result, CensysCertResult)
    assert result.enabled is True
    assert len(result.certs) == 3
    assert result.certs[0]["fingerprint_sha256"] == "a1b2"


async def test_censys__cache_hit_skips_call(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")
    cache.set(
        "censys_host",
        "host::5.6.7.8",
        {
            "ip": "5.6.7.8",
            "enabled": True,
            "services": [{"port": 80}],
            "autonomous_system": None,
            "dns_names": [],
            "operating_system": None,
            "error": None,
        },
    )

    wrapper = CensysWrapper(cache=cache)
    with patch("cdt.tools.censys_wrapper._run_censys_host") as spy:
        result = await wrapper.lookup_host("5.6.7.8")

    assert result.services == [{"port": 80}]
    spy.assert_not_called()


async def test_censys__exception_captured_in_error(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")

    wrapper = CensysWrapper(cache=cache)
    with patch(
        "cdt.tools.censys_wrapper._run_censys_host",
        side_effect=RuntimeError("network down"),
    ):
        result = await wrapper.lookup_host("1.2.3.4")

    assert result.enabled is True
    assert result.error == "network down"
    assert result.services == []


async def test_censys__rate_limit_handled(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 429-shaped error path goes through the quota log branch."""

    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")

    wrapper = CensysWrapper(cache=cache)
    with patch(
        "cdt.tools.censys_wrapper._run_censys_certs",
        side_effect=RuntimeError("HTTP 429 Too Many Requests"),
    ):
        result = await wrapper.search_certs("acme.example")

    assert result.enabled is True
    assert "429" in (result.error or "")


async def test_censys__cert_cache_hit_skips_call(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")
    cache.set(
        "censys_cert",
        "certs::acme.example",
        {
            "domain": "acme.example",
            "enabled": True,
            "certs": [{"fingerprint_sha256": "deadbeef"}],
            "error": None,
        },
    )

    wrapper = CensysWrapper(cache=cache)
    with patch("cdt.tools.censys_wrapper._run_censys_certs") as spy:
        result = await wrapper.search_certs("acme.example")

    assert result.certs and result.certs[0]["fingerprint_sha256"] == "deadbeef"
    spy.assert_not_called()
