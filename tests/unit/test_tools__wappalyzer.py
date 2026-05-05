"""Tests for the Wappalyzer wrapper."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cdt.tools import WappalyzerResult, WappalyzerWrapper

FIXTURES = Path(__file__).parent.parent / "fixtures" / "wappalyzer"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def wrapper() -> WappalyzerWrapper:
    return WappalyzerWrapper(timeout_sec=2.0)


async def test_wappalyzer__detects_wordpress_and_nginx(
    wrapper: WappalyzerWrapper,
) -> None:
    techs = _load("wordpress_nginx.json")
    with patch("cdt.tools.wappalyzer_wrapper._run_wappalyzer", return_value=techs):
        result = await wrapper.detect("https://blog.acme.example/")

    assert isinstance(result, WappalyzerResult)
    assert result.cms == "WordPress"
    assert result.web_server == "nginx"
    assert result.error is None


async def test_wappalyzer__cdn_extracted_when_cloudflare(
    wrapper: WappalyzerWrapper,
) -> None:
    techs = {"cdn": ["Cloudflare"], "web-servers": ["cloudflare"]}
    with patch("cdt.tools.wappalyzer_wrapper._run_wappalyzer", return_value=techs):
        result = await wrapper.detect("https://protected.example/")

    assert result.cdn == "Cloudflare"
    assert result.web_server == "cloudflare"


async def test_wappalyzer__frameworks_aggregated(wrapper: WappalyzerWrapper) -> None:
    """``frameworks`` aggregates JS frameworks + miscellaneous, deduped."""

    techs = _load("wordpress_nginx.json")
    with patch("cdt.tools.wappalyzer_wrapper._run_wappalyzer", return_value=techs):
        result = await wrapper.detect("https://blog.acme.example/")

    assert "jQuery" in result.frameworks
    assert "React" in result.frameworks
    assert "Open Graph" in result.frameworks


async def test_wappalyzer__user_agent_passed() -> None:
    captured: dict[str, str] = {}

    def spy(url: str, ua: str):
        captured["ua"] = ua
        return {}

    wrapper = WappalyzerWrapper(user_agent="custom-ua/9.9")
    with patch("cdt.tools.wappalyzer_wrapper._run_wappalyzer", side_effect=spy):
        await wrapper.detect("https://acme.example/")

    assert captured["ua"] == "custom-ua/9.9"


async def test_wappalyzer__library_exception_captured(
    wrapper: WappalyzerWrapper,
) -> None:
    with patch(
        "cdt.tools.wappalyzer_wrapper._run_wappalyzer",
        side_effect=RuntimeError("rules pack corrupted"),
    ):
        result = await wrapper.detect("https://acme.example/")

    assert result.error == "rules pack corrupted"
    assert result.technologies == {}


async def test_wappalyzer__timeout_returns_error() -> None:
    wrapper = WappalyzerWrapper(timeout_sec=0.05)

    def slow(*_args, **_kwargs):
        import time

        time.sleep(0.5)
        return {}

    with patch("cdt.tools.wappalyzer_wrapper._run_wappalyzer", side_effect=slow):
        result = await wrapper.detect("https://acme.example/")

    assert result.error == "timeout"


async def test_wappalyzer__empty_categories_returns_none_fields(
    wrapper: WappalyzerWrapper,
) -> None:
    """No matching category → cms/web_server/cdn all None, frameworks empty."""

    with patch("cdt.tools.wappalyzer_wrapper._run_wappalyzer", return_value={}):
        result = await wrapper.detect("https://blank.example/")

    assert result.cms is None
    assert result.web_server is None
    assert result.cdn is None
    assert result.frameworks == []
