"""Tests for the whatweb subprocess wrapper."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cdt.tools import WhatWebResult, WhatWebWrapper

FIXTURES = Path(__file__).parent.parent / "fixtures" / "whatweb"


def _load(name: str) -> dict:
    """whatweb writes an array; the wrapper consumes the first element."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))[0]


@pytest.fixture
def wrapper() -> WhatWebWrapper:
    return WhatWebWrapper(timeout_sec=2.0)


async def test_whatweb__detects_nginx_server_header(wrapper: WhatWebWrapper) -> None:
    raw = _load("nginx_clean.json")
    with patch("cdt.tools.whatweb_wrapper._run_whatweb", return_value=(0, raw)):
        result = await wrapper.detect("https://acme.example/")

    assert isinstance(result, WhatWebResult)
    assert result.http_server == "nginx/1.24.0"
    assert result.cms is None
    assert result.error is None
    assert result.exit_code == 0


async def test_whatweb__maps_wordpress_to_cms(wrapper: WhatWebWrapper) -> None:
    raw = _load("wordpress_cloudflare.json")
    with patch("cdt.tools.whatweb_wrapper._run_whatweb", return_value=(0, raw)):
        result = await wrapper.detect("https://blog.acme.example/")

    assert result.cms == "WordPress"
    assert "WordPress" in result.plugins
    assert "6.4.2" in result.plugins["WordPress"]


async def test_whatweb__cdn_signals_extracted_for_cloudfront(
    wrapper: WhatWebWrapper,
) -> None:
    raw = {"plugins": {"CloudFront": {"string": ["CloudFront"]},
                       "HTTPServer": {"string": ["AmazonS3"]}}}
    with patch("cdt.tools.whatweb_wrapper._run_whatweb", return_value=(0, raw)):
        result = await wrapper.detect("https://cdn.example/")

    assert "CloudFront" in result.cdn_signals
    assert result.http_server == "AmazonS3"


async def test_whatweb__waf_signals_extracted_for_fortiweb(
    wrapper: WhatWebWrapper,
) -> None:
    raw = {"plugins": {"FortiWeb": {"string": ["FortiWeb/6.4"]},
                       "HTTPServer": {"string": ["FortiWeb"]}}}
    with patch("cdt.tools.whatweb_wrapper._run_whatweb", return_value=(0, raw)):
        result = await wrapper.detect("https://protected.example/")

    assert "FortiWeb" in result.waf_signals


async def test_whatweb__aggression_level_passed_to_subprocess(
    wrapper: WhatWebWrapper,
) -> None:
    """The per-call aggression overrides the wrapper-level default."""

    captured: dict[str, int] = {}

    def spy(url: str, level: int, ua: str):
        captured["level"] = level
        return 0, {}

    with patch("cdt.tools.whatweb_wrapper._run_whatweb", side_effect=spy):
        await wrapper.detect("https://acme.example/", aggression=4)

    assert captured["level"] == 4


async def test_whatweb__custom_user_agent_applied() -> None:
    captured: dict[str, str] = {}

    def spy(url: str, level: int, ua: str):
        captured["ua"] = ua
        return 0, {}

    wrapper = WhatWebWrapper(user_agent="custom-ua/9.9")
    with patch("cdt.tools.whatweb_wrapper._run_whatweb", side_effect=spy):
        await wrapper.detect("https://acme.example/")

    assert captured["ua"] == "custom-ua/9.9"


async def test_whatweb__subprocess_failure_captured_in_error_field(
    wrapper: WhatWebWrapper,
) -> None:
    """Non-zero exit with empty JSON output → result.error set, no plugins."""

    with patch("cdt.tools.whatweb_wrapper._run_whatweb", return_value=(2, {})):
        result = await wrapper.detect("https://acme.example/")

    assert result.exit_code == 2
    assert result.error is not None
    assert "exit 2" in result.error


async def test_whatweb__timeout_returns_error() -> None:
    """A blocked subprocess past ``timeout_sec`` becomes ``error='timeout'``."""

    wrapper = WhatWebWrapper(timeout_sec=0.05)

    def slow(*_args, **_kwargs):
        import time

        time.sleep(0.5)
        return 0, {}

    with patch("cdt.tools.whatweb_wrapper._run_whatweb", side_effect=slow):
        result = await wrapper.detect("https://acme.example/")

    assert result.error == "timeout"
    assert result.exit_code is None


async def test_whatweb__empty_plugins_dict_returns_empty_result(
    wrapper: WhatWebWrapper,
) -> None:
    """A whatweb run that finds nothing exits 0 with empty plugins."""

    with patch("cdt.tools.whatweb_wrapper._run_whatweb", return_value=(0, {})):
        result = await wrapper.detect("https://blank.example/")

    assert result.error is None
    assert result.exit_code == 0
    assert result.plugins == {}
    assert result.http_server is None


async def test_whatweb__plugin_without_string_keeps_name(
    wrapper: WhatWebWrapper,
) -> None:
    """Plugins that match but expose no detail still appear in ``plugins``."""

    raw = {"plugins": {"OpenGraph": {}}}
    with patch("cdt.tools.whatweb_wrapper._run_whatweb", return_value=(0, raw)):
        result = await wrapper.detect("https://acme.example/")

    assert "OpenGraph" in result.plugins
    assert result.plugins["OpenGraph"] == ["OpenGraph"]
