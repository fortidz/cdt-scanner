"""Tests for the wafw00f library wrapper."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from cdt.tools import WafDetection, WafW00fWrapper


@pytest.fixture
def wrapper() -> WafW00fWrapper:
    return WafW00fWrapper(timeout_sec=2.0)


async def test_detect__single_vendor_hit(wrapper: WafW00fWrapper) -> None:
    """One plugin hit → that vendor wins, generic stays False."""

    with patch(
        "cdt.tools.wafw00f_wrapper._run_wafw00f", return_value=(["Cloudflare"], False)
    ):
        result = await wrapper.detect("https://acme.example")

    assert isinstance(result, WafDetection)
    assert result.vendor == "Cloudflare"
    assert result.generic is False
    assert result.raw_hits == ["Cloudflare"]


async def test_detect__generic_match_no_vendor(wrapper: WafW00fWrapper) -> None:
    """No specific plugin but ``genericdetect`` succeeds → generic=True."""

    with patch(
        "cdt.tools.wafw00f_wrapper._run_wafw00f", return_value=([], True)
    ):
        result = await wrapper.detect("https://acme.example")

    assert result.vendor is None
    assert result.generic is True
    assert result.raw_hits == []


async def test_detect__no_match_returns_none(wrapper: WafW00fWrapper) -> None:
    with patch(
        "cdt.tools.wafw00f_wrapper._run_wafw00f", return_value=([], False)
    ):
        result = await wrapper.detect("https://acme.example")

    assert result.vendor is None
    assert result.generic is False
    assert result.raw_hits == []


async def test_detect__multiple_hits_priority_cloudflare_wins(
    wrapper: WafW00fWrapper,
) -> None:
    """Among multiple plugin hits, the priority list picks Cloudflare first."""

    with patch(
        "cdt.tools.wafw00f_wrapper._run_wafw00f",
        return_value=(["Imperva", "Cloudflare", "Akamai"], False),
    ):
        result = await wrapper.detect("https://acme.example")

    assert result.vendor == "Cloudflare"
    assert sorted(result.raw_hits) == ["Akamai", "Cloudflare", "Imperva"]


async def test_detect__exception_returns_empty_detection(
    wrapper: WafW00fWrapper,
) -> None:
    """A crash in the wafw00f library is captured, not propagated."""

    with patch(
        "cdt.tools.wafw00f_wrapper._run_wafw00f",
        side_effect=RuntimeError("boom"),
    ):
        result = await wrapper.detect("https://acme.example")

    assert result.vendor is None
    assert result.generic is False


async def test_detect__timeout_returns_empty_detection() -> None:
    """A wafw00f probe that exceeds ``timeout_sec`` returns an empty detection."""

    wrapper = WafW00fWrapper(timeout_sec=0.05)

    def slow(*_args, **_kwargs):
        import time

        time.sleep(0.5)
        return ([], False)

    with patch("cdt.tools.wafw00f_wrapper._run_wafw00f", side_effect=slow):
        result = await wrapper.detect("https://acme.example")

    assert result.vendor is None
    assert result.raw_hits == []


def test_pick_vendor__alphabetical_fallback_when_no_priority_match() -> None:
    """Multiple non-priority hits fall through to alphabetical first."""

    from cdt.tools.wafw00f_wrapper import _pick_vendor

    assert _pick_vendor(["Wallarm", "Reblaze", "Sucuri"]) == "Reblaze"


def test_run_wafw00f__plugin_hits_and_no_generic() -> None:
    """``_run_wafw00f`` returns ``(hits, generic)`` from the WAFW00F lib."""

    from unittest.mock import MagicMock

    fake = MagicMock()
    fake.normalRequest.return_value = None
    fake.identwaf.return_value = ["Cloudflare"]
    fake.genericdetect.return_value = False

    with patch("wafw00f.main.WAFW00F", return_value=fake):
        from cdt.tools.wafw00f_wrapper import _run_wafw00f

        hits, generic = _run_wafw00f("https://acme.example", "ua/1.0")

    assert hits == ["Cloudflare"]
    assert generic is False


def test_run_wafw00f__generic_match_only() -> None:
    from unittest.mock import MagicMock

    fake = MagicMock()
    fake.normalRequest.return_value = None
    fake.identwaf.return_value = []
    fake.genericdetect.return_value = True

    with patch("wafw00f.main.WAFW00F", return_value=fake):
        from cdt.tools.wafw00f_wrapper import _run_wafw00f

        hits, generic = _run_wafw00f("https://acme.example", "ua/1.0")

    assert hits == []
    assert generic is True


def test_run_wafw00f__normal_request_failure_short_circuits() -> None:
    from unittest.mock import MagicMock

    fake = MagicMock()
    fake.normalRequest.side_effect = RuntimeError("net down")

    with patch("wafw00f.main.WAFW00F", return_value=fake):
        from cdt.tools.wafw00f_wrapper import _run_wafw00f

        hits, generic = _run_wafw00f("https://acme.example", "ua/1.0")

    assert hits == []
    assert generic is False
    fake.identwaf.assert_not_called()


def test_run_wafw00f__identwaf_exception_falls_back_to_generic() -> None:
    from unittest.mock import MagicMock

    fake = MagicMock()
    fake.normalRequest.return_value = None
    fake.identwaf.side_effect = RuntimeError("plugin crash")
    fake.genericdetect.return_value = True

    with patch("wafw00f.main.WAFW00F", return_value=fake):
        from cdt.tools.wafw00f_wrapper import _run_wafw00f

        hits, generic = _run_wafw00f("https://acme.example", "ua/1.0")

    assert hits == []
    assert generic is True


def test_run_wafw00f__generic_detect_exception_returns_false() -> None:
    from unittest.mock import MagicMock

    fake = MagicMock()
    fake.normalRequest.return_value = None
    fake.identwaf.return_value = []
    fake.genericdetect.side_effect = RuntimeError("boom")

    with patch("wafw00f.main.WAFW00F", return_value=fake):
        from cdt.tools.wafw00f_wrapper import _run_wafw00f

        hits, generic = _run_wafw00f("https://acme.example", "ua/1.0")

    assert hits == []
    assert generic is False
