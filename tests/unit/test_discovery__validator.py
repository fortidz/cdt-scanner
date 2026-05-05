"""Tests for the Validator (DNS + HTTP + parking + title-in-landing)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from cdt.discovery import Validator
from cdt.discovery.models import IssueCode
from cdt.errors import InputError
from cdt.models import AccountIn

FIXTURES = Path(__file__).parent.parent / "fixtures" / "http"


def _read(rel: str) -> str:
    return (FIXTURES / rel).read_text(encoding="utf-8")


@pytest.fixture
def fake_resolver() -> AsyncMock:
    """A dnspython-shaped async resolver. Default: every name resolves."""

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(return_value=[object()])
    return resolver


@pytest.fixture
async def validator(fake_resolver: AsyncMock) -> AsyncIterator[Validator]:
    v = Validator(resolver=fake_resolver)
    try:
        yield v
    finally:
        await v.aclose()


@respx.mock
async def test_validate__dead_domain_no_dns(fake_resolver: AsyncMock) -> None:
    """No A/AAAA records → DEAD_DOMAIN, no HTTP request issued."""

    fake_resolver.resolve = AsyncMock(return_value=[])
    v = Validator(resolver=fake_resolver)
    try:
        account = AccountIn(Title="Acme", Country="Ecuador", Website="dead-acme.example")
        result = await v.validate(account)
    finally:
        await v.aclose()

    assert result.confirmed is False
    assert result.issue == IssueCode.DEAD_DOMAIN


@respx.mock
async def test_validate__parked_domain_detected(validator: Validator) -> None:
    """A 200 response whose body matches a parking signature → PARKED_DOMAIN."""

    body = _read("parking/godaddy_parked.html")
    respx.head("https://example-parked.example/").mock(return_value=httpx.Response(200))
    respx.get("https://example-parked.example/").mock(return_value=httpx.Response(200, text=body))

    account = AccountIn(Title="Acme", Country="Ecuador", Website="example-parked.example")
    result = await validator.validate(account)

    assert result.confirmed is False
    assert result.issue == IssueCode.PARKED_DOMAIN


@respx.mock
async def test_validate__title_in_h1_passes(validator: Validator) -> None:
    """A live page whose ``<h1>`` contains the title → confirmed=True."""

    body = _read("landing/tipti_market_index.html")
    respx.head("https://tipti.market/").mock(return_value=httpx.Response(200))
    respx.get("https://tipti.market/").mock(return_value=httpx.Response(200, text=body))

    account = AccountIn(Title="Tipti", Country="Ecuador", Website="tipti.market")
    result = await validator.validate(account)

    assert result.confirmed is True
    assert result.issue is None
    assert result.canonical_url is not None


@respx.mock
async def test_validate__title_missing_marks_needs_semantic_check(
    validator: Validator,
) -> None:
    """A live, non-parking page that does NOT contain the title → defers
    to BraveSearch via ``needs_semantic_check=True``."""

    body = "<html><head><title>Other</title></head><body><h1>Different</h1></body></html>"
    respx.head("https://acme.example/").mock(return_value=httpx.Response(200))
    respx.get("https://acme.example/").mock(return_value=httpx.Response(200, text=body))

    account = AccountIn(Title="Tipti", Country="Ecuador", Website="acme.example")
    result = await validator.validate(account)

    assert result.confirmed is False
    assert result.issue is None
    assert result.needs_semantic_check is True
    assert result.canonical_url is not None


async def test_validate__invalid_url_raises(validator: Validator) -> None:
    """An unparseable URL → returns INVALID_URL (does not raise to caller)."""

    # AccountIn allows arbitrary website strings; bypass via direct construction.
    account = AccountIn.model_construct(
        title="Acme", country="Ecuador", website="not a url", skip_validation=False
    )
    result = await validator.validate(account)

    assert result.confirmed is False
    assert result.issue == IssueCode.INVALID_URL


def test_validate__invalid_url_normalize_raises_input_error() -> None:
    """``parse_url`` raises ``InputError`` directly for blatantly bad input."""

    from cdt.discovery.normalize import parse_url

    with pytest.raises(InputError):
        parse_url("   ")


def test_is_parking_page__godaddy_signature_matches() -> None:
    """A GoDaddy parking page is recognised by the regex pack."""

    body = _read("parking/godaddy_parked.html")
    assert Validator.is_parking_page(body) is True
    assert Validator.is_parking_page(_read("parking/sedo_parked.html")) is True
    assert Validator.is_parking_page("<h1>Welcome</h1>") is False
