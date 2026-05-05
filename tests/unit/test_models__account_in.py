"""Tests for the AccountIn pydantic model (v0.4 §3.2 input row contract)."""

from __future__ import annotations

import pytest
import structlog
from pydantic import ValidationError

from cdt.models import AccountIn


def test_account_in__valid_row_parses() -> None:
    """A well-formed row populates every field via header aliases."""

    account = AccountIn(Title="X", Country="Ecuador", Website="x.com")

    assert account.title == "X"
    assert account.country == "Ecuador"
    assert account.website == "x.com"
    assert account.skip_validation is False


def test_account_in__missing_title_raises() -> None:
    """Title is required; pydantic should raise without it."""

    with pytest.raises(ValidationError):
        AccountIn(Country="Ecuador", Website="x.com")  # type: ignore[call-arg]


def test_account_in__country_outside_scope_warns() -> None:
    """A country outside the LATAM scope is accepted but emits a structlog warning."""

    with structlog.testing.capture_logs() as captured:
        account = AccountIn(Title="Empresa BR", Country="Brasil", Website="empresa.br")

    assert account.country == "Brasil"
    warnings = [
        entry for entry in captured if entry.get("event") == "country_outside_scope"
    ]
    assert len(warnings) == 1
    assert warnings[0]["country"] == "Brasil"
    assert warnings[0]["log_level"] == "warning"
