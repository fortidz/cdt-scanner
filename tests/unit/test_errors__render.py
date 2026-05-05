"""Tests for CdtError rendering (v0.5 §2.12)."""

from __future__ import annotations

import io
import json

from cdt.errors import (
    CdtError,
    ConfigError,
    ExitCode,
    InputError,
    NetworkError,
    QuotaError,
    UsageError,
)


def test_render_console__uses_e_prefix() -> None:
    err = InputError("missing column 'Country'")
    assert err.code is ExitCode.INPUT
    assert err.render_console() == "cdt error: [E03] missing column 'Country'"


def test_render_json__is_parseable() -> None:
    err = ConfigError("BRAVE_SEARCH_API_KEY is required")
    payload = json.loads(err.render_json())
    assert payload["code"] == "E04"
    assert payload["level"] == "error"
    assert payload["event"] == "config_error"
    assert payload["message"] == "BRAVE_SEARCH_API_KEY is required"
    assert "ts" in payload


def test_emit__writes_to_provided_stream() -> None:
    buf = io.StringIO()
    NetworkError("dns lookup failed").emit(log_format="console", stream=buf)
    assert buf.getvalue().startswith("cdt error: [E05]")


def test_subclass_codes() -> None:
    assert UsageError("x").code is ExitCode.USAGE
    assert QuotaError("x").code is ExitCode.QUOTA
    assert CdtError("x").code is ExitCode.GENERIC
