"""Tests for the structlog configuration helper (v0.5 §2.13)."""

from __future__ import annotations

import structlog

from cdt.context import configure_logging


def test_configure_logging__console_format_does_not_raise() -> None:
    configure_logging(log_level="info", log_format="console")
    structlog.get_logger().info("smoke_event", value=1)


def test_configure_logging__json_format_does_not_raise() -> None:
    configure_logging(log_level="debug", log_format="json")
    structlog.get_logger().debug("smoke_event", value=2)


def test_configure_logging__honours_ci_env(monkeypatch: object) -> None:
    import os

    os.environ["CI"] = "true"
    try:
        configure_logging(log_level="info", log_format="console")
        structlog.get_logger().warning("smoke_event_ci")
    finally:
        os.environ.pop("CI", None)
