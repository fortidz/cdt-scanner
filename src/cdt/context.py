"""Logging configuration. Call ``configure_logging`` once at the start of every CLI command.

Two renderers are supported:
  * ``console`` — Rich/ANSI when the terminal is a TTY.
  * ``json``    — one structured JSON line per event (machine-readable, for CI).

``CI=true`` in the environment forces ``json`` regardless of the requested format,
per spec v0.5 §2.9.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog


def configure_logging(log_level: str = "info", log_format: str = "console") -> None:
    """Initialise stdlib logging + structlog with the requested level/format."""

    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level)

    if os.environ.get("CI") == "true":
        log_format = "json"

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
