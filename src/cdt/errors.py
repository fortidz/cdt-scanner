"""Exit codes and error hierarchy for cdt — see spec v0.5 §2.11–§2.12.

Each ``Enn`` code corresponds 1:1 to a numeric exit status. The mapping is part of the
public CLI contract; breaking changes here require a minor version bump.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from enum import IntEnum
from typing import TextIO


class ExitCode(IntEnum):
    """Numeric exit codes the CLI can return. Mirrors v0.5 §2.11."""

    OK = 0
    GENERIC = 1
    USAGE = 2
    INPUT = 3
    CONFIG = 4
    NETWORK = 5
    QUOTA = 6
    INTERRUPTED = 7


_CODE_PREFIX: dict[ExitCode, str] = {
    ExitCode.OK: "E00",
    ExitCode.GENERIC: "E01",
    ExitCode.USAGE: "E02",
    ExitCode.INPUT: "E03",
    ExitCode.CONFIG: "E04",
    ExitCode.NETWORK: "E05",
    ExitCode.QUOTA: "E06",
    ExitCode.INTERRUPTED: "E07",
}


_EVENT_NAME: dict[ExitCode, str] = {
    ExitCode.OK: "ok",
    ExitCode.GENERIC: "generic_error",
    ExitCode.USAGE: "usage_error",
    ExitCode.INPUT: "input_validation_failed",
    ExitCode.CONFIG: "config_error",
    ExitCode.NETWORK: "network_error",
    ExitCode.QUOTA: "quota_exhausted",
    ExitCode.INTERRUPTED: "interrupted",
}


class CdtError(Exception):
    """Base error class. Carries an ``ExitCode`` and renders to stderr."""

    code: ExitCode = ExitCode.GENERIC

    def __init__(self, message: str, code: ExitCode | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    @property
    def code_label(self) -> str:
        return _CODE_PREFIX[self.code]

    def render_console(self) -> str:
        return f"cdt error: [{self.code_label}] {self.message}"

    def render_json(self) -> str:
        payload = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": "error",
            "code": self.code_label,
            "event": _EVENT_NAME[self.code],
            "message": self.message,
        }
        return json.dumps(payload, ensure_ascii=False)

    def emit(self, log_format: str = "console", stream: TextIO | None = None) -> None:
        out = stream if stream is not None else sys.stderr
        rendered = self.render_json() if log_format == "json" else self.render_console()
        print(rendered, file=out)


class UsageError(CdtError):
    code = ExitCode.USAGE


class InputError(CdtError):
    code = ExitCode.INPUT


class ConfigError(CdtError):
    code = ExitCode.CONFIG


class NetworkError(CdtError):
    code = ExitCode.NETWORK


class QuotaError(CdtError):
    code = ExitCode.QUOTA


class InterruptedError(CdtError):
    code = ExitCode.INTERRUPTED
