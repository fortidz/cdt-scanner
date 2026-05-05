"""Append-only JSONL journals.

Used by the orchestrator (Phase 8) for ``scan_audit.jsonl`` and re-used by
``tools/nikto_wrapper`` for ``nikto_runs.jsonl``. POSIX append + flush+fsync
gives single-line atomicity that is sufficient for our use-case (each line
is independently parseable; a partially-written line at EOF is the only
recovery scenario, and ``json.loads`` on each line skips bad entries).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from cdt.tools.nikto_wrapper import NiktoResult

log = structlog.get_logger()

_DEFAULT_AUDIT_FILE = "scan_audit.jsonl"
_DEFAULT_NIKTO_FILE = "nikto_runs.jsonl"


class ScanJournal:
    """Generic JSONL journal. Thread-safe via a per-instance lock."""

    def __init__(self, out_dir: Path, file_name: str = _DEFAULT_AUDIT_FILE) -> None:
        self._path = Path(out_dir) / file_name
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())

    def append_event(self, event: str, **fields: Any) -> None:
        """Convenience: build a record with ``ts`` + ``event`` + extras."""

        record = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": event,
            **fields,
        }
        self.append(record)


class NiktoJournal(ScanJournal):
    """Specialisation for ``nikto_runs.jsonl`` (v0.4 §14.5.2 schema)."""

    def __init__(self, out_dir: Path) -> None:
        super().__init__(out_dir, file_name=_DEFAULT_NIKTO_FILE)

    def append_result(self, result: NiktoResult, *, trigger_reason: str = "",
                      tuning: str = "") -> None:
        record = {
            "timestamp": result.scanned_at.astimezone(UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "url": result.url,
            "tier": result.mode,
            "trigger_reason": trigger_reason,
            "tuning": tuning,
            "reqs_sent": result.reqs_sent,
            "elapsed_sec": round(result.elapsed_sec, 2),
            "termination": result.termination,
            "resolved_fields": list(result.resolved_fields),
        }
        self.append(record)
        log.info(
            "nikto_journal_appended",
            url=result.url,
            termination=result.termination,
        )
