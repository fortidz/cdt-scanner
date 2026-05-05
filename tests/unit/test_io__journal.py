"""ScanJournal + NiktoJournal tests — append-only, atomic, thread-safe."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from cdt.io import NiktoJournal, ScanJournal
from cdt.tools import NiktoResult


def test_journal__appends_jsonl_line(tmp_path: Path) -> None:
    journal = ScanJournal(tmp_path)
    journal.append({"event": "scan_started", "url": "https://acme.example"})

    body = journal.path.read_text(encoding="utf-8").strip()
    assert json.loads(body) == {
        "event": "scan_started",
        "url": "https://acme.example",
    }


def test_journal__multiple_calls_no_overwrite(tmp_path: Path) -> None:
    journal = ScanJournal(tmp_path)
    journal.append({"event": "a", "n": 1})
    journal.append({"event": "b", "n": 2})
    journal.append({"event": "c", "n": 3})

    lines = journal.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["event"] for p in parsed] == ["a", "b", "c"]


def test_journal__atomic_flush_no_partial_writes(tmp_path: Path) -> None:
    """Each line is independently parseable JSON — no torn lines."""

    journal = ScanJournal(tmp_path)
    for i in range(50):
        journal.append({"event": "tick", "n": i, "payload": "x" * 200})

    lines = journal.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 50
    for line in lines:
        json.loads(line)  # raises if torn


def test_journal__handles_concurrent_writes(tmp_path: Path) -> None:
    """Many threads each append; all messages land, no corrupted lines."""

    journal = ScanJournal(tmp_path)

    def writer(thread_id: int) -> None:
        for i in range(20):
            journal.append({"thread": thread_id, "n": i})

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = journal.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 8 * 20
    parsed = [json.loads(line) for line in lines]
    seen = {(p["thread"], p["n"]) for p in parsed}
    assert len(seen) == 8 * 20  # every (thread, n) pair appeared exactly once


def test_journal__append_event_helper(tmp_path: Path) -> None:
    journal = ScanJournal(tmp_path)
    journal.append_event("scan_finished", url="https://acme.example", duration_ms=1234)

    line = journal.path.read_text(encoding="utf-8").strip()
    record = json.loads(line)
    assert record["event"] == "scan_finished"
    assert record["url"] == "https://acme.example"
    assert "ts" in record


def test_nikto_journal__formats_nikto_result_correctly(tmp_path: Path) -> None:
    journal = NiktoJournal(tmp_path)
    result = NiktoResult(
        url="https://acme.example",
        mode="tier2",
        termination="resolved_all_fields",
        reqs_sent=147,
        elapsed_sec=78.4,
        findings=[],
        resolved_fields=["WAFVendor", "CMSFramework", "WebServer"],
        scanned_at=datetime(2026, 5, 5, 12, 0, 0, tzinfo=UTC),
    )
    journal.append_result(
        result,
        trigger_reason="unresolved_WAFVendor",
        tuning="b,a,5",
    )

    lines = journal.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["url"] == "https://acme.example"
    assert record["tier"] == "tier2"
    assert record["termination"] == "resolved_all_fields"
    assert record["resolved_fields"] == ["WAFVendor", "CMSFramework", "WebServer"]
    assert record["timestamp"] == "2026-05-05T12:00:00Z"


def test_journal__custom_filename(tmp_path: Path) -> None:
    journal = ScanJournal(tmp_path, file_name="custom.jsonl")
    journal.append({"k": "v"})
    assert (tmp_path / "custom.jsonl").exists()
