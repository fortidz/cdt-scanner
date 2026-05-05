"""IO layer — CSV readers/writers + JSONL journal (v0.4 §3, §14.5.2).

Phase 7 scope: file IO only. Producing rows from scan/detect/scoring outputs
is the orchestrator's job (Phase 8+).
"""

from __future__ import annotations

from cdt.io.csv_in import (
    AUTHORIZED_HEADERS,
    OPTIONAL_INPUT_HEADERS,
    REQUIRED_INPUT_HEADERS,
    CsvInputReader,
)
from cdt.io.csv_out import (
    ACCOUNTS_ENRICHED_HEADERS,
    FINDINGS_HEADERS,
    SITES_HEADERS,
    VALIDATION_ISSUES_HEADERS,
    CsvOutputWriter,
)
from cdt.io.journal import NiktoJournal, ScanJournal
from cdt.io.models import AccountInMetadata, Site, TopCandidate, ValidationIssue

__all__ = [
    "ACCOUNTS_ENRICHED_HEADERS",
    "AUTHORIZED_HEADERS",
    "AccountInMetadata",
    "CsvInputReader",
    "CsvOutputWriter",
    "FINDINGS_HEADERS",
    "NiktoJournal",
    "OPTIONAL_INPUT_HEADERS",
    "REQUIRED_INPUT_HEADERS",
    "SITES_HEADERS",
    "ScanJournal",
    "Site",
    "TopCandidate",
    "VALIDATION_ISSUES_HEADERS",
    "ValidationIssue",
]
