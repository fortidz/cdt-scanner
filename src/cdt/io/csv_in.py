"""CSV input reader for ``accounts_in.csv`` and ``authorized.csv``.

UTF-8-with-or-without-BOM is accepted on input (``utf-8-sig`` strips the
BOM when present). Headers must include ``Title``, ``Country``, and
``Website``; ``SkipValidation`` is optional.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import structlog
from pydantic import ValidationError

from cdt.errors import InputError
from cdt.models import AccountIn

log = structlog.get_logger()

REQUIRED_INPUT_HEADERS: tuple[str, ...] = ("Title", "Country", "Website")
OPTIONAL_INPUT_HEADERS: tuple[str, ...] = ("SkipValidation",)
AUTHORIZED_HEADERS: tuple[str, ...] = ("Title", "Country")


class CsvInputReader:
    def __init__(self, path: Path) -> None:
        self._path = path

    def read_accounts(self) -> list[AccountIn]:
        """Bulk read. Returns the full list; raises ``InputError`` on bad shape."""

        return list(self._iter_accounts())

    @contextmanager
    def stream_accounts(self) -> Iterator[Iterator[AccountIn]]:
        """Stream-yield rows. Use as ``with reader.stream_accounts() as it: ...``."""

        f = self._path.open(encoding="utf-8-sig", newline="")
        try:
            yield self._iter_from_handle(f)
        finally:
            f.close()

    def _iter_accounts(self) -> Iterator[AccountIn]:
        with self._path.open(encoding="utf-8-sig", newline="") as f:
            yield from self._iter_from_handle(f)

    def _iter_from_handle(self, f) -> Iterator[AccountIn]:  # type: ignore[no-untyped-def]
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise InputError(
                f"CSV header missing in {self._path}: file appears empty"
            )
        missing = [
            h for h in REQUIRED_INPUT_HEADERS if h not in reader.fieldnames
        ]
        if missing:
            raise InputError(
                f"CSV header missing required columns {missing} in {self._path}"
            )

        for row_idx, row in enumerate(reader, start=2):  # row 1 = header
            payload: dict[str, object] = {
                "Title": (row.get("Title") or "").strip(),
                "Country": (row.get("Country") or "").strip(),
                "Website": (row.get("Website") or "").strip(),
            }
            skip_raw = (row.get("SkipValidation") or "").strip()
            if skip_raw:
                payload["SkipValidation"] = _parse_bool(skip_raw)
            try:
                yield AccountIn.model_validate(payload)
            except ValidationError as exc:
                raise InputError(
                    f"Invalid row {row_idx} in {self._path}: {exc}"
                ) from exc

    def read_authorized(self) -> set[tuple[str, str]]:
        """Return ``{(title, country), ...}`` from ``authorized.csv``."""

        if not self._path.exists():
            raise InputError(f"Authorized CSV not found: {self._path}")

        out: set[tuple[str, str]] = set()
        with self._path.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise InputError(
                    f"Authorized CSV header missing in {self._path}"
                )
            missing = [h for h in AUTHORIZED_HEADERS if h not in reader.fieldnames]
            if missing:
                raise InputError(
                    f"Authorized CSV missing columns {missing} in {self._path}"
                )
            for row in reader:
                title = (row.get("Title") or "").strip()
                country = (row.get("Country") or "").strip()
                if title and country:
                    out.add((title, country))
        log.info("authorized_loaded", path=str(self._path), count=len(out))
        return out


def _parse_bool(raw: str) -> bool:
    """Accept ``"1"``, ``"true"``, ``"yes"`` (case-insensitive) as True."""

    return raw.lower() in {"1", "true", "yes", "y"}
