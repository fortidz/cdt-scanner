"""CsvInputReader tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cdt.errors import InputError
from cdt.io import CsvInputReader


def _write(tmp_path: Path, name: str, body: str, *, prepend_bom: bool = False) -> Path:
    path = tmp_path / name
    if prepend_bom:
        # ﻿ is the BOM character; encoded as utf-8 it's the 3 bytes 0xEF 0xBB 0xBF.
        body = "﻿" + body
    path.write_text(body, encoding="utf-8")
    return path


def test_read_accounts__valid_csv_returns_list_of_account_in(tmp_path: Path) -> None:
    body = (
        "Title,Country,Website\n"
        "Acme,Ecuador,acme.example\n"
        "Beta,Perú,beta.example.pe\n"
    )
    reader = CsvInputReader(_write(tmp_path, "in.csv", body))
    accounts = reader.read_accounts()
    assert len(accounts) == 2
    assert accounts[0].title == "Acme"
    assert accounts[1].country == "Perú"


def test_read_accounts__missing_required_columns_raises(tmp_path: Path) -> None:
    body = "Title,Country\nAcme,Ecuador\n"
    reader = CsvInputReader(_write(tmp_path, "in.csv", body))
    with pytest.raises(InputError, match="Website"):
        reader.read_accounts()


def test_read_accounts__skip_validation_column_optional(tmp_path: Path) -> None:
    body = (
        "Title,Country,Website,SkipValidation\n"
        "Acme,Ecuador,acme.example,1\n"
        "Beta,Perú,beta.example.pe,\n"
    )
    reader = CsvInputReader(_write(tmp_path, "in.csv", body))
    accounts = reader.read_accounts()
    assert accounts[0].skip_validation is True
    assert accounts[1].skip_validation is False


def test_read_accounts__handles_utf8_with_bom_strip(tmp_path: Path) -> None:
    """A BOM at the start of the file must not poison the first header name."""

    body = "Title,Country,Website\nAcme,Ecuador,acme.example\n"
    path = _write(tmp_path, "in.csv", body, prepend_bom=True)
    reader = CsvInputReader(path)
    accounts = reader.read_accounts()
    assert accounts[0].title == "Acme"


def test_read_accounts__empty_file_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "empty.csv", "")
    reader = CsvInputReader(path)
    with pytest.raises(InputError, match="empty"):
        reader.read_accounts()


def test_read_authorized__returns_set_of_tuples(tmp_path: Path) -> None:
    body = "Title,Country\nAcme,Ecuador\nBeta,Perú\n"
    reader = CsvInputReader(_write(tmp_path, "auth.csv", body))
    auth = reader.read_authorized()
    assert ("Acme", "Ecuador") in auth
    assert ("Beta", "Perú") in auth
    assert len(auth) == 2


def test_read_authorized__missing_file_raises(tmp_path: Path) -> None:
    reader = CsvInputReader(tmp_path / "nope.csv")
    with pytest.raises(InputError, match="not found"):
        reader.read_authorized()


def test_stream_accounts__yields_one_at_a_time(tmp_path: Path) -> None:
    body = (
        "Title,Country,Website\n"
        "Acme,Ecuador,acme.example\n"
        "Beta,Perú,beta.example.pe\n"
    )
    reader = CsvInputReader(_write(tmp_path, "in.csv", body))
    seen = []
    with reader.stream_accounts() as it:
        for account in it:
            seen.append(account.title)
    assert seen == ["Acme", "Beta"]
