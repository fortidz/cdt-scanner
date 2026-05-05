"""Lock the exit-code <-> name mapping so it cannot drift silently (v0.5 §2.11)."""

from __future__ import annotations

from cdt.errors import ExitCode

EXPECTED_CODES = {
    "OK": 0,
    "GENERIC": 1,
    "USAGE": 2,
    "INPUT": 3,
    "CONFIG": 4,
    "NETWORK": 5,
    "QUOTA": 6,
    "INTERRUPTED": 7,
}


def test_exit_codes__match_spec() -> None:
    actual = {member.name: member.value for member in ExitCode}
    assert actual == EXPECTED_CODES
