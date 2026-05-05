"""Pydantic v2 models for the discovery subpackage (v0.4 §4)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IssueCode(StrEnum):
    """Issue codes emitted to ``validation_issues.csv`` (v0.4 §3.6)."""

    DEAD_DOMAIN = "DEAD_DOMAIN"
    POSSIBLE_MISMATCH = "POSSIBLE_MISMATCH"
    PARKED_DOMAIN = "PARKED_DOMAIN"
    INVALID_URL = "INVALID_URL"
    NO_RESULTS = "NO_RESULTS"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"


class SearchResult(BaseModel):
    """One result from a search provider (Brave today, others later)."""

    url: str
    title: str = ""
    snippet: str = ""
    score: float = 0.0

    model_config = ConfigDict(str_strip_whitespace=True)


class ValidationResult(BaseModel):
    """Outcome of Validate or Discover modes for a single account.

    ``confirmed`` is the operational signal; everything else is for
    ``validation_issues.csv`` and downstream telemetry.
    """

    confirmed: bool
    canonical_url: str | None = None
    issue: IssueCode | None = None
    suggestion: str | None = None
    top_candidates: list[SearchResult] = Field(default_factory=list)
    needs_semantic_check: bool = False

    model_config = ConfigDict(str_strip_whitespace=True)


class DiscoveryResult(BaseModel):
    """Alias for ValidationResult-shaped output of Discover mode.

    Kept as a separate symbol because the public API in ``__init__`` needs to
    distinguish Discover from Validate even though the wire shape is identical
    today. If the contracts diverge later, this is where the split lives.
    """

    confirmed: bool
    canonical_url: str | None = None
    issue: IssueCode | None = None
    top_candidates: list[SearchResult] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class ExpansionResult(BaseModel):
    """Output of ``Expander.expand`` — websites discovered via crt.sh (v0.4 §4.3)."""

    apex: str
    websites: list[str] = Field(default_factory=list)
    total_subdomains_seen: int = 0

    model_config = ConfigDict(str_strip_whitespace=True)
