"""Pydantic v2 models for CSV input/output contracts.

Only the bare minimum needed for Phase 1 scaffold lives here. Phase 7 (output and
journal) fleshes out ``AccountEnriched`` and the rest of the CSV row models.
"""

from __future__ import annotations

from enum import StrEnum

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Country(StrEnum):
    """Documented LATAM scope (v0.4 §12.13). Inputs outside the set are accepted with a warning."""

    PE = "Perú"
    EC = "Ecuador"
    CL = "Chile"
    BO = "Bolivia"
    PY = "Paraguay"
    UY = "Uruguay"
    VE = "Venezuela"


_SCOPE_VALUES: frozenset[str] = frozenset(c.value for c in Country)


class TierLevel(StrEnum):
    PASSIVE = "passive"
    BROWSER = "browser"
    DAST = "dast"


class AccountIn(BaseModel):
    """One row of ``accounts_in.csv``. Field aliases match the CSV header names."""

    title: str = Field(..., min_length=1, alias="Title")
    country: str = Field(..., min_length=1, alias="Country")
    website: str = Field(default="", alias="Website")
    skip_validation: bool = Field(default=False, alias="SkipValidation")

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)

    @field_validator("country")
    @classmethod
    def warn_if_outside_scope(cls, v: str) -> str:
        if v not in _SCOPE_VALUES:
            structlog.get_logger().warning("country_outside_scope", country=v)
        return v


class AccountEnriched(BaseModel):
    """Placeholder for the enriched row. Phase 7 fills out every column per v0.4 §3.3."""

    title: str = Field(..., alias="Title")
    country: str = Field(..., alias="Country")

    model_config = ConfigDict(populate_by_name=True, extra="allow")
