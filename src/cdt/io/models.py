"""Pydantic models for IO layer rows.

These types are wire-shape contracts between Phase 6 (scoring) and the
output CSVs. A change here implies a CSV-shape review per v0.4 §3.3 / §3.4.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AccountInMetadata(BaseModel):
    """Carrier for account-level fields not present in ``ScoringResult``.

    The orchestrator (Phase 8) builds this alongside each ``ScoringResult``
    so the writer has Title / Country / Website01..05 / ScannedAt plus the
    primary site's stack signals (``cms_framework``, ``web_server``, ``cdn``)
    which ``ScoringResult`` itself does not carry.
    """

    title: str
    country: str
    website01: str = "-"
    website02: str = "-"
    website03: str = "-"
    website04: str = "-"
    website05: str = "-"
    cms_framework: str | None = None
    web_server: str | None = None
    cdn: str | None = None
    scanned_at: datetime

    model_config = ConfigDict(str_strip_whitespace=True)


class Site(BaseModel):
    """One row of ``sites.csv`` — primary or secondary scanned site (v0.4 §3.4)."""

    title: str
    country: str
    site_url: str
    is_primary: bool = False
    alive: bool = False
    status_code: int = 0
    ip: str = ""
    asn: int | None = None
    asn_org: str = ""
    cloud_provider: str = "-"
    origin_cloud_provider: str = "-"  # behind-edge origin (Fase 9 #1)
    cdn: str = "-"
    waf_detected: bool = False
    waf_vendor: str = "-"
    waf_tool: str = ""
    cms_framework: str = "-"
    web_server: str = "-"
    tls_version: str = "-"
    cert_issuer: str = ""
    cert_expires_at: datetime | None = None
    hsts: bool = False
    csp: str = ""
    xfo: str = ""
    xcto: bool = False
    referrer_policy: str = ""
    permissions_policy: str = ""
    scan_tier: str = "browser"
    scanned_at: datetime

    model_config = ConfigDict(str_strip_whitespace=True)


class TopCandidate(BaseModel):
    url: str
    score: float = 0.0

    model_config = ConfigDict(str_strip_whitespace=True)


class ValidationIssue(BaseModel):
    """One row of ``validation_issues.csv`` (v0.4 §3.6)."""

    title: str
    country: str
    provided_website: str = ""
    issue: str  # IssueCode value (DEAD_DOMAIN, POSSIBLE_MISMATCH, ...)
    suggestion: str = ""
    top_candidates: list[TopCandidate] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)
