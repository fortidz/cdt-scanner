"""Pydantic models + enums for risk / opportunity / rationale.

These types are the wire-shape contract between Phase 6 (this package) and
Phase 7 (CSV writer). A change here implies a column-shape review per
v0.4 §3.3.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from cdt.detect.models import (
    CdnDetection,
    CloudDetection,
    StackDetection,
    WafDetection,
)
from cdt.scan.models import TLSInfo


class FindingCode(StrEnum):
    """Stable strings emitted to ``findings.csv`` (v0.4 §3.5)."""

    MISSING_WAF = "MISSING_WAF"
    EXPIRED_CERT = "EXPIRED_CERT"
    WEAK_TLS = "WEAK_TLS"
    MISSING_HSTS = "MISSING_HSTS"
    MISSING_CSP = "MISSING_CSP"
    MISSING_XFO = "MISSING_XFO"
    EXPOSED_ADMIN = "EXPOSED_ADMIN"
    OUTDATED_CMS = "OUTDATED_CMS"
    CVE_KNOWN_VERSION = "CVE_KNOWN_VERSION"
    FORTIAPPSEC_FIT = "FORTIAPPSEC_FIT"
    SECONDARY_SITE_EXPOSED = "SECONDARY_SITE_EXPOSED"
    NIKTO_SKIPPED_SENSITIVE_DOMAIN = "NIKTO_SKIPPED_SENSITIVE_DOMAIN"
    LOW_CONFIDENCE_WAF = "LOW_CONFIDENCE_WAF"
    LOW_CONFIDENCE_CMS = "LOW_CONFIDENCE_CMS"


class Severity(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Finding(BaseModel):
    title: str
    country: str
    site_url: str
    finding_code: FindingCode
    severity: Severity
    message: str
    evidence: str = ""

    model_config = ConfigDict(str_strip_whitespace=True)


class RiskBand(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskBreakdownItem(BaseModel):
    rubric_item: str
    points: int
    reason: str = ""

    model_config = ConfigDict(str_strip_whitespace=True)


class RiskScore(BaseModel):
    score: int
    band: RiskBand
    breakdown: list[RiskBreakdownItem] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)

    @property
    def display(self) -> str:
        """CSV-format string per v0.4 §6: ``"BAND (N/15)"``."""

        return f"{self.band.value} ({self.score}/15)"


class OpportunityFlags(BaseModel):
    """Three Fortinet recommendations.

    Tri-state per field:
      - ``True``  → recommend  ("Yes" in CSV)
      - ``False`` → don't      ("No" in CSV)
      - ``None``  → insufficient data ("-" in CSV)

    ``None`` is reserved for the **passive tier** (Fase 9 #2): a passive
    scan never runs ``wafw00f`` / browser fetch / stack detection, so the
    decision tree has no signal to evaluate. Emitting "Yes"/"No" anyway
    would print confidently wrong recommendations (smoke run 25415496527
    misclassified Cloudflare-fronted BCP/Falabella as "RecommendsFortiWeb=Yes"
    because the WAF column was empty).
    """

    appsec: bool | None = False
    web: bool | None = False
    cnapp: bool | None = False

    model_config = ConfigDict(str_strip_whitespace=True)


class ScoringInput(BaseModel):
    """Everything needed to score one site, IO-free.

    The orchestrator (Phase 7+) constructs this from detection outputs +
    browser data + per-account cross-site aggregation.
    """

    url: str
    title: str
    country: str
    tier: str  # "passive" | "browser" | "dast"
    is_alive: bool = True

    waf: WafDetection
    cdn: CdnDetection
    cloud: CloudDetection
    stack: StackDetection

    headers: dict[str, str] = Field(default_factory=dict)  # lower-case keys
    tls: TLSInfo | None = None

    secondary_sites_protected: list[bool] = Field(default_factory=list)

    server_header_cve_known: bool = False
    admin_panel_exposed: bool = False
    cms_outdated_with_cve: bool = False

    has_aws: bool = False
    has_azure: bool = False
    has_gcp: bool = False
    has_oci: bool = False

    model_config = ConfigDict(str_strip_whitespace=True, arbitrary_types_allowed=True)


class ScoringResult(BaseModel):
    risk: RiskScore
    opportunity: OpportunityFlags
    rationale: str
    findings: list[Finding] = Field(default_factory=list)

    waf_decision: str  # "Yes" | "No" | "Further investigation needed"
    waf_vendor: str  # vendor or "-"
    waf_tool: str  # human-readable tool description
    public_cloud: str  # "Yes" | "No" | "Further investigation needed"
    complexity: str  # "One CSP" | ... | "-"
    primary_hyperscaler: str  # "AWS" | "Azure" | "GCP" | "OCI" | "-"
    has_aws: bool
    has_azure: bool
    has_gcp: bool
    has_oci: bool

    model_config = ConfigDict(str_strip_whitespace=True)
