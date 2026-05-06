"""Public models exposed by the detection engine.

These types are wire-shape contracts between Phase 5 (detect) and Phase 6
(orchestrator/CSV writer). Mutating any field here implies a CSV-shape
review per v0.4 §3.3.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SignalMatch(BaseModel):
    """One predicate that fired. Carried for telemetry + auditing."""

    rule_kind: str  # primary | secondary | block_page | rdns | asn | cname | banner | ip_range
    points: int
    source: str  # vendor name or hypothesis label
    evidence: str  # short, redact-safe string identifying what matched

    model_config = ConfigDict(str_strip_whitespace=True)


class Hypothesis(BaseModel):
    """Internal accumulator state per candidate vendor/provider."""

    name: str
    points: int = 0
    signals_matched: list[SignalMatch] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class WafDetection(BaseModel):
    vendor: str | None = None
    confidence: Confidence = Confidence.LOW
    signals_matched: list[SignalMatch] = Field(default_factory=list)
    waf_active: bool = False
    cdn_capable: bool = False
    runner_up: str | None = None
    gap: int = 0

    model_config = ConfigDict(str_strip_whitespace=True)


class CdnDetection(BaseModel):
    vendor: str | None = None
    confidence: Confidence = Confidence.LOW
    signals_matched: list[SignalMatch] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class CloudDetection(BaseModel):
    provider: str | None = None
    confidence: Confidence = Confidence.LOW
    source: str = "unknown"  # ip_range | rdns | cname | asn | banner | datacenter | unknown
    signals_matched: list[SignalMatch] = Field(default_factory=list)
    # Origin behind edge — populated by ``OriginAttributor`` (Fase 9 #1)
    # when ``role == "edge_only"`` (Cloudflare/Fastly/Akamai/etc.) and a
    # subdomain probe or CNAME chain reveals an underlying hyperscaler.
    origin: str | None = None
    origin_confidence: Confidence = Confidence.LOW
    origin_source: str | None = None  # subdomain_probe | cname_chain | exhausted | not_edge
    role: str = "hyperscaler"  # hyperscaler | edge_only | datacenter
    asn_org: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)

    def effective_provider(self) -> str | None:
        """Origin if known, else the primary provider.

        Used downstream when computing ``has_aws/azure/gcp/oci`` and
        ``PrimaryHyperScaler`` so the cloud columns reflect what is
        actually hosting the application, not the edge in front of it.

        Method (not ``@property``) because pydantic v2 + mypy strict
        do not always infer property attributes through ``BaseModel``.
        """

        return self.origin or self.provider


class StackDetection(BaseModel):
    web_server: str | None = None
    cms: str | None = None
    cms_version: str | None = None
    frameworks: list[str] = Field(default_factory=list)
    signals_matched: list[SignalMatch] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class DetectionInput(BaseModel):
    """All evidence the orchestrator (Phase 6+) collected before calling detect.

    The detect engine never does its own IO — every field here was populated
    by ``scan/passive``, ``scan/browser`` and the ``tools/`` wrappers.
    """

    url: str
    status: int = 0
    headers: dict[str, str] = Field(default_factory=dict)  # lower-cased keys
    cookies: list[str] = Field(default_factory=list)  # raw "name=value" strings
    body_snippet: str = ""
    cnames: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    asn: int | None = None
    asn_org: str | None = None
    rdns_hostnames: list[str] = Field(default_factory=list)
    # Subdomains discovered by the crt.sh expander (Phase 2). Used by
    # ``OriginAttributor`` to widen the origin probe beyond the hardcoded
    # generic catalogue (Fase 9 #1.1).
    expanded_subdomains: list[str] = Field(default_factory=list)

    # External tool corroborations (Fase 4 wrappers).
    wafw00f_vendor: str | None = None
    wafw00f_generic: bool = False
    whatweb_plugins: dict[str, list[str]] = Field(default_factory=dict)
    wappalyzer_techs: dict[str, list[str]] = Field(default_factory=dict)
    shodan_cpes: list[str] = Field(default_factory=list)
    shodan_ports: list[int] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)

    def cookie_names(self) -> list[str]:
        """Extract just the names from ``"name=value"`` cookie strings."""

        names: list[str] = []
        for raw in self.cookies:
            if not raw:
                continue
            head = raw.split(";", 1)[0]
            if "=" in head:
                names.append(head.split("=", 1)[0].strip())
            else:
                names.append(head.strip())
        return names

    def cookie_named(self, name: str) -> str | None:
        """Return the value of a cookie by name, or None."""

        target = name.lower()
        for raw in self.cookies:
            head = raw.split(";", 1)[0]
            if "=" not in head:
                continue
            cname, _, cval = head.partition("=")
            if cname.strip().lower() == target:
                return cval.strip()
        return None


# Re-export ``Any`` to keep the import alive when models grow
# arbitrary-shape extension fields. Avoids "unused import" complaints in
# strict mode while leaving room for future schema growth.
_ = Any
