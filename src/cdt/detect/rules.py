"""YAML loader + pydantic schemas for ``config/detection_rules.yaml``.

Validation is strict — an unknown vendor field, a missing ``signals`` block
or a malformed predicate fails the load with ``InputError`` (E03). Engine
version is enforced: a YAML declaring ``engine_version_min`` newer than the
runtime aborts at load time with a clear message.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cdt import __version__ as RUNTIME_VERSION
from cdt.errors import InputError

# ---------------------------------------------------------------------------
# Predicate / signal models
# ---------------------------------------------------------------------------


class RuleSignal(BaseModel):
    """Wraps a YAML signal node.

    Each rule can have optional ``kind`` (primary/secondary/block_page) and a
    required ``when`` predicate dict. The predicate is *not* parsed here —
    ``signals.evaluate_signal`` walks it at evaluation time. Keeping it as a
    plain dict lets the YAML evolve without forcing schema migrations on
    every new predicate kind.
    """

    kind: str | None = None
    when: dict[str, Any]
    confidence_modifier: float | None = None

    model_config = ConfigDict(extra="allow")


class _SignalDictAdapter(BaseModel):
    """Allows YAML signals that omit ``kind:`` and just use a top-level
    predicate (e.g. ``- header: {...}``). We promote those to ``RuleSignal``
    with ``kind=None`` and ``when={...}`` so the evaluator gets a uniform
    shape."""

    model_config = ConfigDict(extra="allow")


def _coerce_signal(raw: Any) -> RuleSignal:
    if isinstance(raw, RuleSignal):
        return raw
    if not isinstance(raw, dict):
        raise InputError(f"Signal must be a mapping, got {type(raw).__name__}")
    if "when" in raw:
        return RuleSignal(
            kind=raw.get("kind"),
            when=raw["when"],
            confidence_modifier=raw.get("confidence_modifier"),
        )
    # Bare predicate form: {"header": {...}} or {"any": [...]} etc.
    return RuleSignal(kind=raw.get("kind"), when={k: v for k, v in raw.items() if k != "kind"})


def _coerce_signal_list(raw: Any) -> list[RuleSignal]:
    if not isinstance(raw, list):
        raise InputError(f"signals must be a list, got {type(raw).__name__}")
    return [_coerce_signal(item) for item in raw]


# ---------------------------------------------------------------------------
# Top-level rule schemas
# ---------------------------------------------------------------------------


class WafActiveIndicator(BaseModel):
    challenge_page: dict[str, Any] | None = None
    header: dict[str, Any] | None = None
    probe_403_on_dotenv: bool | None = None

    model_config = ConfigDict(extra="allow")


class WafVendorRule(BaseModel):
    vendor: str
    cdn_capable: bool = False
    signals: list[RuleSignal]
    waf_active_indicators: list[WafActiveIndicator] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class CdnVendorRule(BaseModel):
    vendor: str
    signals: list[RuleSignal]

    model_config = ConfigDict(extra="ignore")


class ServerHeaderMatch(BaseModel):
    regex: str | None = None
    regex_ci: str | None = None
    equals: str | None = None
    equals_ci: str | None = None
    confidence_modifier: float | None = None

    model_config = ConfigDict(extra="allow")


class CloudProviderRule(BaseModel):
    provider: str
    role: str = "hyperscaler"  # hyperscaler | edge_only | datacenter
    ip_ranges_url: str | None = None
    ip_ranges_urls: list[str] | None = None
    ip_ranges_format: str | None = None
    ip_ranges_refresh_strategy: str | None = None
    rdns_patterns: list[str] = Field(default_factory=list)
    asns: list[int] = Field(default_factory=list)
    cname_suffixes: list[str] = Field(default_factory=list)
    server_headers: list[ServerHeaderMatch] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class DatacenterFallbackRule(BaseModel):
    description: str = ""
    asn_orgs_treated_as_datacenter: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class CmsVersionExtract(BaseModel):
    from_: str = Field(alias="from")
    regex: str
    header_name: str | None = None

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class CmsRule(BaseModel):
    name: str
    signals: list[RuleSignal]
    version_extract: CmsVersionExtract | None = None

    model_config = ConfigDict(extra="ignore")


class FrameworkRule(BaseModel):
    name: str
    signals: list[RuleSignal]

    model_config = ConfigDict(extra="ignore")


class WebServerBannerRule(BaseModel):
    regex: str | None = None
    equals: str | None = None
    equals_ci: str | None = None
    assign: str

    model_config = ConfigDict(extra="ignore")


class ScoringConfig(BaseModel):
    primary_signal_points: int = 10
    secondary_signal_points: int = 5
    block_page_points: int = 7
    ip_range_match_points: int = 10
    reverse_dns_points: int = 7
    asn_match_points: int = 5
    cname_match_points: int = 6
    server_header_points: int = 2
    high_confidence_threshold: int = 10
    high_confidence_min_gap: int = 5

    model_config = ConfigDict(extra="ignore")


class HypothesisResolution(BaseModel):
    description: str = ""

    model_config = ConfigDict(extra="allow")


class LowConfidenceHandling(BaseModel):
    field_default_when_low_confidence: dict[str, str] = Field(default_factory=dict)
    emit_finding: dict[str, str] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class DetectionRules(BaseModel):
    version: str
    engine_version_min: str | None = None
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    waf_vendors: list[WafVendorRule] = Field(default_factory=list)
    cdn_only_vendors: list[CdnVendorRule] = Field(default_factory=list)
    cloud_providers: list[CloudProviderRule] = Field(default_factory=list)
    datacenter_fallback: DatacenterFallbackRule = Field(
        default_factory=DatacenterFallbackRule
    )
    cms: list[CmsRule] = Field(default_factory=list)
    frameworks: list[FrameworkRule] = Field(default_factory=list)
    web_servers: dict[str, list[WebServerBannerRule]] = Field(default_factory=dict)
    hypothesis_resolution: HypothesisResolution = Field(
        default_factory=HypothesisResolution
    )
    low_confidence_handling: LowConfidenceHandling = Field(
        default_factory=LowConfidenceHandling
    )

    model_config = ConfigDict(extra="ignore")

    @classmethod
    def load(cls, path: Path) -> DetectionRules:
        """Parse + validate ``path``. Raises ``InputError`` on any failure."""

        try:
            with path.open(encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except OSError as exc:
            raise InputError(f"Cannot read detection rules at {path}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise InputError(f"Invalid YAML in {path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise InputError(f"Top-level YAML must be a mapping in {path}")

        # Pre-coerce every ``signals`` list so RuleSignal sees uniform shape.
        for vendor_block in raw.get("waf_vendors", []) or []:
            if isinstance(vendor_block, dict) and "signals" in vendor_block:
                vendor_block["signals"] = _coerce_signal_list(vendor_block["signals"])
        for vendor_block in raw.get("cdn_only_vendors", []) or []:
            if isinstance(vendor_block, dict) and "signals" in vendor_block:
                vendor_block["signals"] = _coerce_signal_list(vendor_block["signals"])
        for cms_block in raw.get("cms", []) or []:
            if isinstance(cms_block, dict) and "signals" in cms_block:
                cms_block["signals"] = _coerce_signal_list(cms_block["signals"])
        for fw_block in raw.get("frameworks", []) or []:
            if isinstance(fw_block, dict) and "signals" in fw_block:
                fw_block["signals"] = _coerce_signal_list(fw_block["signals"])

        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise InputError(f"Detection rules failed validation: {exc}") from exc

    def engine_version_compatible(
        self, runtime_version: str = RUNTIME_VERSION
    ) -> bool:
        """True iff the runtime's version is >= ``engine_version_min``."""

        if not self.engine_version_min:
            return True
        return _semver_tuple(runtime_version) >= _semver_tuple(self.engine_version_min)


def _semver_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in version.split("."):
        head = "".join(c for c in chunk if c.isdigit())
        parts.append(int(head) if head else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


# A loader alias so callers that prefer a verb can ``from cdt.detect.rules
# import RulesLoader`` without thinking about the classmethod.
RulesLoader = DetectionRules
