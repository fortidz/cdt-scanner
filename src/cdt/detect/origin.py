"""Origin cloud attribution behind edge providers.

Spec: v0.4 §14.2.4 (``OriginCloudProvider`` column).
Design: Fase 9 #1.

When the primary IP for an account's apex resolves into an edge ASN
(Cloudflare, Fastly, Akamai, ...), the front-door cloud is the edge,
not the cloud actually hosting the application. This module probes
common origin-bearing subdomains and known cloud-shaped CNAME suffixes
to surface the real hyperscaler underneath.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import dns.exception
import dns.resolver
import structlog

from cdt.detect.models import Confidence

if TYPE_CHECKING:  # pragma: no cover — typing-only import
    import dns.asyncresolver

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Edge ASN catalogue
# ---------------------------------------------------------------------------


# ASN -> edge provider name. The presence of the primary IP in any of these
# ASNs triggers the origin probe. Mirrors the spec v0.4 §14.2.3 ASN table
# but restricted to *edge_only* providers.
EDGE_ASNS: dict[int, str] = {
    13335: "Cloudflare",
    54113: "Fastly",
    20940: "Akamai",
    16625: "Akamai",
    16702: "Akamai",
    21342: "Akamai",
    23454: "Akamai",
    19551: "Imperva",
    30148: "Sucuri",
}


# Subdomains that operators routinely point *direct* to the origin (no CDN
# fronting) for backend / API / admin traffic. Probing each one with a fresh
# A-record lookup occasionally reveals the real cloud.
ORIGIN_PROBE_SUBDOMAINS: tuple[str, ...] = (
    "origin",
    "direct",
    "api",
    "app",
    "backend",
    "srv",
    "internal",
    "admin",
    "panel",
    "dashboard",
    "ws",
    "ws1",
    "api1",
)


# CNAME suffix patterns that strongly imply a cloud provider. Compiled at
# import time. Order is intentional: more specific patterns first.
CLOUD_CNAME_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "AWS": (
        re.compile(r".*\.elb\.amazonaws\.com$", re.IGNORECASE),
        re.compile(r".*\.cloudfront\.net$", re.IGNORECASE),
        re.compile(r".*\.s3-website[^.]*\.amazonaws\.com$", re.IGNORECASE),
        re.compile(r".*\.execute-api\.[^.]+\.amazonaws\.com$", re.IGNORECASE),
        re.compile(r".*\.amplifyapp\.com$", re.IGNORECASE),
    ),
    "Azure": (
        re.compile(r".*\.azureedge\.net$", re.IGNORECASE),
        re.compile(r".*\.cloudapp\.net$", re.IGNORECASE),
        re.compile(r".*\.cloudapp\.azure\.com$", re.IGNORECASE),
        re.compile(r".*\.azurefd\.net$", re.IGNORECASE),
        re.compile(r".*\.trafficmanager\.net$", re.IGNORECASE),
        re.compile(r".*\.windows\.net$", re.IGNORECASE),
        re.compile(r".*\.azurewebsites\.net$", re.IGNORECASE),
    ),
    "GCP": (
        re.compile(r".*\.appspot\.com$", re.IGNORECASE),
        re.compile(r".*\.run\.app$", re.IGNORECASE),
        re.compile(r".*\.googleusercontent\.com$", re.IGNORECASE),
        re.compile(r".*\.googleapis\.com$", re.IGNORECASE),
        re.compile(r".*\.cloudfunctions\.net$", re.IGNORECASE),
    ),
    "OCI": (
        re.compile(r".*\.oraclecloud\.com$", re.IGNORECASE),
        re.compile(r".*\.oci\.customer-oci\.com$", re.IGNORECASE),
    ),
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class OriginResult:
    """Origin attribution outcome.

    ``provider`` is None when the primary is not edge OR every probe
    failed to surface a non-edge cloud.
    """

    provider: str | None
    confidence: Confidence
    source: str  # subdomain_probe | cname_chain | exhausted | not_edge | disabled
    evidence: dict[str, str]


# ---------------------------------------------------------------------------
# Attributor
# ---------------------------------------------------------------------------


class OriginAttributor:
    """Detects the cloud underneath an edge provider.

    Stateless aside from the injected DNS resolver; safe to share across
    accounts in one run. The attributor never raises — every failure path
    yields an ``OriginResult(provider=None, ...)`` so the caller can fall
    back to the edge attribution.
    """

    def __init__(
        self,
        resolver: dns.asyncresolver.Resolver | None = None,
        *,
        ip_range_lookup: object | None = None,
    ) -> None:
        # Lazy import keeps ``dns.asyncresolver`` out of import time when
        # callers swap in a stub for tests.
        if resolver is None:
            import dns.asyncresolver as _r

            resolver = _r.Resolver()
        self._resolver = resolver
        # ``ip_range_lookup`` should be an ``IPRangesIndex`` from the scan
        # layer; typed as object here to avoid a cycle. Optional — when
        # absent, subdomain probes can still match by ASN-via-CNAME.
        self._ip_ranges = ip_range_lookup

    # ----- public API ----------------------------------------------------

    async def detect(
        self,
        apex: str,
        *,
        primary_asn: int | None,
        primary_cnames: list[str] | None = None,
    ) -> OriginResult:
        if primary_asn is None or primary_asn not in EDGE_ASNS:
            return OriginResult(
                provider=None,
                confidence=Confidence.LOW,
                source="not_edge",
                evidence={},
            )

        edge_name = EDGE_ASNS[primary_asn]
        log.info("origin_probe_started", apex=apex, edge=edge_name)

        # 1. Subdomain probe — strongest signal. A direct-to-origin host
        # like ``api.example.com`` resolving into AWS/Azure/GCP/OCI IP
        # space is an unambiguous attribution.
        sub = await self._probe_subdomains(apex)
        if sub.provider:
            log.info(
                "origin_probe_subdomain_hit",
                apex=apex,
                provider=sub.provider,
                hostname=sub.evidence.get("hostname"),
            )
            return sub

        # 2. CNAME chain on the apex / known subdomains.
        cname = self._probe_cnames(apex, primary_cnames or [])
        if cname.provider:
            log.info(
                "origin_probe_cname_hit",
                apex=apex,
                provider=cname.provider,
                cname=cname.evidence.get("cname"),
            )
            return cname

        log.info("origin_probe_exhausted", apex=apex, edge=edge_name)
        return OriginResult(
            provider=None,
            confidence=Confidence.LOW,
            source="exhausted",
            evidence={"edge": edge_name},
        )

    # ----- strategy 1: subdomain probe ----------------------------------

    async def _probe_subdomains(self, apex: str) -> OriginResult:
        """Resolve each ``ORIGIN_PROBE_SUBDOMAINS`` entry; classify by IP.

        Multiple subdomains agreeing on the same provider boost confidence
        from MEDIUM to HIGH.
        """

        per_provider_hits: dict[str, list[str]] = {}

        for sub in ORIGIN_PROBE_SUBDOMAINS:
            host = f"{sub}.{apex}"
            ips = await self._resolve_a(host)
            if not ips:
                continue
            for ip in ips:
                provider = self._classify_ip(ip)
                if provider and provider not in EDGE_ASNS.values():
                    per_provider_hits.setdefault(provider, []).append(host)
                    break  # one IP per host is enough

        if not per_provider_hits:
            return OriginResult(
                provider=None,
                confidence=Confidence.LOW,
                source="exhausted",
                evidence={},
            )

        # Pick the provider with the most subdomains agreeing.
        winner = max(per_provider_hits.items(), key=lambda kv: len(kv[1]))
        provider, hostnames = winner

        confidence = Confidence.HIGH if len(hostnames) >= 2 else Confidence.MEDIUM
        return OriginResult(
            provider=provider,
            confidence=confidence,
            source="subdomain_probe",
            evidence={"hostname": hostnames[0], "matches": ",".join(hostnames)},
        )

    async def _resolve_a(self, host: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(host, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException:
            return []
        out: list[str] = []
        for rec in answer:
            try:
                out.append(str(rec.address))
            except AttributeError:
                continue
        return out

    def _classify_ip(self, ip: str) -> str | None:
        """Map an IP to ``AWS|Azure|GCP|OCI|<edge>|None`` via the trie.

        Without an ``ip_range_lookup`` the probe gracefully falls back to
        returning None (i.e., we never claim a provider on weak evidence).
        """

        if self._ip_ranges is None:
            return None
        try:
            match = self._ip_ranges.lookup(ip)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return None
        if match is None:
            return None
        # ``match.provider`` exists on IPRangeMatch.
        return getattr(match, "provider", None)

    # ----- strategy 2: CNAME chain --------------------------------------

    def _probe_cnames(
        self, apex: str, primary_cnames: list[str]
    ) -> OriginResult:
        """Match the apex CNAME chain (already resolved upstream) against
        known cloud-suffix patterns. Pure function — no DNS calls."""

        for cname in primary_cnames:
            provider = match_cname_provider(cname)
            if provider:
                return OriginResult(
                    provider=provider,
                    confidence=Confidence.MEDIUM,
                    source="cname_chain",
                    evidence={"cname": cname},
                )
        return OriginResult(
            provider=None,
            confidence=Confidence.LOW,
            source="exhausted",
            evidence={},
        )


# ---------------------------------------------------------------------------
# Pure helpers (testable without DNS)
# ---------------------------------------------------------------------------


def is_edge_asn(asn: int | None) -> bool:
    return asn is not None and asn in EDGE_ASNS


def edge_name_for_asn(asn: int | None) -> str | None:
    if asn is None:
        return None
    return EDGE_ASNS.get(asn)


def match_cname_provider(cname: str) -> str | None:
    """Return ``"AWS"``/``"Azure"``/``"GCP"``/``"OCI"`` for a known
    cloud-suffix CNAME, else ``None``."""

    if not cname:
        return None
    cname_l = cname.lower().rstrip(".")
    for provider, patterns in CLOUD_CNAME_PATTERNS.items():
        for pat in patterns:
            if pat.search(cname_l):
                return provider
    return None
