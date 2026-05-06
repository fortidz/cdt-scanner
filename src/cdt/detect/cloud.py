"""Cloud attribution orchestrator.

Two-stage pipeline:

  1. Primary attribution — pytricia IP-range trie + rDNS / CNAME / ASN
     / banner signals from the rule pack (delegates to ``ScoringEngine``).
  2. Origin probe — when the primary lands on an edge ASN
     (``role=="edge_only"``), invoke ``OriginAttributor`` to surface the
     real hyperscaler underneath via subdomain probes + CNAME suffix
     matching. Spec v0.4 §14.2.4.

Both stages are best-effort: a failing origin probe never demotes the
primary attribution, only adds the ``origin`` / ``origin_confidence`` /
``origin_source`` fields when it succeeds.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from cdt.detect.models import CloudDetection, DetectionInput
from cdt.detect.origin import OriginAttributor, is_edge_asn
from cdt.detect.rules import DetectionRules
from cdt.detect.scoring import ScoringEngine
from cdt.discovery.normalize import apex_of

if TYPE_CHECKING:
    from cdt.scan.models import IPRangeMatch
    from cdt.scan.passive import IPRangesIndex

log = structlog.get_logger()


class CloudAttributor:
    def __init__(
        self,
        rules: DetectionRules,
        engine: ScoringEngine | None = None,
        ip_ranges_index: IPRangesIndex | None = None,
        origin_attributor: OriginAttributor | None = None,
    ) -> None:
        self._rules = rules
        self._engine = engine or ScoringEngine(rules)
        self._ip_ranges = ip_ranges_index
        self._origin = origin_attributor

    async def attribute(self, ctx: DetectionInput) -> CloudDetection:
        log.info("detection_cloud_started", url=ctx.url, ips=len(ctx.ip_addresses))

        ip_match: IPRangeMatch | None = None
        if self._ip_ranges and ctx.ip_addresses:
            for ip in ctx.ip_addresses:
                hit = self._ip_ranges.lookup(ip)
                if hit is not None:
                    ip_match = hit
                    break

        result = self._engine.evaluate_cloud(ctx, ip_range_match=ip_match)
        log.info(
            "detection_cloud_resolved",
            url=ctx.url,
            provider=result.provider,
            source=result.source,
            confidence=result.confidence.value,
        )

        # Origin probe — only when we have an edge result and an attributor
        # injected (offline mode passes None).
        if (
            self._origin is not None
            and result.role == "edge_only"
            and is_edge_asn(ctx.asn)
        ):
            try:
                apex = apex_of(ctx.url)
            except Exception:  # noqa: BLE001 — bad URL is operator's bug
                apex = ""
            if apex:
                try:
                    origin = await self._origin.detect(
                        apex,
                        primary_asn=ctx.asn,
                        primary_cnames=list(ctx.cnames),
                    )
                except Exception as exc:  # noqa: BLE001 — best-effort
                    log.warning(
                        "origin_probe_error",
                        apex=apex,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                else:
                    if origin.provider is not None:
                        result = result.model_copy(
                            update={
                                "origin": origin.provider,
                                "origin_confidence": origin.confidence,
                                "origin_source": origin.source,
                            }
                        )
                        log.info(
                            "detection_origin_resolved",
                            url=ctx.url,
                            origin=origin.provider,
                            source=origin.source,
                            confidence=origin.confidence.value,
                        )

        return result
