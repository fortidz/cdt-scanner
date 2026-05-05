"""Cloud attribution orchestrator. Combines pytricia IP-range lookup with the
rule pack's rDNS / CNAME / ASN / banner signals."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from cdt.detect.models import CloudDetection, DetectionInput
from cdt.detect.rules import DetectionRules
from cdt.detect.scoring import ScoringEngine

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
    ) -> None:
        self._rules = rules
        self._engine = engine or ScoringEngine(rules)
        self._ip_ranges = ip_ranges_index

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
        return result
