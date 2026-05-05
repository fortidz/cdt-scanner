"""CDN orchestrator. Reuses a CDN-capable WAF result when available."""

from __future__ import annotations

import structlog

from cdt.detect.models import CdnDetection, DetectionInput, WafDetection
from cdt.detect.rules import DetectionRules
from cdt.detect.scoring import ScoringEngine

log = structlog.get_logger()


class CdnDetector:
    def __init__(
        self,
        rules: DetectionRules,
        engine: ScoringEngine | None = None,
    ) -> None:
        self._rules = rules
        self._engine = engine or ScoringEngine(rules)

    def detect(
        self,
        ctx: DetectionInput,
        waf_detection: WafDetection | None = None,
    ) -> CdnDetection:
        log.info("detection_cdn_started", url=ctx.url)
        result = self._engine.evaluate_cdn(ctx, waf_detection=waf_detection)
        log.info(
            "detection_cdn_resolved",
            url=ctx.url,
            vendor=result.vendor,
            confidence=result.confidence.value,
        )
        return result
