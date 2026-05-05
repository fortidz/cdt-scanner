"""WAF orchestrator. Thin wrapper over ScoringEngine.evaluate_waf."""

from __future__ import annotations

import structlog

from cdt.detect.models import Confidence, DetectionInput, WafDetection
from cdt.detect.rules import DetectionRules
from cdt.detect.scoring import ScoringEngine

log = structlog.get_logger()


class WafDetector:
    def __init__(
        self,
        rules: DetectionRules,
        engine: ScoringEngine | None = None,
    ) -> None:
        self._rules = rules
        self._engine = engine or ScoringEngine(rules)

    def detect(self, ctx: DetectionInput) -> WafDetection:
        log.info("detection_waf_started", url=ctx.url)
        result = self._engine.evaluate_waf(ctx)

        if result.confidence == Confidence.HIGH:
            log.info(
                "detection_waf_high_confidence",
                url=ctx.url,
                vendor=result.vendor,
                gap=result.gap,
                runner_up=result.runner_up,
                waf_active=result.waf_active,
            )
        elif result.confidence == Confidence.MEDIUM:
            log.info(
                "detection_waf_runner_up",
                url=ctx.url,
                vendor=result.vendor,
                runner_up=result.runner_up,
                gap=result.gap,
            )
        else:
            log.info(
                "detection_waf_low_confidence",
                url=ctx.url,
                runner_up=result.runner_up,
            )
        return result
