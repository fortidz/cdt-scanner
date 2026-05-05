"""Tech stack orchestrator (web server + CMS + frameworks)."""

from __future__ import annotations

import structlog

from cdt.detect.models import DetectionInput, StackDetection
from cdt.detect.rules import DetectionRules
from cdt.detect.scoring import ScoringEngine

log = structlog.get_logger()


class StackDetector:
    def __init__(
        self,
        rules: DetectionRules,
        engine: ScoringEngine | None = None,
    ) -> None:
        self._rules = rules
        self._engine = engine or ScoringEngine(rules)

    def detect(self, ctx: DetectionInput) -> StackDetection:
        log.info("detection_stack_started", url=ctx.url)
        result = self._engine.evaluate_stack(ctx)
        log.info(
            "detection_stack_resolved",
            url=ctx.url,
            web_server=result.web_server,
            cms=result.cms,
            cms_version=result.cms_version,
            frameworks=len(result.frameworks),
        )
        return result
