"""Detection engine — applies the rule pack to evidence collected upstream.

Phase 5 scope: stand-alone detectors with no IO of their own. The orchestrator
(Phase 6+) constructs a ``DetectionInput`` from passive + browser + tool
wrapper outputs and passes it through ``WafDetector`` / ``CdnDetector`` /
``CloudAttributor`` / ``StackDetector``.
"""

from __future__ import annotations

from cdt.detect.cdn import CdnDetector
from cdt.detect.cloud import CloudAttributor
from cdt.detect.models import (
    CdnDetection,
    CloudDetection,
    Confidence,
    DetectionInput,
    Hypothesis,
    SignalMatch,
    StackDetection,
    WafDetection,
)
from cdt.detect.rules import DetectionRules, RulesLoader
from cdt.detect.scoring import HypothesisAccumulator, ScoringEngine
from cdt.detect.stack import StackDetector
from cdt.detect.waf import WafDetector

__all__ = [
    "CdnDetection",
    "CdnDetector",
    "CloudAttributor",
    "CloudDetection",
    "Confidence",
    "DetectionInput",
    "DetectionRules",
    "Hypothesis",
    "HypothesisAccumulator",
    "RulesLoader",
    "ScoringEngine",
    "SignalMatch",
    "StackDetection",
    "StackDetector",
    "WafDetection",
    "WafDetector",
]
