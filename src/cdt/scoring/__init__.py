"""Risk score + Fortinet opportunity recommendation + rationale.

Phase 6 scope: pure business logic over already-collected detection data.
No IO, no external calls; the orchestrator (Phase 7+) wires it.
"""

from __future__ import annotations

from cdt.scoring.engine import ScoringEngine
from cdt.scoring.models import (
    Finding,
    FindingCode,
    OpportunityFlags,
    RiskBand,
    RiskBreakdownItem,
    RiskScore,
    ScoringInput,
    ScoringResult,
    Severity,
)
from cdt.scoring.opportunity import (
    OpportunityCalculator,
    compute_complexity,
    compute_primary_hyperscaler,
    compute_public_cloud,
    compute_waf_decision,
    list_csps,
)
from cdt.scoring.rationale import RationaleRenderer
from cdt.scoring.risk import RiskScorer

__all__ = [
    "Finding",
    "FindingCode",
    "OpportunityCalculator",
    "OpportunityFlags",
    "RationaleRenderer",
    "RiskBand",
    "RiskBreakdownItem",
    "RiskScore",
    "RiskScorer",
    "ScoringEngine",
    "ScoringInput",
    "ScoringResult",
    "Severity",
    "compute_complexity",
    "compute_primary_hyperscaler",
    "compute_public_cloud",
    "compute_waf_decision",
    "list_csps",
]
