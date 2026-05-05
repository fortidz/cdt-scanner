"""Rationale renderer.

Loads ``rationale_templates.yaml`` (drop-in v0.5 §5.9) and applies the four
templates that the spec defines. Template *conditions* in the YAML are
documentation-only — the matching logic lives in code. We deliberately
do NOT parse the condition strings to keep the engine deterministic and
free of expression-language bugs.
"""

from __future__ import annotations

from pathlib import Path

import structlog
import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from cdt.errors import InputError
from cdt.scoring.models import OpportunityFlags, RiskScore, ScoringInput
from cdt.scoring.opportunity import (
    compute_public_cloud,
    compute_waf_decision,
    list_csps,
)

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# YAML model
# ---------------------------------------------------------------------------


class TemplateEntry(BaseModel):
    condition: str = ""
    template: str

    model_config = ConfigDict(extra="ignore")


class TemplatesConfig(BaseModel):
    templates: dict[str, TemplateEntry]

    model_config = ConfigDict(extra="ignore")


# Template keys we render against. Anything else in the YAML is ignored.
APPSEC_NO_WAF_CLOUD = "appsec_no_waf_cloud"
APPSEC_DISPLACEMENT = "appsec_displacement"
CNAPP_MULTICSP = "cnapp_multicsp"
FORTIWEB_ONPREM = "fortiweb_onprem"


class RationaleRenderer:
    def __init__(self, templates_path: Path) -> None:
        self._templates = _load_templates(templates_path)

    def render(
        self,
        opportunity: OpportunityFlags,
        scoring_input: ScoringInput,
        risk: RiskScore,
        *,
        primary_hyperscaler: str,
        complexity: str,
    ) -> str:
        waf_decision = compute_waf_decision(scoring_input.waf)
        public_cloud = compute_public_cloud(scoring_input.cloud)

        parts: list[str] = []

        if (
            opportunity.appsec
            and waf_decision == "No"
            and public_cloud == "Yes"
            and APPSEC_NO_WAF_CLOUD in self._templates
        ):
            parts.append(
                self._templates[APPSEC_NO_WAF_CLOUD].template.format(
                    PrimaryHyperScaler=primary_hyperscaler,
                )
            )

        if (
            opportunity.appsec
            and waf_decision == "Yes"
            and APPSEC_DISPLACEMENT in self._templates
        ):
            parts.append(
                self._templates[APPSEC_DISPLACEMENT].template.format(
                    WAFVendor=scoring_input.waf.vendor or "-",
                    RiskScoreBand=risk.band.value,
                )
            )

        if opportunity.cnapp and CNAPP_MULTICSP in self._templates:
            parts.append(
                self._templates[CNAPP_MULTICSP].template.format(
                    Complexity=complexity,
                    ListCSPs=list_csps(
                        has_aws=scoring_input.has_aws,
                        has_azure=scoring_input.has_azure,
                        has_gcp=scoring_input.has_gcp,
                        has_oci=scoring_input.has_oci,
                    ),
                )
            )

        if opportunity.web and FORTIWEB_ONPREM in self._templates:
            parts.append(self._templates[FORTIWEB_ONPREM].template)

        result = "; ".join(parts)
        log.info(
            "rationale_rendered",
            url=scoring_input.url,
            applied=len(parts),
            result_len=len(result),
        )
        return result


def _load_templates(path: Path) -> dict[str, TemplateEntry]:
    try:
        with path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except OSError as exc:
        raise InputError(f"Cannot read rationale templates at {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise InputError(f"Invalid YAML in {path}: {exc}") from exc

    try:
        config = TemplatesConfig.model_validate(raw)
    except ValidationError as exc:
        raise InputError(
            f"Rationale templates failed validation: {exc}"
        ) from exc

    return config.templates
