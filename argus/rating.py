"""Threat disposition + deterministic OWASP rating of verified threats.

Threat discovery and false-positive review are ADK agent responsibilities. This module only:

  - defines the OWASP factor schema + the report-facing :class:`RatedThreat` /
    :class:`ThreatStatus` types, and
  - maps each verified threat's agent-assigned OWASP factor scores to a **deterministic**
    severity via :func:`argus.risk.rate`.

Because the factor→severity mapping lives in :mod:`argus.risk` (a pure function), the same
factor scores always yield the same severity — the rating is "deterministic based on skill
usage": the agent scores factors per the ``owasp-risk-rating`` skill, the matrix does the
rest. Only threats the verifier confirmed as real *and* reachable are REPORTED; everything
else is kept as NOT_APPLICABLE / SUPPRESSED with the verifier's reason, for auditability.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from argus.models import SystemModel
from argus.risk import RiskRating, rate


class LikelihoodFactors(BaseModel):
    """OWASP likelihood factor scores (0–9), assigned by the verifier from the attack path.

    Scoring guidance lives in the ``owasp-risk-rating`` skill. Higher = more likely.
    ``intrusion_detection`` is scored inversely to detection strength (weak/none → high).
    """

    ease_of_discovery: float = Field(default=5.0, ge=0, le=9)
    ease_of_exploit: float = Field(default=5.0, ge=0, le=9)
    awareness: float = Field(default=5.0, ge=0, le=9)
    intrusion_detection: float = Field(default=5.0, ge=0, le=9)

    @model_validator(mode="before")
    @classmethod
    def _from_agent_list(cls, value: Any) -> Any:
        if isinstance(value, list):
            keys = ("ease_of_discovery", "ease_of_exploit", "awareness", "intrusion_detection")
            return dict(zip(keys, value, strict=False))
        return value


class ImpactFactors(BaseModel):
    """OWASP impact factor scores (0–9), assigned by the verifier from evidence.

    Scoring guidance lives in the ``owasp-risk-rating`` skill. Higher = worse impact,
    calibrated by the data classification the affected element handles.
    """

    loss_of_confidentiality: float = Field(default=5.0, ge=0, le=9)
    loss_of_integrity: float = Field(default=5.0, ge=0, le=9)
    non_compliance: float = Field(default=5.0, ge=0, le=9)
    privacy_violation: float = Field(default=5.0, ge=0, le=9)

    @model_validator(mode="before")
    @classmethod
    def _from_agent_list(cls, value: Any) -> Any:
        if isinstance(value, list):
            keys = (
                "loss_of_confidentiality",
                "loss_of_integrity",
                "non_compliance",
                "privacy_violation",
            )
            return dict(zip(keys, value, strict=False))
        return value


class ThreatStatus(str, Enum):
    """Disposition of a threat in the final report."""

    REPORTED = "reported"              # confirmed real + reachable; in the ranked table
    SUPPRESSED = "suppressed"          # ruled out: covered by an existing control
    NOT_APPLICABLE = "not_applicable"  # ruled out: false positive / not reachable


class RatedThreat(BaseModel):
    """A fully evaluated threat: evidenced, attack-path-grounded, and (if reported) rated.

    ``element_id`` is the evidence field — it points to a real model element.
    ``attack_path`` is the grounded path that makes the threat real (the false-positive gate).
    ``controls`` are the mitigating controls the verifier identified.
    ``rating`` is set only for REPORTED threats; ruled-out threats carry a reason instead.
    """

    template_id: str
    title: str
    stride: str
    element_id: str       # evidence: the model element this threat is bound to
    element_kind: str     # "component" | "data_flow" | ""
    status: ThreatStatus
    reason: str = ""
    attack_path: str = ""
    controls: list[str] = Field(default_factory=list)
    rating: RiskRating | None = None  # set only when REPORTED

    @property
    def severity(self) -> str | None:
        """Convenience accessor for the OWASP severity label."""
        return self.rating.severity if self.rating else None


def _kind_of(model: SystemModel, element_id: str) -> str:
    """Return ``"component"`` / ``"data_flow"`` for an element id, or ``""`` if unknown."""
    if any(c.id == element_id for c in model.components):
        return "component"
    if any(f.id == element_id for f in model.data_flows):
        return "data_flow"
    return ""


def rate_threats(verified: list, model: SystemModel) -> list[RatedThreat]:
    """Rate verifier output with the deterministic OWASP matrix.

    Only threats the verifier confirmed as real *and* reachable become REPORTED (and get a
    deterministic severity from their factor scores). False positives / unreachable threats
    are kept as NOT_APPLICABLE with the verifier's reason for the report's transparency
    section. Verified threats whose element id is not in the model are dropped (structural
    anti-hallucination backstop).

    Args:
        verified: List of :class:`argus.threats.VerifiedThreat` (duck-typed).
        model: The system model (used to label ``element_kind`` and validate element ids).

    Returns:
        List of :class:`RatedThreat`, one per surviving verified threat.
    """
    out: list[RatedThreat] = []
    for i, v in enumerate(verified):
        kind = _kind_of(model, v.element_id)
        if not kind:
            continue  # element not in model — hallucinated id, drop

        verdict = getattr(v, "verdict", "confirmed")
        confirmed = (
            verdict == "confirmed"
            and getattr(v, "reachable", True)
        )
        if confirmed:
            status = ThreatStatus.REPORTED
            rating = rate(v.likelihood.model_dump(), v.impact.model_dump())
        elif verdict == "suppressed":
            status = ThreatStatus.SUPPRESSED
            rating = None
        else:
            status = ThreatStatus.NOT_APPLICABLE
            rating = None

        out.append(RatedThreat(
            template_id=f"T-{i:03d}",
            title=v.title,
            stride=v.stride,
            element_id=v.element_id,
            element_kind=kind,
            status=status,
            reason=getattr(v, "reason", ""),
            attack_path=getattr(v, "attack_path", ""),
            controls=list(getattr(v, "mitigating_controls", [])),
            rating=rating,
        ))
    return out
