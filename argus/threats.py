"""Threat workflow schemas shared by ADK agents and deterministic tools."""

from pydantic import BaseModel, Field

from argus.models import SystemModel
from argus.rating import ImpactFactors, LikelihoodFactors


class ProposedThreat(BaseModel):
    """A lightweight candidate threat from the scenario enumeration stage."""

    title: str
    stride: str
    element_id: str
    rationale: str
    scenario: str = ""
    entry_point_id: str = ""
    owasp_refs: list[str] = Field(default_factory=list)


class ProposedThreats(BaseModel):
    """Wrapper for candidate threats."""

    threats: list[ProposedThreat] = Field(default_factory=list)


class VerifiedThreat(BaseModel):
    """A candidate threat after agent false-positive review."""

    title: str
    stride: str
    element_id: str
    reachable: bool = False
    attack_path: str = ""
    mitigating_controls: list[str] = Field(default_factory=list)
    likelihood: LikelihoodFactors = Field(default_factory=LikelihoodFactors)
    impact: ImpactFactors = Field(default_factory=ImpactFactors)
    verdict: str = "confirmed"
    reason: str = ""


class VerifiedThreats(BaseModel):
    """Wrapper for verified threats."""

    threats: list[VerifiedThreat] = Field(default_factory=list)


def validate_proposed(proposed: ProposedThreats, model: SystemModel) -> list[ProposedThreat]:
    """Return only candidates tied to real model component or data-flow ids."""
    known_elements = {c.id for c in model.components} | {f.id for f in model.data_flows}
    return [threat for threat in proposed.threats if threat.element_id in known_elements]
