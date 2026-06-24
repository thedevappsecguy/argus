"""ADK stage output schemas for the Argus agent workflow."""

from typing import Literal

from pydantic import BaseModel, Field

from argus.models import SystemModel

ArtifactType = Literal["prd", "design_doc", "feature_doc", "rfc", "adr", "generic_doc"]


class IngestionResult(BaseModel):
    artifact_type: ArtifactType
    system_model: SystemModel
    source_summary: str
    security_relevant_facts: list[str]
    open_questions: list[str] = Field(default_factory=list)


class SecurityZone(BaseModel):
    id: str
    name: str
    members: list[str] = Field(default_factory=list)
    trust_level: str = ""
    notes: str = ""


class ArchitectureZones(BaseModel):
    zones: list[SecurityZone] = Field(default_factory=list)


class EntryPoint(BaseModel):
    id: str
    zone_id: str = ""
    element_id: str
    channel: str
    attacker_controlled_input: str
    notes: str = ""


class EntryPoints(BaseModel):
    entry_points: list[EntryPoint] = Field(default_factory=list)


class SchemaValidationResult(BaseModel):
    valid: bool
    schema_name: str
    errors: str = ""
    normalized: dict = Field(default_factory=dict)


class ControlChallenge(BaseModel):
    title: str
    element_id: str
    challenged_controls: list[str] = Field(default_factory=list)
    bypass_scenarios: list[str] = Field(default_factory=list)
    residual_risk: str = ""


class ControlChallenges(BaseModel):
    challenges: list[ControlChallenge] = Field(default_factory=list)


class FinalReport(BaseModel):
    markdown: str
