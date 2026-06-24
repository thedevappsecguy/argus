"""Narrow deterministic tools used by the ADK agent workflow."""

from typing import Any

from google.adk.tools.tool_context import ToolContext
from pydantic import BaseModel, ValidationError

from argus.agents.schemas import IngestionResult
from argus.context import model_to_context
from argus.models import SystemModel
from argus.rating import RatedThreat, rate_threats
from argus.report import render_report
from argus.skills import load_selected_skills
from argus.threats import ProposedThreats, VerifiedThreats, validate_proposed


class RatedThreats(BaseModel):
    threats: list[RatedThreat]


_SCHEMAS: dict[str, type[BaseModel]] = {
    "IngestionResult": IngestionResult,
    "SystemModel": SystemModel,
    "ProposedThreats": ProposedThreats,
    "VerifiedThreats": VerifiedThreats,
    "RatedThreats": RatedThreats,
}


def _dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _state_value(tool_context: ToolContext | None, key: str) -> Any:
    if tool_context is None:
        return None
    return getattr(tool_context, "state", {}).get(key)


def _state_or_arg(tool_context: ToolContext | None, key: str, arg: Any) -> Any:
    state_value = _state_value(tool_context, key)
    return state_value if state_value is not None else arg


def _proposal_payload(tool_context: ToolContext | None, arg: Any) -> Any:
    schema_validation = _state_value(tool_context, "schema_validation")
    if isinstance(schema_validation, dict) and schema_validation.get("valid"):
        normalized = schema_validation.get("normalized")
        if normalized is not None:
            return normalized
    return _state_or_arg(tool_context, "proposed_threats", arg)


def _ingestion(ingestion_result: dict[str, Any]) -> IngestionResult:
    try:
        return IngestionResult.model_validate(ingestion_result)
    except ValidationError:
        if not isinstance(ingestion_result, dict):
            raise

        if "system_model" in ingestion_result:
            system_model_payload = ingestion_result["system_model"]
        else:
            model_fields = set(SystemModel.model_fields)
            system_model_payload = {
                key: value
                for key, value in ingestion_result.items()
                if key in model_fields
            }
            system_model_payload.setdefault(
                "name",
                ingestion_result.get("system_name") or "System under review",
            )
        artifact_type = ingestion_result.get("artifact_type", "generic_doc")
        if artifact_type not in {"prd", "design_doc", "feature_doc", "rfc", "adr", "generic_doc"}:
            artifact_type = "generic_doc"

        return IngestionResult(
            artifact_type=artifact_type,
            system_model=SystemModel.model_validate(system_model_payload),
            source_summary=str(ingestion_result.get("source_summary") or ""),
            security_relevant_facts=_as_list(ingestion_result.get("security_relevant_facts")),
            open_questions=_as_list(ingestion_result.get("open_questions")),
        )


def _source_context(ingestion: IngestionResult) -> str:
    facts = "\n".join(f"  - {fact}" for fact in ingestion.security_relevant_facts)
    questions = "\n".join(f"  - {q}" for q in ingestion.open_questions) or "  - none"
    return (
        f"SOURCE ARTIFACT: {ingestion.artifact_type}\n"
        f"SOURCE SUMMARY: {ingestion.source_summary}\n"
        "SECURITY-RELEVANT FACTS:\n"
        f"{facts}\n"
        "OPEN QUESTIONS:\n"
        f"{questions}\n\n"
        "NORMALIZED SYSTEM MODEL:\n"
    )


def model_context_tool(
    ingestion_result: dict[str, Any] | None = None,
    tool_context: ToolContext | None = None,
) -> str:
    """Build structured threat-model context from an IngestionResult dictionary."""
    ingestion_result = _state_or_arg(tool_context, "ingestion_result", ingestion_result)
    ingestion = _ingestion(ingestion_result)
    return _source_context(ingestion) + model_to_context(ingestion.system_model)


def skills_tool(
    ingestion_result: dict[str, Any] | None = None,
    tool_context: ToolContext | None = None,
) -> str:
    """Load exact-reference Argus skills selected from an IngestionResult."""
    ingestion_result = _state_or_arg(tool_context, "ingestion_result", ingestion_result)
    return load_selected_skills(_ingestion(ingestion_result).system_model)


def schema_validation_tool(schema_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate payload against a named Argus Pydantic schema."""
    schema = _SCHEMAS.get(schema_name)
    if schema is None:
        return {
            "valid": False,
            "schema_name": schema_name,
            "errors": f"Unknown schema: {schema_name}",
            "normalized": {},
        }
    try:
        normalized = schema.model_validate(payload)
    except ValidationError as exc:
        return {
            "valid": False,
            "schema_name": schema_name,
            "errors": str(exc),
            "normalized": {},
        }
    return {
        "valid": True,
        "schema_name": schema_name,
        "errors": "",
        "normalized": _dump(normalized),
    }


def element_validation_tool(
    ingestion_result: dict[str, Any] | None = None,
    proposed_threats: dict[str, Any] | None = None,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Filter candidate threats to real SystemModel component or data-flow ids."""
    ingestion_result = _state_or_arg(tool_context, "ingestion_result", ingestion_result)
    proposed_threats = _proposal_payload(tool_context, proposed_threats)
    model = _ingestion(ingestion_result).system_model
    proposed = ProposedThreats.model_validate(proposed_threats)
    return _dump(ProposedThreats(threats=validate_proposed(proposed, model)))


def risk_rating_tool(
    ingestion_result: dict[str, Any] | None = None,
    verified_threats: dict[str, Any] | None = None,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Convert agent-assigned OWASP factor scores into deterministic rated threats."""
    ingestion_result = _state_or_arg(tool_context, "ingestion_result", ingestion_result)
    verified_threats = _state_or_arg(tool_context, "verified_threats", verified_threats)
    model = _ingestion(ingestion_result).system_model
    verified = VerifiedThreats.model_validate(verified_threats)
    rated = rate_threats(verified.threats, model)
    threats: list[dict[str, Any]] = []
    for threat in rated:
        dumped = threat.model_dump(mode="json")
        dumped["severity"] = threat.severity
        threats.append(dumped)
    return {"threats": threats}


def report_render_tool(
    ingestion_result: dict[str, Any] | None = None,
    rated_threats: dict[str, Any] | None = None,
    tool_context: ToolContext | None = None,
) -> dict[str, str]:
    """Render the final Markdown report from typed model and rated threats."""
    ingestion_result = _state_or_arg(tool_context, "ingestion_result", ingestion_result)
    rated_threats = _state_or_arg(tool_context, "rated_threats", rated_threats)
    model = _ingestion(ingestion_result).system_model
    rated = RatedThreats.model_validate(rated_threats)
    return {"markdown": render_report(model, rated.threats)}
