"""Tests for ADK tools that enforce typed gates inside the agent workflow."""

from argus.agents.tools import (
    element_validation_tool,
    report_render_tool,
    risk_rating_tool,
    schema_validation_tool,
)


def _model_dict() -> dict:
    return {
        "name": "payments",
        "actors": [{"id": "net", "name": "Internet", "privilege": "anon"}],
        "components": [{"id": "api", "name": "API", "type": "api", "properties": []}],
        "data_flows": [{"id": "in", "source": "net", "dest": "api", "authenticated": False}],
    }


def _ingestion_dict() -> dict:
    return {
        "artifact_type": "feature_doc",
        "system_model": _model_dict(),
        "source_summary": "Feature document for payments.",
        "security_relevant_facts": ["Anonymous clients call the API."],
        "open_questions": ["Authentication is not specified."],
    }


class _ToolContext:
    def __init__(self, state: dict):
        self.state = state


def test_schema_validation_tool_accepts_known_schema_payload() -> None:
    result = schema_validation_tool("IngestionResult", _ingestion_dict())
    assert result["valid"] is True
    assert result["normalized"]["artifact_type"] == "feature_doc"
    assert result["normalized"]["system_model"]["name"] == "payments"


def test_schema_validation_tool_rejects_invalid_payload() -> None:
    result = schema_validation_tool("IngestionResult", {"artifact_type": "feature_doc"})
    assert result["valid"] is False
    assert "system_model" in result["errors"]


def test_schema_validation_tool_accepts_all_document_artifact_types() -> None:
    for artifact_type in ("prd", "design_doc", "feature_doc", "rfc", "adr", "generic_doc"):
        payload = _ingestion_dict() | {"artifact_type": artifact_type}
        result = schema_validation_tool("IngestionResult", payload)
        assert result["valid"] is True


def test_element_validation_tool_filters_fake_element_ids() -> None:
    proposed = {
        "threats": [
            {
                "title": "BOLA",
                "stride": "E",
                "element_id": "api",
                "rationale": "api serves objects",
            },
            {"title": "Ghost", "stride": "T", "element_id": "ghost", "rationale": "not real"},
        ]
    }
    result = element_validation_tool(_ingestion_dict(), proposed)
    assert [threat["title"] for threat in result["threats"]] == ["BOLA"]


def test_risk_rating_tool_calculates_severity_from_agent_factors() -> None:
    verified = {
        "threats": [
            {
                "title": "BOLA",
                "stride": "E",
                "element_id": "api",
                "reachable": True,
                "attack_path": "net -> in -> api",
                "mitigating_controls": ["object-level authorization"],
                "likelihood": {
                    "ease_of_discovery": 9,
                    "ease_of_exploit": 9,
                    "awareness": 9,
                    "intrusion_detection": 9,
                },
                "impact": {
                    "loss_of_confidentiality": 9,
                    "loss_of_integrity": 9,
                    "non_compliance": 9,
                    "privacy_violation": 9,
                },
                "verdict": "confirmed",
                "reason": "attacker can request another object",
            }
        ]
    }
    result = risk_rating_tool(_ingestion_dict(), verified)
    assert result["threats"][0]["severity"] == "Critical"


def test_risk_rating_tool_prefers_authoritative_state_ingestion() -> None:
    verified = {
        "threats": [
            {
                "title": "BOLA",
                "stride": "E",
                "element_id": "api",
                "reachable": True,
                "attack_path": "net -> in -> api",
                "verdict": "confirmed",
                "reason": "attacker can request another object",
            }
        ]
    }
    corrupt_ingestion_arg = {
        "artifact_type": "generic_doc",
        "system_model": {
            "name": "corrupt",
            "actors": [1, 2, 3],
            "components": [1, 2, 3],
            "data_flows": [1, 2, 3],
        },
    }

    result = risk_rating_tool(
        corrupt_ingestion_arg,
        verified,
        tool_context=_ToolContext({"ingestion_result": _ingestion_dict()}),
    )

    assert result["threats"][0]["element_id"] == "api"


def test_report_render_tool_uses_renderer_not_freeform_markdown() -> None:
    rated = risk_rating_tool(
        _ingestion_dict(),
        {
            "threats": [
                {
                    "title": "BOLA",
                    "stride": "E",
                    "element_id": "api",
                    "reachable": True,
                    "attack_path": "net -> in -> api",
                    "mitigating_controls": ["object-level authorization"],
                    "verdict": "confirmed",
                    "reason": "attacker can request another object",
                }
            ]
        },
    )
    result = report_render_tool(_ingestion_dict(), rated)
    assert result["markdown"].startswith("# Threat Model: payments")
    assert "| Severity |" in result["markdown"]
