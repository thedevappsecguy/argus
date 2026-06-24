"""Tests for the ADK-only Argus agent graph."""


def _tool_names(agent) -> set[str]:
    return {tool.name for tool in agent.tools}


def test_adk_app_has_stage_agents_in_order() -> None:
    from google.adk.agents import SequentialAgent

    from argus.agents import adk_app

    assert isinstance(adk_app.root_agent, SequentialAgent)
    assert [agent.name for agent in adk_app.root_agent.sub_agents] == [
        "ingestion_agent",
        "architecture_zone_agent",
        "entry_point_agent",
        "scenario_enumeration_agent",
        "schema_validation_agent",
        "element_binding_agent",
        "false_positive_validation_agent",
        "control_challenge_agent",
        "risk_rating_agent",
        "report_agent",
    ]


def test_adk_agents_write_expected_state_keys() -> None:
    from argus.agents import adk_app

    output_keys = {agent.name: agent.output_key for agent in adk_app.root_agent.sub_agents}
    assert output_keys == {
        "ingestion_agent": "ingestion_result",
        "architecture_zone_agent": "architecture_zones",
        "entry_point_agent": "entry_points",
        "scenario_enumeration_agent": "proposed_threats",
        "schema_validation_agent": "schema_validation",
        "element_binding_agent": "validated_proposals",
        "false_positive_validation_agent": "verified_threats",
        "control_challenge_agent": "control_challenges",
        "risk_rating_agent": "rated_threats",
        "report_agent": "final_report",
    }


def test_adk_agents_have_only_stage_relevant_tools() -> None:
    from argus.agents import adk_app

    agents = {agent.name: agent for agent in adk_app.root_agent.sub_agents}
    assert _tool_names(agents["ingestion_agent"]) == set()
    assert _tool_names(agents["architecture_zone_agent"]) == {"model_context_tool"}
    assert _tool_names(agents["entry_point_agent"]) == {"model_context_tool"}
    assert _tool_names(agents["scenario_enumeration_agent"]) == {
        "model_context_tool",
        "skills_tool",
    }
    assert _tool_names(agents["schema_validation_agent"]) == {"schema_validation_tool"}
    assert _tool_names(agents["element_binding_agent"]) == {"element_validation_tool"}
    assert _tool_names(agents["false_positive_validation_agent"]) == {
        "model_context_tool",
        "skills_tool",
    }
    assert _tool_names(agents["control_challenge_agent"]) == {
        "model_context_tool",
        "skills_tool",
    }
    assert _tool_names(agents["risk_rating_agent"]) == {
        "skills_tool",
        "risk_rating_tool",
    }
    assert _tool_names(agents["report_agent"]) == {"report_render_tool"}


def test_adk_app_does_not_expose_removed_runtime_tools() -> None:
    from argus.agents import adk_app

    assert not hasattr(adk_app, "kb_toolset")
    assert not hasattr(adk_app, "assess_tool")
    all_tools = set().union(*(_tool_names(agent) for agent in adk_app.root_agent.sub_agents))
    assert "lookup_weaknesses" not in all_tools
    assert "get_attack_patterns" not in all_tools


def test_downstream_agents_use_ingestion_result_context() -> None:
    from argus.agents import adk_app

    for agent in adk_app.root_agent.sub_agents[1:]:
        assert "ingestion_result" in agent.instruction


def test_element_binding_uses_schema_validated_payload() -> None:
    from argus.agents import adk_app

    instruction = adk_app.element_binding_agent.instruction
    assert "schema_validation.normalized" in instruction
    assert "{proposed_threats}" not in instruction


def test_ingestion_response_schema_is_gemini_compatible() -> None:
    from argus.agents.schemas import IngestionResult

    def _contains_key(value, key: str) -> bool:  # noqa: ANN001
        if isinstance(value, dict):
            return key in value or any(_contains_key(v, key) for v in value.values())
        if isinstance(value, list):
            return any(_contains_key(item, key) for item in value)
        return False

    assert not _contains_key(IngestionResult.model_json_schema(), "uniqueItems")
