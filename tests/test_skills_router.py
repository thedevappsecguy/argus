"""Tests for argus.skills_router — just-in-time skill selection."""

from argus.models import Component, SystemModel
from argus.skills_router import select_skills, system_tags


def _model_with(component: Component) -> SystemModel:
    return SystemModel(name="m", components=[component])


def test_always_loads_only_risk_rating() -> None:
    skills = select_skills(SystemModel(name="empty"))
    assert skills == ["owasp-risk-rating"]


def test_web_component_adds_web_skill() -> None:
    skills = select_skills(_model_with(Component(id="ui", name="UI", type="web")))
    assert "owasp-web-top10" in skills


def test_api_component_adds_api_skill() -> None:
    skills = select_skills(_model_with(Component(id="api", name="API", type="api")))
    assert "owasp-api-top10" in skills


def test_llm_property_pulls_atlas_and_llm_list() -> None:
    skills = select_skills(_model_with(Component(id="c", name="c", properties={"llm"})))
    assert {
        "owasp-llm-top10",
        "owasp-llm-apps-top10",
        "mitre-atlas",
        "owasp-asvs",
        "owasp-cheatsheets",
        "owasp-proactive-controls",
    } <= set(skills)


def test_ml_property_pulls_atlas_and_ml_list() -> None:
    skills = select_skills(_model_with(Component(id="c", name="c", properties={"ml"})))
    assert {"owasp-ml-top10", "mitre-atlas"} <= set(skills)


def test_mcp_property_pulls_mcp_agentic_and_atlas() -> None:
    skills = select_skills(_model_with(Component(id="c", name="c", properties={"mcp"})))
    assert {
        "owasp-mcp-security",
        "owasp-agentic-top10",
        "owasp-llm-top10",
        "owasp-llm-apps-top10",
        "aiuc-agent-standard",
        "mitre-atlas",
        "owasp-asvs",
        "owasp-cheatsheets",
        "owasp-proactive-controls",
    } <= set(skills)


def test_agentic_property_pulls_agentic_and_atlas() -> None:
    skills = select_skills(_model_with(Component(id="c", name="c", properties={"agentic"})))
    assert {
        "owasp-agentic-top10",
        "owasp-llm-top10",
        "owasp-llm-apps-top10",
        "aiuc-agent-standard",
        "mitre-atlas",
        "owasp-asvs",
        "owasp-cheatsheets",
        "owasp-proactive-controls",
    } <= set(skills)


def test_system_tags_reads_type_and_properties() -> None:
    m = _model_with(Component(id="c", name="c", type="web", properties={"agentic"}))
    tags = system_tags(m)
    assert {"web", "agentic"} <= tags


def test_system_tags_ignores_unknown_properties() -> None:
    m = _model_with(Component(id="c", name="c", properties={"unknown_tag"}))
    tags = system_tags(m)
    assert "unknown_tag" not in tags


def test_result_is_sorted() -> None:
    """select_skills must return a sorted list for deterministic prompts."""
    skills = select_skills(SystemModel(name="m"))
    assert skills == sorted(skills)
