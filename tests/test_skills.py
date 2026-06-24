"""Tests for argus.skills — skill loader and list_skills."""

import tomllib
from importlib import resources
from pathlib import Path

from argus.models import SystemModel
from argus.skills import SKILLS_DIR, list_skills, load_selected_skills, load_skill

ALL_OWASP = [
    "owasp-web-top10",
    "owasp-api-top10",
    "owasp-llm-top10",
    "owasp-ml-top10",
    "owasp-asvs",
    "owasp-cheatsheets",
    "owasp-agentic-top10",
    "owasp-mcp-security",
    "owasp-llm-apps-top10",
    "owasp-proactive-controls",
]

EXPECTED_SOURCE_URLS = {
    "owasp-cheatsheets": "https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets",
    "owasp-llm-apps-top10": "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/tree/main/2_0_vulns",
    "owasp-api-top10": "https://github.com/OWASP/API-Security/tree/master/editions/2023/en",
    "owasp-web-top10": "https://github.com/OWASP/Top10/tree/master/2025/docs/en",
    "owasp-mcp-security": "https://github.com/OWASP/www-project-mcp-top-10/tree/main/2025",
    "owasp-llm-top10": "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026",
    "owasp-agentic-top10": "https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative/tree/main/agentic-top-10/0.5-initial-candidates",
    "mitre-atlas": "https://github.com/mitre-atlas/atlas-data/blob/main/dist/ATLAS.yaml",
    "owasp-proactive-controls": "https://github.com/OWASP/www-project-proactive-controls/tree/master/docs/the-top-10",
    "aiuc-agent-standard": "https://www.aiuc-1.com/",
    "owasp-ml-top10": "https://github.com/OWASP/www-project-machine-learning-security-top-10/tree/master/docs",
    "owasp-asvs": "https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json",
}


def test_web_skill_loads_with_frontmatter_and_items() -> None:
    skill = load_skill("owasp-web-top10")
    assert skill["name"] == "owasp-web-top10"
    assert "web" in skill["description"].lower()
    assert len(skill["items"]) >= 5  # the Top-10 list
    assert "body" in skill and skill["body"].strip()


def test_list_skills_includes_web() -> None:
    assert "owasp-web-top10" in list_skills()


def test_all_owasp_skills_load_and_have_items() -> None:
    names = list_skills()
    for skill_name in ALL_OWASP:
        assert skill_name in names, f"Missing skill: {skill_name}"
        loaded = load_skill(skill_name)
        assert loaded["description"], f"{skill_name} has empty description"
        assert loaded["items"], f"{skill_name} has no items"


def test_nine_skills_total_including_atlas() -> None:
    names = list_skills()
    assert "mitre-atlas" in names
    assert len(names) >= 9


def test_exact_reference_urls_are_in_skill_body_and_items() -> None:
    """Every exact user-supplied reference URL must be preserved verbatim."""
    for skill_name, source_url in EXPECTED_SOURCE_URLS.items():
        loaded = load_skill(skill_name)
        skill_md = SKILLS_DIR / skill_name / "SKILL.md"
        assert source_url in skill_md.read_text(encoding="utf-8")
        assert loaded["items"], f"{skill_name} has no corpus items"
        assert all(i.get("source_url") == source_url for i in loaded["items"])


def test_skills_are_packaged_as_argus_resources() -> None:
    """Installed wheels must carry the exact-reference skill corpus."""
    skill_root = resources.files("argus.skill_corpus")
    assert (skill_root / "owasp-risk-rating" / "SKILL.md").is_file()
    assert (skill_root / "owasp-risk-rating" / "resources" / "list.yaml").is_file()


def test_pyproject_declares_skill_corpus_package_data() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]["argus.skill_corpus"]
    assert "*/SKILL.md" in package_data
    assert "*/resources/list.yaml" in package_data


def test_load_selected_skills_returns_always_loaded_content() -> None:
    """Empty model → only the compact risk-rating skill is always loaded."""
    text = load_selected_skills(SystemModel(name="m"))
    assert "owasp-risk-rating" in text
    assert "owasp-asvs" not in text
    assert "owasp-cheatsheets" not in text
    assert "owasp-proactive-controls" not in text
    assert len(text) > 50


def test_load_selected_skills_includes_api_skill_for_api_component() -> None:
    from argus.models import Component

    model = SystemModel(
        name="m",
        components=[Component(id="api", name="API", type="api")],
    )
    text = load_selected_skills(model)
    assert "owasp-api-top10" in text


def test_load_selected_skills_includes_item_names_and_source_urls() -> None:
    from argus.models import Component

    model = SystemModel(
        name="m",
        components=[Component(id="api", name="API", type="api")],
    )
    text = load_selected_skills(model)
    assert "API1:2023" in text
    assert "Broken Object Level Authorization" in text
    assert EXPECTED_SOURCE_URLS["owasp-api-top10"] in text


def test_load_skill_raises_for_unknown() -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        load_skill("nonexistent-skill-xyz")
