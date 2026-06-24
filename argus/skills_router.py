"""Just-in-time skill selection: map a SystemModel to relevant Agent Skills."""

from argus.models import SystemModel

# Component.type values that map directly to a skill domain.
_TYPE_TO_SKILL: dict[str, str] = {
    "web": "owasp-web-top10",
    "api": "owasp-api-top10",
}

# Component.properties flags that signal an AI/agent/MCP domain.
_CONTROL_SKILLS: frozenset[str] = frozenset({
    "owasp-asvs",
    "owasp-cheatsheets",
    "owasp-proactive-controls",
})

_PROP_TO_SKILLS: dict[str, set[str]] = {
    "llm": {
        "owasp-llm-top10",
        "owasp-llm-apps-top10",
        "mitre-atlas",
        *_CONTROL_SKILLS,
    },
    "ml": {"owasp-ml-top10", "mitre-atlas"},
    "agentic": {
        "owasp-agentic-top10",
        "owasp-llm-top10",
        "owasp-llm-apps-top10",
        "aiuc-agent-standard",
        "mitre-atlas",
        *_CONTROL_SKILLS,
    },
    "mcp": {
        "owasp-mcp-security",
        "owasp-agentic-top10",
        "owasp-llm-top10",
        "owasp-llm-apps-top10",
        "aiuc-agent-standard",
        "mitre-atlas",
        *_CONTROL_SKILLS,
    },
}

_ALWAYS: frozenset[str] = frozenset({"owasp-risk-rating"})


def system_tags(model: SystemModel) -> set[str]:
    """Collect domain tags from component types and AI property flags."""
    tags: set[str] = set()
    prop_tags = set(_PROP_TO_SKILLS.keys())
    for component in model.components:
        if component.type in _TYPE_TO_SKILL:
            tags.add(component.type)
        tags |= set(component.properties) & prop_tags
    return tags


def select_skills(model: SystemModel) -> list[str]:
    """Return a sorted list of skill names to load for this system model."""
    skills: set[str] = set(_ALWAYS)
    tags = system_tags(model)

    for tag, skill_name in _TYPE_TO_SKILL.items():
        if tag in tags:
            skills.add(skill_name)

    for tag, tag_skills in _PROP_TO_SKILLS.items():
        if tag in tags:
            skills |= tag_skills

    return sorted(skills)
