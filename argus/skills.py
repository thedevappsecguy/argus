"""Load and validate Agent Skills (SKILL.md + resources/list.yaml folders).

A skill = a folder under ``argus/skill_corpus/<name>/`` with:
- ``SKILL.md``: YAML frontmatter (name, description) + markdown body (when-to-use, key-checks)
- ``resources/list.yaml``: the corpus items as structured data

The threat-modeling agents (Plan 4) load the body + items of the skills chosen by
``skills_router.select_skills`` and include them in their prompts as grounding context.
"""

from __future__ import annotations

from importlib import resources

import yaml

SKILLS_DIR = resources.files("argus.skill_corpus")


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split a ``---``-delimited YAML frontmatter block from the markdown body.

    Args:
        text: Full SKILL.md file content.

    Returns:
        A (frontmatter_dict, body_str) tuple.
    """
    if text.startswith("---"):
        _, fm_block, body = text.split("---", 2)
        return yaml.safe_load(fm_block) or {}, body.strip()
    return {}, text.strip()


def list_skills() -> list[str]:
    """Return names of all skill folders that contain a SKILL.md."""
    if not SKILLS_DIR.exists():
        return []
    return sorted(
        p.name
        for p in SKILLS_DIR.iterdir()
        if p.is_dir() and (p / "SKILL.md").exists()
    )


def load_skill(name: str) -> dict:
    """Load a skill by name and return its metadata, body, and items.

    Args:
        name: The skill folder name (e.g. ``"owasp-web-top10"``).

    Returns:
        Dict with keys: ``name``, ``description``, ``body``, ``items``.

    Raises:
        FileNotFoundError: If the skill folder or SKILL.md does not exist.
        ValueError: If frontmatter is missing required name or description.
    """
    folder = SKILLS_DIR / name
    skill_md = folder / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(f"Skill not found: {name}")

    fm, body = _parse_frontmatter(skill_md.read_text(encoding="utf-8"))

    if not fm.get("name") or not fm.get("description"):
        raise ValueError(f"Skill {name}: SKILL.md frontmatter requires 'name' and 'description'")

    list_path = folder / "resources" / "list.yaml"
    items: list = []
    if list_path.exists():
        items = yaml.safe_load(list_path.read_text(encoding="utf-8")) or []

    return {
        "name": fm["name"],
        "description": fm["description"],
        "body": body,
        "items": items,
    }


def _format_item(item) -> str:  # noqa: ANN001
    """Render one skill resource item as compact prompt grounding text."""
    if not isinstance(item, dict):
        return f"- {item}"

    fields: list[str] = []
    item_id = item.get("id")
    name = item.get("name")
    if item_id and name:
        fields.append(f"{item_id}: {name}")
    elif item_id:
        fields.append(str(item_id))
    elif name:
        fields.append(str(name))

    for key in ("key_checks", "cwe", "asvs", "cheatsheet", "atlas_refs"):
        value = item.get(key)
        if not value:
            continue
        if isinstance(value, list):
            rendered = ", ".join(str(v) for v in value)
        else:
            rendered = str(value)
        fields.append(f"{key}=[{rendered}]")

    if item.get("source_url"):
        fields.append(f"source={item['source_url']}")

    return "- " + " | ".join(fields)


def load_selected_skills(model, max_items: int = 20) -> str:
    """Concatenate the body + items of every skill the router selects for this model.

    This is the missing link between the skill router (which picks skill *names*) and the
    agent prompts (which need skill *content*). Called by ADK tools to build grounding text
    passed to enumeration, verification, control-challenge, and risk-rating agents.

    Args:
        model: A SystemModel instance.
        max_items: Maximum number of item ids to include per skill.

    Returns:
        A multi-section string with each skill's body and item list.
    """
    from argus.skills_router import select_skills  # avoid circular import at module level

    blocks: list[str] = []
    for skill_name in select_skills(model):
        skill = load_skill(skill_name)
        item_lines = "\n".join(_format_item(i) for i in skill["items"][:max_items])
        blocks.append(
            f"## {skill['name']}: {skill['description']}\n"
            f"{skill['body']}\n"
            f"Items:\n{item_lines}"
        )
    return "\n\n".join(blocks)
