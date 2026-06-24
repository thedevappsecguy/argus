"""Tests for dependency declaration hygiene."""

import pathlib
import tomllib


def _declared_specs() -> list[str]:
    data = tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))
    specs = list(data["project"]["dependencies"])
    for optional_specs in data["project"].get("optional-dependencies", {}).values():
        specs.extend(optional_specs)
    specs.extend(data["build-system"]["requires"])
    return specs


def test_direct_dependency_specs_are_exactly_pinned() -> None:
    for spec in _declared_specs():
        assert "==" in spec
        assert not any(operator in spec for operator in ("*", ">=", "<=", ">", "<", "~=", "^"))
