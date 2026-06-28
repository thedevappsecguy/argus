"""Tests for argus.config - model ids and runtime config resolution."""

from pathlib import Path

import pytest

from argus import config


def test_default_models_are_non_empty() -> None:
    resolved = config.resolve_runtime_config(load_env_file=False)
    assert resolved.pro_model and "gemini" in resolved.pro_model
    assert resolved.flash_model and "gemini" in resolved.flash_model


def test_temperature_is_low() -> None:
    resolved = config.resolve_runtime_config(load_env_file=False)
    assert 0.0 <= resolved.temperature <= 0.5


def test_resolve_runtime_config_prefers_cli_specific_models_over_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_PRO_MODEL", "gemini-env-pro")
    monkeypatch.setenv("ARGUS_FLASH_MODEL", "gemini-env-flash")

    resolved = config.resolve_runtime_config(
        pro_model="gemini-cli-pro",
        flash_model="gemini-cli-flash",
        load_env_file=False,
    )

    assert resolved.pro_model == "gemini-cli-pro"
    assert resolved.flash_model == "gemini-cli-flash"


def test_resolve_runtime_config_uses_model_shortcut_unless_specific_model_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARGUS_PRO_MODEL", raising=False)
    monkeypatch.delenv("ARGUS_FLASH_MODEL", raising=False)

    resolved = config.resolve_runtime_config(
        model="gemini-cheap",
        flash_model="gemini-fast",
        load_env_file=False,
    )

    assert resolved.pro_model == "gemini-cheap"
    assert resolved.flash_model == "gemini-fast"


def test_resolve_runtime_config_loads_dotenv_without_overriding_exported_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "GEMINI_API_KEY=dotenv-key",
                "ARGUS_PRO_MODEL=dotenv-pro",
                "ARGUS_FLASH_MODEL=dotenv-flash",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARGUS_PRO_MODEL", "exported-pro")
    monkeypatch.delenv("ARGUS_FLASH_MODEL", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    resolved = config.resolve_runtime_config()

    assert resolved.api_key == "dotenv-key"
    assert resolved.pro_model == "exported-pro"
    assert resolved.flash_model == "dotenv-flash"


def test_resolve_runtime_config_rejects_blank_cli_model() -> None:
    with pytest.raises(ValueError, match="--model cannot be blank"):
        config.resolve_runtime_config(model=" ", load_env_file=False)


def test_resolve_runtime_config_rejects_invalid_temperature() -> None:
    with pytest.raises(ValueError, match="temperature"):
        config.resolve_runtime_config(temperature=-0.1, load_env_file=False)


def test_api_key_returns_none_when_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert config.api_key(load_env_file=False) is None
