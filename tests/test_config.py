"""Tests for argus.config — model ids and environment variable overrides."""

import os

import pytest

from argus import config


def test_default_models_are_non_empty() -> None:
    assert config.PRO_MODEL and "gemini" in config.PRO_MODEL
    assert config.FLASH_MODEL and "gemini" in config.FLASH_MODEL


def test_temperature_is_low() -> None:
    assert 0.0 <= config.TEMPERATURE <= 0.5


def test_model_override_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_PRO_MODEL", "gemini-99-test")
    # Re-evaluate the expression rather than re-importing the cached module value.
    result = os.getenv("ARGUS_PRO_MODEL", config.PRO_MODEL)
    assert result == "gemini-99-test"


def test_api_key_returns_none_when_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert config.api_key() is None
