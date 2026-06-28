"""Runtime configuration for Argus.

Model IDs and generation settings are resolved at runtime so CLI flags can
override exported environment variables, .env values, and built-in defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import find_dotenv, load_dotenv

DEFAULT_PRO_MODEL = "gemini-2.5-pro"
DEFAULT_FLASH_MODEL = "gemini-2.5-flash"
DEFAULT_TEMPERATURE = 0.1

# Backward-compatible defaults for callers that still import module constants.
PRO_MODEL: str = os.getenv("ARGUS_PRO_MODEL", DEFAULT_PRO_MODEL)
FLASH_MODEL: str = os.getenv("ARGUS_FLASH_MODEL", DEFAULT_FLASH_MODEL)
TEMPERATURE: float = float(os.getenv("ARGUS_TEMPERATURE", str(DEFAULT_TEMPERATURE)))


@dataclass(frozen=True)
class RuntimeConfig:
    """Resolved runtime configuration for one Argus run."""

    pro_model: str
    flash_model: str
    temperature: float
    api_key: str | None


def load_env() -> None:
    """Load .env from the current working tree without overriding exported env."""
    dotenv_path = find_dotenv(usecwd=True)
    if dotenv_path:
        load_dotenv(dotenv_path, override=False)


def _clean_cli_value(value: str | None, flag_name: str) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{flag_name} cannot be blank")
    return cleaned


def _env_value(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _temperature_from_env() -> float:
    value = _env_value("ARGUS_TEMPERATURE")
    if value is None:
        return DEFAULT_TEMPERATURE
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError("ARGUS_TEMPERATURE must be a number") from exc


def _validate_temperature(value: float) -> float:
    if not 0.0 <= value <= 2.0:
        raise ValueError("temperature must be between 0.0 and 2.0")
    return value


def resolve_runtime_config(
    *,
    model: str | None = None,
    pro_model: str | None = None,
    flash_model: str | None = None,
    temperature: float | None = None,
    load_env_file: bool = True,
) -> RuntimeConfig:
    """Resolve runtime config from CLI values, environment, .env, and defaults."""
    if load_env_file:
        load_env()

    model_value = _clean_cli_value(model, "--model")
    pro_model_value = _clean_cli_value(pro_model, "--pro-model")
    flash_model_value = _clean_cli_value(flash_model, "--flash-model")

    resolved_temperature = temperature if temperature is not None else _temperature_from_env()
    resolved_temperature = _validate_temperature(float(resolved_temperature))

    return RuntimeConfig(
        pro_model=pro_model_value
        or model_value
        or _env_value("ARGUS_PRO_MODEL")
        or DEFAULT_PRO_MODEL,
        flash_model=flash_model_value
        or model_value
        or _env_value("ARGUS_FLASH_MODEL")
        or DEFAULT_FLASH_MODEL,
        temperature=resolved_temperature,
        api_key=_env_value("GEMINI_API_KEY"),
    )


def api_key(*, load_env_file: bool = True) -> str | None:
    """Return the Gemini API key from environment or .env.

    The API key intentionally has no CLI flag so it is not exposed through shell
    history or process listings.
    """
    return resolve_runtime_config(load_env_file=load_env_file).api_key
