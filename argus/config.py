"""Single source of truth for Gemini model ids and LLM settings.

DESIGN GOTCHA (§5 of the design spec): the Gemini model line moves fast.
Gemini 2.0 was retired 2026-06-01; 3.x models now exist. Always pin current
GA aliases here and re-verify at build time. Override via environment variables
without any code changes.

Never hardcode model ids anywhere else in the codebase — import from here.
"""

import os

#: Reasoning/enumeration model — use Gemini Pro for the threat-enumeration agent.
PRO_MODEL: str = os.getenv("ARGUS_PRO_MODEL", "gemini-2.5-pro")

#: Lighter model for ingestion, triage, and report rendering.
FLASH_MODEL: str = os.getenv("ARGUS_FLASH_MODEL", "gemini-2.5-flash")

#: Low temperature for deterministic, auditable output.
TEMPERATURE: float = float(os.getenv("ARGUS_TEMPERATURE", "0.1"))


def api_key() -> str | None:
    """Return the Gemini API key from the environment. Never hardcode this value.

    Uses the AI Studio free-tier key (same key works for ADK). Set via:
        export GEMINI_API_KEY=your-key-here
    or copy .env.example → .env (gitignored).
    """
    return os.getenv("GEMINI_API_KEY")
