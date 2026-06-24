# mypy: ignore-errors
"""Runtime bridge for executing the ADK-only Argus workflow."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from uuid import uuid4

from google.adk.runners import InMemoryRunner
from google.genai import types

from argus.agents.adk_app import root_agent
from argus.agents.tools import report_render_tool
from argus.security.input_guard import wrap_untrusted


def build_runner() -> InMemoryRunner:
    """Create the ADK runner for the Argus workflow."""
    return InMemoryRunner(agent=root_agent, app_name="argus")


async def _create_session(runner, user_id: str, session_id: str, state: dict):
    return await runner.session_service.create_session(
        app_name=runner.app_name,
        user_id=user_id,
        session_id=session_id,
        state=state,
    )


async def _get_session(runner, user_id: str, session_id: str):
    return await runner.session_service.get_session(
        app_name=runner.app_name,
        user_id=user_id,
        session_id=session_id,
    )


def _render_authoritative_report(state: dict) -> str | None:
    ingestion_result = state.get("ingestion_result")
    rated_threats = state.get("rated_threats")
    if not isinstance(ingestion_result, dict) or not isinstance(rated_threats, dict):
        return None

    rendered = report_render_tool(ingestion_result, rated_threats)
    markdown = rendered.get("markdown")
    return markdown if isinstance(markdown, str) and markdown.strip() else None


def run_threat_model_adk(
    input_text: str,
    source_name: str,
    *,
    runner_factory: Callable[[], object] | None = None,
) -> str:
    """Run the ADK agent workflow and return the final Markdown report."""
    runner = runner_factory() if runner_factory else build_runner()
    user_id = "argus-cli"
    session_id = f"argus-{uuid4()}"
    guarded_input = wrap_untrusted(source_name, input_text)
    state = {
        "input_text": input_text,
        "input_text_guarded": guarded_input,
        "source_name": source_name,
    }

    asyncio.run(_create_session(runner, user_id, session_id, state))
    message = types.UserContent(
        parts=[
            types.Part(
                text=(
                    "Run the complete Argus ADK threat-model workflow for the system described "
                    "in this source document. Threat-model the document content, not Argus or "
                    "the workflow runtime.\n\n"
                    f"SOURCE NAME: {source_name}\n\n"
                    f"{guarded_input}"
                )
            )
        ]
    )
    for _event in runner.run(
        user_id=user_id,
        session_id=session_id,
        new_message=message,
    ):
        pass

    session = asyncio.run(_get_session(runner, user_id, session_id))
    session_state = session.state if session else {}
    markdown = _render_authoritative_report(session_state)
    if markdown:
        return markdown

    final_report = session_state.get("final_report")
    if isinstance(final_report, dict):
        markdown = final_report.get("markdown")
    else:
        markdown = final_report
    if not isinstance(markdown, str) or not markdown.strip():
        raise RuntimeError("ADK workflow completed without final_report markdown.")
    return markdown
