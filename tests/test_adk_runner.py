"""Tests for the ADK runtime bridge."""

import pytest

from argus.agents.runner import run_threat_model_adk


class _NodeInfo:
    def __init__(self, name: str):
        self.name = name
        self.path = f"argus/{name}"


class _Event:
    def __init__(self, author: str):
        self.author = author
        self.node_info = _NodeInfo(author)


class _Session:
    def __init__(self, state: dict):
        self.state = state
        self.id = "session-1"


class _SessionService:
    def __init__(self):
        self.session = None

    async def create_session(self, *, app_name, user_id, state=None, session_id=None):
        self.session = _Session(dict(state or {}))
        return self.session

    async def get_session(self, *, app_name, user_id, session_id, config=None):
        return self.session


class _Runner:
    app_name = "argus"

    def __init__(
        self,
        final_report: dict | None = None,
        state_update: dict | None = None,
        events: list[_Event] | None = None,
    ):
        self.session_service = _SessionService()
        self.final_report = final_report
        self.state_update = state_update or {}
        self.events = events or []
        self.run_calls = []

    def run(self, **kwargs):
        self.run_calls.append(kwargs)
        self.session_service.session.state.update(self.state_update)
        if self.final_report is not None:
            self.session_service.session.state["final_report"] = self.final_report
        return iter(self.events)


def test_run_threat_model_adk_seeds_input_state_and_returns_final_markdown() -> None:
    runner = _Runner(final_report={"markdown": "# Threat Model: payments"})
    report = run_threat_model_adk(
        input_text="# Feature\nPayments API",
        source_name="feature.md",
        runner_factory=lambda: runner,
    )

    assert report == "# Threat Model: payments"
    assert runner.session_service.session.state["input_text"] == "# Feature\nPayments API"
    assert runner.session_service.session.state["source_name"] == "feature.md"
    assert "untrusted-data" in runner.session_service.session.state["input_text_guarded"]
    assert runner.run_calls
    message_text = runner.run_calls[0]["new_message"].parts[0].text
    assert "# Feature\nPayments API" in message_text
    assert "<untrusted-data" in message_text


def test_run_threat_model_adk_fails_when_report_agent_does_not_write_final_report() -> None:
    runner = _Runner(final_report=None)
    with pytest.raises(RuntimeError, match="final_report"):
        run_threat_model_adk("design text", "design.md", runner_factory=lambda: runner)


def test_run_threat_model_adk_returns_deterministic_renderer_output_when_state_is_available() -> (
    None
):
    runner = _Runner(
        final_report={"markdown": "# Freehand report"},
        state_update={
            "ingestion_result": {
                "artifact_type": "prd",
                "system_model": {
                    "name": "payments",
                    "actors": [{"id": "net", "name": "Internet", "privilege": "anon"}],
                    "components": [{"id": "api", "name": "API", "type": "api"}],
                    "data_flows": [{"id": "in", "source": "net", "dest": "api"}],
                },
                "source_summary": "Payments PRD.",
                "security_relevant_facts": ["Public API."],
            },
            "rated_threats": {
                "threats": [
                    {
                        "template_id": "T-000",
                        "title": "Missing authorization",
                        "stride": "E",
                        "element_id": "api",
                        "element_kind": "component",
                        "status": "reported",
                        "attack_path": "net -> in -> api",
                        "controls": [],
                        "rating": {
                            "likelihood_level": "HIGH",
                            "impact_level": "HIGH",
                            "severity": "Critical",
                        },
                    }
                ]
            },
        },
    )

    report = run_threat_model_adk("prd text", "prd.md", runner_factory=lambda: runner)

    assert report.startswith("# Threat Model: payments")
    assert "# Freehand report" not in report


def test_run_threat_model_adk_reports_progress_from_stage_events() -> None:
    progress = []
    runner = _Runner(
        final_report={"markdown": "# Threat Model: payments"},
        events=[
            _Event("ingestion_agent"),
            _Event("architecture_zone_agent"),
            _Event("report_agent"),
        ],
    )

    run_threat_model_adk(
        "prd text",
        "prd.md",
        runner_factory=lambda: runner,
        progress_callback=lambda stage, status: progress.append((stage, status)),
    )

    assert progress == [
        ("ingestion_agent", "started"),
        ("ingestion_agent", "completed"),
        ("architecture_zone_agent", "started"),
        ("architecture_zone_agent", "completed"),
        ("report_agent", "started"),
        ("report_agent", "completed"),
    ]
