"""Live integration test for the ADK workflow. Skipped without GEMINI_API_KEY."""

import os

import pytest


@pytest.mark.live
def test_live_pipeline_produces_report_with_real_gemini() -> None:
    if os.getenv("ARGUS_RUN_LIVE") != "1":
        pytest.skip("ARGUS_RUN_LIVE=1 not set")
    if not os.getenv("GEMINI_API_KEY"):
        pytest.skip("GEMINI_API_KEY not set")

    from argus.agents.runner import run_threat_model_adk

    doc = (
        "We are building a REST API for a fintech startup. "
        "The API accepts HTTP POST requests from anonymous mobile clients. "
        "It stores PII and PCI data in a PostgreSQL database. "
        "It makes outbound calls to a payment processor. "
        "There is no authentication on the intake endpoint yet."
    )
    report = run_threat_model_adk(doc, "doc")

    assert "# Threat Model" in report
    assert "Severity" in report
    assert len(report) > 200
