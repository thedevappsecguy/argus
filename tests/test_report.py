"""Tests for argus.report — developer-facing Markdown renderer (no CWE, attack path + controls)."""

from argus.models import Actor, Component, DataFlow, Privilege, SystemModel
from argus.rating import RatedThreat, ThreatStatus
from argus.report import render_report
from argus.risk import rate


def _webhook_model() -> SystemModel:
    return SystemModel(
        name="x",
        scope="webhook test",
        actors=[Actor(id="net", name="Internet", privilege=Privilege.ANON)],
        components=[Component(id="hook", name="Webhook", properties={"makes_outbound_requests"})],
        data_flows=[DataFlow(id="in", source="net", dest="hook", authenticated=False)],
    )


def _ssrf_threat() -> RatedThreat:
    return RatedThreat(
        template_id="T-000",
        title="Server-Side Request Forgery",
        stride="I",
        element_id="hook",
        element_kind="component",
        status=ThreatStatus.REPORTED,
        reason="hook makes outbound requests reachable from net",
        attack_path="net -> in -> hook -> attacker-controlled URL",
        controls=["egress allowlist", "block link-local/metadata IPs"],
        rating=rate({"a": 7}, {"b": 7}),
    )


def test_render_report_contains_header_and_model_name() -> None:
    report = render_report(_webhook_model(), [_ssrf_threat()])
    assert "# Threat Model: x" in report
    assert "webhook test" in report


def test_render_report_contains_threats_table_with_attack_path_and_controls() -> None:
    report = render_report(_webhook_model(), [_ssrf_threat()])
    assert "| Severity |" in report
    assert "Server-Side Request Forgery" in report
    assert "net -> in -> hook" in report  # grounded attack path
    assert "egress allowlist" in report  # mitigating controls


def test_render_report_has_no_cwe() -> None:
    """CWE is intentionally absent from the developer-facing report."""
    report = render_report(_webhook_model(), [_ssrf_threat()])
    assert "CWE" not in report


def test_render_report_shows_ruled_out_section() -> None:
    fp = RatedThreat(
        template_id="T-001",
        title="Theoretical tampering",
        stride="T",
        element_id="hook",
        element_kind="component",
        status=ThreatStatus.NOT_APPLICABLE,
        reason="no untrusted path reaches this internal step",
    )
    report = render_report(_webhook_model(), [_ssrf_threat(), fp])
    assert "Ruled out" in report
    assert "Theoretical tampering" in report
    assert "no untrusted path" in report


def test_render_report_shows_open_questions() -> None:
    m = _webhook_model()
    m.assumptions.append("OPEN QUESTION: Is the webhook rate-limited?")
    report = render_report(m, [_ssrf_threat()])
    assert "OPEN QUESTION" in report
    assert "rate-limited" in report


def test_render_report_includes_coverage_note() -> None:
    report = render_report(_webhook_model(), [_ssrf_threat()])
    assert "Coverage & limitations" in report
    assert "augment" in report.lower()
    assert "false-positive gate" in report.lower()


def test_render_report_empty_threats_renders_cleanly() -> None:
    report = render_report(_webhook_model(), [])
    assert "_No threats reported_" in report


def test_render_report_dfd_shows_flows() -> None:
    report = render_report(_webhook_model(), [_ssrf_threat()])
    assert "net" in report and "hook" in report
