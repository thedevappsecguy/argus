"""Tests for argus.rating — deterministic OWASP rating of verified threats."""

import pytest
from pydantic import ValidationError

from argus.models import Actor, Component, DataFlow, Privilege, SystemModel
from argus.rating import ImpactFactors, LikelihoodFactors, RatedThreat, ThreatStatus, rate_threats
from argus.threats import VerifiedThreat


def _model() -> SystemModel:
    return SystemModel(
        name="m",
        actors=[Actor(id="net", name="Internet", privilege=Privilege.ANON)],
        components=[Component(id="api", name="API", properties={"handles_user_input"})],
        data_flows=[DataFlow(id="in", source="net", dest="api", authenticated=False)],
    )


def _verified(
    element_id: str, verdict: str = "confirmed", reachable: bool = True, **kw
) -> VerifiedThreat:
    return VerifiedThreat(
        title=f"threat on {element_id}",
        stride="I",
        element_id=element_id,
        reachable=reachable,
        attack_path=kw.get("attack_path", "net -> in -> api"),
        mitigating_controls=kw.get("mitigating_controls", ["require auth on flow in"]),
        likelihood=kw.get("likelihood", {}),
        impact=kw.get("impact", {}),
        verdict=verdict,
        reason=kw.get("reason", "grounded in the model"),
    )


def test_rate_threats_reports_confirmed_reachable() -> None:
    m = _model()
    rated = rate_threats([_verified("api"), _verified("in")], m)
    assert len(rated) == 2
    assert all(isinstance(r, RatedThreat) for r in rated)
    assert all(r.status is ThreatStatus.REPORTED for r in rated)
    assert all(r.rating is not None for r in rated)
    # Attack path + controls carried through for the report.
    assert all(r.attack_path for r in rated)
    assert all(r.controls for r in rated)
    kinds = {r.element_id: r.element_kind for r in rated}
    assert kinds["api"] == "component"
    assert kinds["in"] == "data_flow"


def test_rate_threats_severity_is_deterministic_from_factors() -> None:
    m = _model()
    v = _verified(
        "api",
        likelihood={
            "ease_of_discovery": 9,
            "ease_of_exploit": 9,
            "awareness": 9,
            "intrusion_detection": 9,
        },
        impact={
            "loss_of_confidentiality": 9,
            "loss_of_integrity": 9,
            "non_compliance": 9,
            "privacy_violation": 9,
        },
    )
    assert rate_threats([v], m)[0].severity == "Critical"


def test_rate_threats_false_positive_is_not_applicable() -> None:
    """The agent's false-positive verdict → ruled out, no rating, reason kept."""
    m = _model()
    v = _verified("api", verdict="false_positive", reason="no untrusted path reaches api")
    rated = rate_threats([v], m)
    assert rated[0].status is ThreatStatus.NOT_APPLICABLE
    assert rated[0].rating is None
    assert "no untrusted path" in rated[0].reason


def test_rate_threats_suppressed_verdict_is_suppressed() -> None:
    """Threats fully covered by existing controls should be distinct from N/A."""
    m = _model()
    v = _verified("api", verdict="suppressed", reason="existing control fully breaks path")
    rated = rate_threats([v], m)
    assert rated[0].status is ThreatStatus.SUPPRESSED
    assert rated[0].rating is None
    assert "existing control" in rated[0].reason


def test_rate_threats_unreachable_is_not_applicable() -> None:
    """Confirmed-but-unreachable (agent judgement) is also ruled out."""
    m = _model()
    v = _verified("api", verdict="confirmed", reachable=False, reason="internal only")
    rated = rate_threats([v], m)
    assert rated[0].status is ThreatStatus.NOT_APPLICABLE
    assert rated[0].rating is None


def test_rate_threats_drops_unknown_element_id() -> None:
    """Structural anti-hallucination backstop: unknown element ids are dropped."""
    m = _model()
    v = _verified("ghost")
    assert rate_threats([v], m) == []


def test_likelihood_factor_scores_must_be_in_owasp_range() -> None:
    with pytest.raises(ValidationError):
        LikelihoodFactors(ease_of_exploit=10)

    with pytest.raises(ValidationError):
        LikelihoodFactors(ease_of_discovery=-1)


def test_impact_factor_scores_must_be_in_owasp_range() -> None:
    with pytest.raises(ValidationError):
        ImpactFactors(loss_of_confidentiality=10)

    with pytest.raises(ValidationError):
        ImpactFactors(privacy_violation=-1)


def test_factor_scores_accept_agent_list_shorthand() -> None:
    likelihood = LikelihoodFactors.model_validate([1, 2, 3, 4])
    impact = ImpactFactors.model_validate([5, 6, 7, 8])

    assert likelihood.ease_of_discovery == 1
    assert likelihood.ease_of_exploit == 2
    assert likelihood.awareness == 3
    assert likelihood.intrusion_detection == 4
    assert impact.loss_of_confidentiality == 5
    assert impact.loss_of_integrity == 6
    assert impact.non_compliance == 7
    assert impact.privacy_violation == 8
