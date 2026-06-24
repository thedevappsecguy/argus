"""Tests for shared ADK threat schemas and element binding."""

from argus.models import Actor, Component, DataFlow, Privilege, SystemModel
from argus.threats import ProposedThreat, ProposedThreats, validate_proposed


def _model() -> SystemModel:
    return SystemModel(
        name="m",
        actors=[Actor(id="net", name="Internet", privilege=Privilege.ANON)],
        components=[
            Component(id="api", name="API", properties={"handles_user_input", "serves_objects"}),
            Component(id="cache", name="Cache"),
        ],
        data_flows=[DataFlow(id="in", source="net", dest="api", authenticated=False)],
    )


def test_proposed_threat_is_lightweight_candidate_no_cwe() -> None:
    p = ProposedThreat(
        title="IDOR on API",
        stride="E",
        element_id="api",
        rationale="serves_objects flag on api component",
        scenario="attacker requests another user's object through the API",
    )
    assert p.title == "IDOR on API"
    assert not hasattr(p, "cwe")
    assert not hasattr(p, "likelihood")


def test_validate_proposed_keeps_valid_known_element() -> None:
    proposed = ProposedThreats(
        threats=[
            ProposedThreat(
                title="IDOR on API",
                stride="E",
                element_id="api",
                rationale="serves_objects flag on api component",
                owasp_refs=["API1:2023"],
            )
        ]
    )
    valid = validate_proposed(proposed, _model())
    assert len(valid) == 1
    assert valid[0].title == "IDOR on API"


def test_validate_proposed_drops_unknown_element_id() -> None:
    proposed = ProposedThreats(
        threats=[
            ProposedThreat(
                title="Ghost threat", stride="T", element_id="nonexistent", rationale="x"
            )
        ]
    )
    valid = validate_proposed(proposed, _model())
    assert len(valid) == 0
