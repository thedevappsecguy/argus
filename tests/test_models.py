"""Tests for argus.models — the canonical SystemModel and its sub-types."""

from argus.models import (
    SENSITIVE,
    Actor,
    Classification,
    Component,
    Control,
    DataFlow,
    Privilege,
    SystemModel,
    TrustBoundary,
)


def test_build_minimal_system_model() -> None:
    m = SystemModel(
        name="demo",
        actors=[Actor(id="anon", name="Anonymous user", privilege=Privilege.ANON)],
        components=[Component(id="api", name="API", type="service",
                              properties={"handles_user_input"})],
        data_flows=[DataFlow(id="f1", source="anon", dest="api",
                             authenticated=False, data=[Classification.PII])],
        existing_controls=[Control(id="c1", name="WAF", mitigates=["T-RATELIMIT"])],
    )
    assert m.components[0].properties == ["handles_user_input"]
    assert m.data_flows[0].authenticated is False
    assert Classification.PII in m.data_flows[0].data
    assert m.existing_controls[0].mitigates == ["T-RATELIMIT"]


def test_sensitive_frozenset_contains_pii_pci_phi() -> None:
    assert Classification.PII in SENSITIVE
    assert Classification.PCI in SENSITIVE
    assert Classification.PHI in SENSITIVE
    assert Classification.SECRET in SENSITIVE
    assert Classification.IP in SENSITIVE
    assert Classification.PUBLIC not in SENSITIVE
    assert Classification.INTERNAL not in SENSITIVE


def test_privilege_enum_values() -> None:
    assert Privilege.ANON.value == "anon"
    assert Privilege.ADMIN.value == "admin"


def test_trust_boundary_model() -> None:
    tb = TrustBoundary(id="b1", name="Internet→App", members=["api", "db"])
    assert len(tb.members) == 2


def test_actor_trusted_flag_defaults_false() -> None:
    a = Actor(id="svc", name="Internal Service", privilege=Privilege.SERVICE)
    assert a.trusted is False
    a2 = Actor(id="svc2", name="Trusted Service", privilege=Privilege.SERVICE, trusted=True)
    assert a2.trusted is True


def test_system_model_defaults_to_empty_lists() -> None:
    m = SystemModel(name="empty")
    assert m.actors == []
    assert m.components == []
    assert m.data_flows == []
    assert m.existing_controls == []
    assert m.assumptions == []
