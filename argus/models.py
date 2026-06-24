"""Canonical, framework-agnostic representation of a system under threat modeling.

ADK ingestion normalizes document input into a SystemModel; the threat workflow reasons only
about this type. This module must remain free of agent runtime concerns.

Design: each class has a single responsibility. Enums provide typed vocabulary across
the whole codebase, eliminating magic strings.
"""

from enum import Enum

from pydantic import BaseModel, Field


class Privilege(str, Enum):
    """Actor privilege levels, from least- to most-trusted."""

    ANON = "anon"
    USER = "user"
    ADMIN = "admin"
    SERVICE = "service"
    THIRD_PARTY = "third_party"


class Classification(str, Enum):
    """Data sensitivity classifications used to calibrate impact scoring."""

    PUBLIC = "public"
    INTERNAL = "internal"
    PII = "pii"
    PCI = "pci"
    PHI = "phi"
    SECRET = "secret"
    IP = "ip"


#: Classifications that count as "sensitive" for impact scoring and the plaintext check.
SENSITIVE: frozenset[Classification] = frozenset({
    Classification.PII,
    Classification.PCI,
    Classification.PHI,
    Classification.SECRET,
    Classification.IP,
})


class Actor(BaseModel):
    """A human or system principal that initiates data flows.

    Trusted actors (internal jobs, admins marked trusted=True) are excluded from the
    reachability graph — they do not widen the attacker-reachable surface.
    """

    id: str
    name: str
    privilege: Privilege
    trusted: bool = False  # internal/admin/service may be explicitly trusted


class Component(BaseModel):
    """A deployable element: service, datastore, external entity, or queue.

    ``properties`` are free-form capability tags the catalog matches against.
    Examples: ``handles_user_input``, ``makes_outbound_requests``, ``queries_datastore``,
    ``serves_objects``, ``stores_sensitive``.
    """

    id: str
    name: str
    type: str = "service"  # service | datastore | external | queue | api | web
    properties: list[str] = Field(default_factory=list)


class DataFlow(BaseModel):
    """A directed data exchange between two elements.

    ``source`` and ``dest`` are Actor.id or Component.id values.
    ``data`` records which classifications of data cross this flow.
    """

    id: str
    source: str
    dest: str
    protocol: str = "https"
    authenticated: bool = True
    data: list[Classification] = Field(default_factory=list)


class TrustBoundary(BaseModel):
    """A named perimeter grouping components that share a trust level."""

    id: str
    name: str
    members: list[str] = Field(default_factory=list)  # Component.ids inside the boundary


class Control(BaseModel):
    """An existing security control the verifier reasons about when judging reachability.

    ``mitigates`` is a free-form list of what this control covers (threat names, areas, or
    flow ids); the verification agent uses it to rule out threats already fully covered.
    """

    id: str
    name: str
    mitigates: list[str] = Field(default_factory=list)


class SystemModel(BaseModel):
    """The canonical representation of a system under threat modeling.

    The ingestion agent produces a SystemModel; the engine consumes only this type.
    ``scope`` narrows the model to a feature delta rather than the whole universe.
    ``assumptions`` records gaps the ingestion agent had to assume.
    """

    name: str
    scope: str = ""
    actors: list[Actor] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    existing_controls: list[Control] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
