"""Serialize a SystemModel into structured prompt context for the LLM/agent.

Replaces the old ``engine.build_model_context``. It deliberately does NOT pre-compute a
reachability set — under the LLM-primary design the agent reasons about exposure itself
from actor privileges, the data-flow graph, and trust boundaries (all presented below).
This keeps threat discovery free of hardcoded graph heuristics that could drop findings.
"""

from argus.models import SystemModel

#: Privilege values considered untrusted ingress (for the agent's exposure reasoning hint).
_UNTRUSTED = {"anon", "user", "third_party"}


def model_to_context(model: SystemModel) -> str:
    """Build a structured plaintext description of the full SystemModel for LLM prompts.

    Presents actors (with privilege), components (with type + capability properties),
    data flows (with auth/protocol/data classification), trust boundaries, existing
    controls, and assumptions — everything the agent needs to reason about threats and
    exposure without any precomputed gate.

    Args:
        model: The system model to describe.

    Returns:
        A structured multi-line string suitable for inclusion in an LLM prompt.
    """
    lines: list[str] = [f"SYSTEM: {model.name}"]
    if model.scope:
        lines.append(f"SCOPE: {model.scope}")

    untrusted_actors = sorted(
        a.id for a in model.actors
        if a.privilege.value in _UNTRUSTED or not a.trusted
    )

    lines.append("\nACTORS:")
    for a in model.actors:
        trust = "trusted" if a.trusted else "untrusted"
        lines.append(f"  - {a.id} (privilege={a.privilege.value}, {trust})")

    lines.append("\nCOMPONENTS:")
    for c in model.components:
        props = ", ".join(sorted(c.properties)) if c.properties else "none"
        lines.append(f"  - {c.id} (type={c.type})  properties: {props}")

    lines.append("\nDATA FLOWS:")
    for f in model.data_flows:
        auth_tag = "authenticated" if f.authenticated else "UNAUTHENTICATED"
        data_str = ", ".join(d.value for d in f.data) if f.data else "unclassified"
        lines.append(
            f"  - {f.id}: {f.source} -> {f.dest}"
            f"  [{f.protocol}, {auth_tag}, data={data_str}]"
        )

    if model.trust_boundaries:
        lines.append("\nTRUST BOUNDARIES:")
        for tb in model.trust_boundaries:
            lines.append(f"  - {tb.name}: contains {tb.members}")

    if model.existing_controls:
        lines.append("\nEXISTING CONTROLS (reason about what these already mitigate):")
        for ctrl in model.existing_controls:
            lines.append(f"  - {ctrl.id} ({ctrl.name}): mitigates {ctrl.mitigates}")

    if model.assumptions:
        lines.append("\nASSUMPTIONS / OPEN QUESTIONS:")
        for assumption in model.assumptions:
            lines.append(f"  - {assumption}")

    lines.append(
        "\nEXPOSURE: untrusted ingress actors are "
        f"{untrusted_actors or 'none'}; treat any element reachable from them by "
        "following data flows (directly or transitively) as attacker-exposed."
    )

    return "\n".join(lines)
