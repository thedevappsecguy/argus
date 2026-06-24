"""Report renderer: a developer-facing Markdown threat model from verified, rated threats.

Each reported threat is real and reachable for this system (it survived the agent
false-positive gate), so the report shows what a developer needs to act: the threat, the
element, the **grounded attack path**, the **mitigating controls**, and the OWASP severity —
no CWE taxonomy noise. Ruled-out candidates (false positive / not applicable) are listed with
the agent's reason for auditability, plus a coverage note (augment, not replace, a reviewer).
"""

from argus.models import SystemModel
from argus.rating import RatedThreat, ThreatStatus

# Severity ordering for the threats table — Critical first, Note last.
_SEV_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Note": 4,
}


def _dfd(model: SystemModel) -> str:
    """Render a simple ASCII Data Flow Diagram from the model's flows."""
    if not model.data_flows:
        return "_No data flows defined._"
    lines = []
    for flow in model.data_flows:
        auth = "" if flow.authenticated else " [unauthenticated]"
        lines.append(f"- `{flow.source}` → `{flow.dest}` ({flow.protocol}{auth})")
    return "\n".join(lines)


def render_report(model: SystemModel, threats: list[RatedThreat]) -> str:
    """Render a Markdown threat model report.

    Args:
        model: The system model being reported on.
        threats: All rated threats (REPORTED survived the FP gate; NOT_APPLICABLE / SUPPRESSED
            were ruled out by the verifier).

    Returns:
        A Markdown report string.
    """
    reported = sorted(
        [t for t in threats if t.status is ThreatStatus.REPORTED],
        key=lambda t: _SEV_ORDER.get(t.severity or "Note", 9),
    )
    ruled_out = [t for t in threats if t.status is not ThreatStatus.REPORTED]

    def _cell(text: str) -> str:
        """Make free text safe for a Markdown table cell (no raw pipes/newlines)."""
        return (text or "—").replace("|", "\\|").replace("\n", " ").strip() or "—"

    def _row(t: RatedThreat) -> str:
        controls = "; ".join(t.controls) if t.controls else "—"
        return (
            f"| {t.severity} | {t.stride} | {_cell(t.title)} | {t.element_id} | "
            f"{_cell(t.attack_path)} | {_cell(controls)} |"
        )

    out: list[str] = [
        f"# Threat Model: {model.name}",
        "",
        f"_Scope: {model.scope or 'n/a'}_",
        "",
        "## Architecture (DFD)",
        _dfd(model),
        "",
        "## Threats (real & reachable, ranked by severity)",
        "",
        "| Severity | STRIDE | Threat | Element | Attack path | Mitigating controls |",
        "|---|---|---|---|---|---|",
    ]
    out += [_row(t) for t in reported] or ["| — | — | _No threats reported_ | — | — | — |"]

    out += ["", "## Ruled out (false positive / not applicable, with reasons)", ""]
    if ruled_out:
        out += [
            f"- **{_cell(t.title)}** (`{t.element_id}`) — *{t.status.value}*: {_cell(t.reason)}"
            for t in ruled_out
        ]
    else:
        out.append("- (none)")

    out += ["", "## Assumptions & open questions", ""]
    out += [f"- {a}" for a in model.assumptions] or ["- (none recorded)"]

    out += [
        "",
        "## Coverage & limitations",
        "",
        "_Threats were enumerated by an LLM, then confirmed by an agent false-positive gate that "
        "grounds each one in a concrete attack path for this system, and rated with the OWASP "
        "Risk Rating methodology (deterministic factor→severity matrix). This augments, but does "
        "not replace, review by a security engineer — confirm findings and treat the absence of a "
        "threat as 'not yet found', not 'not present'._",
    ]

    return "\n".join(out)
