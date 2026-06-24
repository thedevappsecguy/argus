"""OWASP Risk Rating Methodology: Risk = Likelihood × Impact.

Factor scores (0–9) are averaged into LOW/MEDIUM/HIGH levels, which are then mapped
through the OWASP overall-severity matrix. The factor→severity mapping is deterministic;
in Plan 4 the LLM only proposes factor *scores* with a one-line justification tied to a
model element — never the final severity.

Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
"""

from pydantic import BaseModel

# OWASP overall risk severity matrix: (likelihood_level, impact_level) → severity label.
# Source: OWASP Risk Rating Methodology table.
_SEVERITY_MATRIX: dict[tuple[str, str], str] = {
    ("LOW", "LOW"):      "Note",
    ("LOW", "MEDIUM"):   "Low",
    ("LOW", "HIGH"):     "Medium",
    ("MEDIUM", "LOW"):   "Low",
    ("MEDIUM", "MEDIUM"): "Medium",
    ("MEDIUM", "HIGH"):  "High",
    ("HIGH", "LOW"):     "Medium",
    ("HIGH", "MEDIUM"):  "High",
    ("HIGH", "HIGH"):    "Critical",
}


class RiskRating(BaseModel):
    """The result of an OWASP risk rating computation."""

    likelihood_level: str   # LOW | MEDIUM | HIGH
    impact_level: str       # LOW | MEDIUM | HIGH
    severity: str           # Note | Low | Medium | High | Critical


def level_of(average: float) -> str:
    """Map an averaged factor score to an OWASP risk level.

    OWASP bands: 0–<3 = LOW, 3–<6 = MEDIUM, ≥6 = HIGH.

    Args:
        average: Averaged factor score in [0, 9].

    Returns:
        One of "LOW", "MEDIUM", "HIGH".
    """
    if average < 3:
        return "LOW"
    if average < 6:
        return "MEDIUM"
    return "HIGH"


def severity(likelihood_level: str, impact_level: str) -> str:
    """Look up the OWASP overall risk severity for a (likelihood, impact) pair.

    Args:
        likelihood_level: One of "LOW", "MEDIUM", "HIGH".
        impact_level: One of "LOW", "MEDIUM", "HIGH".

    Returns:
        One of "Note", "Low", "Medium", "High", "Critical".

    Raises:
        KeyError: If the level pair is not in the matrix.
    """
    return _SEVERITY_MATRIX[(likelihood_level, impact_level)]


def _average(factors: dict[str, float]) -> float:
    """Compute the unweighted average of a factor dictionary."""
    return sum(factors.values()) / len(factors) if factors else 0.0


def rate(
    likelihood_factors: dict[str, float],
    impact_factors: dict[str, float],
) -> RiskRating:
    """Compute a full OWASP risk rating from factor dictionaries.

    Args:
        likelihood_factors: Named scores (0–9) for ease of discovery, exploit, etc.
        impact_factors: Named scores (0–9) for confidentiality, integrity, compliance, etc.

    Returns:
        A RiskRating with levels and overall severity.
    """
    like_level = level_of(_average(likelihood_factors))
    impact_level = level_of(_average(impact_factors))
    return RiskRating(
        likelihood_level=like_level,
        impact_level=impact_level,
        severity=severity(like_level, impact_level),
    )
