"""Tests for argus.risk — OWASP Risk Rating methodology."""

from argus.risk import RiskRating, level_of, rate, severity


def test_level_thresholds() -> None:
    assert level_of(0) == "LOW"
    assert level_of(2.9) == "LOW"
    assert level_of(3) == "MEDIUM"
    assert level_of(5.9) == "MEDIUM"
    assert level_of(6) == "HIGH"
    assert level_of(9) == "HIGH"


def test_owasp_severity_matrix_corners() -> None:
    assert severity("LOW", "LOW") == "Note"
    assert severity("HIGH", "HIGH") == "Critical"
    assert severity("LOW", "HIGH") == "Medium"   # low likelihood, high impact
    assert severity("HIGH", "LOW") == "Medium"   # high likelihood, low impact


def test_owasp_severity_matrix_middle() -> None:
    assert severity("MEDIUM", "MEDIUM") == "Medium"
    assert severity("LOW", "MEDIUM") == "Low"
    assert severity("MEDIUM", "LOW") == "Low"
    assert severity("MEDIUM", "HIGH") == "High"
    assert severity("HIGH", "MEDIUM") == "High"


def test_rate_averages_factors_then_maps() -> None:
    r = rate(
        likelihood_factors={"ease_of_exploit": 9, "ease_of_discovery": 9},
        impact_factors={"loss_of_confidentiality": 9, "non_compliance": 9},
    )
    assert isinstance(r, RiskRating)
    assert r.likelihood_level == "HIGH"
    assert r.impact_level == "HIGH"
    assert r.severity == "Critical"


def test_rate_with_low_factors() -> None:
    r = rate(
        likelihood_factors={"ease_of_exploit": 1, "ease_of_discovery": 1},
        impact_factors={"loss_of_confidentiality": 1, "loss_of_integrity": 1},
    )
    assert r.likelihood_level == "LOW"
    assert r.impact_level == "LOW"
    assert r.severity == "Note"


def test_rate_with_empty_factors() -> None:
    """Empty factor dicts produce LOW levels (average of 0)."""
    r = rate(likelihood_factors={}, impact_factors={})
    assert r.severity == "Note"
