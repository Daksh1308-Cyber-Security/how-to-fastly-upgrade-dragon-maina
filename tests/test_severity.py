"""Severity scoring: determinism, band boundaries, rationale completeness."""

from __future__ import annotations

import pytest

from soar.severity import (
    TECHNIQUE_IMPACT,
    WEIGHTS,
    auto_run_allowed,
    band,
    score_alert,
)


def test_weights_sum_to_one():
    """A maximal alert must be able to reach 100, not 87 or 113."""
    assert sum(WEIGHTS.values()) == pytest.approx(1.0)


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [(85, "critical"), (84, "high"), (70, "high"), (69, "medium"), (40, "medium"), (39, "low"), (0, "low")],
)
def test_band_boundaries(threshold, expected):
    assert band(threshold) == expected


def test_deterministic(ransomware_alert):
    """The same alert must always score identically -- no clock, no randomness."""
    first = score_alert(ransomware_alert)
    for _ in range(50):
        assert score_alert(ransomware_alert) == first


def test_rationale_explains_every_contribution(ransomware_alert):
    score, rationale = score_alert(ransomware_alert)
    assert rationale, "a score with no rationale is not auditable"
    # Criticality + confidence + technique + harm flags all fire on this alert.
    joined = " ".join(rationale)
    assert "asset criticality" in joined
    assert "detection confidence" in joined
    assert "T1486" in joined
    assert "pts" in joined


def test_ransomware_alert_scores_critical(ransomware_alert):
    score, _ = score_alert(ransomware_alert)
    assert band(score) == "critical", f"expected critical, got {score}"


def test_recon_alert_scores_low(port_scan_alert):
    """Discovery activity is early-stage; it must not score as an incident."""
    score, _ = score_alert(port_scan_alert)
    assert band(score) == "low", f"expected low, got {score}"


def test_missing_criticality_is_not_treated_as_zero(ransomware_alert):
    """An unknown asset is not an unimportant one.

    Zeroing a missing criticality would let a malformed alert look benign.
    """
    alert = dict(ransomware_alert)
    alert["asset"] = {"id": "HOST-999", "zone": "corp"}
    score_with_missing, rationale = score_alert(alert)
    assert any("assumed medium" in line for line in rationale)
    assert score_with_missing > 0


def test_unparseable_criticality_degrades_gracefully(ransomware_alert):
    """Triage must never be the thing that fails during an incident."""
    alert = dict(ransomware_alert)
    alert["asset"] = {"id": "HOST-999", "criticality": "not-a-number"}
    score, rationale = score_alert(alert)
    assert 0 <= score <= 100
    assert any("unparseable" in line for line in rationale)


def test_empty_alert_does_not_raise():
    score, _ = score_alert({})
    assert 0 <= score <= 100


def test_privileged_account_scores_above_standard(monkey_alert, standard_alert):
    privileged_score, _ = score_alert(monkey_alert)
    standard_score, _ = score_alert(standard_alert)
    assert privileged_score > standard_score


def test_harm_signals_increase_score(ransomware_alert):
    with_flags, _ = score_alert(ransomware_alert)
    stripped = dict(ransomware_alert)
    stripped["context"] = {}
    without_flags, _ = score_alert(stripped)
    assert with_flags > without_flags


def test_technique_falls_back_to_parent():
    """T1486.001 must inherit T1486's impact."""
    alert = {
        "asset": {"criticality": 3},
        "detection": {"confidence": 0.5},
        "mitre": {"technique_id": "T1486.001", "technique_name": "Data Encrypted for Impact"},
    }
    score, rationale = score_alert(alert)
    parent_score, _ = score_alert(
        {
            "asset": {"criticality": 3},
            "detection": {"confidence": 0.5},
            "mitre": {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
        }
    )
    assert score == parent_score
    assert any("T1486.001" in line for line in rationale)


def test_unknown_technique_uses_default_impact():
    score, _ = score_alert(
        {
            "asset": {"criticality": 3},
            "detection": {"confidence": 0.5},
            "mitre": {"technique_id": "T9999", "technique_name": "made up"},
        }
    )
    expected_term = WEIGHTS["technique_impact"] * 0.50 * 100
    assert score >= int(expected_term) - 1


def test_only_critical_may_auto_run():
    assert auto_run_allowed("critical")
    assert not auto_run_allowed("high")
    assert not auto_run_allowed("medium")
    assert not auto_run_allowed("low")


def test_technique_table_values_are_normalised():
    assert all(0.0 <= v <= 1.0 for v in TECHNIQUE_IMPACT.values())


@pytest.mark.parametrize("filename", ["port_scan_reconnaissance.json", "phishing_credential_harvest.json"])
def test_low_band_closes_without_containment(request, filename):
    """A low-severity alert must not be permitted to auto-contain."""
    from tests.conftest import load_alert

    score, _ = score_alert(load_alert(filename))
    assert not auto_run_allowed(band(score))