"""Deterministic, explainable alert severity scoring.

**Not ML.** A responder must be able to read :func:`score_alert`'s rationale and
independently arrive at the same score (docs/COMPONENTS.md -> ``severity``). The
same alert must always produce the same score -- there is no clock, no
randomness, and no learned model (AGENTS.md section 4).

Scoring is a weighted sum of five normalised signals clamped to 0-100:

.. code-block:: text

    score = clamp(0, 100,
            asset_criticality_weight    * asset_criticality_norm
          + detection_confidence_weight * detection_confidence
          + technique_impact_weight     * technique_impact_norm
          + privilege_context_weight    * privilege_context_norm
          + active_c2_weight            * active_c2_signal)

Every non-zero term appends one sentence to the rationale. A zero term appends
nothing, so the rationale is exactly the explanation of the score.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "WEIGHTS",
    "TECHNIQUE_IMPACT",
    "score_alert",
    "band",
    "auto_run_allowed",
    "requires_approval_for_containment",
]

#: Signal weights. These sum to 1.0 so a maximal alert scores 100.
#: This is the single config location (docs/COMPONENTS.md -> ``severity``).
WEIGHTS: dict[str, float] = {
    "asset_criticality": 0.25,
    "detection_confidence": 0.25,
    "technique_impact": 0.25,
    "privilege_context": 0.15,
    "active_c2": 0.10,
}

#: Normalised impact for the MITRE techniques the shipped playbooks cover,
#: plus the neighbouring techniques an analyst would plausibly feed in.
#: Unknown techniques fall back to :data:`_DEFAULT_TECHNIQUE_IMPACT`.
TECHNIQUE_IMPACT: dict[str, float] = {
    # Impact -- irreversible or highly destructive.
    "T1486": 1.00,  # Data Encrypted for Impact
    "T1490": 0.95,  # Inhibit System Recovery
    "T1489": 0.95,  # Service Stop
    "T1486.001": 1.00,
    # Credential access.
    "T1003": 0.80,  # OS Credential Dumping
    "T1110": 0.70,  # Brute Force
    "T1558": 0.75,  # Steal or Forge Kerberos Tickets
    "T1056": 0.55,  # Input Capture
    # Exfiltration.
    "T1041": 0.85,  # Exfiltration Over C2 Channel
    "T1048": 0.80,  # Exfiltration Over Alternative Protocol
    "T1567": 0.80,  # Exfiltration Over Web Service
    # Initial access / execution -- lower, because by definition less progressed.
    "T1190": 0.60,  # Exploit Public-Facing Application
    "T1566": 0.65,  # Phishing
    # Lateral movement.
    "T1021": 0.70,  # Remote Services
    "T1570": 0.65,  # Lateral Tool Transfer
    # Persistence / defence evasion.
    "T1547": 0.60,  # Boot or Logon Autostart
    "T1055": 0.85,  # Process Injection
    # Discovery / recon -- low; early stage.
    "T1046": 0.25,  # Network Service Discovery
    "T1087": 0.25,  # Account Discovery
    "T1018": 0.30,  # Remote System Discovery
}

_DEFAULT_TECHNIQUE_IMPACT = 0.50

#: Severity bands, highest first.
_BANDS: tuple[tuple[int, str], ...] = (
    (85, "critical"),
    (70, "high"),
    (40, "medium"),
    (0, "low"),
)

#: Severity levels permitted to auto-run containment without an approval gate.
#: Everything else gates containment behind a human (docs/SECURITY.md section 6).
_AUTO_RUN_SEVERITIES: frozenset[str] = frozenset({"critical"})


def band(score: int) -> str:
    """Map a 0-100 score to a severity label."""
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "low"


def auto_run_allowed(severity: str) -> bool:
    """Whether containment may run without a human approval gate."""
    return severity in _AUTO_RUN_SEVERITIES


def requires_approval_for_containment(severity: str) -> bool:
    """Inverse of :func:`auto_run_allowed`, spelled out for playbook authors."""
    return not auto_run_allowed(severity)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, result))


def _technique_impact(alert: dict[str, Any]) -> float:
    technique = str(alert.get("mitre", {}).get("technique_id", "") or "").strip()
    if not technique:
        return _DEFAULT_TECHNIQUE_IMPACT
    if technique in TECHNIQUE_IMPACT:
        return TECHNIQUE_IMPACT[technique]
    # Sub-techniques (T1486.001) fall back to their parent (T1486).
    parent = technique.split(".", 1)[0]
    return TECHNIQUE_IMPACT.get(parent, _DEFAULT_TECHNIQUE_IMPACT)


def score_alert(alert: dict[str, Any], context: dict[str, Any] | None = None) -> tuple[int, list[str]]:
    """Score an alert 0-100 and explain the score.

    Args:
        alert: The alert payload. Missing or malformed fields degrade to a
            neutral value rather than raising -- triage must never be the
            thing that fails during an incident.
        context: Optional supplementary context merged over ``alert["context"]``.
            Reserved for enrichment at detection time; unused by default.

    Returns:
        ``(score, rationale)`` where ``score`` is an int in 0-100 and
        ``rationale`` explains each non-zero contributing term in plain English.
    """
    rationale: list[str] = []
    raw_context: dict[str, Any] = dict(alert.get("context", {}) or {})
    if context:
        raw_context.update(context)

    total = 0.0

    # --- 1. Asset criticality -------------------------------------------------
    # 1-5 on a 0-1 scale. A missing or unparseable criticality is treated as
    # medium (0.6) rather than zero: an unknown asset is not an unimportant
    # one, and zeroing it would let a malformed alert look benign.
    criticality_raw = alert.get("asset", {}).get("criticality")
    if criticality_raw is None:
        crit, asset_note = 3.0, "asset criticality unknown, assumed medium"
    else:
        try:
            crit = max(1.0, min(5.0, float(criticality_raw)))
        except (TypeError, ValueError):
            crit, asset_note = 3.0, "asset criticality unparseable, assumed medium"
        else:
            asset_note = ""
    asset_norm = (crit - 1.0) / 4.0
    term = WEIGHTS["asset_criticality"] * asset_norm * 100
    total += term
    if asset_note:
        rationale.append(f"{term:.1f} pts - {asset_note}")
    else:
        zone = alert.get("asset", {}).get("zone", "unknown")
        rationale.append(
            f"{term:.1f} pts - asset criticality {criticality_raw}/5 in {zone} zone"
        )

    # --- 2. Detection confidence ---------------------------------------------
    confidence = _as_float(alert.get("detection", {}).get("confidence"), default=0.60)
    term = WEIGHTS["detection_confidence"] * confidence * 100
    total += term
    if confidence > 0:
        source = alert.get("detection", {}).get("source", "unspecified")
        rationale.append(
            f"{term:.1f} pts - detection confidence {confidence:.0%} from {source}"
        )

    # --- 3. Technique impact --------------------------------------------------
    technique = str(alert.get("mitre", {}).get("technique_id", "") or "unknown")
    technique_name = alert.get("mitre", {}).get("technique_name") or "unspecified technique"
    impact = _technique_impact(alert)
    term = WEIGHTS["technique_impact"] * impact * 100
    total += term
    rationale.append(
        f"{term:.1f} pts - {technique} ({technique_name}) carries impact {impact:.0%}"
    )

    # --- 4. Privilege context -------------------------------------------------
    user = alert.get("user", {}) or {}
    if bool(user.get("privileged", False)):
        privilege_norm = 1.0
        privilege_note = "activity is by a privileged account"
    elif bool(user.get("name")):
        privilege_norm = 0.5
        privilege_note = "activity is by a standard user account"
    else:
        # No account attribution is not itself a risk signal, so no points and
        # deliberately no rationale line.
        privilege_norm = 0.0
        privilege_note = ""

    term = WEIGHTS["privilege_context"] * privilege_norm * 100
    total += term
    if privilege_note:
        rationale.append(f"{term:.1f} pts - {privilege_note}")

    # --- 5. Active C2 / concrete harm signals ---------------------------------
    harm_flags = {
        "active_c2": "active C2 communication observed",
        "ransom_note_found": "ransom note artefact found",
        "shadow_copies_deleted": "shadow copies deleted",
        "lateral_movement": "lateral movement indicators present",
        "data_staged": "data staged for exfiltration",
    }
    triggered = [msg for flag, msg in harm_flags.items() if bool(raw_context.get(flag))]
    if triggered:
        term = WEIGHTS["active_c2"] * 100
        total += term
        rationale.append(f"{term:.1f} pts - " + "; ".join(triggered))

    score = int(max(0, min(100, round(total))))
    return score, rationale