"""NIST SP 800-61 incident response phase model.

The execution state machine follows **SP 800-61 rev2**, whose incident response
lifecycle is Preparation -> Detection -> Containment -> Eradication -> Recovery.
That is what the project brief specifies and what the engine executes.

**SP 800-61 rev3** (April 2025) superseded rev2 and reorganised the lifecycle
around the CSF 2.0 functional split (Govern / Identify / Protect / Detect /
Respond / Recover). This module carries the mapping in :data:`R3_MAPPING` so a
report can cite either dialect without the engine changing.

Pure module: no I/O, no clock, no randomness.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "Phase",
    "PHASE_ORDER",
    "VALID_TRANSITIONS",
    "R3_MAPPING",
    "ABORTED",
    "CLOSED",
    "can_transition",
    "csf2_subcategories",
]


class Phase(StrEnum):
    """SP 800-61 rev2 incident response lifecycle phase."""

    PREPARATION = "preparation"
    DETECTION = "detection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"


#: Terminal pseudo-state used when a run aborts and compensations run.
ABORTED = "aborted"

#: Terminal pseudo-state for a closed incident (including false positives).
CLOSED = "closed"

#: Canonical ordering. Preparation is the always-on baseline; the other four
#: are the lifecycle phases named in the project brief.
PHASE_ORDER: tuple[Phase, ...] = (
    Phase.PREPARATION,
    Phase.DETECTION,
    Phase.CONTAINMENT,
    Phase.ERADICATION,
    Phase.RECOVERY,
)

#: Legal transitions.
#:
#: Two transitions in here are easy to forget and both matter:
#:
#: * ``CONTAINMENT -> RECOVERY`` exists so a **confirmed false positive** can be
#:   closed without performing containment. A state machine that forces
#:   containment would strand every benign alert.
#: * Any phase may abort, and aborting runs compensations in reverse order.
VALID_TRANSITIONS: dict[Phase | str, set[Phase | str]] = {
    Phase.PREPARATION: {Phase.DETECTION},
    Phase.DETECTION: {
        Phase.CONTAINMENT,
        # Auto-contained / benign: straight to recovery, or closed.
        Phase.RECOVERY,
        CLOSED,
    },
    Phase.CONTAINMENT: {
        Phase.ERADICATION,
        Phase.RECOVERY,
        CLOSED,
    },
    Phase.ERADICATION: {Phase.RECOVERY, CLOSED},
    Phase.RECOVERY: {CLOSED},
    ABORTED: set(),
    CLOSED: set(),
}

# Every live phase can abort.
for _phase in PHASE_ORDER:
    VALID_TRANSITIONS[_phase].add(ABORTED)

#: Mapping from the rev2 phases we execute to the CSF 2.0 functions and
#: representative subcategories used by SP 800-61 rev3. Used by the report
#: generator so a reader working from either revision can navigate.
#:
#: Reference: NIST CSF 2.0 (2024), SP 800-61 rev3 (April 2025).
R3_MAPPING: dict[Phase, dict[str, object]] = {
    Phase.PREPARATION: {
        "csf_function": "GOVERN",
        "csf_categories": ["GV.PO", "GV.OC", "GV.RR", "GV.RM"],
        "rev3_note": (
            "Preparation is not a discrete rev3 step; it is the standing governance "
            "and readiness programme that makes the other phases possible."
        ),
    },
    Phase.DETECTION: {
        "csf_function": "DETECT",
        "csf_categories": ["DE.CM", "DE.AE", "DE.DP"],
        "rev3_note": "Monitoring, analytics and event-value determination.",
    },
    Phase.CONTAINMENT: {
        "csf_function": "RESPOND",
        "csf_categories": ["RS.MA", "RS.AN", "RS.MI", "RS.IM"],
        "rev3_note": (
            "rev3 merges rev2's Containment and Eradication into Respond; the split "
            "is retained here because containment and eradication carry different "
            "approval and reversibility requirements."
        ),
    },
    Phase.ERADICATION: {
        "csf_function": "RESPOND",
        "csf_categories": ["RS.RP", "RS.RA"],
        "rev3_note": "Remediation and recovery planning within Respond.",
    },
    Phase.RECOVERY: {
        "csf_function": "RECOVER",
        "csf_categories": ["RC.RP", "RC.IM", "RC.CO"],
        "rev3_note": "Recovery planning, execution and communications.",
    },
}


def can_transition(from_: Phase | str, to: Phase | str) -> bool:
    """Return ``True`` if ``from_ -> to`` is a legal incident transition.

    Args:
        from_: Current phase or terminal pseudo-state.
        to: Desired next phase or terminal pseudo-state.

    Returns:
        Whether the transition is permitted by :data:`VALID_TRANSITIONS`.
    """
    try:
        allowed = VALID_TRANSITIONS[from_]
    except KeyError:
        # An unknown state can never transition. Silently allowing this
        # would let a typo in the store advance an incident to "closed".
        return False
    return to in allowed


def csf2_subcategories(phase: Phase | str) -> list[str]:
    """Return the CSF 2.0 subcategories for a phase (empty if unknown)."""
    try:
        return list(R3_MAPPING[Phase(phase)]["csf_categories"])  # type: ignore[index]
    except (KeyError, ValueError):
        return []