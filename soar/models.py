"""Domain model for the SOAR engine.

Pure dataclasses shared by the engine, connectors, store, API and reporting
layer. See docs/COMPONENTS.md for the binding field contracts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from soar.nist import Phase

__all__ = [
    "Severity",
    "ActionStatus",
    "RunStatus",
    "FailurePolicy",
    "Incident",
    "Action",
    "Playbook",
    "ActionResult",
    "Evidence",
    "Run",
    "Ioc",
]

Severity = Literal["low", "medium", "high", "critical"]

#: Ordered low -> critical. Index is the sort key.
SEVERITY_ORDER: tuple[str, ...] = ("low", "medium", "high", "critical")

ActionStatus = Literal[
    "pending",
    "running",
    "awaiting_approval",
    "succeeded",
    "failed",
    "skipped",
    "compensated",
]

RunStatus = Literal[
    "pending",
    "running",
    "awaiting_approval",
    "completed",
    "failed",
    "aborted",
    "skipped",
]

FailurePolicy = Literal["abort", "continue", "compensate"]


@dataclass(slots=True)
class Incident:
    """A triaged alert under (or about to be under) response."""

    id: str
    alert: dict[str, Any]
    severity: Severity = "medium"
    score: int = 0
    rationale: list[str] = field(default_factory=list)
    phase: Phase = Phase.PREPARATION
    status: str = "pending"
    playbook_id: str | None = None
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Action:
    """One playbook step.

    Attributes:
        compensates: Id of the action this one undoes. Used to pair forward
            actions with their inverses for reporting and rollback tests.
        forward_only: Declared when an action genuinely cannot be reversed
            (e.g. eradicating a persistence artifact from the simulated
            estate). Must be set explicitly and is reported as an accepted
            asymmetry -- see docs/SECURITY.md section 3.1.
    """

    id: str
    name: str
    phase: Phase
    connector: str
    params: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    requires_approval: bool = False
    on_failure: FailurePolicy = "abort"
    compensates: str | None = None
    forward_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Playbook:
    """A parsed, validated playbook definition."""

    id: str
    name: str
    description: str = ""
    phases: list[Phase] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    min_severity: Severity = "low"
    actions: list[Action] = field(default_factory=list)

    def actions_for_phase(self, phase: Phase) -> list[Action]:
        """Return actions belonging to ``phase``, preserving declared order."""
        return [a for a in self.actions if a.phase == phase]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["phases"] = [str(p) for p in self.phases]
        data["actions"] = [a.to_dict() for a in self.actions]
        for a in data["actions"]:
            a["phase"] = str(a["phase"])
        return data


@dataclass(slots=True)
class ActionResult:
    """Outcome of a single action execution."""

    action_id: str
    connector: str
    status: ActionStatus
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    started_at: str = ""
    ended_at: str = ""
    duration_ms: int = 0
    #: Populated when this result was produced by undoing a forward action.
    compensation_of: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Evidence:
    """A collected artifact with its integrity hash and provenance."""

    id: str
    incident_id: str
    artifact: str
    sha256: str
    size: int
    source: str
    collected_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Ioc:
    """An indicator of compromise with source attribution."""

    type: str
    value: str
    source: str
    confidence: float = 0.5

    def key(self) -> tuple[str, str]:
        return (self.type, self.value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Run:
    """One execution of a playbook against an incident."""

    id: str
    incident_id: str
    playbook_id: str
    status: RunStatus = "pending"
    phase_timings: dict[str, float] = field(default_factory=dict)
    started_at: str = ""
    ended_at: str = ""
    #: True when at least one action reported ``skipped`` (e.g. Volatility
    #: unavailable). Reports must state this rather than implying completeness.
    incomplete: bool = False
    #: Actions that could not be reversed. Non-empty is an accepted asymmetry
    #: and is surfaced in the report.
    forward_only_applied: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)