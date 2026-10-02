"""Pydantic request/response schemas for the API.

Response models are deliberately permissive about extra fields (``model_config``
allows extras) so that adding a field to the domain model does not break an
existing client.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "AlertIn",
    "IncidentOut",
    "IncidentListOut",
    "RunRequest",
    "RunOut",
    "ActionResultOut",
    "ApprovalOut",
    "TimelineOut",
    "CoverageOut",
    "HealthOut",
]


class AlertIn(BaseModel):
    """An inbound detection alert. Passed through to triage unchanged."""

    model_config = {"extra": "allow"}

    alert: dict[str, Any] = Field(..., description="The raw alert payload")


class IncidentOut(BaseModel):
    model_config = {"extra": "allow"}

    id: str
    severity: str
    score: int
    rationale: list[str]
    phase: str
    status: str
    playbook_id: str | None = None
    alert: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class IncidentListOut(BaseModel):
    total: int
    incidents: list[IncidentOut]


class RunRequest(BaseModel):
    """Body of ``POST /incidents/{id}/run``.

    ``auto_approve`` defaults to ``False`` and must stay that way for anything
    other than the demo and benchmark harnesses
    (docs/SECURITY.md section 6, docs/METRICS.md section 4.4).
    """

    auto_approve: bool = Field(
        default=False,
        description="Skip human approval gates. Disclosed in every report and benchmark.",
    )
    playbook_id: str | None = Field(
        default=None, description="Override the playbook chosen at triage."
    )


class ActionResultOut(BaseModel):
    model_config = {"extra": "allow"}

    action_id: str
    connector: str
    status: str
    error: str | None = None
    duration_ms: int = 0
    compensation_of: str | None = None


class RunOut(BaseModel):
    model_config = {"extra": "allow"}

    id: str
    incident_id: str
    playbook_id: str
    status: str
    incomplete: bool = False
    phase_timings: dict[str, float] = Field(default_factory=dict)
    forward_only_applied: list[str] = Field(default_factory=list)
    started_at: str = ""
    ended_at: str = ""
    results: list[ActionResultOut] = Field(default_factory=list)
    awaiting_action: str | None = None


class ApprovalOut(BaseModel):
    run_id: str
    approved_action: str
    status: str


class TimelineEvent(BaseModel):
    model_config = {"extra": "allow"}

    at: str
    phase: str
    action_id: str
    connector: str
    status: str
    duration_ms: int = 0


class TimelineOut(BaseModel):
    incident_id: str
    run_id: str | None = None
    events: list[TimelineEvent]


class CoverageOut(BaseModel):
    """Playbook coverage, with an explicit gap list.

    ``gaps`` is required to be present even when empty -- reporting coverage
    without naming what is uncovered would misrepresent readiness
    (docs/PLAN.md W3.4).
    """

    covered_techniques: list[str]
    covered_playbooks: list[str]
    gaps: list[str]
    gap_count: int


class HealthOut(BaseModel):
    status: str
    version: str
    playbooks_loaded: int
    volatility_available: bool
    forensic_source: str
    execution_mode: str