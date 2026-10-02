"""FastAPI application -- playbook triggers and incident query endpoints.

Endpoint contracts: docs/ARCHITECTURE.md section 8.

Execution model
---------------
``POST /incidents/{id}/run`` starts the playbook on an in-process background
thread and returns immediately, because a full run can exceed an HTTP client
timeout. Progress is polled with ``GET /runs/{id}``.

This is a thread, not a distributed worker. **Runs do not survive an API
restart** -- a known limitation recorded in docs/STATUS.md. It is not a Celery
queue (AGENTS.md section 3).

Reporting endpoints (``/incidents/{id}/report``) are declared in the contract
but land in Week 3; until then they answer ``501`` rather than pretending.
"""

from __future__ import annotations

import os
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from soar import __version__
from soar.api.schemas import (
    AlertIn,
    ApprovalOut,
    CoverageOut,
    HealthOut,
    IncidentListOut,
    IncidentOut,
    RunOut,
    RunRequest,
    TimelineOut,
)
from soar.connectors import build_default_registry, verify_registry
from soar.engine import Engine
from soar.estate import SqliteEstate, seed_demo_estate
from soar.forensics.memory import find_image, find_recorded_dir, vol_version
from soar.models import Incident, Playbook, Run
from soar.nist import PHASE_ORDER, Phase
from soar.playbook_loader import PlaybookValidationError, load_all, select
from soar.severity import auto_run_allowed, band, score_alert
from soar.store import Store

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("SOAR_DATA_DIR", "data"))
REPORTS_DIR = Path(os.environ.get("SOAR_REPORTS_DIR", "reports"))
PLAYBOOKS_DIR = Path(os.environ.get("SOAR_PLAYBOOKS_DIR", "playbooks"))
EVIDENCE_ROOTS = [
    Path(p) for p in os.environ.get("SOAR_EVIDENCE_ROOTS", "fixtures").split(os.pathsep) if p
]
EXECUTION_MODE = os.environ.get("SOAR_EXECUTION_MODE", "simulated")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AppState:
    """Everything the endpoints need, built once at startup."""

    def __init__(self) -> None:
        self.store = Store(DATA_DIR / "ir.db")
        self.estate = seed_demo_estate(SqliteEstate(self.store.conn))
        self.registry = build_default_registry()
        verify_registry(self.registry)
        self.engine = Engine(
            registry=self.registry,
            estate=self.estate,
            data_dir=DATA_DIR,
            evidence_roots=EVIDENCE_ROOTS,
        )
        self.playbooks: dict[str, Playbook] = {}
        self.reload_playbooks()
        #: run_id -> lock, so two approves cannot resume the same run twice.
        self._run_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def reload_playbooks(self) -> None:
        self.playbooks = {p.id: p for p in load_all(PLAYBOOKS_DIR)}

    def run_lock(self, run_id: str) -> threading.Lock:
        with self._locks_guard:
            if run_id not in self._run_locks:
                self._run_locks[run_id] = threading.Lock()
            return self._run_locks[run_id]

    def shutdown(self) -> None:
        self.engine.shutdown()
        self.store.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.soar = AppState()
    yield
    app.state.soar.shutdown()


app = FastAPI(
    title="Incident Response Automation",
    version=__version__,
    description=(
        "Custom SOAR engine executing NIST SP 800-61 playbooks. "
        "Containment is SIMULATED; forensics is real. See docs/SECURITY.md."
    ),
    lifespan=lifespan,
)


def _soar() -> AppState:
    return app.state.soar


def _run_to_out(run: Run, soar: AppState, awaiting: str | None = None) -> RunOut:
    results = soar.store.get_action_results(run.id)
    return RunOut(
        id=run.id,
        incident_id=run.incident_id,
        playbook_id=run.playbook_id,
        status=run.status,
        incomplete=run.incomplete,
        phase_timings=run.phase_timings,
        forward_only_applied=run.forward_only_applied,
        started_at=run.started_at,
        ended_at=run.ended_at,
        # to_dict() is required: RunOut.results is a list of Pydantic models,
        # and passing ActionResult dataclasses directly fails validation.
        results=[r.to_dict() for r in results],
        awaiting_action=awaiting,
    )


def _drive_run(
    soar: AppState,
    incident: Incident,
    playbook: Playbook,
    run: Run,
    auto_approve: bool,
    approved: set[str],
) -> None:
    """Execute a run to its next terminal state, then persist. Runs on the
    background thread started by the endpoint."""
    lock = soar.run_lock(run.id)
    with lock:
        prior = soar.store.get_action_results(run.id)
        shared = _rebuild_shared(prior)
        run_obj, results = soar.engine.execute(
            incident=incident,
            playbook=playbook,
            run=run,
            auto_approve=auto_approve,
            prior_results=prior,
            shared=shared,
            approved=approved,
        )
        soar.store.save_run(run_obj)

        # engine.execute() returns the FULL cumulative result list for the run.
        # Persisting all of it on resume would duplicate every earlier action
        # row, so only the delta from this invocation is written.
        new_results = results[len(prior):]
        soar.store.save_action_results(run.id, new_results)

        # Persist evidence rows so the incident view can list artifacts.
        from soar.models import Evidence

        artifacts: list[Evidence] = []
        for result in new_results:
            for entry in result.result.get("collected", []) if isinstance(result.result, dict) else []:
                artifacts.append(
                    Evidence(
                        id=uuid.uuid4().hex[:12],
                        incident_id=incident.id,
                        artifact=entry.get("artifact", ""),
                        sha256=entry.get("sha256", ""),
                        size=int(entry.get("size", 0)),
                        source=entry.get("source", ""),
                        collected_at=entry.get("ts", _now()),
                    )
                )
        if artifacts:
            soar.store.save_evidence(artifacts)

        incident.status = run_obj.status
        incident.updated_at = _now()
        soar.store.save_incident(incident)


def _rebuild_shared(prior_results: list[Any]) -> dict[str, Any]:
    """Reconstruct cross-action outputs from a resumed run.

    ``ioc.extract`` consumes ``vol_output`` produced by an earlier action. When a
    run is resumed after an approval gate, that output is not re-produced, so it
    is recovered from the persisted results.
    """
    from soar.engine import _output_key

    shared: dict[str, Any] = {}
    for result in prior_results:
        if result.status != "succeeded" or not result.result:
            continue
        shared[_output_key(result.connector)] = result.result
    return shared


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


@app.get("/healthz", response_model=HealthOut, tags=["ops"])
def healthz() -> HealthOut:
    """Liveness plus the forensic inputs actually available right now."""
    soar = _soar()
    image = find_image()
    recorded = find_recorded_dir()
    if image is not None:
        source = "live-memory-image"
    elif recorded is not None:
        source = "recorded-fixtures"
    else:
        source = "none"

    return HealthOut(
        status="ok",
        version=__version__,
        playbooks_loaded=len(soar.playbooks),
        volatility_available=vol_version() is not None,
        forensic_source=source,
        execution_mode=EXECUTION_MODE,
    )


@app.post("/alerts", response_model=IncidentOut, status_code=201, tags=["triage"])
def ingest_alert(payload: AlertIn) -> IncidentOut:
    """Ingest an alert, triage it, select a playbook, create the incident.

    This is the only endpoint that both scores and selects. An alert whose
    technique no playbook covers is still recorded -- with ``playbook_id=None``
    -- so the gap shows up in coverage reporting rather than being hidden
    (docs/PLAN.md W3.4).
    """
    soar = _soar()
    alert = payload.alert

    score, rationale = score_alert(alert)
    severity = band(score)
    playbook = select(list(soar.playbooks.values()), alert, severity)

    incident = Incident(
        id=f"INC-{uuid.uuid4().hex[:12].upper()}",
        alert=alert,
        severity=severity,  # type: ignore[arg-type]
        score=score,
        rationale=rationale,
        phase=Phase.DETECTION,
        status="triaged",
        playbook_id=playbook.id if playbook else None,
        created_at=_now(),
        updated_at=_now(),
    )
    soar.store.save_incident(incident)
    return IncidentOut(**incident.to_dict())


@app.get("/incidents", response_model=IncidentListOut, tags=["incidents"])
def list_incidents(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> IncidentListOut:
    soar = _soar()
    incidents = soar.store.list_incidents(severity=severity, status=status, limit=limit)
    return IncidentListOut(total=len(incidents), incidents=[IncidentOut(**i.to_dict()) for i in incidents])


@app.get("/incidents/{incident_id}", response_model=IncidentOut, tags=["incidents"])
def get_incident(incident_id: str) -> IncidentOut:
    soar = _soar()
    incident = soar.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"unknown incident {incident_id}")
    return IncidentOut(**incident.to_dict())


@app.post("/incidents/{incident_id}/run", response_model=RunOut, status_code=202, tags=["runs"])
def start_run(incident_id: str, body: RunRequest | None = None) -> RunOut:
    """Start (or resume) the playbook for an incident.

    Returns 202 with the run record. Poll ``GET /runs/{id}``.
    """
    soar = _soar()
    incident = soar.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"unknown incident {incident_id}")

    body = body or RunRequest()
    playbook_id = body.playbook_id or incident.playbook_id
    if not playbook_id:
        raise HTTPException(
            status_code=409,
            detail=(
                f"incident {incident_id} has no playbook (technique not covered). "
                "Pass playbook_id explicitly to override."
            ),
        )
    playbook = soar.playbooks.get(playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail=f"unknown playbook {playbook_id!r}")

    existing = soar.store.latest_run_for(incident_id)
    if existing and existing.status in {"running", "awaiting_approval"}:
        run = existing
    else:
        run = Run(
            id=f"RUN-{uuid.uuid4().hex[:12].upper()}",
            incident_id=incident_id,
            playbook_id=playbook_id,
        )
        soar.store.save_run(run)

    thread = threading.Thread(
        target=_drive_run,
        args=(soar, incident, playbook, run, body.auto_approve, set()),
        name=f"soar-run-{run.id}",
        daemon=True,
    )
    thread.start()

    return _run_to_out(run, soar)


@app.post(
    "/incidents/{incident_id}/actions/{action_id}/approve",
    response_model=ApprovalOut,
    tags=["runs"],
)
def approve_action(incident_id: str, action_id: str) -> ApprovalOut:
    """Release a single approval gate and resume the run.

    Grants approval for exactly this action; later gates still require their own
    approval. This is the deliberate counterpart to ``auto_approve``.
    """
    soar = _soar()
    incident = soar.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"unknown incident {incident_id}")

    run = soar.store.latest_run_for(incident_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"no run for incident {incident_id}")
    if run.status != "awaiting_approval":
        raise HTTPException(
            status_code=409, detail=f"run {run.id} is {run.status!r}, not awaiting approval"
        )

    playbook = soar.playbooks.get(run.playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail=f"unknown playbook {run.playbook_id!r}")

    pending = next((a.id for a in playbook.actions if a.id == action_id), None)
    if pending is None:
        raise HTTPException(status_code=404, detail=f"unknown action {action_id!r} in {run.playbook_id}")

    thread = threading.Thread(
        target=_drive_run,
        args=(soar, incident, playbook, run, False, {action_id}),
        name=f"soar-approve-{run.id}",
        daemon=True,
    )
    thread.start()

    return ApprovalOut(run_id=run.id, approved_action=action_id, status="approved")


@app.get("/runs/{run_id}", response_model=RunOut, tags=["runs"])
def get_run(run_id: str) -> RunOut:
    soar = _soar()
    run = soar.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"unknown run {run_id}")

    awaiting = None
    if run.status == "awaiting_approval":
        playbook = soar.playbooks.get(run.playbook_id)
        results = soar.store.get_action_results(run.id)
        awaiting = next(
            (r.action_id for r in results if r.status == "awaiting_approval"),
            None,
        )
        if awaiting is None and playbook is not None:
            awaiting = playbook.actions[-1].id if playbook.actions else None
    return _run_to_out(run, soar, awaiting)


@app.get("/incidents/{incident_id}/timeline", response_model=TimelineOut, tags=["reporting"])
def timeline(incident_id: str) -> TimelineOut:
    """Phase-ordered action timeline for the incident's latest run."""
    soar = _soar()
    if soar.store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail=f"unknown incident {incident_id}")

    run = soar.store.latest_run_for(incident_id)
    if run is None:
        return TimelineOut(incident_id=incident_id, run_id=None, events=[])

    playbook = soar.playbooks.get(run.playbook_id)
    phase_of = {a.id: str(a.phase) for a in playbook.actions} if playbook else {}

    events = []
    for result in soar.store.get_action_results(run.id):
        events.append(
            {
                "at": result.started_at,
                "phase": phase_of.get(result.action_id, "unknown"),
                "action_id": result.action_id,
                "connector": result.connector,
                "status": result.status,
                "duration_ms": result.duration_ms,
            }
        )

    order = {str(p): i for i, p in enumerate(PHASE_ORDER)}
    events.sort(key=lambda e: (order.get(e["phase"], 99), e["at"]))
    return TimelineOut(incident_id=incident_id, run_id=run.id, events=events)


@app.get("/playbooks", response_model=CoverageOut, tags=["coverage"])
def coverage() -> CoverageOut:
    """Playbook coverage with an explicit gap list.

    Naming what is *not* covered is the point
    (docs/PLAN.md W3.4, AGENTS.md section 3).
    """
    soar = _soar()
    covered: list[str] = []
    for playbook in soar.playbooks.values():
        covered.extend(playbook.mitre_techniques)

    gaps = _known_gaps(covered)
    return CoverageOut(
        covered_techniques=sorted(set(covered)),
        covered_playbooks=sorted(soar.playbooks),
        gaps=gaps,
        gap_count=len(gaps),
    )


def _known_gaps(covered: list[str]) -> list[str]:
    """Common enterprise techniques with no shipped playbook.

    Documented as a deliberate, accepted gap rather than silently omitted. The
    list is short on purpose: expanding it belongs with expanding coverage, and
    both need the user's approval (AGENTS.md section 3).
    """
    candidates = [
        "T1490 Inhibit System Recovery",
        "T1489 Service Stop",
        "T1566 Phishing",
        "T1190 Exploit Public-Facing Application",
        "T1055 Process Injection",
        "T1547 Boot or Logon Autostart Execution",
        "T1021 Remote Services",
        "T1056 Input Capture",
        "T1078 Valid Accounts",
    ]
    covered_ids = {t.split(" ", 1)[0] for t in covered}
    return [c for c in candidates if c.split(" ", 1)[0] not in covered_ids]


@app.get("/incidents/{incident_id}/report", tags=["reporting"])
def report(incident_id: str, format: str = Query(default="json", pattern="^(json|html|md)$")) -> JSONResponse:
    """Generated IR report.

    Week 3 deliverable (docs/PLAN.md W3.1-W3.2). Answers 501 until the Jinja2
    templates land rather than returning a placeholder report that might be
    mistaken for a real one.
    """
    raise HTTPException(
        status_code=501,
        detail=(
            "report generation is scheduled for Week 3 "
            "(docs/PLAN.md W3.1/W3.2). Use GET /incidents/{id}/timeline meanwhile."
        ),
    )


@app.post("/playbooks/reload", tags=["ops"])
def reload_playbooks() -> dict[str, Any]:
    """Reload playbooks from disk. Fails loudly on an invalid playbook."""
    soar = _soar()
    try:
        soar.reload_playbooks()
    except PlaybookValidationError as exc:
        raise HTTPException(status_code=400, detail={"source": exc.source, "problems": exc.problems}) from exc
    return {"loaded": sorted(soar.playbooks), "count": len(soar.playbooks)}