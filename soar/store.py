"""SQLite persistence.

Standard library ``sqlite3`` only -- no ORM (docs/ARCHITECTURE.md section 9.1).
Schema is created idempotently at startup, so there are no migrations to manage.

WAL mode is enabled so a long-running playbook does not block the API from
serving reads.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from soar.estate import ensure_schema as ensure_estate_schema
from soar.models import ActionResult, Evidence, Incident, Run
from soar.nist import Phase

__all__ = ["Store", "connect"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id           TEXT PRIMARY KEY,
    alert        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    score        INTEGER NOT NULL,
    rationale    TEXT NOT NULL,
    phase        TEXT NOT NULL,
    status       TEXT NOT NULL,
    playbook_id  TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id                       TEXT PRIMARY KEY,
    incident_id              TEXT NOT NULL,
    playbook_id              TEXT NOT NULL,
    status                   TEXT NOT NULL,
    phase_timings            TEXT NOT NULL DEFAULT '{}',
    incomplete               INTEGER NOT NULL DEFAULT 0,
    forward_only_applied     TEXT NOT NULL DEFAULT '[]',
    started_at               TEXT,
    ended_at                 TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents (id)
);
CREATE TABLE IF NOT EXISTS actions (
    run_id          TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    action_id       TEXT NOT NULL,
    connector       TEXT NOT NULL,
    status          TEXT NOT NULL,
    result          TEXT NOT NULL DEFAULT '{}',
    error           TEXT,
    started_at      TEXT,
    ended_at        TEXT,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    compensation_of TEXT,
    PRIMARY KEY (run_id, seq),
    FOREIGN KEY (run_id) REFERENCES runs (id)
);
CREATE TABLE IF NOT EXISTS evidence (
    id           TEXT PRIMARY KEY,
    incident_id  TEXT NOT NULL,
    artifact     TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size         INTEGER NOT NULL,
    source       TEXT NOT NULL,
    collected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_runs_incident ON runs (incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions (run_id, seq);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence (incident_id);
"""


def connect(db_path: str | Path = "data/ir.db") -> sqlite3.Connection:
    """Open (and if needed create) the database with WAL mode enabled."""
    path = Path(db_path)
    if path.parent != Path(""):
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    ensure_estate_schema(conn)
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


class Store:
    """Thin data-access layer. Thread-safe for the API's access pattern."""

    def __init__(self, db_path: str | Path = "data/ir.db") -> None:
        self.db_path = Path(db_path)
        self.conn = connect(db_path)
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- incidents ------------------------------------------------------------

    def save_incident(self, incident: Incident) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO incidents"
                " (id,alert,severity,score,rationale,phase,status,playbook_id,created_at,updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    incident.id,
                    json.dumps(incident.alert),
                    incident.severity,
                    incident.score,
                    json.dumps(incident.rationale),
                    str(incident.phase),
                    incident.status,
                    incident.playbook_id,
                    incident.created_at,
                    incident.updated_at,
                ),
            )
            self.conn.commit()

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self.conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return self._row_to_incident(row) if row else None

    def list_incidents(
        self, severity: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[Incident]:
        clauses, params = [], []
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if status:
            clauses.append("status=?")
            params.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM incidents{where} ORDER BY created_at DESC LIMIT ?", params
        ).fetchall()
        return [self._row_to_incident(r) for r in rows]

    @staticmethod
    def _row_to_incident(row: sqlite3.Row) -> Incident:
        return Incident(
            id=row["id"],
            alert=json.loads(row["alert"]),
            severity=row["severity"],
            score=row["score"],
            rationale=json.loads(row["rationale"]),
            phase=Phase(row["phase"]) if row["phase"] in {str(p) for p in Phase} else Phase.PREPARATION,
            status=row["status"],
            playbook_id=row["playbook_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # -- runs -----------------------------------------------------------------

    def save_run(self, run: Run) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO runs"
                " (id,incident_id,playbook_id,status,phase_timings,incomplete,forward_only_applied,started_at,ended_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run.id,
                    run.incident_id,
                    run.playbook_id,
                    run.status,
                    json.dumps(run.phase_timings),
                    int(run.incomplete),
                    json.dumps(run.forward_only_applied),
                    run.started_at,
                    run.ended_at,
                ),
            )
            self.conn.commit()

    def get_run(self, run_id: str) -> Run | None:
        row = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._row_to_run(row) if row else None

    def latest_run_for(self, incident_id: str) -> Run | None:
        row = self.conn.execute(
            "SELECT * FROM runs WHERE incident_id=? ORDER BY started_at DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
        return self._row_to_run(row) if row else None

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> Run:
        return Run(
            id=row["id"],
            incident_id=row["incident_id"],
            playbook_id=row["playbook_id"],
            status=row["status"],
            phase_timings=json.loads(row["phase_timings"]),
            incomplete=bool(row["incomplete"]),
            forward_only_applied=json.loads(row["forward_only_applied"]),
            started_at=row["started_at"] or "",
            ended_at=row["ended_at"] or "",
        )

    # -- action results -------------------------------------------------------

    def save_action_results(self, run_id: str, results: Iterable[ActionResult]) -> None:
        """Append action results. ``seq`` is derived from the existing row count
        so results append in order across resume invocations."""
        with self._lock:
            start = self.conn.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 FROM actions WHERE run_id=?", (run_id,)
            ).fetchone()[0]
            for offset, result in enumerate(results):
                self.conn.execute(
                    "INSERT OR REPLACE INTO actions"
                    " (run_id,seq,action_id,connector,status,result,error,started_at,ended_at,duration_ms,compensation_of)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        run_id,
                        start + offset,
                        result.action_id,
                        result.connector,
                        result.status,
                        json.dumps(result.result, default=str),
                        result.error,
                        result.started_at,
                        result.ended_at,
                        result.duration_ms,
                        result.compensation_of,
                    ),
                )
            self.conn.commit()

    def get_action_results(self, run_id: str) -> list[ActionResult]:
        rows = self.conn.execute(
            "SELECT * FROM actions WHERE run_id=? ORDER BY seq", (run_id,)
        ).fetchall()
        return [
            ActionResult(
                action_id=r["action_id"],
                connector=r["connector"],
                status=r["status"],
                result=json.loads(r["result"]),
                error=r["error"],
                started_at=r["started_at"] or "",
                ended_at=r["ended_at"] or "",
                duration_ms=r["duration_ms"],
                compensation_of=r["compensation_of"],
            )
            for r in rows
        ]

    # -- evidence -------------------------------------------------------------

    def save_evidence(self, evidence: Iterable[Evidence]) -> None:
        with self._lock:
            for item in evidence:
                self.conn.execute(
                    "INSERT OR REPLACE INTO evidence"
                    " (id,incident_id,artifact,sha256,size,source,collected_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        item.id,
                        item.incident_id,
                        item.artifact,
                        item.sha256,
                        item.size,
                        item.source,
                        item.collected_at,
                    ),
                )
            self.conn.commit()

    def get_evidence(self, incident_id: str) -> list[Evidence]:
        rows = self.conn.execute(
            "SELECT * FROM evidence WHERE incident_id=? ORDER BY collected_at", (incident_id,)
        ).fetchall()
        return [
            Evidence(
                id=r["id"],
                incident_id=r["incident_id"],
                artifact=r["artifact"],
                sha256=r["sha256"],
                size=r["size"],
                source=r["source"],
                collected_at=r["collected_at"],
            )
            for r in rows
        ]