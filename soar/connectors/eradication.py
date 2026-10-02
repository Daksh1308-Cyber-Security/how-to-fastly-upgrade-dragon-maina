"""Eradication connectors -- **simulated**.

Eradication removes the adversary's footholds. In this project those footholds
live in a per-incident *virtualised host view* (a JSON document), not on any
real filesystem.

Both eradication actions are reversible, which is a deliberate design choice
over declaring them ``forward_only``: the removed items are recorded so
compensation can put them back, and the rollback invariant in
docs/SECURITY.md section 3.1 therefore holds for these too. ``forward_only``
remains supported by the model for genuinely irreversible steps, but nothing in
the shipped playbooks needs it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soar.connectors.base import ActionContext, ConnectorError

__all__ = [
    "HostView",
    "RemovePersistenceConnector",
    "QuarantineFileConnector",
    "RestoreFileConnector",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class HostView:
    """A per-incident virtualised host: its files and persistence artifacts.

    This is a JSON document, not a real filesystem. Nothing here is capable of
    touching a real file.
    """

    def __init__(self, ctx: ActionContext) -> None:
        if ctx.data_dir is None:
            raise ConnectorError("eradication connectors require a data directory")
        self._path = ctx.data_dir / "incidents" / ctx.incident_id / "host_view.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] = {"quarantined": {}, "persistence_removed": {}}
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                # A corrupt view is worse than an empty one: silently starting
                # from empty would make quarantine look like it never ran.
                self._data = {"quarantined": {}, "persistence_removed": {}, "corrupt": True}

    def _flush(self) -> None:
        self._path.write_text(json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8")

    def snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._data))

    def restore(self, snap: dict[str, Any]) -> None:
        self._data = snap
        self._flush()

    # quarantine ------------------------------------------------------------
    def quarantine(self, path: str, reason: str, action_id: str) -> dict[str, Any]:
        if path in self._data["quarantined"]:
            return {"path": path, "already_quarantined": True}
        record = {"path": path, "reason": reason, "action_id": action_id, "ts": _now_iso()}
        self._data["quarantined"][path] = record
        self._flush()
        return record

    def restore_file(self, path: str, action_id: str) -> dict[str, Any]:
        record = self._data["quarantined"].pop(path, None)
        self._flush()
        return {"path": path, "restored": record is not None, "record": record}

    # persistence -----------------------------------------------------------
    def remove_persistence(self, artifact: str, kind: str, action_id: str) -> dict[str, Any]:
        slot = artifact if artifact in self._data["persistence_removed"] else None
        if slot:
            return {"artifact": artifact, "already_removed": True}
        record = {"artifact": artifact, "kind": kind, "action_id": action_id, "ts": _now_iso()}
        self._data["persistence_removed"][artifact] = record
        self._flush()
        return record

    def restore_persistence(self, artifact: str, action_id: str) -> dict[str, Any]:
        record = self._data["persistence_removed"].pop(artifact, None)
        self._flush()
        return {"artifact": artifact, "restored": record is not None, "record": record}


class RemovePersistenceConnector:
    """Eradicate a persistence mechanism from the virtualised host."""

    name = "eradication.remove_persistence"
    phase = "eradication"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        artifact = str(params.get("artifact", "") or "")
        if not artifact:
            raise ConnectorError("remove_persistence requires 'artifact'")
        view = HostView(ctx)
        record = view.remove_persistence(artifact, str(params.get("kind", "unknown")), ctx.action_id)
        return {**record, "simulated": True}

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        artifact = result.get("artifact") or params.get("artifact")
        view = HostView(ctx)
        # Only re-add something we actually removed; a no-op forward action must
        # not manufacture a persistence entry that never existed.
        if result.get("already_removed"):
            return {"artifact": artifact, "skipped": "was already absent before the forward action"}
        return view.restore_persistence(str(artifact), ctx.action_id)


class QuarantineFileConnector:
    """Quarantine a malicious file in the virtualised host."""

    name = "eradication.quarantine_file"
    phase = "eradication"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        path = str(params.get("path", "") or "")
        if not path:
            raise ConnectorError("quarantine_file requires 'path'")
        view = HostView(ctx)
        record = view.quarantine(path, str(params.get("reason", "incident eradication")), ctx.action_id)
        return {**record, "simulated": True}

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        path = result.get("path") or params.get("path")
        if result.get("already_quarantined"):
            return {"path": path, "skipped": "was already quarantined before the forward action"}
        view = HostView(ctx)
        return view.restore_file(str(path), ctx.action_id)


class RestoreFileConnector:
    """Return a quarantined file to the virtualised host (recovery)."""

    name = "eradication.restore_file"
    phase = "recovery"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        path = str(params.get("path", "") or "")
        if not path:
            raise ConnectorError("restore_file requires 'path'")
        view = HostView(ctx)
        return view.restore_file(path, ctx.action_id)

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        path = result.get("path") or params.get("path")
        view = HostView(ctx)
        reason = (result.get("record") or {}).get("reason", "re-quarantined during rollback")
        return view.quarantine(str(path), reason, ctx.action_id)