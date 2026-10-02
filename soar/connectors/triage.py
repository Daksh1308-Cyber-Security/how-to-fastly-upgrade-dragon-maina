"""``triage.score`` -- deterministic severity scoring connector.

Real, and pure: it computes the score and returns the rationale that a responder
can audit (docs/ARCHITECTURE.md section 3.1). Read-only, so no compensation.
"""

from __future__ import annotations

from typing import Any

from soar.connectors.base import ActionContext, ConnectorError
from soar.severity import band, score_alert

__all__ = ["TriageScoreConnector"]


class TriageScoreConnector:
    name = "triage.score"
    phase = "detection"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        alert = ctx.var("alert")
        if not isinstance(alert, dict):
            raise ConnectorError("triage.score requires an 'alert' variable in the context")

        score, rationale = score_alert(alert)
        severity = band(score)
        return {
            "score": score,
            "severity": severity,
            "rationale": rationale,
            "auto_run_allowed": severity == "critical",
        }

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        # Pure function; nothing to undo.
        return {"noop": True}