"""Forensic connectors -- **real**.

``forensics.volatility`` and ``ioc.extract`` do genuine work. What makes them
safe is that both operate on files the operator supplied under ``fixtures/``,
and neither can reach anything else (docs/SECURITY.md section 2).

Both are read-only, so neither has a compensation.
"""

from __future__ import annotations

from typing import Any

from soar.connectors.base import ActionContext, ConnectorError
from soar.connectors.evidence import manifest
from soar.forensics import ioc as ioc_module
from soar.forensics.memory import ForensicsUnavailable, analyze

__all__ = ["VolatilityConnector", "IocExtractConnector"]


class VolatilityConnector:
    """Run Volatility 3 plugins against the available memory input."""

    name = "forensics.volatility"
    phase = "detection"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        plugins = params.get("plugins")
        try:
            result = analyze(
                plugins=list(plugins) if isinstance(plugins, list) else None,
                prefer_recorded=bool(params.get("prefer_recorded", False)),
            )
        except ForensicsUnavailable as exc:
            # A skipped step, not a failure. The engine marks the run incomplete
            # so the report says forensics did not run rather than implying it
            # found nothing (docs/METRICS.md section 4.5).
            return {
                "status": "skipped",
                "reason": str(exc),
                "plugins": {},
                "outcomes": [],
                "skipped": [],
                "source": None,
                "image": None,
            }
        return result

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        return {"noop": True, "reason": "forensics.volatility is read-only"}


class IocExtractConnector:
    """Extract IOCs from Volatility output and collected evidence."""

    name = "ioc.extract"
    phase = "detection"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        vol_output = params.get("vol_output") or ctx.var("vol_output") or {}
        if not isinstance(vol_output, dict):
            raise ConnectorError("ioc.extract expects 'vol_output' to be a mapping of plugin -> rows")

        evidence = manifest(ctx) if ctx.data_dir is not None else []
        iocs = ioc_module.extract(vol_output=vol_output, artifacts=evidence)

        by_type: dict[str, int] = {}
        for ioc in iocs:
            by_type[ioc["type"]] = by_type.get(ioc["type"], 0) + 1

        return {
            "iocs": iocs,
            "count": len(iocs),
            "by_type": by_type,
            "high_confidence": [i for i in iocs if float(i.get("confidence", 0)) >= 0.7],
        }

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        return {"noop": True, "reason": "ioc.extract is a pure function"}