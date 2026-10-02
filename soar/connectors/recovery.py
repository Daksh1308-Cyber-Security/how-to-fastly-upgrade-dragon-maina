"""``recovery.verify`` -- post-containment health checks (simulated).

Read-only, so it has no compensation. Its job is to answer the question the
incident report needs answered: **did containment actually hold?**

Each check returns ``{"name", "passed", "detail"}``. The connector fails loudly
if a check does not pass rather than reporting a healthy recovery it cannot
substantiate.
"""

from __future__ import annotations

from typing import Any

from soar.connectors.base import ActionContext, ConnectorError
from soar.connectors.evidence import verify as verify_evidence

__all__ = ["RecoveryVerifyConnector"]


class RecoveryVerifyConnector:
    name = "recovery.verify"
    phase = "recovery"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        estate = ctx.estate

        # 1. Host still isolated -- containment held.
        host_id = str(params.get("host_id", "") or "")
        if host_id and estate is not None:
            host = estate.get_host(host_id)
            if host is None:
                checks.append(
                    {"name": "host_isolated", "passed": False, "detail": f"host {host_id} not in estate"}
                )
            else:
                checks.append(
                    {
                        "name": "host_isolated",
                        "passed": bool(host.isolated),
                        "detail": f"{host.hostname} isolated={host.isolated}",
                    }
                )

        # 2. Account still locked.
        account_id = str(params.get("account_id", "") or "")
        if account_id and estate is not None:
            account = estate.get_account(account_id)
            if account is None:
                checks.append(
                    {"name": "account_locked", "passed": False, "detail": f"account {account_id} not in estate"}
                )
            else:
                checks.append(
                    {
                        "name": "account_locked",
                        "passed": bool(account.locked),
                        "detail": f"{account.username} locked={account.locked}",
                    }
                )

        # 3. No IOC reappeared after containment, compared against the baseline
        #    captured during detection.
        #
        #    IOCs are dicts with type/value. A prior version read ``i.get("key")``
        #    and unpacked the result, which raised AttributeError on every run --
        #    recovery.verify was failing in production while passing in unit
        #    tests that supplied no IOCs.
        def _ioc_set(raw: Any) -> set[tuple[str, str]]:
            keys: set[tuple[str, str]] = set()
            for item in raw or []:
                if isinstance(item, dict):
                    ioc_type, value = item.get("type"), item.get("value")
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    ioc_type, value = item
                else:
                    continue
                if ioc_type and value:
                    keys.add((str(ioc_type), str(value)))
            return keys

        baseline = _ioc_set(ctx.var("iocs"))
        current = _ioc_set(ctx.var("iocs_rescan") or baseline)
        new_iocs = sorted(f"{t}:{v}" for t, v in (current - baseline))
        checks.append(
            {
                "name": "no_new_iocs",
                "passed": not new_iocs,
                "detail": "no new indicators since containment" if not new_iocs else f"new: {new_iocs}",
            }
        )

        # 4. Eradicated persistence is still absent.
        from soar.connectors.eradication import HostView

        try:
            view = HostView(ctx)
            remaining = list(view.snapshot()["persistence_removed"].keys())
        except ConnectorError:
            remaining = []
        checks.append(
            {
                "name": "persistence_eradicated",
                "passed": not remaining,
                "detail": "no persistence artifacts recorded" if not remaining else f"remaining: {remaining}",
            }
        )

        # 5. Evidence integrity still passes.
        integrity = verify_evidence(ctx)
        checks.append(
            {
                "name": "evidence_integrity",
                "passed": bool(integrity["ok"]),
                "detail": f"{integrity['integrity']} ({len(integrity['artifacts'])} artifacts)",
            }
        )

        failed = [c for c in checks if not c["passed"]]
        return {
            "checks": checks,
            "passed": not failed,
            "failed_checks": [c["name"] for c in failed],
            "healthy": not failed,
        }

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        return {"noop": True, "reason": "recovery.verify is read-only"}