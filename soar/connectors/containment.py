"""Containment connectors -- **simulated**.

These mutate the model in :mod:`soar.estate` and nothing else. There is no live
mode, no shell-out, and no path to a real network
(docs/SECURITY.md section 1-2).

Compensation correctness
------------------------

Each forward action returns the state it found (``was_isolated`` /
``was_locked``), and each inverse restores *that recorded value* rather than
assuming a default. Without this, a playbook that isolates an already-isolated
host would, on rollback, leave it un-isolated -- silently breaking the invariant
in docs/SECURITY.md section 3.1.

Every inverse is idempotent, so a double compensation is harmless.
"""

from __future__ import annotations

from typing import Any

from soar.connectors.base import ActionContext, ConnectorError

__all__ = [
    "IsolateHostConnector",
    "ReleaseHostConnector",
    "FirewallBlockConnector",
    "FirewallUnblockConnector",
    "LockAccountConnector",
    "UnlockAccountConnector",
]


def _require_estate(ctx: ActionContext):
    if ctx.estate is None:
        raise ConnectorError("containment connectors require an estate in the action context")
    return ctx.estate


class IsolateHostConnector:
    """Network-isolate an affected host (simulated)."""

    name = "estate.isolate_host"
    phase = "containment"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        estate = _require_estate(ctx)
        host_id = str(params.get("host_id", "") or "")
        if not host_id:
            raise ConnectorError("isolate_host requires 'host_id'")
        result = estate.isolate_host(host_id, ctx.action_id)
        return {
            **result,
            "hostname": (estate.get_host(host_id).hostname if estate.get_host(host_id) else None),
            "simulated": True,
        }

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        estate = _require_estate(ctx)
        host_id = result.get("host_id") or params.get("host_id")
        # Restore the state the forward action found, not a hard-coded False.
        was_isolated = bool(result.get("was_isolated", False))
        out = estate.release_host(str(host_id), ctx.action_id, was_isolated=was_isolated)
        return {"restored_was_isolated": was_isolated, **out}


class ReleaseHostConnector:
    """Explicitly return a host to the network (simulated).

    Only used as a standalone recovery action. ``compensate`` re-isolates,
    because the point of this action is that it changes state.
    """

    name = "estate.release_host"
    phase = "recovery"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        estate = _require_estate(ctx)
        host_id = str(params.get("host_id", "") or "")
        if not host_id:
            raise ConnectorError("release_host requires 'host_id'")
        return estate.release_host(host_id, ctx.action_id, was_isolated=False)

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        estate = _require_estate(ctx)
        host_id = result.get("host_id") or params.get("host_id")
        return estate.isolate_host(str(host_id), ctx.action_id)


class FirewallBlockConnector:
    """Add a block rule to the simulated ruleset."""

    name = "firewall.block"
    phase = "containment"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        estate = _require_estate(ctx)
        zone_from = str(params.get("zone_from", "corp"))
        zone_to = str(params.get("zone_to", "restricted"))
        subject = str(params.get("subject", "") or "")
        if not subject:
            raise ConnectorError("firewall.block requires 'subject'")
        result = estate.block(zone_from, zone_to, subject, ctx.action_id)
        return {**result, "simulated": True}

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        estate = _require_estate(ctx)
        rule_id = result.get("rule_id")
        if not rule_id:
            raise ConnectorError("cannot compensate firewall.block: no rule_id was recorded")
        return estate.unblock(str(rule_id), ctx.action_id)


class FirewallUnblockConnector:
    """Remove a block rule from the simulated ruleset."""

    name = "firewall.unblock"
    phase = "recovery"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        estate = _require_estate(ctx)
        rule_id = str(params.get("rule_id", "") or "")
        if not rule_id:
            raise ConnectorError("firewall.unblock requires 'rule_id'")
        return estate.unblock(rule_id, ctx.action_id)

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        # Removing a rule destroys the definition needed to re-create it, so
        # the forward result carries it and compensation re-adds it verbatim.
        estate = _require_estate(ctx)
        rule_id = result.get("rule_id")
        if not rule_id:
            raise ConnectorError("cannot compensate firewall.unblock: no rule_id was recorded")
        rule = estate.add_rule(
            str(result.get("zone_from", "corp")),
            str(result.get("zone_to", "restricted")),
            "block",
            str(result.get("subject", "restored")),
            ctx.action_id,
        )
        return {"rule_id": rule.id, "restored": True}


class LockAccountConnector:
    """Lock a compromised account in the simulated directory."""

    name = "identity.lock_account"
    phase = "containment"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        estate = _require_estate(ctx)
        account_id = str(params.get("account_id", "") or "")
        if not account_id:
            raise ConnectorError("identity.lock_account requires 'account_id'")
        result = estate.lock_account(account_id, ctx.action_id)
        account = estate.get_account(account_id)
        return {**result, "username": account.username if account else None, "simulated": True}

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        estate = _require_estate(ctx)
        account_id = result.get("account_id") or params.get("account_id")
        was_locked = bool(result.get("was_locked", False))
        out = estate.unlock_account(str(account_id), ctx.action_id, was_locked=was_locked)
        return {"restored_was_locked": was_locked, **out}


class UnlockAccountConnector:
    """Unlock an account in the simulated directory."""

    name = "identity.unlock_account"
    phase = "recovery"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        estate = _require_estate(ctx)
        account_id = str(params.get("account_id", "") or "")
        if not account_id:
            raise ConnectorError("identity.unlock_account requires 'account_id'")
        return estate.unlock_account(account_id, ctx.action_id, was_locked=False)

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        estate = _require_estate(ctx)
        account_id = result.get("account_id") or params.get("account_id")
        return estate.lock_account(str(account_id), ctx.action_id)