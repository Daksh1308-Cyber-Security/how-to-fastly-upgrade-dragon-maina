"""Connector registry.

:func:`build_default_registry` is the single place connectors are wired up, and
its result must stay consistent with ``REGISTERED_CONNECTORS`` in
:mod:`soar.connectors.base` -- a name registered in one but absent from the
other is a bug, and :func:`verify_registry` asserts it.

Adding a connector name to ``REGISTERED_CONNECTORS`` without implementing it
here would let a playbook validate and then fail mid-incident, which is exactly
what the allow-list exists to prevent.
"""

from __future__ import annotations

from typing import Any

from soar.connectors.base import REGISTERED_CONNECTORS, ActionContext, Connector, ConnectorError
from soar.connectors.containment import (
    FirewallBlockConnector,
    FirewallUnblockConnector,
    IsolateHostConnector,
    LockAccountConnector,
    ReleaseHostConnector,
    UnlockAccountConnector,
)
from soar.connectors.eradication import (
    QuarantineFileConnector,
    RemovePersistenceConnector,
    RestoreFileConnector,
)
from soar.connectors.evidence import EvidenceCollectConnector
from soar.connectors.forensics import IocExtractConnector, VolatilityConnector
from soar.connectors.recovery import RecoveryVerifyConnector
from soar.connectors.triage import TriageScoreConnector

__all__ = ["build_default_registry", "verify_registry", "Connector", "ActionContext", "ConnectorError"]


def build_default_registry() -> dict[str, Any]:
    """Instantiate every shipped connector, keyed by name."""
    connectors = (
        TriageScoreConnector(),
        EvidenceCollectConnector(),
        VolatilityConnector(),
        IocExtractConnector(),
        IsolateHostConnector(),
        ReleaseHostConnector(),
        FirewallBlockConnector(),
        FirewallUnblockConnector(),
        LockAccountConnector(),
        UnlockAccountConnector(),
        RemovePersistenceConnector(),
        QuarantineFileConnector(),
        RestoreFileConnector(),
        RecoveryVerifyConnector(),
    )
    return {c.name: c for c in connectors}


def verify_registry(registry: dict[str, Any]) -> None:
    """Assert the registry and the allow-list agree in both directions.

    Raises:
        ConnectorError: on any discrepancy. Called at API startup so a wiring
            mistake fails loudly on boot rather than during an incident.
    """
    implemented = set(registry)
    declared = set(REGISTERED_CONNECTORS)

    missing = declared - implemented
    if missing:
        raise ConnectorError(f"connectors declared in REGISTERED_CONNECTORS but not implemented: {sorted(missing)}")

    undeclared = implemented - declared
    if undeclared:
        raise ConnectorError(f"connectors implemented but not declared in REGISTERED_CONNECTORS: {sorted(undeclared)}")

    for name, connector in registry.items():
        for attr in ("name", "phase"):
            if not hasattr(connector, attr):
                raise ConnectorError(f"connector {name!r} is missing required attribute {attr!r}")
        if not callable(getattr(connector, "execute", None)):
            raise ConnectorError(f"connector {name!r} has no callable execute()")
        if not callable(getattr(connector, "compensate", None)):
            raise ConnectorError(f"connector {name!r} has no callable compensate()")