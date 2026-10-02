"""Connector base types and the canonical connector registry.

Everything the engine can do is a connector with ``execute()`` and
``compensate()``. That single interface is why containment can be automated
safely: it is the *only* way the engine reaches the estate, and every connector
that changes state must be able to undo itself.

``REGISTERED_CONNECTORS`` is also the validation allow-list used by
:mod:`soar.playbook_loader`. A playbook naming a connector that does not exist
fails validation rather than failing at run time, half-way through an incident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "ActionContext",
    "Connector",
    "ConnectorError",
    "REGISTERED_CONNECTORS",
    "READ_ONLY_CONNECTORS",
    "SIMULATED_CONNECTORS",
]


class ConnectorError(RuntimeError):
    """A connector could not complete its action.

    Raising this (rather than returning a falsy result) is how a connector
    signals failure to the engine, which then applies the action's
    ``on_failure`` policy.
    """


@dataclass(slots=True)
class ActionContext:
    """Everything a connector is allowed to see.

    Note what is *not* here: no shell, no network client, no credential store.
    The only outbound capability in the project is the ``vol`` subprocess
    inside ``soar/forensics/memory.py``.
    """

    run_id: str
    incident_id: str
    action_id: str
    severity: str = "medium"
    estate: Any = None
    data_dir: Path | None = None
    #: Read-only roots that evidence collection may copy *from*.
    evidence_roots: list[Path] = field(default_factory=list)
    #: Values available to ``{{ }}`` substitution, including ``alert.*``.
    variables: dict[str, Any] = field(default_factory=dict)

    def var(self, name: str, default: Any = "") -> Any:
        """Look up a template variable without raising."""
        return self.variables.get(name, default)


@runtime_checkable
class Connector(Protocol):
    """The interface the engine depends on."""

    name: str
    phase: str

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        """Perform the action and return a result dict recorded in the journal.

        The returned dict must carry whatever a compensating action needs to
        undo it -- e.g. ``firewall.block`` returns ``rule_id``.
        """
        ...

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        """Undo ``execute`` using values it recorded. Must be idempotent."""
        ...


#: Canonical connector names. Keep in sync with docs/ARCHITECTURE.md section 3.1.
REGISTERED_CONNECTORS: frozenset[str] = frozenset(
    {
        # Detection -- real
        "triage.score",
        "evidence.collect",
        "forensics.volatility",
        "ioc.extract",
        # Containment -- simulated
        "estate.isolate_host",
        "estate.release_host",
        "firewall.block",
        "firewall.unblock",
        "identity.lock_account",
        "identity.unlock_account",
        # Eradication -- simulated
        "eradication.remove_persistence",
        "eradication.quarantine_file",
        "eradication.restore_file",
        # Recovery -- simulated
        "recovery.verify",
    }
)

#: Connectors that cannot change state, and so have no compensation.
READ_ONLY_CONNECTORS: frozenset[str] = frozenset(
    {"triage.score", "forensics.volatility", "ioc.extract", "recovery.verify"}
)

#: Connectors that mutate the simulated estate or virtual filesystem.
SIMULATED_CONNECTORS: frozenset[str] = frozenset(
    {
        "estate.isolate_host",
        "estate.release_host",
        "firewall.block",
        "firewall.unblock",
        "identity.lock_account",
        "identity.unlock_account",
        "eradication.remove_persistence",
        "eradication.quarantine_file",
        "eradication.restore_file",
    }
)