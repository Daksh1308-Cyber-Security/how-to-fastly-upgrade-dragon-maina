"""The simulated lab estate.

**This is the safety boundary.** Every containment, eradication and recovery
action in this project operates on the model in this module and nothing else.
There is no live mode and no code path that reaches a real network, host, or
directory (docs/SECURITY.md section 1).

Isolation is a boolean, not a packet filter. A "firewall rule" is a row in a
table. Nothing here touches a real network stack.

The rollback invariant
---------------------

> Estate state after any compensated run must equal estate state before.

``snapshot()`` deliberately excludes the mutation journal. The journal grows
monotonically by design, so including it would make the invariant untestable.
Only host / account / firewall state is compared.

Idempotence and the already-isolated edge case
----------------------------------------------

Compensation restores the state that the *forward* action recorded, not a
hard-coded "un-isolated" value. This matters: if a host was **already isolated**
when ``isolate_host`` ran, the forward action changed nothing, and a naive
inverse that simply sets ``isolated = False`` would leave the estate in a
different state from before -- silently breaking the invariant. So
``isolate_host`` returns ``was_isolated`` and ``release_host`` restores exactly
that value.
"""

from __future__ import annotations

import copy
import json
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

__all__ = [
    "Host",
    "Account",
    "FirewallRule",
    "Estate",
    "InMemoryEstate",
    "SqliteEstate",
    "ensure_schema",
    "utc_now_iso",
]

VALID_ZONES = frozenset({"corp", "dmz", "restricted"})
VALID_RULE_ACTIONS = frozenset({"allow", "block"})


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(slots=True)
class Host:
    id: str
    hostname: str
    ip: str
    zone: str = "corp"
    criticality: int = 3
    isolated: bool = False


@dataclass(slots=True)
class Account:
    id: str
    username: str
    host_id: str
    privileged: bool = False
    locked: bool = False


@dataclass(slots=True)
class FirewallRule:
    id: str
    zone_from: str
    zone_to: str
    action: str
    subject: str
    created_by_action_id: str | None = None


class EstateError(RuntimeError):
    """Raised when an estate operation is not valid (unknown entity, bad zone)."""


class Estate(ABC):
    """A small model of a network: hosts, accounts and firewall rules.

    Subclasses supply storage. The state-machine semantics and the journal
    contract are defined here so that every implementation behaves identically
    -- which is what lets the same rollback tests run against both backends.
    """

    # -- Read -----------------------------------------------------------------

    @abstractmethod
    def get_host(self, host_id: str) -> Host | None: ...

    @abstractmethod
    def list_hosts(self) -> list[Host]: ...

    @abstractmethod
    def get_account(self, account_id: str) -> Account | None: ...

    @abstractmethod
    def list_accounts(self) -> list[Account]: ...

    @abstractmethod
    def list_rules(self) -> list[FirewallRule]: ...

    # -- Write ----------------------------------------------------------------

    @abstractmethod
    def set_host_isolated(self, host_id: str, value: bool, action_id: str) -> dict[str, Any]: ...

    @abstractmethod
    def set_account_locked(self, account_id: str, value: bool, action_id: str) -> dict[str, Any]: ...

    @abstractmethod
    def add_rule(
        self, zone_from: str, zone_to: str, action: str, subject: str, action_id: str
    ) -> FirewallRule: ...

    @abstractmethod
    def remove_rule(self, rule_id: str, action_id: str) -> FirewallRule | None: ...

    # -- Snapshot / journal ---------------------------------------------------

    @abstractmethod
    def snapshot(self) -> dict[str, Any]: ...

    @abstractmethod
    def restore(self, snap: dict[str, Any]) -> None: ...

    @abstractmethod
    def journal(self) -> list[dict[str, Any]]: ...

    # -- High-level operations ------------------------------------------------
    #
    # These wrap the primitives above and add the undo information that makes
    # compensation correct. Connectors call these, not the primitives.

    def isolate_host(self, host_id: str, action_id: str) -> dict[str, Any]:
        """Isolate a host. Idempotent.

        Returns ``{"host_id", "was_isolated", "changed"}``. ``was_isolated`` is
        the pre-action value and must be handed back to :meth:`release_host`
        during compensation -- see the module docstring.
        """
        host = self.get_host(host_id)
        if host is None:
            raise EstateError(f"unknown host {host_id!r}")
        return self.set_host_isolated(host_id, True, action_id)

    def release_host(self, host_id: str, action_id: str, was_isolated: bool = False) -> dict[str, Any]:
        """Return a host to its recorded pre-isolation state."""
        host = self.get_host(host_id)
        if host is None:
            raise EstateError(f"unknown host {host_id!r}")
        return self.set_host_isolated(host_id, bool(was_isolated), action_id)

    def lock_account(self, account_id: str, action_id: str) -> dict[str, Any]:
        """Lock an account. Idempotent. Returns ``was_locked`` for compensation."""
        account = self.get_account(account_id)
        if account is None:
            raise EstateError(f"unknown account {account_id!r}")
        return self.set_account_locked(account_id, True, action_id)

    def unlock_account(self, account_id: str, action_id: str, was_locked: bool = False) -> dict[str, Any]:
        """Return an account to its recorded pre-lock state."""
        account = self.get_account(account_id)
        if account is None:
            raise EstateError(f"unknown account {account_id!r}")
        return self.set_account_locked(account_id, bool(was_locked), action_id)

    def block(self, zone_from: str, zone_to: str, subject: str, action_id: str) -> dict[str, Any]:
        """Create a block rule. Returns ``{"rule_id"}`` for compensation."""
        rule = self.add_rule(zone_from, zone_to, "block", subject, action_id)
        return {"rule_id": rule.id, "zone_from": zone_from, "zone_to": zone_to, "subject": subject}

    def unblock(self, rule_id: str, action_id: str) -> dict[str, Any]:
        """Remove a block rule. Idempotent -- a missing rule is not an error.

        The removed rule's definition is echoed back so a compensating action
        can re-create it. Removing a rule destroys the only copy of what it
        blocked, so the undo data has to travel with the removal.
        """
        removed = self.remove_rule(rule_id, action_id)
        payload: dict[str, Any] = {"rule_id": rule_id, "removed": removed is not None}
        if removed is not None:
            payload.update(
                {
                    "zone_from": removed.zone_from,
                    "zone_to": removed.zone_to,
                    "action": removed.action,
                    "subject": removed.subject,
                }
            )
        return payload


# ---------------------------------------------------------------------------
# Journal helper -- shared by both backends so the record format is identical.
# ---------------------------------------------------------------------------


class _Journal:
    """Ordered, append-only mutation record."""

    def __init__(self, now_fn: Callable[[], str] = utc_now_iso) -> None:
        self._entries: list[dict[str, Any]] = []
        self._now = now_fn

    def record(
        self, action_id: str, entity: str, entity_id: str, before: Any, after: Any
    ) -> dict[str, Any]:
        entry = {
            "seq": len(self._entries),
            "ts": self._now(),
            "action_id": action_id,
            "entity": entity,
            "entity_id": entity_id,
            "before": before,
            "after": after,
        }
        self._entries.append(entry)
        return entry

    def all(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._entries)


class InMemoryEstate(Estate):
    """Non-persistent estate. Used by the test suite (docs/COMPONENTS.md)."""

    def __init__(
        self,
        hosts: Iterable[Host] | None = None,
        accounts: Iterable[Account] | None = None,
        now_fn: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._hosts: dict[str, Host] = {h.id: h for h in (hosts or [])}
        self._accounts: dict[str, Account] = {a.id: a for a in (accounts or [])}
        self._rules: dict[str, FirewallRule] = {}
        self._journal = _Journal(now_fn)
        self._rule_seq = 0

    # -- Read -----------------------------------------------------------------

    def get_host(self, host_id: str) -> Host | None:
        return self._hosts.get(host_id)

    def list_hosts(self) -> list[Host]:
        return [copy.copy(h) for h in self._hosts.values()]

    def get_account(self, account_id: str) -> Account | None:
        return self._accounts.get(account_id)

    def list_accounts(self) -> list[Account]:
        return [copy.copy(a) for a in self._accounts.values()]

    def list_rules(self) -> list[FirewallRule]:
        return [copy.copy(r) for r in self._rules.values()]

    # -- Write ----------------------------------------------------------------

    def set_host_isolated(self, host_id: str, value: bool, action_id: str) -> dict[str, Any]:
        host = self._hosts[host_id]
        before = {"isolated": host.isolated}
        host.isolated = bool(value)
        after = {"isolated": host.isolated}
        # No-op writes are not journalled: a compensation of an unchanged
        # action must not leave a trace that suggests real work happened.
        if before != after:
            self._journal.record(action_id, "host", host_id, before, after)
        return {"host_id": host_id, "was_isolated": before["isolated"], "changed": before != after}

    def set_account_locked(self, account_id: str, value: bool, action_id: str) -> dict[str, Any]:
        account = self._accounts[account_id]
        before = {"locked": account.locked}
        account.locked = bool(value)
        after = {"locked": account.locked}
        if before != after:
            self._journal.record(action_id, "account", account_id, before, after)
        return {
            "account_id": account_id,
            "was_locked": before["locked"],
            "changed": before != after,
        }

    def add_rule(
        self, zone_from: str, zone_to: str, action: str, subject: str, action_id: str
    ) -> FirewallRule:
        if zone_from not in VALID_ZONES or zone_to not in VALID_ZONES:
            raise EstateError(f"unknown zone in {zone_from!r} -> {zone_to!r}")
        if action not in VALID_RULE_ACTIONS:
            raise EstateError(f"invalid rule action {action!r}")
        self._rule_seq += 1
        rule = FirewallRule(
            id=f"FW-{self._rule_seq:04d}",
            zone_from=zone_from,
            zone_to=zone_to,
            action=action,
            subject=subject,
            created_by_action_id=action_id,
        )
        self._rules[rule.id] = rule
        self._journal.record(action_id, "firewall_rule", rule.id, None, asdict(rule))
        return rule

    def remove_rule(self, rule_id: str, action_id: str) -> FirewallRule | None:
        rule = self._rules.pop(rule_id, None)
        if rule is None:
            return None
        self._journal.record(action_id, "firewall_rule", rule_id, asdict(rule), None)
        return rule

    # -- Snapshot / journal ---------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Deep-copyable state. Excludes the journal by design."""
        return {
            "hosts": {k: asdict(v) for k, v in self._hosts.items()},
            "accounts": {k: asdict(v) for k, v in self._accounts.items()},
            "rules": {k: asdict(v) for k, v in self._rules.items()},
        }

    def restore(self, snap: dict[str, Any]) -> None:
        self._hosts = {k: Host(**v) for k, v in snap["hosts"].items()}
        self._accounts = {k: Account(**v) for k, v in snap["accounts"].items()}
        self._rules = {k: FirewallRule(**v) for k, v in snap["rules"].items()}

    def journal(self) -> list[dict[str, Any]]:
        return self._journal.all()


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    ip          TEXT NOT NULL,
    zone        TEXT NOT NULL,
    criticality INTEGER NOT NULL,
    isolated    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS accounts (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    host_id    TEXT NOT NULL,
    privileged INTEGER NOT NULL DEFAULT 0,
    locked     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS firewall_rules (
    id                  TEXT PRIMARY KEY,
    zone_from           TEXT NOT NULL,
    zone_to             TEXT NOT NULL,
    action              TEXT NOT NULL,
    subject             TEXT NOT NULL,
    created_by_action_id TEXT
);
CREATE TABLE IF NOT EXISTS estate_journal (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    action_id TEXT NOT NULL,
    entity    TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    before    TEXT,
    after     TEXT
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the estate tables if absent. Idempotent (AGENTS.md section 9.1)."""
    conn.executescript(_SCHEMA)
    conn.commit()


def seed_demo_estate(estate: Estate, now_fn: Callable[[], str] = utc_now_iso) -> Estate:
    """Populate an estate with the small demo network the playbooks assume.

    Documented here so fixture alerts, playbooks and tests agree on host and
    account ids (HOST-014, ACC-JOK, ...).
    """
    if isinstance(estate, SqliteEstate):
        conn = estate.conn
        hosts = [
            ("HOST-014", "WS-FIN-014", "10.20.4.31", "corp", 5),
            ("HOST-022", "WS-ENG-022", "10.20.4.52", "corp", 4),
            ("HOST-031", "DC-EU-031", "10.20.1.10", "restricted", 5),
            ("HOST-007", "SRV-FILE-007", "10.20.2.7", "dmz", 4),
            ("HOST-002", "WKS-ENG-002", "10.20.4.2", "corp", 2),
        ]
        accounts = [
            ("ACC-JOK", "j.okafor", "HOST-014", 0),
            ("ACC-DMS", "d.mensah", "HOST-022", 0),
            ("ACC-SVC", "svc-backup", "DC-EU-031", 1),
            ("ACC-ADM", "a.renard", "HOST-031", 1),
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO hosts (id,hostname,ip,zone,criticality,isolated)"
            " VALUES (?,?,?,?,?,0)",
            hosts,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO accounts (id,username,host_id,privileged,locked)"
            " VALUES (?,?,?,?,0)",
            accounts,
        )
        conn.commit()
    else:
        assert isinstance(estate, InMemoryEstate)
        for host_id, hostname, ip, zone, crit in [
            ("HOST-014", "WS-FIN-014", "10.20.4.31", "corp", 5),
            ("HOST-022", "WS-ENG-022", "10.20.4.52", "corp", 4),
            ("HOST-031", "DC-EU-031", "10.20.1.10", "restricted", 5),
            ("HOST-007", "SRV-FILE-007", "10.20.2.7", "dmz", 4),
            ("HOST-002", "WKS-ENG-002", "10.20.4.2", "corp", 2),
        ]:
            estate._hosts.setdefault(host_id, Host(host_id, hostname, ip, zone, crit))
        for acc_id, username, host_id, privileged in [
            ("ACC-JOK", "j.okafor", "HOST-014", False),
            ("ACC-DMS", "d.mensah", "HOST-022", False),
            ("ACC-SVC", "svc-backup", "HOST-031", True),
            ("ACC-ADM", "a.renard", "HOST-031", True),
        ]:
            estate._accounts.setdefault(acc_id, Account(acc_id, username, host_id, privileged))
    return estate


class SqliteEstate(Estate):
    """Runtime estate backed by SQLite. Share a connection with the store."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        now_fn: Callable[[], str] = utc_now_iso,
        db_path: Path | None = None,
    ) -> None:
        self.conn = conn
        self._journal = _Journal(now_fn)
        self._now = now_fn
        self._db_path = db_path
        ensure_schema(conn)

    # -- Read -----------------------------------------------------------------

    def get_host(self, host_id: str) -> Host | None:
        row = self.conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        return _row_to_host(row) if row else None

    def list_hosts(self) -> list[Host]:
        rows = self.conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
        return [_row_to_host(r) for r in rows]

    def get_account(self, account_id: str) -> Account | None:
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return _row_to_account(row) if row else None

    def list_accounts(self) -> list[Account]:
        rows = self.conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
        return [_row_to_account(r) for r in rows]

    def list_rules(self) -> list[FirewallRule]:
        rows = self.conn.execute("SELECT * FROM firewall_rules ORDER BY id").fetchall()
        return [_row_to_rule(r) for r in rows]

    # -- Write ----------------------------------------------------------------

    def _persist_journal(self, entry: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO estate_journal (ts,action_id,entity,entity_id,before,after)"
            " VALUES (?,?,?,?,?,?)",
            (
                entry["ts"],
                entry["action_id"],
                entry["entity"],
                entry["entity_id"],
                json.dumps(entry["before"]) if entry["before"] is not None else None,
                json.dumps(entry["after"]) if entry["after"] is not None else None,
            ),
        )
        self.conn.commit()

    def set_host_isolated(self, host_id: str, value: bool, action_id: str) -> dict[str, Any]:
        host = self.get_host(host_id)
        if host is None:
            raise EstateError(f"unknown host {host_id!r}")
        before = {"isolated": host.isolated}
        self.conn.execute("UPDATE hosts SET isolated=? WHERE id=?", (int(bool(value)), host_id))
        self.conn.commit()
        after = {"isolated": bool(value)}
        if before != after:
            self._persist_journal(self._journal.record(action_id, "host", host_id, before, after))
        return {"host_id": host_id, "was_isolated": before["isolated"], "changed": before != after}

    def set_account_locked(self, account_id: str, value: bool, action_id: str) -> dict[str, Any]:
        account = self.get_account(account_id)
        if account is None:
            raise EstateError(f"unknown account {account_id!r}")
        before = {"locked": account.locked}
        self.conn.execute("UPDATE accounts SET locked=? WHERE id=?", (int(bool(value)), account_id))
        self.conn.commit()
        after = {"locked": bool(value)}
        if before != after:
            self._persist_journal(
                self._journal.record(action_id, "account", account_id, before, after)
            )
        return {"account_id": account_id, "was_locked": before["locked"], "changed": before != after}

    def add_rule(
        self, zone_from: str, zone_to: str, action: str, subject: str, action_id: str
    ) -> FirewallRule:
        if zone_from not in VALID_ZONES or zone_to not in VALID_ZONES:
            raise EstateError(f"unknown zone in {zone_from!r} -> {zone_to!r}")
        if action not in VALID_RULE_ACTIONS:
            raise EstateError(f"invalid rule action {action!r}")
        seq = self.conn.execute("SELECT COUNT(*) FROM firewall_rules").fetchone()[0]
        rule = FirewallRule(
            id=f"FW-{seq + 1:04d}",
            zone_from=zone_from,
            zone_to=zone_to,
            action=action,
            subject=subject,
            created_by_action_id=action_id,
        )
        self.conn.execute(
            "INSERT INTO firewall_rules (id,zone_from,zone_to,action,subject,created_by_action_id)"
            " VALUES (?,?,?,?,?,?)",
            (rule.id, rule.zone_from, rule.zone_to, rule.action, rule.subject, action_id),
        )
        self.conn.commit()
        self._persist_journal(self._journal.record(action_id, "firewall_rule", rule.id, None, asdict(rule)))
        return rule

    def remove_rule(self, rule_id: str, action_id: str) -> FirewallRule | None:
        rule = self.get_rule(rule_id)
        if rule is None:
            return None
        self.conn.execute("DELETE FROM firewall_rules WHERE id=?", (rule_id,))
        self.conn.commit()
        self._persist_journal(self._journal.record(action_id, "firewall_rule", rule_id, asdict(rule), None))
        return rule

    def get_rule(self, rule_id: str) -> FirewallRule | None:
        row = self.conn.execute("SELECT * FROM firewall_rules WHERE id=?", (rule_id,)).fetchone()
        return _row_to_rule(row) if row else None

    # -- Snapshot / journal ---------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        return {
            "hosts": {h.id: asdict(h) for h in self.list_hosts()},
            "accounts": {a.id: asdict(a) for a in self.list_accounts()},
            "rules": {r.id: asdict(r) for r in self.list_rules()},
        }

    def restore(self, snap: dict[str, Any]) -> None:
        """Rebuild estate state from a snapshot. Used by tests and by
        ``POST /incidents/{id}/run?reset_estate=true`` style drills."""
        self.conn.execute("DELETE FROM hosts")
        self.conn.execute("DELETE FROM accounts")
        self.conn.execute("DELETE FROM firewall_rules")
        self.conn.executemany(
            "INSERT INTO hosts (id,hostname,ip,zone,criticality,isolated) VALUES (?,?,?,?,?,?)",
            [
                (v["id"], v["hostname"], v["ip"], v["zone"], v["criticality"], int(v["isolated"]))
                for v in snap["hosts"].values()
            ],
        )
        self.conn.executemany(
            "INSERT INTO accounts (id,username,host_id,privileged,locked) VALUES (?,?,?,?,?)",
            [
                (v["id"], v["username"], v["host_id"], int(v["privileged"]), int(v["locked"]))
                for v in snap["accounts"].values()
            ],
        )
        self.conn.executemany(
            "INSERT INTO firewall_rules (id,zone_from,zone_to,action,subject,created_by_action_id)"
            " VALUES (?,?,?,?,?,?)",
            [
                (
                    v["id"],
                    v["zone_from"],
                    v["zone_to"],
                    v["action"],
                    v["subject"],
                    v.get("created_by_action_id"),
                )
                for v in snap["rules"].values()
            ],
        )
        self.conn.commit()

    def journal(self) -> list[dict[str, Any]]:
        """Read the persistent journal from SQLite, newest entries last."""
        rows = self.conn.execute(
            "SELECT seq,ts,action_id,entity,entity_id,before,after FROM estate_journal ORDER BY seq"
        ).fetchall()
        return [
            {
                "seq": r[0],
                "ts": r[1],
                "action_id": r[2],
                "entity": r[3],
                "entity_id": r[4],
                "before": json.loads(r[5]) if r[5] else None,
                "after": json.loads(r[6]) if r[6] else None,
            }
            for r in rows
        ]


def _row_to_host(row: Any) -> Host:
    return Host(
        id=row["id"],
        hostname=row["hostname"],
        ip=row["ip"],
        zone=row["zone"],
        criticality=row["criticality"],
        isolated=bool(row["isolated"]),
    )


def _row_to_account(row: Any) -> Account:
    return Account(
        id=row["id"],
        username=row["username"],
        host_id=row["host_id"],
        privileged=bool(row["privileged"]),
        locked=bool(row["locked"]),
    )


def _row_to_rule(row: Any) -> FirewallRule:
    return FirewallRule(
        id=row["id"],
        zone_from=row["zone_from"],
        zone_to=row["zone_to"],
        action=row["action"],
        subject=row["subject"],
        created_by_action_id=row["created_by_action_id"],
    )