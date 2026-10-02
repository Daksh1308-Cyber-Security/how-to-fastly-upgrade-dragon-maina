"""The rollback invariant -- the most important safety property in the project.

> Estate state after any compensated run must equal estate state before.

(docs/SECURITY.md section 3.1)

These tests assert that on **full** estate state, not a convenient subset. A
test that only checked ``host.isolated`` would pass while leaving a firewall
rule behind.
"""

from __future__ import annotations

import pytest

from soar.connectors.containment import (
    FirewallBlockConnector,
    FirewallUnblockConnector,
    IsolateHostConnector,
    LockAccountConnector,
    ReleaseHostConnector,
    UnlockAccountConnector,
)
from soar.connectors.base import ActionContext
from soar.engine import Engine
from soar.models import Action, Playbook, Run
from soar.nist import Phase


def _ctx(estate, action_id="a-test"):
    return ActionContext(
        run_id="RUN-T",
        incident_id="INC-T",
        action_id=action_id,
        estate=estate,
    )


# --- per-connector inverses -------------------------------------------------


def test_isolate_then_release_restores_host(estate):
    connector = IsolateHostConnector()
    before = estate.snapshot()

    result = connector.execute({"host_id": "HOST-014"}, _ctx(estate))
    assert estate.get_host("HOST-014").isolated is True

    connector.compensate({"host_id": "HOST-014"}, _ctx(estate), result)
    assert estate.snapshot() == before


def test_lock_then_unlock_restores_account(estate):
    connector = LockAccountConnector()
    before = estate.snapshot()

    result = connector.execute({"account_id": "ACC-JOK"}, _ctx(estate))
    assert estate.get_account("ACC-JOK").locked is True

    connector.compensate({"account_id": "ACC-JOK"}, _ctx(estate), result)
    assert estate.snapshot() == before


def test_block_then_unblock_restores_ruleset(estate):
    connector = FirewallBlockConnector()
    before = estate.snapshot()

    result = connector.execute(
        {"zone_from": "corp", "zone_to": "restricted", "subject": "203.0.113.44"}, _ctx(estate)
    )
    assert len(estate.list_rules()) == 1

    connector.compensate({}, _ctx(estate), result)
    assert estate.snapshot() == before


def test_already_isolated_host_survives_rollback(estate):
    """The edge case a naive inverse gets wrong.

    If the host was *already* isolated when ``isolate_host`` ran, the forward
    action changed nothing. An inverse that hard-codes ``isolated = False``
    would leave it un-isolated -- silently breaking the invariant.
    """
    estate.set_host_isolated("HOST-014", True, "pre-existing")
    before = estate.snapshot()

    connector = IsolateHostConnector()
    result = connector.execute({"host_id": "HOST-014"}, _ctx(estate))
    assert result["changed"] is False, "no-op should report changed=False"

    connector.compensate({"host_id": "HOST-014"}, _ctx(estate), result)
    assert estate.snapshot() == before, "already-isolated host was wrongly un-isolated"


def test_already_locked_account_survives_rollback(estate):
    estate.set_account_locked("ACC-JOK", True, "pre-existing")
    before = estate.snapshot()

    connector = LockAccountConnector()
    result = connector.execute({"account_id": "ACC-JOK"}, _ctx(estate))
    assert result["changed"] is False

    connector.compensate({"account_id": "ACC-JOK"}, _ctx(estate), result)
    assert estate.snapshot() == before


def test_compensation_is_idempotent(estate):
    """A double compensation must be harmless."""
    before = estate.snapshot()
    connector = IsolateHostConnector()
    result = connector.execute({"host_id": "HOST-022"}, _ctx(estate))

    connector.compensate({}, _ctx(estate), result)
    after_first = estate.snapshot()
    connector.compensate({}, _ctx(estate), result)
    assert estate.snapshot() == after_first == before


def test_release_host_standalone_is_reversible(estate):
    before = estate.snapshot()
    estate.set_host_isolated("HOST-002", True, "seed")

    connector = ReleaseHostConnector()
    result = connector.execute({"host_id": "HOST-002"}, _ctx(estate))
    assert estate.get_host("HOST-002").isolated is False

    connector.compensate({"host_id": "HOST-002"}, _ctx(estate), result)
    assert estate.get_host("HOST-002").isolated is True
    assert estate.snapshot() != before


def test_unlock_account_standalone_is_reversible(estate):
    estate.set_account_locked("ACC-DMS", True, "seed")
    connector = UnlockAccountConnector()
    result = connector.execute({"account_id": "ACC-DMS"}, _ctx(estate))
    assert estate.get_account("ACC-DMS").locked is False

    connector.compensate({}, _ctx(estate), result)
    assert estate.get_account("ACC-DMS").locked is True


def test_unblock_standalone_recreates_rule(estate):
    """Removing a rule destroys its definition; compensation must rebuild it."""
    estate.add_rule("corp", "restricted", "block", "203.0.113.44", "seed")
    rule_id = estate.list_rules()[0].id
    before = estate.snapshot()

    connector = FirewallUnblockConnector()
    result = connector.execute({"rule_id": rule_id}, _ctx(estate))
    assert estate.list_rules() == []

    connector.compensate({}, _ctx(estate), result)
    after = estate.snapshot()
    assert len(after["rules"]) == 1
    # The recreated rule must carry the same subject, or the block is useless.
    assert list(after["rules"].values())[0]["subject"] == before["rules"][rule_id]["subject"]


# --- engine-level abort -----------------------------------------------------


class _ExplodingConnector:
    """Fails on execute; records that compensate ran."""

    name = "test.explode"
    phase = "eradication"

    def __init__(self) -> None:
        self.compensated = 0

    def execute(self, params, ctx):
        raise RuntimeError("deliberate failure for rollback testing")

    def compensate(self, params, ctx, result):
        self.compensated += 1
        return {"compensated": True}


def test_run_abort_restores_full_estate_state(registry, estate, data_dir, ransomware_alert):
    """Containment succeeds, eradication fails -> everything is undone."""
    from soar.models import Incident

    exploding = _ExplodingConnector()
    test_registry = {**registry, exploding.name: exploding}
    engine = Engine(
        registry=test_registry,
        estate=estate,
        data_dir=data_dir,
        evidence_roots=[],
        verify=False,
    )

    playbook = Playbook(
        id="rollback-test",
        name="Rollback test",
        phases=[Phase.DETECTION, Phase.CONTAINMENT, Phase.ERADICATION],
        actions=[
            Action(id="isolate", name="Isolate", phase=Phase.CONTAINMENT,
                   connector="estate.isolate_host", params={"host_id": "HOST-014"}),
            Action(id="lock", name="Lock", phase=Phase.CONTAINMENT,
                   connector="identity.lock_account", params={"account_id": "ACC-JOK"}),
            Action(id="boom", name="Fail", phase=Phase.ERADICATION,
                   connector=exploding.name, params={}, on_failure="abort"),
        ],
    )

    before = estate.snapshot()
    incident = Incident(
        id="INC-RB", alert=ransomware_alert, severity="critical", score=95,
        phase=Phase.DETECTION, playbook_id="rollback-test",
    )
    run_obj = Run(id="RUN-RB", incident_id="INC-RB", playbook_id="rollback-test")

    engine.execute(incident, playbook, run_obj, auto_approve=True)
    engine.shutdown()

    assert run_obj.status == "aborted"
    assert estate.snapshot() == before, "estate not fully restored after abort"
    # Reverse-order compensation is asserted precisely in the next test.
    ids = [j["action_id"] for j in estate.journal()]
    assert ids, "mutations should have been journalled"


def test_compensation_runs_in_reverse_order(registry, estate, data_dir, ransomware_alert):
    from soar.models import Incident

    exploding = _ExplodingConnector()
    engine = Engine(
        registry={**registry, exploding.name: exploding},
        estate=estate,
        data_dir=data_dir,
        evidence_roots=[],
        verify=False,
    )

    playbook = Playbook(
        id="order-test",
        name="Order test",
        phases=[Phase.CONTAINMENT, Phase.ERADICATION],
        actions=[
            Action(id="a_isolate", name="Isolate", phase=Phase.CONTAINMENT,
                   connector="estate.isolate_host", params={"host_id": "HOST-014"}),
            Action(id="b_lock", name="Lock", phase=Phase.CONTAINMENT,
                   connector="identity.lock_account", params={"account_id": "ACC-JOK"}),
            Action(id="c_boom", name="Fail", phase=Phase.ERADICATION,
                   connector=exploding.name, params={}, on_failure="abort"),
        ],
    )
    incident = Incident(id="INC-ORD", alert=ransomware_alert, severity="critical", score=95,
                        phase=Phase.DETECTION, playbook_id="order-test")
    run_obj = Run(id="RUN-ORD", incident_id="INC-ORD", playbook_id="order-test")

    _, results = engine.execute(incident, playbook, run_obj, auto_approve=True)
    engine.shutdown()

    compensated = [r.compensation_of for r in results if r.compensation_of]
    assert compensated == ["b_lock", "a_isolate"], "compensation must run newest-first"


def test_failure_with_no_prior_mutations_leaves_estate_untouched(registry, estate, data_dir, ransomware_alert):
    from soar.models import Incident

    exploding = _ExplodingConnector()
    engine = Engine(
        registry={**registry, exploding.name: exploding},
        estate=estate,
        data_dir=data_dir,
        evidence_roots=[],
        verify=False,
    )
    playbook = Playbook(
        id="clean-abort", name="Clean abort",
        phases=[Phase.DETECTION, Phase.ERADICATION],
        actions=[Action(id="boom", name="Fail", phase=Phase.ERADICATION,
                        connector=exploding.name, params={}, on_failure="abort")],
    )
    incident = Incident(id="INC-CLEAN", alert=ransomware_alert, severity="critical", score=95,
                        phase=Phase.DETECTION, playbook_id="clean-abort")
    run_obj = Run(id="RUN-CLEAN", incident_id="INC-CLEAN", playbook_id="clean-abort")

    before = estate.snapshot()
    engine.execute(incident, playbook, run_obj, auto_approve=True)
    engine.shutdown()

    assert run_obj.status == "aborted"
    assert estate.snapshot() == before


def test_evidence_is_never_rolled_back(registry, estate, data_dir, ransomware_alert):
    """Evidence is append-only; a rollback must not delete it."""
    from soar.models import Incident
    from tests.conftest import EVIDENCE

    exploding = _ExplodingConnector()
    engine = Engine(
        registry={**registry, exploding.name: exploding},
        estate=estate,
        data_dir=data_dir,
        evidence_roots=[EVIDENCE],
        verify=False,
    )

    playbook = Playbook(
        id="evid-test", name="Evidence test",
        phases=[Phase.DETECTION, Phase.ERADICATION],
        actions=[
            Action(id="collect", name="Collect", phase=Phase.DETECTION,
                   connector="evidence.collect",
                   params={"artifacts": ["evidence/host-inventory.json"]}),
            Action(id="boom", name="Fail", phase=Phase.ERADICATION,
                   connector=exploding.name, params={}, on_failure="abort"),
        ],
    )
    incident = Incident(id="INC-EV", alert=ransomware_alert, severity="critical", score=95,
                        phase=Phase.DETECTION, playbook_id="evid-test")
    run_obj = Run(id="RUN-EV", incident_id="INC-EV", playbook_id="evid-test")

    engine.execute(incident, playbook, run_obj, auto_approve=True)
    engine.shutdown()

    collected = data_dir / "incidents" / "INC-EV" / "evidence" / "host-inventory.json"
    assert collected.exists(), "rollback must not destroy collected evidence"
    custody = data_dir / "incidents" / "INC-EV" / "chain_of_custody.jsonl"
    assert custody.exists(), "chain of custody must survive a rollback"