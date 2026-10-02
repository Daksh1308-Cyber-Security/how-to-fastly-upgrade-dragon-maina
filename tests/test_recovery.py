"""Recovery verification checks.

Added because ``recovery.verify`` shipped with a latent ``AttributeError``: its
IOC-baseline check called ``.get("key")`` on IOC dicts and then unpacked the
result. Unit tests passed because they supplied no IOCs, so the branch was never
exercised -- and it failed on every real run. These tests exercise each branch
with the shapes the engine actually produces.
"""

from __future__ import annotations

import json

import pytest

from soar.connectors.base import ActionContext, ConnectorError
from soar.connectors.evidence import EvidenceCollectConnector
from soar.connectors.recovery import RecoveryVerifyConnector
from tests.conftest import EVIDENCE


def _ctx(data_dir, estate, **variables) -> ActionContext:
    """Recovery checks read the estate from ``ctx.estate``.

    The estate is passed as a *separate* argument rather than folded into
    ``variables``, because ``ActionContext.estate`` is a dedicated field that
    connectors read directly.
    """
    return ActionContext(
        run_id="RUN-R",
        incident_id="INC-R",
        action_id="verify",
        data_dir=data_dir,
        estate=estate,
        evidence_roots=[EVIDENCE],
        variables=variables,
    )


@pytest.fixture
def ctx(data_dir, estate) -> ActionContext:
    return _ctx(data_dir, estate)


def test_checks_are_returned(ctx):
    result = RecoveryVerifyConnector().execute({"host_id": "HOST-014", "account_id": "ACC-JOK"}, ctx)
    assert result["checks"]
    assert "healthy" in result


def test_host_isolation_is_verified(ctx, estate):
    connector = RecoveryVerifyConnector()

    # Not isolated -> check fails.
    failed = connector.execute({"host_id": "HOST-014"}, ctx)
    check = next(c for c in failed["checks"] if c["name"] == "host_isolated")
    assert check["passed"] is False
    assert failed["healthy"] is False

    # Isolated -> check passes.
    estate.isolate_host("HOST-014", "setup")
    passed = connector.execute({"host_id": "HOST-014"}, ctx)
    check = next(c for c in passed["checks"] if c["name"] == "host_isolated")
    assert check["passed"] is True


def test_account_lock_is_verified(estate, data_dir):
    ctx = _ctx(data_dir, estate)
    estate.lock_account("ACC-JOK", "setup")
    result = RecoveryVerifyConnector().execute({"account_id": "ACC-JOK"}, ctx)
    check = next(c for c in result["checks"] if c["name"] == "account_locked")
    assert check["passed"] is True


def test_unknown_entities_fail_the_check(estate, data_dir):
    ctx = _ctx(data_dir, estate)
    result = RecoveryVerifyConnector().execute(
        {"host_id": "HOST-NOPE", "account_id": "ACC-NOPE"}, ctx
    )
    names = {c["name"]: c["passed"] for c in result["checks"]}
    assert names["host_isolated"] is False
    assert names["account_locked"] is False


# --- the regression ---------------------------------------------------------


def test_ioc_baseline_with_dict_iocs(estate, data_dir):
    """IOCs are dicts with type/value. This is the shape the engine produces.

    The shipped bug raised AttributeError on exactly this input.
    """
    ctx = _ctx(data_dir, estate, iocs=[{"type": "ipv4", "value": "203.0.113.44",
                                               "source": "volatility:windows.netscan",
                                               "confidence": 0.6}])
    result = RecoveryVerifyConnector().execute({}, ctx)
    check = next(c for c in result["checks"] if c["name"] == "no_new_iocs")
    assert check["passed"] is True


def test_new_iocs_are_detected(estate, data_dir):
    baseline = [{"type": "ipv4", "value": "203.0.113.44", "source": "s", "confidence": 0.6}]
    rescan = baseline + [{"type": "domain", "value": "evil.example", "source": "s", "confidence": 0.8}]
    ctx = _ctx(data_dir, estate, iocs=baseline, iocs_rescan=rescan)

    result = RecoveryVerifyConnector().execute({}, ctx)
    check = next(c for c in result["checks"] if c["name"] == "no_new_iocs")
    assert check["passed"] is False
    assert "evil.example" in check["detail"]


def test_empty_ioc_lists_do_not_crash(estate, data_dir):
    ctx = _ctx(data_dir, estate, iocs=[], iocs_rescan=[])
    result = RecoveryVerifyConnector().execute({}, ctx)
    check = next(c for c in result["checks"] if c["name"] == "no_new_iocs")
    assert check["passed"] is True


def test_malformed_ioc_entries_are_skipped(estate, data_dir):
    ctx = _ctx(data_dir, estate, iocs=["garbage", 42, None, {"type": "ipv4"}])
    result = RecoveryVerifyConnector().execute({}, ctx)
    assert result["checks"]


def test_tuple_form_iocs_supported(estate, data_dir):
    ctx = _ctx(data_dir, estate, iocs=[("ipv4", "1.2.3.4")])
    result = RecoveryVerifyConnector().execute({}, ctx)
    check = next(c for c in result["checks"] if c["name"] == "no_new_iocs")
    assert check["passed"] is True


# --- eradication + integrity -------------------------------------------------


def test_persistence_check(estate, data_dir):
    ctx = _ctx(data_dir, estate)
    result = RecoveryVerifyConnector().execute({}, ctx)
    check = next(c for c in result["checks"] if c["name"] == "persistence_eradicated")
    assert check["passed"] is True, "an empty host view has no persistence"


def test_evidence_integrity_check(estate, data_dir):
    ctx = _ctx(data_dir, estate)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)

    result = RecoveryVerifyConnector().execute({}, ctx)
    check = next(c for c in result["checks"] if c["name"] == "evidence_integrity")
    assert check["passed"] is True

    # Tamper -> integrity check must fail.
    target = data_dir / "incidents" / "INC-R" / "evidence" / "ransom-note.txt"
    target.write_text("tampered", encoding="utf-8")
    after = RecoveryVerifyConnector().execute({}, ctx)
    check = next(c for c in after["checks"] if c["name"] == "evidence_integrity")
    assert check["passed"] is False


def test_compensation_is_noop(ctx):
    connector = RecoveryVerifyConnector()
    result = connector.execute({}, ctx)
    assert connector.compensate({}, ctx, result)["noop"] is True


def test_requires_data_dir():
    ctx = ActionContext(run_id="R", incident_id="I", action_id="v", data_dir=None)
    with pytest.raises(ConnectorError):
        RecoveryVerifyConnector().execute({}, ctx)


def test_full_recovery_run_is_healthy(estate, data_dir, ransomware_alert):
    """The end state a real run should reach."""
    ctx = _ctx(data_dir, estate)
    estate.isolate_host("HOST-014", "containment")
    estate.lock_account("ACC-JOK", "containment")
    EvidenceCollectConnector().execute({"artifacts": ["evidence/host-inventory.json"]}, ctx)

    result = RecoveryVerifyConnector().execute(
        {"host_id": "HOST-014", "account_id": "ACC-JOK"}, ctx
    )
    assert result["healthy"] is True, result["failed_checks"]