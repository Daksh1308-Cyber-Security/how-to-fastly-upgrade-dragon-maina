"""Simulated estate: transitions, journal integrity, snapshot/restore."""

from __future__ import annotations

import pytest

from soar.estate import (
    Account,
    EstateError,
    FirewallRule,
    Host,
    InMemoryEstate,
    SqliteEstate,
    VALID_ZONES,
    utc_now_iso,
)
from soar.nist import CLOSED, PHASE_ORDER, Phase, can_transition


# --- NIST phase model -------------------------------------------------------


def test_phase_order_matches_the_brief():
    """Detection -> Containment -> Eradication -> Recovery, with Preparation first."""
    assert PHASE_ORDER == (
        Phase.PREPARATION,
        Phase.DETECTION,
        Phase.CONTAINMENT,
        Phase.ERADICATION,
        Phase.RECOVERY,
    )


@pytest.mark.parametrize(
    ("src", "dst", "legal"),
    [
        (Phase.PREPARATION, Phase.DETECTION, True),
        (Phase.DETECTION, Phase.CONTAINMENT, True),
        (Phase.CONTAINMENT, Phase.ERADICATION, True),
        (Phase.ERADICATION, Phase.RECOVERY, True),
        (Phase.RECOVERY, CLOSED, True),
        # A confirmed false positive must be closeable without containment.
        (Phase.CONTAINMENT, Phase.RECOVERY, True),
        (Phase.DETECTION, CLOSED, True),
        # Illegal: phases never run backwards.
        (Phase.RECOVERY, Phase.DETECTION, False),
        (Phase.ERADICATION, Phase.CONTAINMENT, False),
        (Phase.PREPARATION, Phase.RECOVERY, False),
    ],
)
def test_transition_legality(src, dst, legal):
    assert can_transition(src, dst) is legal


def test_any_phase_can_abort():
    for phase in PHASE_ORDER:
        assert can_transition(phase, "aborted") is True


def test_terminal_states_have_no_exits():
    assert can_transition("aborted", Phase.DETECTION) is False
    assert can_transition(CLOSED, Phase.DETECTION) is False


def test_unknown_state_never_transitions():
    """A typo must not be able to advance an incident to closed."""
    assert can_transition("teatime", CLOSED) is False
    assert can_transition(Phase.DETECTION, "teatime") is False


def test_csf2_mapping_covers_every_phase():
    from soar.nist import R3_MAPPING

    for phase in PHASE_ORDER:
        assert phase in R3_MAPPING
        assert R3_MAPPING[phase]["csf_categories"]


# --- estate state machine ---------------------------------------------------


def test_isolate_is_idempotent(estate):
    first = estate.isolate_host("HOST-014", "a1")
    second = estate.isolate_host("HOST-014", "a2")
    assert first["changed"] is True
    assert second["changed"] is False
    assert estate.get_host("HOST-014").isolated is True


def test_lock_is_idempotent(estate):
    assert estate.lock_account("ACC-JOK", "a1")["changed"] is True
    assert estate.lock_account("ACC-JOK", "a2")["changed"] is False


def test_unknown_entity_raises(estate):
    with pytest.raises(EstateError, match="unknown host"):
        estate.isolate_host("HOST-NOPE", "a1")
    with pytest.raises(EstateError, match="unknown account"):
        estate.lock_account("ACC-NOPE", "a1")


def test_invalid_zone_rejected(estate):
    with pytest.raises(EstateError, match="unknown zone"):
        estate.block("moon", "corp", "1.2.3.4", "a1")


def test_invalid_rule_action_rejected(estate):
    with pytest.raises(EstateError, match="invalid rule action"):
        estate.add_rule("corp", "dmz", "obliterate", "1.2.3.4", "a1")


def test_remove_missing_rule_is_not_an_error(estate):
    assert estate.unblock("FW-9999", "a1")["removed"] is False


def test_journal_records_only_real_mutations(estate):
    estate.isolate_host("HOST-014", "a1")
    estate.isolate_host("HOST-014", "a2")  # no-op
    entries = estate.journal()
    assert len(entries) == 1, "a no-op must not be journalled as a change"
    assert entries[0]["action_id"] == "a1"
    assert entries[0]["before"] == {"isolated": False}
    assert entries[0]["after"] == {"isolated": True}


def test_journal_sequence_is_monotonic(estate):
    estate.isolate_host("HOST-014", "a1")
    estate.lock_account("ACC-JOK", "a2")
    estate.block("corp", "restricted", "1.2.3.4", "a3")
    assert [e["seq"] for e in estate.journal()] == [0, 1, 2]


def test_snapshot_excludes_journal(estate):
    """The journal grows monotonically, so including it would make the
    rollback invariant untestable."""
    estate.isolate_host("HOST-014", "a1")
    snap = estate.snapshot()
    assert set(snap) == {"hosts", "accounts", "rules"}
    assert len(estate.journal()) == 1


def test_snapshot_is_deep_copied(estate):
    snap = estate.snapshot()
    estate.isolate_host("HOST-014", "a1")
    assert snap["hosts"]["HOST-014"]["isolated"] is False, "snapshot aliased live state"


def test_restore_round_trip(estate):
    before = estate.snapshot()
    estate.isolate_host("HOST-014", "a1")
    estate.lock_account("ACC-JOK", "a2")
    estate.block("corp", "restricted", "1.2.3.4", "a3")
    estate.restore(before)
    assert estate.snapshot() == before


def test_zone_constants_are_the_documented_three():
    assert VALID_ZONES == {"corp", "dmz", "restricted"}


def test_utc_now_iso_format():
    ts = utc_now_iso()
    assert ts.endswith("Z")
    assert len(ts) == 20


# --- SQLite backend parity --------------------------------------------------


@pytest.fixture
def sqlite_estate(tmp_path):
    from soar.store import connect

    conn = connect(tmp_path / "estate.db")
    yield SqliteEstate(conn)
    conn.close()


def _compare(estate_a, estate_b, before, after_fn):
    after_fn(estate_a)
    after_fn(estate_b)
    assert estate_a.snapshot() == estate_b.snapshot(), "backends disagree"
    assert estate_a.snapshot() != before


def test_backends_agree_on_isolation(estate, sqlite_estate):
    sqlite_estate.restore(estate.snapshot())
    before = estate.snapshot()
    _compare(
        estate,
        sqlite_estate,
        before,
        lambda e: e.isolate_host("HOST-014", "a1"),
    )


def test_backends_agree_on_locking(estate, sqlite_estate):
    sqlite_estate.restore(estate.snapshot())
    before = estate.snapshot()
    _compare(
        estate,
        sqlite_estate,
        before,
        lambda e: e.lock_account("ACC-JOK", "a1"),
    )


def test_backends_agree_on_rules(estate, sqlite_estate):
    sqlite_estate.restore(estate.snapshot())
    before = estate.snapshot()
    _compare(
        estate,
        sqlite_estate,
        before,
        lambda e: e.block("corp", "restricted", "203.0.113.44", "a1"),
    )


def test_sqlite_journal_persists(estate, sqlite_estate, tmp_path):
    sqlite_estate.restore(estate.snapshot())
    sqlite_estate.isolate_host("HOST-014", "a1")

    from soar.store import connect

    second_conn = connect(tmp_path / "estate.db")
    reopened = SqliteEstate(second_conn)
    entries = reopened.journal()
    assert any(e["action_id"] == "a1" for e in entries), "journal must survive a reconnect"
    assert reopened.get_host("HOST-014").isolated is True
    second_conn.close()


def test_sqlite_snapshot_matches_in_memory(estate, sqlite_estate):
    sqlite_estate.restore(estate.snapshot())
    assert sqlite_estate.snapshot() == estate.snapshot()