"""Playbook loading, schema validation, template substitution and selection."""

from __future__ import annotations

import pytest

from soar.connectors.base import REGISTERED_CONNECTORS
from soar.nist import PHASE_ORDER
from soar.playbook_loader import (
    PlaybookValidationError,
    load,
    load_all,
    select,
    substitute,
    validate,
)

EXPECTED_IDS = {"ransomware", "credential_theft", "data_exfiltration", "brute_force"}


def test_exactly_four_playbooks(playbooks):
    """Playbook count is capped at 4 (AGENTS.md section 3).

    Growing the set is a scope change, not an improvement -- gaps are the
    Week 3 deliverable instead.
    """
    assert set(playbooks) == EXPECTED_IDS
    assert len(playbooks) == 4


def test_all_playbooks_load(playbooks):
    assert len(playbooks) == 4, "a playbook on disk is invalid and should fail loudly"


@pytest.mark.parametrize("playbook_id", sorted(EXPECTED_IDS))
def test_playbook_schema_is_valid(playbooks, playbook_id):
    pb = playbooks[playbook_id]
    assert pb.id == playbook_id
    assert pb.actions, "a playbook with no actions cannot do anything"
    assert validate(pb.to_dict()) == []


@pytest.mark.parametrize("playbook_id", sorted(EXPECTED_IDS))
def test_playbook_covers_the_lifecycle(playbooks, playbook_id):
    """Every playbook must span all four lifecycle phases named in the brief."""
    pb = playbooks[playbook_id]
    phases = {str(a.phase) for a in pb.actions}
    for required in ("detection", "containment", "eradication", "recovery"):
        assert required in phases, f"{playbook_id} has no {required} action"


@pytest.mark.parametrize("playbook_id", sorted(EXPECTED_IDS))
def test_connectors_are_registered(playbooks, playbook_id):
    for action in playbooks[playbook_id].actions:
        assert action.connector in REGISTERED_CONNECTORS


@pytest.mark.parametrize("playbook_id", sorted(EXPECTED_IDS))
def test_actions_are_ordered_by_phase(playbooks, playbook_id):
    """Actions must appear in lifecycle order, not declaration order."""
    order = {str(p): i for i, p in enumerate(PHASE_ORDER)}
    positions = [order[str(a.phase)] for a in playbooks[playbook_id].actions]
    assert positions == sorted(positions), "playbook runs phases out of order"


@pytest.mark.parametrize("playbook_id", sorted(EXPECTED_IDS))
def test_action_ids_unique(playbooks, playbook_id):
    ids = [a.id for a in playbooks[playbook_id].actions]
    assert len(ids) == len(set(ids))


def test_loader_rejects_unregistered_connector(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "id: bad\nname: Bad\nphases: [recovery]\nmitre_techniques: ['T9999']\n"
        "actions:\n  - id: a1\n    phase: recovery\n    connector: rm_rf_slash\n",
        encoding="utf-8",
    )
    with pytest.raises(PlaybookValidationError) as exc:
        load(bad)
    assert any("not registered" in p for p in exc.value.problems)


def test_loader_rejects_playbook_without_recovery(tmp_path):
    """An incident a playbook handles must be closeable."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "id: bad\nname: Bad\nphases: [detection]\nmitre_techniques: ['T9999']\n"
        "actions:\n  - id: a1\n    phase: detection\n    connector: triage.score\n",
        encoding="utf-8",
    )
    problems = validate(
        __import__("yaml").safe_load(bad.read_text(encoding="utf-8"))
    )
    assert any("never be closed" in p for p in problems)


def test_loader_rejects_bad_phase(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "id: bad\nname: Bad\nphases: [teatime]\nmitre_techniques: ['T9999']\n"
        "actions:\n  - id: a1\n    phase: teatime\n    connector: triage.score\n",
        encoding="utf-8",
    )
    problems = validate(__import__("yaml").safe_load(bad.read_text(encoding="utf-8")))
    assert any("unknown phase" in p for p in problems)


def test_loader_rejects_duplicate_action_ids():
    problems = validate(
        {
            "id": "x",
            "name": "X",
            "phases": ["recovery"],
            "mitre_techniques": ["T9999"],
            "actions": [
                {"id": "a1", "phase": "recovery", "connector": "recovery.verify"},
                {"id": "a1", "phase": "recovery", "connector": "recovery.verify"},
            ],
        }
    )
    assert any("duplicate action id" in p for p in problems)


# --- substitution -----------------------------------------------------------


def test_substitute_resolves_dotted_paths():
    variables = {"alert": {"source": {"ip": "10.0.0.1"}}, "incident": {"id": "INC-1"}}
    assert substitute("ip={{ alert.source.ip }}", variables) == "ip=10.0.0.1"
    assert substitute("{{ incident.id }}", variables) == "INC-1"


def test_substitute_missing_path_yields_default():
    assert substitute("{{ alert.nope | fallback }}", {}) == "fallback"
    assert substitute("{{ alert.nope }}", {}) == ""


def test_substitute_never_raises_on_missing_path():
    """A playbook must not blow up mid-incident over a missing template var."""
    for template in ("{{ a.b.c.d.e }}", "{{ }}", "{{ x | }}", "{{ 123 }}"):
        substitute(template, {})  # must not raise


def test_substitute_preserves_non_string_types():
    """A numeric timeout must not become a string."""
    params = {"timeout": 300, "flag": True, "none": None, "items": [1, "two", True]}
    assert substitute(params, {}) == params


def test_substitute_leaves_no_eval_constructs():
    """The grammar cannot express arithmetic or calls -- they stay literal."""
    out = substitute("{{ __import__('os').system('calc') }}", {})
    assert "system('calc')" in out  # inert literal text, never evaluated
    assert "{{" in out


def test_substitute_walks_nested_structures():
    variables = {"alert": {"asset": {"id": "HOST-014"}}}
    out = substitute({"a": ["{{ alert.asset.id }}"], "b": {"c": "{{ alert.asset.id }}"}}, variables)
    assert out == {"a": ["HOST-014"], "b": {"c": "HOST-014"}}


# --- selection --------------------------------------------------------------


def test_select_by_exact_technique(playbooks, ransomware_alert):
    assert select(list(playbooks.values()), ransomware_alert, "critical").id == "ransomware"


def test_select_by_parent_technique(playbooks):
    alert = {"mitre": {"technique_id": "T1486.001"}}
    assert select(list(playbooks.values()), alert, "critical").id == "ransomware"


def test_select_returns_none_for_uncovered_technique(playbooks, port_scan_alert):
    """Running the wrong playbook is worse than running none."""
    assert select(list(playbooks.values()), port_scan_alert, "low") is None


def test_select_returns_none_for_missing_technique(playbooks):
    assert select(list(playbooks.values()), {}, "critical") is None


def test_select_returns_none_for_empty_playbook_list(ransomware_alert):
    assert select([], ransomware_alert, "critical") is None


@pytest.mark.parametrize(
    ("alert_file", "expected"),
    [
        ("ransomware_finance_host.json", "ransomware"),
        ("ransomware_file_server.json", "ransomware"),
        ("credential_theft_lsass_dump.json", "credential_theft"),
        ("credential_theft_kerberos_ticket.json", "credential_theft"),
        ("brute_force_password_spray.json", "brute_force"),
        ("data_exfil_c2_channel.json", "data_exfiltration"),
        ("data_exfil_web_service.json", "data_exfiltration"),
    ],
)
def test_every_covered_fixture_selects_its_playbook(playbooks, alert_file, expected):
    from tests.conftest import load_alert

    assert select(list(playbooks.values()), load_alert(alert_file), "high").id == expected


@pytest.mark.parametrize(
    "alert_file",
    [
        "phishing_credential_harvest.json",
        "port_scan_reconnaissance.json",
        "service_stop_critical_service.json",
    ],
)
def test_uncovered_fixtures_are_reported_as_gaps(playbooks, alert_file):
    """These three must surface as gaps, not be silently absorbed."""
    from tests.conftest import load_alert

    assert select(list(playbooks.values()), load_alert(alert_file), "high") is None


def test_load_all_on_missing_directory(tmp_path):
    assert load_all(tmp_path / "does-not-exist") == []