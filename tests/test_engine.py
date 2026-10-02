"""Engine sequencing, timeouts, approval gates and failure policies."""

from __future__ import annotations

import time

import pytest

from soar.engine import Engine
from soar.models import Action, Incident, Playbook, Run
from soar.nist import Phase


class _SlowConnector:
    name = "test.slow"
    phase = "detection"

    def execute(self, params, ctx):
        time.sleep(params.get("seconds", 5))
        return {"slept": True}

    def compensate(self, params, ctx, result):
        return {"noop": True}


class _FailingConnector:
    name = "test.fail"
    phase = "eradication"

    def __init__(self, error="boom"):
        self.error = error

    def execute(self, params, ctx):
        raise RuntimeError(self.error)

    def compensate(self, params, ctx, result):
        return {"noop": True}


def _playbook(*actions, phases=None) -> Playbook:
    return Playbook(
        id="test-pb",
        name="Test",
        phases=phases or [Phase.DETECTION],
        mitre_techniques=["T9999"],
        actions=list(actions),
    )


def _incident(severity="medium", **kw) -> Incident:
    base = dict(id="INC-E", alert={"mitre": {"technique_id": "T9999"}}, severity=severity,
                score=50, phase=Phase.DETECTION, playbook_id="test-pb")
    base.update(kw)
    return Incident(**base)


def _run() -> Run:
    return Run(id="RUN-E", incident_id="INC-E", playbook_id="test-pb")


# --- sequencing -------------------------------------------------------------


def test_actions_execute_in_declared_order(registry, estate, data_dir):
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="a", name="A", phase=Phase.DETECTION, connector="triage.score"),
        Action(id="b", name="B", phase=Phase.CONTAINMENT,
               connector="estate.isolate_host", params={"host_id": "HOST-014"}),
    )
    _, results = engine.execute(_incident("critical"), pb, _run(), auto_approve=True)
    engine.shutdown()
    assert [r.action_id for r in results] == ["a", "b"]


def test_completed_run_is_not_re_executed(registry, estate, data_dir):
    """Idempotence: re-running a completed run must not repeat its actions.

    Resume works off ``prior_results``; without them the engine cannot know
    what already ran. This passes the prior results back, exactly as the API's
    ``_drive_run`` does.
    """
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="a", name="A", phase=Phase.DETECTION, connector="triage.score"),
    )
    incident, run_obj = _incident("critical"), _run()
    _, first = engine.execute(incident, pb, run_obj, auto_approve=True)

    _, cumulative = engine.execute(incident, pb, run_obj, auto_approve=True, prior_results=first)
    engine.shutdown()
    assert cumulative[len(first):] == [], "a completed run must not re-run its actions"
    # The estate is the real check: containment must not be applied twice.
    assert estate.list_rules() == []


def test_resume_skips_already_completed_actions(registry, estate, data_dir):
    """Resume after an approval gate must not repeat finished work."""
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="a", name="A", phase=Phase.DETECTION, connector="triage.score"),
        Action(id="gate", name="Gate", phase=Phase.CONTAINMENT,
               connector="estate.isolate_host", params={"host_id": "HOST-014"},
               requires_approval=True),
        Action(id="c", name="C", phase=Phase.RECOVERY,
               connector="recovery.verify", params={}),
    )
    incident, run_obj = _incident("medium"), _run()

    _, first = engine.execute(incident, pb, run_obj, auto_approve=False)
    assert run_obj.status == "awaiting_approval"
    assert [r.action_id for r in first] == ["a", "gate"]
    assert first[-1].status == "awaiting_approval"

    # Resume. execute() returns the CUMULATIVE list for the run, so the new
    # work this invocation did is the tail after the prior results.
    _, cumulative = engine.execute(
        incident, pb, run_obj, auto_approve=False,
        prior_results=first, approved={"gate"},
    )
    engine.shutdown()
    new_ids = [r.action_id for r in cumulative[len(first):]]

    assert new_ids == ["c"], "resume re-ran completed actions or missed the last one"
    assert run_obj.status == "completed"


def test_resume_retries_a_failed_action(registry, estate, data_dir):
    """A failed action must be retried on resume, not silently skipped."""
    from soar.connectors.base import ConnectorError

    class FlakyConnector:
        name = "test.flaky"
        phase = "detection"

        def __init__(self):
            self.calls = 0

        def execute(self, params, ctx):
            self.calls += 1
            if self.calls == 1:
                raise ConnectorError("transient failure")
            return {"attempts": self.calls}

        def compensate(self, params, ctx, result):
            return {"noop": True}

    flaky = FlakyConnector()
    engine = Engine(registry={**registry, flaky.name: flaky},
                    estate=estate, data_dir=data_dir, evidence_roots=[], verify=False)
    pb = _playbook(
        Action(id="flaky", name="Flaky", phase=Phase.DETECTION, connector=flaky.name,
               on_failure="continue"),
        Action(id="after", name="After", phase=Phase.RECOVERY, connector="triage.score"),
    )
    incident, run_obj = _incident(), _run()

    _, first = engine.execute(incident, pb, run_obj, auto_approve=True)
    assert first[0].status == "failed"
    assert run_obj.status == "completed"

    # Resume: the failed action is retried (flaky.calls 1 -> 2) and now succeeds.
    # "after" already succeeded, so it is not repeated.
    _, cumulative = engine.execute(incident, pb, run_obj, auto_approve=True, prior_results=first)
    engine.shutdown()
    new = cumulative[len(first):]

    assert [r.action_id for r in new] == ["flaky"], "resume re-ran a succeeded action"
    assert new[0].status == "succeeded"
    assert flaky.calls == 2, "the failed action should have been retried exactly once"


# --- approval gates ---------------------------------------------------------


def test_containment_gates_on_non_critical_severity(registry, estate, data_dir):
    """A `medium` incident must not auto-isolate a host."""
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="iso", name="Isolate", phase=Phase.CONTAINMENT,
               connector="estate.isolate_host", params={"host_id": "HOST-014"}),
    )
    run_obj = _run()
    engine.execute(_incident("medium"), pb, run_obj, auto_approve=False)
    engine.shutdown()

    assert run_obj.status == "awaiting_approval"
    assert estate.get_host("HOST-014").isolated is False


def test_critical_severity_may_contain_unattended(registry, estate, data_dir):
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="iso", name="Isolate", phase=Phase.CONTAINMENT,
               connector="estate.isolate_host", params={"host_id": "HOST-014"}),
    )
    run_obj = _run()
    engine.execute(_incident("critical"), pb, run_obj, auto_approve=False)
    engine.shutdown()

    assert run_obj.status == "completed"
    assert estate.get_host("HOST-014").isolated is True


def test_explicit_requires_approval_gates_critical_too(registry, estate, data_dir):
    """Even critical containment honours a playbook author's explicit gate."""
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="iso", name="Isolate", phase=Phase.CONTAINMENT,
               connector="estate.isolate_host", params={"host_id": "HOST-014"},
               requires_approval=True),
    )
    run_obj = _run()
    engine.execute(_incident("critical"), pb, run_obj, auto_approve=False)
    engine.shutdown()
    assert run_obj.status == "awaiting_approval"


def test_auto_approve_bypasses_every_gate(registry, estate, data_dir):
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="iso", name="Isolate", phase=Phase.CONTAINMENT,
               connector="estate.isolate_host", params={"host_id": "HOST-014"},
               requires_approval=True),
    )
    run_obj = _run()
    engine.execute(_incident("medium"), pb, run_obj, auto_approve=True)
    engine.shutdown()
    assert run_obj.status == "completed"


def test_approved_set_releases_only_the_named_action(registry, estate, data_dir):
    """Approving one gate must not wave through the next one."""
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="first", name="First", phase=Phase.CONTAINMENT,
               connector="estate.isolate_host", params={"host_id": "HOST-014"}),
        Action(id="second", name="Second", phase=Phase.CONTAINMENT,
               connector="firewall.block",
               params={"zone_from": "corp", "zone_to": "restricted", "subject": "1.2.3.4"}),
    )
    run_obj = _run()
    engine.execute(_incident("medium"), pb, run_obj, auto_approve=False, approved={"first"})
    engine.shutdown()

    assert run_obj.status == "awaiting_approval"
    assert estate.get_host("HOST-014").isolated is True
    assert estate.list_rules() == [], "second gate must still be closed"


# --- timeouts ---------------------------------------------------------------


def test_timeout_fails_the_action(registry, estate, data_dir):
    engine = Engine(registry={**registry, "test.slow": _SlowConnector()},
                    estate=estate, data_dir=data_dir, evidence_roots=[], verify=False)
    pb = _playbook(
        Action(id="slow", name="Slow", phase=Phase.DETECTION, connector="test.slow",
               params={"seconds": 5}, timeout_seconds=1, on_failure="continue"),
    )
    _, results = engine.execute(_incident(), pb, _run(), auto_approve=True)
    engine.shutdown()

    assert results[0].status == "failed"
    assert "timeout" in (results[0].error or "")


def test_timeout_error_is_surfaced_not_swallowed(registry, estate, data_dir):
    engine = Engine(registry={**registry, "test.slow": _SlowConnector()},
                    estate=estate, data_dir=data_dir, evidence_roots=[], verify=False)
    pb = _playbook(
        Action(id="slow", name="Slow", phase=Phase.DETECTION, connector="test.slow",
               params={"seconds": 3}, timeout_seconds=1, on_failure="continue"),
    )
    _, results = engine.execute(_incident(), pb, _run(), auto_approve=True)
    engine.shutdown()
    assert results[0].error is not None, "a timeout must be reported, not hidden"


# --- failure policies -------------------------------------------------------


def test_abort_policy_stops_the_run(registry, estate, data_dir):
    engine = Engine(registry={**registry, "test.fail": _FailingConnector()},
                    estate=estate, data_dir=data_dir, evidence_roots=[], verify=False)
    pb = _playbook(
        Action(id="ok1", name="Ok", phase=Phase.DETECTION, connector="triage.score"),
        Action(id="boom", name="Boom", phase=Phase.DETECTION, connector="test.fail",
               on_failure="abort"),
        Action(id="never", name="Never", phase=Phase.RECOVERY, connector="triage.score"),
    )
    run_obj = _run()
    _, results = engine.execute(_incident(), pb, run_obj, auto_approve=True)
    engine.shutdown()

    assert run_obj.status == "aborted"
    assert "never" not in [r.action_id for r in results]


def test_continue_policy_proceeds(registry, estate, data_dir):
    engine = Engine(registry={**registry, "test.fail": _FailingConnector()},
                    estate=estate, data_dir=data_dir, evidence_roots=[], verify=False)
    pb = _playbook(
        Action(id="boom", name="Boom", phase=Phase.DETECTION, connector="test.fail",
               on_failure="continue"),
        Action(id="after", name="After", phase=Phase.RECOVERY, connector="triage.score"),
    )
    run_obj = _run()
    _, results = engine.execute(_incident(), pb, run_obj, auto_approve=True)
    engine.shutdown()

    assert run_obj.status == "completed"
    assert "after" in [r.action_id for r in results]


def test_compensate_policy_undoes_then_continues(registry, estate, data_dir):
    engine = Engine(registry={**registry, "test.fail": _FailingConnector()},
                    estate=estate, data_dir=data_dir, evidence_roots=[], verify=False)
    pb = _playbook(
        Action(id="boom", name="Boom", phase=Phase.DETECTION, connector="test.fail",
               on_failure="compensate"),
        Action(id="after", name="After", phase=Phase.RECOVERY, connector="triage.score"),
    )
    run_obj = _run()
    _, results = engine.execute(_incident(), pb, run_obj, auto_approve=True)
    engine.shutdown()

    assert run_obj.status == "completed"
    assert any(r.compensation_of == "boom" for r in results)


# --- misc -------------------------------------------------------------------


def test_unknown_connector_fails_the_run(registry, estate, data_dir):
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    action = Action(id="x", name="X", phase=Phase.DETECTION, connector="does.not.exist")
    run_obj = _run()
    _, results = engine.execute(_incident(), _playbook(action), run_obj, auto_approve=True)
    engine.shutdown()

    assert run_obj.status == "failed"
    assert "not registered" in (results[0].error or "")


def test_skipped_forensics_marks_run_incomplete(registry, estate, data_dir, monkeypatch):
    """A skipped step must be reported as incomplete, never as a fast success."""
    import soar.connectors.forensics as fc

    monkeypatch.setattr(fc, "analyze", lambda *a, **k: (_ for _ in ()).throw(fc.ForensicsUnavailable("no input")))

    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="mem", name="Memory", phase=Phase.DETECTION, connector="forensics.volatility"),
    )
    run_obj = _run()
    engine.execute(_incident(), pb, run_obj, auto_approve=True)
    engine.shutdown()

    assert run_obj.incomplete is True
    assert run_obj.status == "completed"


def test_phase_timings_recorded(registry, estate, data_dir):
    engine = Engine(registry=registry, estate=estate, data_dir=data_dir, evidence_roots=[])
    pb = _playbook(
        Action(id="a", name="A", phase=Phase.DETECTION, connector="triage.score"),
        Action(id="b", name="B", phase=Phase.RECOVERY, connector="triage.score"),
    )
    run_obj = _run()
    engine.execute(_incident(), pb, run_obj, auto_approve=True)
    engine.shutdown()

    assert set(run_obj.phase_timings) == {"detection", "recovery"}
    assert all(v >= 0 for v in run_obj.phase_timings.values())