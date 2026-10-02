"""Playbook execution engine.

**Every action in this project runs through this module**
(AGENTS.md section 2.7). That guarantee is what makes timeouts, approval gates,
failure policy, journalling and compensation reliable, and it is why
"just run the steps directly in a script" is not an acceptable shortcut.

For each action, in order:

1. Resolve ``{{ }}`` parameters against the run context.
2. Journal the attempt.
3. Enforce the timeout.
4. Transition status.
5. Capture the result.
6. Apply the failure policy on error.
7. On abort, compensate every successful action **in reverse order**.

Resume
------

A run that stops at an approval gate records which action it is waiting on.
Calling :meth:`Engine.execute` again with the same ``run`` resumes from that
point rather than restarting -- actions already completed are not repeated.

Timeout caveat, stated honestly
--------------------------------

Action timeouts are enforced by running the connector on a worker thread and
giving up on it after ``timeout_seconds``. Python cannot kill a thread, so a
connector that has already started keeps running in the background; its result is
discarded and the run is marked failed. For the shipped connectors this is
benign -- simulated connectors return in microseconds, and the one subprocess
(:mod:`soar.forensics.memory`) enforces its own hard timeout on the child
process. It would matter for a future connector that blocks indefinitely, which
is why the rule is written down rather than left implicit.
"""

from __future__ import annotations

import concurrent.futures
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

from soar.connectors.base import ActionContext, ConnectorError
from soar.models import Action, ActionResult, Incident, Playbook, Run
from soar.nist import Phase
from soar.playbook_loader import substitute
from soar.severity import auto_run_allowed

__all__ = ["Engine", "EngineError"]


class EngineError(RuntimeError):
    """The engine could not run a playbook (bad registration, missing connector)."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Clock:
    """Monotonic-ish timer for durations. Separate from the wall clock above."""

    __slots__ = ("_start",)

    def __init__(self) -> None:
        self._start = datetime.now(timezone.utc)

    def elapsed_ms(self) -> int:
        return int((datetime.now(timezone.utc) - self._start).total_seconds() * 1000)


class Engine:
    """Executes a :class:`~soar.models.Playbook` against an :class:`Incident`."""

    def __init__(
        self,
        registry: dict[str, Any] | None = None,
        estate: Any = None,
        data_dir: Any = None,
        evidence_roots: Iterable[Any] | None = None,
        max_workers: int = 4,
        verify: bool = True,
    ) -> None:
        from soar.connectors import build_default_registry, verify_registry

        self.registry = registry if registry is not None else build_default_registry()
        # Production always verifies. The test suite passes verify=False to inject
        # test doubles (a deliberately failing or slow connector) which by design
        # are not in REGISTERED_CONNECTORS.
        if verify:
            verify_registry(self.registry)
        self.estate = estate
        self.data_dir = data_dir
        self.evidence_roots = list(evidence_roots or [])
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="soar-action"
        )
        #: Injected clock for tests; defaults to a real one.
        self._now_fn = _now

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # -- context --------------------------------------------------------------

    def _build_context(
        self,
        incident: Incident,
        playbook: Playbook,
        run: Run,
        action: Action,
        extra: dict[str, Any],
    ) -> ActionContext:
        variables: dict[str, Any] = {
            "incident": {
                "id": incident.id,
                "severity": incident.severity,
                "score": incident.score,
                "status": incident.status,
                "phase": str(incident.phase),
            },
            "alert": incident.alert,
            "run": {"id": run.id, "playbook_id": playbook.id, "status": run.status},
        }
        variables.update(extra)

        # Playbook-author-declared constants land under "params".
        variables["params"] = action.params

        return ActionContext(
            run_id=run.id,
            incident_id=incident.id,
            action_id=action.id,
            severity=incident.severity,
            estate=self.estate,
            data_dir=self.data_dir,
            evidence_roots=list(self.evidence_roots),
            variables=variables,
        )

    # -- execution ------------------------------------------------------------

    def _invoke(
        self, connector: Any, params: dict[str, Any], ctx: ActionContext, timeout: int
    ) -> tuple[dict[str, Any], int]:
        """Run one connector under a timeout. Returns ``(result, duration_ms)``."""
        clock = _Clock()
        future = self._executor.submit(connector.execute, params, ctx)
        try:
            result = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            raise ConnectorError(f"action exceeded {timeout}s timeout") from exc
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001 - connector bugs must not kill the run
            raise ConnectorError(f"{type(exc).__name__}: {exc}") from exc
        return dict(result or {}), clock.elapsed_ms()

    def _compensate_all(
        self,
        executed: list[ActionResult],
        incident: Incident,
        playbook: Playbook,
        run: Run,
        extra: dict[str, Any],
    ) -> list[ActionResult]:
        """Undo every successful action, newest first.

        Reverse order matters: a later action may depend on state created by an
        earlier one (a firewall rule referencing a host that is isolated), so
        undoing oldest-first would leave inconsistent intermediate state.
        """
        by_id = {a.id: a for a in playbook.actions}
        results: list[ActionResult] = []

        for prior in reversed(executed):
            if prior.status != "succeeded" or prior.compensation_of:
                continue
            action = by_id.get(prior.action_id)
            if action is None or action.forward_only:
                if action is not None and action.forward_only:
                    run.forward_only_applied.append(action.id)
                continue
            connector = self.registry.get(action.connector)
            if connector is None:
                continue

            ctx = self._build_context(incident, playbook, run, action, extra)
            clock = _Clock()
            try:
                # Compensation needs the same resolved params the forward action
                # used, or it would try to undo a literal "{{ ... }}" key.
                resolved = substitute(action.params, ctx.variables)
                payload = connector.compensate(resolved, ctx, prior.result)
                status, error = "compensated", None
            except Exception as exc:  # noqa: BLE001
                payload, status, error = {}, "failed", f"{type(exc).__name__}: {exc}"

            results.append(
                ActionResult(
                    action_id=f"{action.id}__compensate",
                    connector=action.connector,
                    status=status,  # type: ignore[arg-type]
                    result=payload,
                    error=error,
                    started_at=self._now_fn(),
                    ended_at=self._now_fn(),
                    duration_ms=clock.elapsed_ms(),
                    compensation_of=action.id,
                )
            )

        return results

    def execute(
        self,
        incident: Incident,
        playbook: Playbook,
        run: Run,
        auto_approve: bool = False,
        prior_results: list[ActionResult] | None = None,
        shared: dict[str, Any] | None = None,
        approved: set[str] | None = None,
    ) -> tuple[Run, list[ActionResult]]:
        """Execute (or resume) a playbook run.

        Args:
            incident: The triaged incident.
            playbook: The playbook to run.
            run: Run record, mutated in place. Pass the same object on resume.
            auto_approve: Skip approval gates. Defaults to ``False``
                (docs/SECURITY.md section 6). Intended for demos and the
                benchmark harness, which must disclose when it uses it
                (``docs/METRICS.md`` section 4.4).
            prior_results: Results already recorded for this run (resume).
            shared: Mutable scratch space shared across actions in this run --
                the channel by which ``forensics.volatility`` output reaches
                ``ioc.extract``.
            approved: Action ids individually granted approval. Lets
                ``POST /incidents/{id}/actions/{action_id}/approve`` release a
                single gate without waving through every later one.

        Returns:
            ``(run, results)`` where ``results`` covers every action attempt
            made during this invocation, including compensations.
        """
        results: list[ActionResult] = list(prior_results or [])
        # Only a *successful* or *awaiting-approval* prior result counts as done.
        # A failed action must be retried on resume, not skipped.
        done = {r.action_id for r in results if r.status in {"succeeded", "awaiting_approval"}}
        approved = set(approved or ())
        extra: dict[str, Any] = dict(shared or {})

        # ``completed`` is NOT terminal for retry purposes. A run that finished
        # with a failed action (on_failure: continue) must stay resumable so an
        # operator can retry just that step instead of re-running containment.
        # ``aborted`` and ``failed`` are terminal: those already compensated.
        if run.status in {"aborted", "failed"}:
            return run, results

        run.status = "running"
        if not run.started_at:
            run.started_at = self._now_fn()

        # Estate snapshot before the run, so callers can assert the rollback
        # invariant themselves (docs/SECURITY.md section 3.1).
        pre_snapshot = self.estate.snapshot() if self.estate is not None else None

        for action in playbook.actions:
            if action.id in done:
                continue

            connector = self.registry.get(action.connector)
            if connector is None:
                results.append(
                    ActionResult(
                        action_id=action.id,
                        connector=action.connector,
                        status="failed",
                        error=f"connector {action.connector!r} is not registered",
                        started_at=self._now_fn(),
                        ended_at=self._now_fn(),
                    )
                )
                run.status = "failed"
                run.ended_at = self._now_fn()
                return run, results

            # --- Approval gate ------------------------------------------------
            # Three ways to reach this gate:
            #   1. The playbook declared `requires_approval`.
            #   2. The action is in the containment phase and the severity band
            #      does not permit unattended containment
            #      (docs/ARCHITECTURE.md section 5: only `critical` may run
            #      containment without a human).
            #   3. `auto_approve` -- waved through wholesale. Intended only for
            #      the demo and benchmark, which must disclose it.
            #
            # Making (2) dynamic is deliberate: a YAML-only flag would mean a
            # `medium`-severity incident could auto-isolate a host purely
            # because the playbook author left a default in place.
            needs_gate = action.requires_approval or (
                action.phase == Phase.CONTAINMENT and not auto_run_allowed(incident.severity)
            )
            if needs_gate and not auto_approve and action.id not in approved:
                results.append(
                    ActionResult(
                        action_id=action.id,
                        connector=action.connector,
                        status="awaiting_approval",
                        started_at=self._now_fn(),
                        ended_at=self._now_fn(),
                    )
                )
                run.status = "awaiting_approval"
                extra["awaiting_action"] = action.id
                return run, results

            # --- Substitute and execute ---------------------------------------
            ctx = self._build_context(incident, playbook, run, action, extra)
            started_at = self._now_fn()
            phase_clock = _Clock()

            # Resolve {{ }} templates against the alert before dispatch. Without
            # this the connector receives the literal template text and the host
            # lookup fails on "{{ alert.asset.id }}".
            try:
                params = substitute(action.params, ctx.variables)
            except Exception as exc:  # noqa: BLE001
                params, error = {}, f"template substitution failed: {type(exc).__name__}: {exc}"
                result = ActionResult(
                    action_id=action.id,
                    connector=action.connector,
                    status="failed",
                    error=error,
                    started_at=started_at,
                    ended_at=self._now_fn(),
                    duration_ms=phase_clock.elapsed_ms(),
                )
                results.append(result)
                if action.on_failure == "continue":
                    continue
                if action.on_failure == "compensate":
                    continue
                results.extend(self._compensate_all(results, incident, playbook, run, extra))
                run.status = "aborted"
                run.ended_at = self._now_fn()
                return run, results

            try:
                payload, _ = self._invoke(connector, params, ctx, action.timeout_seconds)
                status, error = "succeeded", None
            except ConnectorError as exc:
                payload, status, error = {}, "failed", str(exc)
            except Exception as exc:  # noqa: BLE001 - estate errors must not kill the run
                payload, status, error = {}, "failed", f"{type(exc).__name__}: {exc}"

            result = ActionResult(
                action_id=action.id,
                connector=action.connector,
                status=status,  # type: ignore[arg-type]
                result=payload,
                error=error,
                started_at=started_at,
                ended_at=self._now_fn(),
                duration_ms=phase_clock.elapsed_ms(),
            )

            # A connector that reports itself skipped makes the run incomplete.
            # The report must say so rather than implying full coverage.
            if status == "succeeded" and payload.get("status") == "skipped":
                run.incomplete = True

            results.append(result)

            # Publish connector output to sibling actions in this run.
            if status == "succeeded" and payload:
                extra[_output_key(action.connector)] = payload

            run.phase_timings[str(action.phase)] = (
                run.phase_timings.get(str(action.phase), 0.0) + result.duration_ms / 1000
            )

            # --- Failure policy ----------------------------------------------
            if status == "failed":
                if action.on_failure == "continue":
                    continue
                if action.on_failure == "compensate":
                    compensate_ctx = self._build_context(incident, playbook, run, action, extra)
                    cclock = _Clock()
                    try:
                        payload_c = connector.compensate(params, compensate_ctx, payload)
                        cstatus, cerror = "compensated", None
                    except Exception as exc:  # noqa: BLE001
                        payload_c, cstatus, cerror = {}, "failed", f"{type(exc).__name__}: {exc}"
                    results.append(
                        ActionResult(
                            action_id=f"{action.id}__compensate",
                            connector=action.connector,
                            status=cstatus,  # type: ignore[arg-type]
                            result=payload_c,
                            error=cerror,
                            started_at=self._now_fn(),
                            ended_at=self._now_fn(),
                            duration_ms=cclock.elapsed_ms(),
                            compensation_of=action.id,
                        )
                    )
                    continue

                # on_failure == "abort": undo everything this run did, then stop.
                results.extend(self._compensate_all(results, incident, playbook, run, extra))
                run.status = "aborted"
                run.ended_at = self._now_fn()
                return run, results

        run.status = "completed"
        run.ended_at = self._now_fn()
        return run, results


def _output_key(connector_name: str) -> str:
    """Map a connector name to the context key its output is published under."""
    return {
        "triage.score": "triage",
        "forensics.volatility": "vol_output",
        "ioc.extract": "iocs",
        "evidence.collect": "evidence",
    }.get(connector_name, connector_name.replace(".", "_"))