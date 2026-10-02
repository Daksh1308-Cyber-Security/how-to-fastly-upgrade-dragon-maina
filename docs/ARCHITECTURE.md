# ARCHITECTURE.md — System Design

Companion to [`COMPONENTS.md`](COMPONENTS.md) (contracts) and [`SECURITY.md`](SECURITY.md)
(mandatory safety rules).

---

## 1. Design in one paragraph

An alert arrives at a FastAPI endpoint, is scored by a deterministic severity function that returns
an explainable rationale, is matched to a YAML playbook by MITRE technique and severity band, and is
executed by a small engine that walks the playbook action by action. Each action is dispatched to a
**connector**. Forensic actions — evidence collection, Volatility analysis, IOC extraction — are
real. Containment, eradication and recovery actions are **simulated** against a SQLite-backed model
of a small network. Every action is journalled with timing and outcome; on abort the engine runs
compensations in reverse order. The run produces evidence with SHA-256 chain of custody, a timeline,
and a Jinja2 report.

## 2. System diagram

```
                        ┌──────────────────────────────────────┐
   alert JSON  ───────▶ │ POST /alerts                         │
                        └───────────────┬──────────────────────┘
                                        ▼
                        ┌───────────────────────────────┐
                        │ triage.score                  │  deterministic
                        │ → severity 0-100 + rationale  │  0-100 + why
                        └───────────────┬───────────────┘
                                        ▼
                        ┌───────────────────────────────┐
                        │ playbook_loader               │  YAML + schema
                        │ select by MITRE + severity    │  validation
                        └───────────────┬───────────────┘
                                        ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │                          soar/engine.py                             │
   │  sequence · timeout · approval gate · failure policy · compensation │
   └───┬───────────────┬───────────────┬───────────────┬────────────────┘
       ▼               ▼               ▼               ▼
  ┌─────────┐   ┌────────────┐  ┌───────────┐  ┌──────────────┐
  │ EVIDENCE│   │  FORENSICS │  │CONTAINMENT│  │  ERADICATION │
  │  REAL   │   │    REAL    │  │ SIMULATED │  │   SIMULATED  │
  └────┬────┘   └─────┬──────┘  └─────┬─────┘  └──────┬───────┘
       │             │               │               │
       │        ┌────▼─────┐   ┌────▼──────┐        │
       │        │  vol 3   │   │soar/      │        │
       │        │ (subproc)│   │estate.py  │◀───────┘
       │        └────┬─────┘   │ SQLite    │
       │             │         │ + journal  │
       │        ┌────▼─────┐   └────┬──────┘
       │        │ioc.py    │        │
       └───────▶└──────────┘        ▼
              evidence/      ┌──────────────┐
        chain_of_custody     │  soar/store  │  stdlib sqlite3
              .jsonl         └──────┬───────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │ reporting/generator.py        │
                    │ Jinja2 · timeline · exec sum  │
                    └───────────────────────────────┘
```

## 3. The connector abstraction

Everything the engine can do is a connector. This is the single most important interface in the
project: it is what makes simulated containment safe while keeping the engine real.

```python
class Connector(Protocol):
    name: str
    phase: Phase

    def execute(self, params: dict, ctx: ActionContext) -> dict:
        """Perform the action. Returns a result dict recorded in the run journal."""

    def compensate(self, params: dict, ctx: ActionContext, result: dict) -> dict:
        """Undo execute() using the values it recorded. Must be idempotent."""
```

`compensate()` takes the original `result` because that is where the undo data lives — e.g. the
`rule_id` created by `firewall.block`. A compensating action cannot know what to remove unless the
forward action recorded it.

### 3.1 Connector inventory

| Connector | Phase | Boundary | Compensates |
|---|---|---|---|
| `triage.score` | Detection | Real (pure) | n/a |
| `evidence.collect` | Detection | **Real** | n/a (append-only custody) |
| `forensics.volatility` | Detection | **Real** | n/a (read-only) |
| `ioc.extract` | Detection | **Real** (pure) | n/a |
| `estate.isolate_host` | Containment | Simulated | `estate.release_host` |
| `firewall.block` | Containment | Simulated | `firewall.unblock` |
| `identity.lock_account` | Containment | Simulated | `identity.unlock_account` |
| `eradication.remove_persistence` | Eradication | Simulated | *(forward-only, declared)* |
| `eradication.quarantine_file` | Eradication | Simulated | `eradication.restore_file` |
| `recovery.verify` | Recovery | Simulated | n/a (read-only) |

Boundary assignments are mandated by [`SECURITY.md`](SECURITY.md) §1 and are not a code detail —
changing one is a safety change, not a feature change.

### 3.2 Failure policy

Each action declares `on_failure`:

- `abort` — stop the run, execute compensations in reverse order, mark run `failed`.
- `continue` — record the failure, proceed to the next action.
- `compensate` — undo just this action, then continue.

`requires_approval: true` actions block the run in `awaiting_approval` until
`POST /incidents/{id}/actions/{action_id}/approve` is called. `auto_approve` exists on the run
request for demo/benchmark purposes and **defaults to `false`** ([`SECURITY.md`](SECURITY.md) §6).

## 4. Phase model — SP 800-61 rev2 with an r3 mapping

The original brief specifies Detection → Containment → Eradication → Recovery, which is the
**SP 800-61 rev2** incident response lifecycle. That remains the execution state machine, with
Preparation added as the always-on baseline (it is a lifecycle phase in rev2 and was otherwise
missing).

> **Revision note.** SP 800-61 **rev3** (April 2025) superseded rev2 and reorganises the lifecycle
> around the CSF 2.0 functional split. This project executes rev2 phases because that is what the
> brief specifies, and carries the mapping table below so reports can speak both dialects. See
> [`METRICS.md`](METRICS.md) for how revisions are cited.

| rev2 phase (executed) | CSF 2.0 function | Representative CSF 2.0 subcategories |
|---|---|---|
| Preparation | Govern | GV.PO, GV.OC, GV.RR, GV.RM |
| Detection | Detect | DE.CM, DE.AE, DE.DP |
| Containment | Respond | RS.MA, RS.AN, RS.MI, RS.IM |
| Eradication | Respond | RS.RP, RS.RA |
| Recovery | Recover | RC.RP, RC.IM, RC.CO |

**Valid transitions** (enforced by `soar/nist.py`):

```
preparation ──▶ detection ──▶ containment ──▶ eradication ──▶ recovery
                    │              │
                    └──────────────┴──▶ eradication ──▶ recovery   (auto-contained)
                                    └──▶ recovery                    (false positive)

recovery ──▶ closed
Any phase ──▶ aborted  (compensations run in reverse order)
```

Containment → recovery is legal for confirmed false positives and must be reachable; a state
machine that cannot close an incident without performing containment would strand every benign
alert.

## 5. Severity scoring

Deterministic and explainable. Not ML — a reviewer must be able to read the rationale and arrive at
the same score.

```
score = clamp(0, 100,
        asset_criticality_weight   * asset_criticality_norm
      + detection_confidence_weight * detection_confidence
      + technique_impact_weight    * technique_impact_norm
      + privilege_context_weight   * privilege_context_norm
      + active_c2_weight           * active_c2_signal)
```

Every non-zero term appends a sentence to `rationale`. Bands:

| Score | Severity | Auto-run policy |
|---|---|---|
| 85–100 | `critical` | Run containment automatically, no approval gate |
| 70–84 | `high` | Run, containment requires approval |
| 40–69 | `medium` | Triage + evidence only; containment requires approval |
| 0–39 | `low` | Record and close as suspected false positive |

Weights live in one config dict in `soar/severity.py` and are unit-tested. Randomness is forbidden —
the same alert must always produce the same score ([`AGENTS.md`](../AGENTS.md) §4).

## 6. Data model (SQLite)

WAL mode. Stdlib `sqlite3` only — no ORM.

| Table | Purpose |
|---|---|
| `incidents` | id, alert JSON, severity, score, rationale, phase, status, timestamps |
| `runs` | id, incident_id, playbook_id, status, started_at, ended_at, phase timings |
| `actions` | id, run_id, action_id, phase, connector, params, status, result JSON, timings |
| `evidence` | id, incident_id, artifact, sha256, size, source, collected_at |
| `journal` | estate mutation journal — sequence, action_id, entity, before/after |

`journal` is what makes the rollback invariant testable: estate state can be reconstructed exactly
as it was before a run.

## 7. Memory forensics

`soar/forensics/memory.py` shells out to `vol` — this is the **only** permitted subprocess in the
project, and it reads a file the operator supplied.

- **Default input is `fixtures/volatility/*.json`** — recorded plugin output. Tests and demos run
  offline and deterministically.
- **Optional input is `fixtures/memory/*.raw`** — a real image the operator deliberately placed
  there. `scripts/fetch_memory_image.sh` fetches a public Volatility test image on request. It is
  never automatic and never committed.
- When Volatility or the image is absent, `forensics.volatility` returns `skipped` and the run
  continues. The report then states forensics were **not performed**. Silence is not an acceptable
  substitute for reporting a skipped step.
- Per-plugin timeouts gate the run against the [`METRICS.md`](METRICS.md) budget.

Symbol tables download on first Windows use and are slow; the cache is a mounted volume
(`data/vol-cache/`) so it survives restarts.

## 8. API surface

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/alerts` | Ingest alert → triage → select playbook → create incident |
| `GET` | `/incidents` | List, filterable by severity/phase/status |
| `GET` | `/incidents/{id}` | Full incident detail |
| `POST` | `/incidents/{id}/run` | Execute the selected playbook |
| `POST` | `/incidents/{id}/actions/{action_id}/approve` | Satisfy an approval gate |
| `GET` | `/runs/{id}` | Run status + per-action results (poll target) |
| `GET` | `/incidents/{id}/timeline` | Phase timeline as JSON |
| `GET` | `/incidents/{id}/report` | `?format=html\|md\|json` |
| `GET` | `/playbooks` | Technique coverage **with explicit gaps** |
| `GET` | `/healthz` | Liveness + Volatility availability |

`POST /incidents/{id}/run` starts the run on an in-process background thread and returns
`{"run_id", "status": "running"}` immediately, because a full run (forensics + report) can exceed
an HTTP client timeout. Progress is then polled via `GET /runs/{id}`. A run blocked on an approval
gate reports `awaiting_approval` and stays there until approved or aborted.

This is an in-process thread, not a distributed worker — single-node by design. No Celery, no Redis,
no separate worker service ([`AGENTS.md`](../AGENTS.md) §3). The consequence to respect: runs do
**not** survive an API restart. An interrupted run stays `running` in SQLite forever unless
`GET /runs/{id}` is taught to reconcile it — tracked as a known limitation in
[`STATUS.md`](STATUS.md).

## 9. Toolchain

| Package | Version | Why |
|---|---|---|
| `fastapi` | pinned | API layer. Brief specifies FastAPI. |
| `uvicorn` | pinned | ASGI server. |
| `pydantic` | pinned | Request/response validation. |
| `jinja2` | pinned | Report generation. Brief specifies Jinja2. |
| `pyyaml` | pinned | Playbook definitions. Brief specifies YAML. |
| `volatility3` | `2.28.2` | Memory forensics. Brief specifies Volatility. |
| `httpx` | pinned (dev) | Test client. |
| `pytest` | pinned (dev) | Test runner. |

**Python 3.11 in containers**, not the host's 3.14. Volatility's optional extras and the wider IR
tool ecosystem are validated on 3.11, and the sibling projects already pin 3.11-slim. The host has
no `python3-venv`, so container-only execution is also the only workable option
([`AGENTS.md`](../AGENTS.md) §7).

Everything else is standard library: `sqlite3`, `hashlib`, `json`, `subprocess`, `asyncio`,
`dataclasses`, `enum`, `datetime`, `re`.

### 9.1 Deliberately rejected

| Rejected | Reason |
|---|---|
| **Celery + Redis** | Distributed queue for a single-node engine. YAGNI. |
| **SQLAlchemy** | `sqlite3` is sufficient and inspectable. |
| **matplotlib** | Heavy; Chart.js covers the timeline in ~20 lines of template. |
| **Alembic** | No migration history to manage. Schema is created idempotently at startup. |
| **ML severity model** | Irreproducible, unexplainable scores. A score a responder cannot audit is worse than no score. |
| **Playbook DSL / expressions** | `{{ field }}` substitution only — see [`SECURITY.md`](SECURITY.md) §5. |
| **Live connectors** | Fixed boundary, [`SECURITY.md`](SECURITY.md) §1. |

## 10. Relation to sibling projects

| Project | Owns |
|---|---|
| **AI-Powered Threat Detection System** | Detection rules, ML models, and **playbook generation** (`automation/ir-playbook/playbook_generator.py`) |
| **Malware Analysis Sandbox** | Sample detonation, IOC/YARA generation, STIX/TAXII |
| **This project** | **Playbook execution**, containment, evidence custody, memory forensics, IR reporting |

This project consumes playbooks; it does not generate them. Do not reimplement generation
([`AGENTS.md`](../AGENTS.md) §1).