# Incident Response Automation

A custom Python SOAR engine that **executes** incident-response playbooks across the NIST SP 800-61
lifecycle: triage alerts, contain threats against a simulated estate, collect real forensic evidence
with chain of custody, analyse memory with Volatility 3, and generate IR reports automatically.

> **⚠️ SAFETY NOTICE**
> Containment, eradication and recovery actions in this project are **simulated** against an
> in-memory/SQLite model of a small network. This project has **no live mode** and never executes
> commands against real infrastructure. Read [`docs/SECURITY.md`](docs/SECURITY.md) and
> [`AGENTS.md`](AGENTS.md) before running anything.

## Visual overview

| Report artefact | What it shows | Where to find it |
|---|---|---|
| **HTML report** | Full incident report with Chart.js action timeline, evidence integrity, caveats and labelling (MEASURED/TARGET). | [`reports/html/INC-E145A308EA3F.html`](reports/html/INC-E145A308EA3F.html) |
| **Markdown report** | Ticket-ready technical report. | [`reports/md/INC-E145A308EA3F.md`](reports/md/INC-E145A308EA3F.md) |
| **Executive summary** | Non-technical, one-page briefing. | [`reports/md/INC-E145A308EA3F-exec.md`](reports/md/INC-E145A308EA3F-exec.md) |

Every figure is explicitly labelled **MEASURED** or **TARGET** per [`docs/METRICS.md`](docs/METRICS.md). The HTML template loads Chart.js from a CDN as a reporting convenience only — the report degrades gracefully without it and the project has no other runtime dependency on it.

---

## Project status

| Week | Description | Status |
|---|---|---|
| 1 | Playbook framework | 🟢 Gate met |
| 2 | Forensics & response | 🟢 Gate met |
| 3 | Reporting & documentation | 🟢 Gate met |

The engine, playbooks, containment, forensics and IOC extraction are built and tested
(**270 tests passing**, no network required). Reporting (HTML/Markdown/executive summary), timeline generation
and evidence integrity verification are all implemented and covered by tests. Live progress lives in
[`docs/STATUS.md`](docs/STATUS.md) — update it and this table in the same change as work lands.

## What it does (one paragraph)

An alert arrives at `POST /alerts`, is scored by a **deterministic** severity function that returns a
human-readable rationale for every contributing factor, and is matched to a YAML playbook by MITRE
technique and severity band. The engine walks the playbook action by action with per-action timeouts,
approval gates and three failure policies. Forensic actions — **real** — copy evidence read-only,
SHA-256 each artifact into an append-only chain-of-custody log, run Volatility 3 plugins against a
memory image, and extract IOCs with source attribution. Containment actions — **simulated** — mutate
a modelled estate of hosts, firewall rules and accounts; every mutation is journalled so that on
abort, compensations run in reverse order and restore the estate **exactly**. Each run produces a
timeline and a Jinja2 report in HTML, Markdown and an executive-summary form. Evidence integrity is
recomputed on-the-fly (stored SHA-256 vs recomputed digest) so that missing or tampered artifacts
are surfaced as report caveats rather than being trusted blindly.

## Architecture at a glance

```
   alert JSON ──▶ POST /alerts ──▶ triage.score ──▶ playbook_loader (YAML)
                        │              0-100              │
                        │            + rationale         ▼
                        │                          soar/engine.py
                        │              sequence · timeout · approval
                        │              failure policy · compensation
                        └──────────────────────┬───────────┴──────────────┐
                                               ▼                          ▼
                              ┌────────────────────────┐      ┌──────────────────────────┐
                              │  REAL                  │      │  SIMULATED               │
                              │  evidence.collect      │      │  estate.isolate_host     │
                              │  forensics.volatility  │      │  firewall.block          │
                              │  ioc.extract           │      │  identity.lock_account   │
                              │  triage.score          │      │  eradication.*           │
                              └───────────┬────────────┘      │  recovery.verify         │
                                          │                   └────────────┬─────────────┘
                             chain_of_custody.jsonl                      │
                                          │                        soar/estate.py
                                          ▼                       (SQLite + journal)
                              ┌────────────────────────┐                      │
                              │ reporting/generator    │◀─────────────────────┘
                              │ HTML · MD · timeline   │
                              └────────────────────────┘
```

Full design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · module contracts:
[`docs/COMPONENTS.md`](docs/COMPONENTS.md)

## The one idea worth knowing

**Everything the engine can do is a `Connector` with an `execute()` and a `compensate()`.**

That single interface is why this project can automate containment while staying safe, and why the
most valuable test in it is a one-line assertion:

> Estate state after compensation **must equal** estate state before.

Containment that is provably reversible is the actual skill being sold here. If you change
anything about the estate, the engine, or a connector, that assertion must still hold.

## Quick start

Requires Docker only. Python 3.14 on the host is never used — everything runs in the pinned
`python:3.11-slim` container, and no local venv is created.

```bash
# 1. Run the test suite (234 tests, no network access required)
docker compose run --rm api pytest

# 2. Seed a demo incident and run its playbook end to end
docker compose run --rm api python scripts/seed_incident.py \
    --alert fixtures/alerts/ransomware_finance_host.json --run --auto-approve

# 3. Or bring up the API
docker compose up --build -d
curl http://localhost:8000/healthz

# 4. Triage an alert
curl -X POST http://localhost:8000/alerts \
    -H 'Content-Type: application/json' \
    -d "{\"alert\": $(cat fixtures/alerts/ransomware_finance_host.json)}"

# 5. Run the playbook. auto_approve defaults to FALSE, so containment waits for a
#    human unless the incident scored `critical`.
curl -X POST http://localhost:8000/incidents/<id>/run \
    -H 'Content-Type: application/json' -d '{}'
curl http://localhost:8000/runs/<run_id>

# 6. Release a single approval gate (approves that action only)
curl -X POST http://localhost:8000/incidents/<id>/actions/<action_id>/approve

# 7. Phase timeline and coverage gaps
curl http://localhost:8000/incidents/<id>/timeline
curl http://localhost:8000/playbooks

# 8. Generate the IR report (HTML, Markdown, exec summary, or raw JSON)
curl http://localhost:8000/incidents/<id>/report?format=html > reports/html/<id>.html
curl http://localhost:8000/incidents/<id>/report?format=md > reports/md/<id>.md
curl http://localhost:8000/incidents/<id>/report?format=exec > reports/md/<id>-exec.md
curl http://localhost:8000/incidents/<id>/report?format=json
```

### Verified walkthrough output

Real output from `seed_incident.py` — not aspirational:

```
Incident    : INC-17438761B387
Alert       : ALT-2026-0001 -- Mass file encryption on finance workstation
Score       : 91/100  ->  CRITICAL
Technique   : T1486 (Data Encrypted for Impact)
Playbook    : ransomware

Rationale:
  - 25.0 pts - asset criticality 5/5 in corp zone
  - 23.5 pts - detection confidence 94% from edr
  - 25.0 pts - T1486 (Data Encrypted for Impact) carries impact 100%
  -  7.5 pts - activity is by a standard user account
  - 10.0 pts - active C2 communication observed; ransom note artefact found; shadow copies deleted

Status      : completed
Incomplete  : False
   [succeeded] triage_alert
   [succeeded] collect_evidence (167 ms)
   [succeeded] memory_forensics (171 ms)
   [succeeded] extract_iocs (9 ms)
   [succeeded] isolate_affected_host (3 ms)
   [succeeded] block_actor_network (14 ms)
   [succeeded] disable_compromised_account (3 ms)
   [succeeded] quarantine_payload (10 ms)
   [succeeded] remove_persistence (19 ms)
   [succeeded] verify_containment (50 ms)

Estate after run:
  WS-FIN-014   isolated=True
  j.okafor     locked=True
  rule FW-0001  corp->restricted block 203.0.113.44
```

The rationale lines sum to exactly 91 — the score is auditable term by term, which is the point
of a deterministic severity function ([`docs/METRICS.md`](docs/METRICS.md) §4).

Generate the full report on demand via `GET /incidents/{id}/report?format=html|md|exec|json` (see Quick start below). Use
`GET /incidents/{id}/timeline` for the raw phase sequence.

## Metrics

> **No benchmark has been run. No performance figure is claimed below.**
> Measured numbers appear here only after a committed `scripts/benchmark.py` run
> ([`docs/METRICS.md`](docs/METRICS.md) §4). The per-action timings in the walkthrough above
> are illustrative output from one run, **not** a benchmark result.

The project brief proposes these **targets**:

| Metric | Manual (TARGET) | Automated (TARGET) |
|---|---|---|
| Mean time to respond | 4 hours | 15 minutes |
| Mean time to contain | 8 hours | 30 minutes |
| Evidence collection | 2 hours manual | 5 minutes automated |
| Report generation | 4 hours | 5 minutes |

These are **aspirational goals from the brief, not measurements of this system**, and will never be
presented as results. This project measures what is actually reproducible — automated *execution
time* on a fixed input set — and labels the manual column as a clearly-marked **ESTIMATE** inherited
from the brief. Definitions, methodology and the anti-gaming rules are fixed in
[`docs/METRICS.md`](docs/METRICS.md).

One metric has a hard 100% target with no tolerance: **rollback correctness**.

## Docs index

| File | Purpose |
|---|---|
| [`AGENTS.md`](AGENTS.md) | **Read first.** Ground rules that keep agents and contributors on track. |
| [`docs/PLAN.md`](docs/PLAN.md) | 3-week plan with Definition of Done gates and non-goals. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, connector inventory, phase model, toolchain & rejected alternatives. |
| [`docs/COMPONENTS.md`](docs/COMPONENTS.md) | **Binding** per-module contracts: inputs, outputs, API surface, constraints. |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Mandatory safety rules: real vs simulated, rollback invariant, evidence custody. |
| [`docs/METRICS.md`](docs/METRICS.md) | Metric definitions, fixed methodology, anti-gaming rules. |
| [`docs/STATUS.md`](docs/STATUS.md) | Live progress, gates, metrics log, known gaps, decisions log. |

## Relationship to sibling projects

Part of a three-project set:

| Project | Owns |
|---|---|
| **AI-Powered Threat Detection System** | Detection rules, ML models, and **playbook generation** |
| **Malware Analysis Sandbox** | Sample detonation, IOC/YARA generation, STIX/TAXII |
| **This project** | **Playbook execution**, containment, evidence custody, memory forensics, IR reporting |

This project consumes playbooks; it does not generate them.

## Interacting with AI agents

If you are an AI agent or onboarding a contributor: **read [`AGENTS.md`](AGENTS.md) first.** It is the
source of truth for scope, safety, phasing, metric integrity and doc-sync rules. The short version:

1. Containment is **simulated**. Never add anything that touches real infrastructure.
2. Tests must pass **without network access**.
3. **Don't** quote performance numbers that no committed benchmark run supports.
4. Update `docs/STATUS.md` and the table above in the same change as the work.