# AGENTS.md — Agent & Contributor Ground Rules

This file is the **source of truth for how to work in this repository**. AI agents and human
contributors must read it fully before making any change. If a rule conflicts with a user request,
**raise it with the user** instead of silently picking a side.

---

## 1. What this repository is

A custom Python SOAR (Security Orchestration, Automation & Response) engine that executes
incident-response playbooks following the NIST SP 800-61 incident response lifecycle:

- **Triages** incoming alerts with deterministic, explainable severity scoring.
- **Executes** YAML-defined playbooks across the SP 800-61 lifecycle phases.
- **Contains** threats against a **simulated** lab estate (hosts, firewall rules, accounts).
- **Collects** real forensic evidence with SHA-256 chain of custody.
- **Analyses** memory images with Volatility 3 and extracts IOCs.
- **Reports** with Jinja2 (full HTML, Markdown, executive summary) plus a timeline.

This project **executes** playbooks. It does **not** generate them — see
[`../AI-Powered Threat Detection System/automation/ir-playbook/playbook_generator.py`](../AI-Powered%20Threat%20Detection%20System/automation/ir-playbook/playbook_generator.py),
which owns MITRE-templated playbook generation. Do not rebuild generation here.

See [`README.md`](README.md) and [`docs/PLAN.md`](docs/PLAN.md).

## 2. Non-negotiable safety rules

> These apply to **everyone**, including agents. Violating them is the one way to be "off track".

1. **Never execute containment actions against real infrastructure.** Host isolation, firewall
   rules, account lockout, eradication and recovery actions operate **only** on the simulated
   estate in [`soar/estate.py`](soar/estate.py). There is no live mode. There is no "just testing
   it for real" exception.
2. **Never add a connector that shells out to a real admin tool.** No `subprocess` call to
   `powershell`, `pwsh`, `netsh`, `New-NetFirewallRule`, `Disable-ADAccount`, `ssh`, `docker run`
   against a live host, or any equivalent. If a capability seems to need one, that is a signal to
   model it in the estate instead — raise it with the user if you disagree.
3. **Never capture memory from this host or any real machine.** Do not write a RAM capture tool, do
   not use `DumpIt`, `LiME`, `winpmem`, `AVML`, or `/proc/kcore`. Memory images may only come from
   `fixtures/memory/` (git-ignored, user-supplied) via
   `scripts/fetch_memory_image.sh`.
4. **Evidence is read-only, always.** Collection copies bytes and never modifies, "cleans", or
   re-saves the source. Every collected artifact is SHA-256 hashed and appended to the chain of
   custody log. Never regenerate or overwrite an evidence artifact — collect a new one.
5. **`fixtures/memory/`, `data/` and `reports/` must never be committed, pushed, or shared.**
   If the repo is ever initialized with git, `.gitignore` already covers them — verify it exists
   (see §6) before the first commit.
6. **Every containment action must have a tested inverse.** An action without a `compensate`
   implementation and a rollback test in `tests/test_rollback.py` is incomplete and must not merge.
7. **Never bypass the engine.** No ad-hoc scripts that execute playbook actions directly. All
   action execution goes through `soar/engine.py` so that timeouts, approval gates, failure policy,
   journalling and compensation are guaranteed.

## 3. Scope discipline

- Work in the **order defined by [`docs/PLAN.md`](docs/PLAN.md)**. Do not skip a phase to start a
  later one; each week has a Definition of Done gate (see §5.6).
- Do **not** invent modules, features, or endpoints that are not in
  [`docs/COMPONENTS.md`](docs/COMPONENTS.md). If you believe something is missing, propose it to the
  user and update the docs **in the same change** once approved.
- Follow the **module contracts** in `docs/COMPONENTS.md`. If a contract must change, update the doc
  in the same change that changes the code.
- **Playbook count is capped at 4** (`ransomware`, `credential_theft`, `data_exfiltration`,
  `brute_force`). Documenting the *gaps* is a deliverable ([`docs/PLAN.md`](docs/PLAN.md) Week 3),
  not a reason to add more playbooks.
- **YAGNI.** Prefer the standard library and the already-pinned toolchain. The approved dependency
  list is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) → *Toolchain*. No new dependencies
  without a documented reason in that section and the user's approval. Specifically: no Celery, no
  Redis, no SQLAlchemy, no matplotlib.
- Keep a full playbook run **under the target in [`docs/METRICS.md`](docs/METRICS.md)**. If a stage
  would blow the budget, gate it (e.g. a Volatility plugin timeout) instead of letting the run stall.

## 4. Metric integrity (anti-gaming)

Methodology is fixed in [`docs/METRICS.md`](docs/METRICS.md).

- The `4 hours → 15 minutes` MTTR figures from the original project brief are an **aspirational
  target, not a measurement.** Never present them as results.
- Do **not** lower targets or change methodology to make numbers look better.
- Report **raw counts + methodology** alongside any metric claim.
- **Measured and estimated figures must be visually and textually labelled** as such, everywhere —
  README, reports, and dashboards. No exceptions.
- Do **not** cherry-pick which incidents appear in the benchmark. `scripts/benchmark.py` replays
  the **entire** fixture alert set; exclusions must be documented with a reason.
- A metric with no committed benchmark run behind it does not get quoted.

## 5. Workflow for every task

1. **Read before acting:** `README.md` → `AGENTS.md` → `docs/PLAN.md` → the relevant section of
   `docs/COMPONENTS.md`. Never start from memory or assumptions.
2. **Do the smallest change** that satisfies the current plan task.
3. **Keep docs in sync:** if behavior, contracts, or layout change, update the corresponding doc in
   the same change.
4. **Update [`docs/STATUS.md`](docs/STATUS.md) and the README status table** when a checklist item or
   week gate completes.
5. **Tests are mandatory** for: severity scoring, engine sequencing/timeouts/failure policy, the
   rollback invariant, IOC extractors, the chain-of-custody manifest, playbook schema validation,
   and the API surface. Running the test suite must **not** require network access.
6. **Gate check:** do not move to the next week until the current Definition of Done
   ([`docs/PLAN.md`](docs/PLAN.md)) is met and `docs/STATUS.md` is updated.

## 6. Data & storage conventions

| Artifact | Location |
|---|---|
| Incident state (SQLite, WAL) | `data/ir.db` |
| Evidence artifacts | `data/incidents/<incident_id>/evidence/` |
| Chain of custody (append-only JSONL) | `data/incidents/<incident_id>/chain_of_custody.jsonl` |
| Run journal (per-action results) | `data/incidents/<incident_id>/runs/<run_id>.json` |
| Generated reports | `reports/html/<incident_id>.html`, `reports/md/<incident_id>.md` |
| Benchmark output | `data/metrics/benchmark.json` |
| Volatility symbol cache | `data/vol-cache/` (container volume) |
| Replayable alert fixtures | `fixtures/alerts/*.json` |
| Recorded Volatility plugin output | `fixtures/volatility/*.json` |
| Optional real memory image | `fixtures/memory/` — **git-ignored**, never committed |

`fixtures/volatility/*.json` is the **default** forensic input. `fixtures/memory/` is optional and
only used when the operator has deliberately supplied an image. Tests must pass using fixtures
alone.

## 7. Working directory & environment

- This repo lives on a Windows machine. Python on the host is 3.14.
- **Do not create local venvs.** The WSL host has no `python3-venv` and there is no passwordless
  sudo to install it. Run everything in the pinned `python:3.11-slim` container, e.g.
  `docker compose run --rm api pytest`.
- Python **3.11** in containers (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) → *Toolchain*
  for why 3.14 is not used).
- Volatility is pinned. Symbol tables download on first Windows run and are slow — the cache lives
  on a mounted volume so it survives container restarts.
- Never `docker compose down -v`; it destroys the symbol cache and evidence volume.

## 8. When in doubt

Ask the user. Do not guess on: safety questions, scope changes, metric changes, or anything that
would execute containment, capture memory, or modify evidence.