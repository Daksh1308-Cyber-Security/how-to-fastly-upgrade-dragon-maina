# PLAN.md — 3-Week Implementation Plan

Binding work order. Phases run in sequence; each week has a **Definition of Done** gate that must
pass before the next week starts ([`AGENTS.md`](../AGENTS.md) §5.6).

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

**Live progress:** [`STATUS.md`](STATUS.md). Update it in the same change that completes an item.

---

## Week 1 — Playbook Framework

Goal: a YAML playbook runs end to end against the simulated estate, and rollback is provable.

- [ ] **W1.1** Repo skeleton — `soar/` package layout, `docker-compose.yml`, `requirements.txt`,
      `requirements-dev.txt`, `docker/Dockerfile`, pinned `python:3.11-slim` toolchain.
- [ ] **W1.2** Domain model — `soar/models.py`: `Incident`, `Playbook`, `Action`, `ActionResult`,
      `Evidence`, `Severity`. `soar/nist.py`: `Phase` enum + SP 800-61r3 / CSF 2.0 mapping table.
- [ ] **W1.3** Severity scoring — `soar/severity.py`. Deterministic 0–100 score from asset
      criticality, detection confidence, MITRE technique impact, privilege context, and active-C2
      evidence. Must return a `rationale: list[str]` explaining every contributing factor.
      No ML, no randomness.
- [ ] **W1.4** Playbook loader — `soar/playbook_loader.py`. YAML load, schema validation, and
      `{{ field }}` parameter substitution from incident context (grammar in
      [`COMPONENTS.md`](COMPONENTS.md)).
- [ ] **W1.5** Simulated estate — `soar/estate.py`. Hosts, accounts, firewall rules, mutation
      journal. SQLite for runtime, in-memory for tests.
- [ ] **W1.6** Execution engine — `soar/engine.py`. Action sequencing, per-action timeout,
      approval gate, failure policy (`abort` / `continue` / `compensate`), reverse-order
      compensation on abort.
- [ ] **W1.7** Persistence — `soar/store.py` with stdlib `sqlite3`. Tables: `incidents`, `runs`,
      `actions`, `evidence`. WAL mode.
- [ ] **W1.8** API skeleton — `soar/api/main.py`, `soar/api/schemas.py`. `POST /alerts`,
      `GET /incidents`, `GET /incidents/{id}`, `POST /incidents/{id}/run`, `GET /runs/{id}`.
- [ ] **W1.9** Four playbooks — `playbooks/{ransomware,credential_theft,data_exfiltration,brute_force}.yaml`.
      Each spans all five phases and every containment action declares a `compensate`.
- [ ] **W1.10** Tests — `tests/test_severity.py`, `test_engine.py`, `test_rollback.py`,
      `test_playbooks.py`, `test_estate.py`, `test_api.py`. Must pass with **no network access**.
- [ ] **W1.11** Seed fixtures — `fixtures/alerts/*.json`, 12 replayable alerts spanning severities
      and MITRE techniques.

### Week 1 Definition of Done

- [ ] `pytest` green with no network access.
- [ ] A seeded alert runs a complete playbook end to end in the API.
- [ ] **Rollback invariant holds:** estate state after compensation is identical to pre-run state
      ([`SECURITY.md`](SECURITY.md) §3.1).
- [ ] Timeout, approval gate, and all three failure policies covered by tests.
- [ ] `playbooks/*.yaml` all pass schema validation.
- [ ] `STATUS.md` and the README status table updated.

---

## Week 2 — Forensics & Response

Goal: real evidence collection and memory forensics producing real IOCs, offline.

- [ ] **W2.1** Evidence collection — `soar/evidence.py`. Read-only copy, SHA-256, chain-of-custody
      JSONL append ([`SECURITY.md`](SECURITY.md) §4).
- [ ] **W2.2** Memory forensics — `soar/forensics/memory.py`. `vol` subprocess wrapper, JSON plugin
      parsing, per-plugin timeout, graceful degradation when Volatility is absent. **Must never**
      attempt to capture host memory.
- [ ] **W2.3** Volatility fixtures — `fixtures/volatility/*.json`: recorded output for
      `windows.info`, `pslist`, `pstree`, `netscan`, `filescan`, `malfind`, `cmdline`, `handles`.
      These are the **default** forensic input.
- [ ] **W2.4** IOC extraction — `soar/forensics/ioc.py`. IPs, domains, URLs, file hashes, mutexes,
      injected processes, persistence artifacts — sourced from Volatility output and collected
      artifacts, each with a source attribution.
- [ ] **W2.5** Fetch script — `scripts/fetch_memory_image.sh`. Optional operator-initiated pull of
      a public Volatility test image into git-ignored `fixtures/memory/`. Never automatic.
- [ ] **W2.6** Containment connectors — complete `firewall.block`, `identity.lock_account`,
      `estate.isolate_host` and their inverses.
- [ ] **W2.7** Eradication — `connectors/eradication.py`: remove persistence, quarantine file,
      disable compromised account — all simulated.
- [ ] **W2.8** Recovery verification — `connectors/recovery.py`: health checks against estate
      state, re-scan, confirmation that containment still holds.
- [ ] **W2.9** Tests — `test_ioc.py`, `test_custody.py`, `test_forensics.py`, plus rollback tests
      extended to **every** connector.

### Week 2 Definition of Done

- [ ] Memory forensics yields IOCs from `fixtures/volatility/` **fully offline**.
- [ ] Chain-of-custody manifest passes integrity verification; tampering is detected by test.
- [ ] Every connector has a tested inverse; `test_rollback.py` covers all of them.
- [ ] Volatility absent → forensics step degrades to `skipped`, run still succeeds and is reported
      honestly as incomplete.
- [ ] No code path can capture host memory (review against `SECURITY.md` §2).
- [ ] `STATUS.md` and the README status table updated.

---

## Week 3 — Reporting & Documentation

Goal: reports a human can act on, and metrics that are honestly labelled.

- [ ] **W3.1** Report generator — `soar/reporting/generator.py`. Renders incident, timeline, IOCs,
      action results, evidence manifest, integrity status.
- [ ] **W3.2** Templates — `soar/reporting/templates/`: `report.html.j2`, `report.md.j2`,
      `exec_summary.md.j2`. Every template must label measured vs estimated figures
      ([`AGENTS.md`](../AGENTS.md) §4).
- [ ] **W3.3** Timeline visualization — per-phase timeline in HTML. Chart.js, no matplotlib.
- [ ] **W3.4** Coverage & gaps — `GET /playbooks` returns technique coverage with explicit gap list;
      rendered into [`README.md`](../README.md) and a generated section of `STATUS.md`.
- [ ] **W3.5** Benchmark harness — `scripts/benchmark.py`. Replays the **entire** `fixtures/alerts/`
      set through the engine, records per-phase wall-clock, writes `data/metrics/benchmark.json`.
- [ ] **W3.6** Metrics — [`METRICS.md`](METRICS.md) updated with **measured** results and the
      documented manual baseline estimate with assumptions listed.
- [ ] **W3.7** README — full walkthrough: alert → triage → playbook → containment → forensics →
      report, with real captured output.
- [ ] **W3.8** Doc sync — `AGENTS.md`, `ARCHITECTURE.md`, `COMPONENTS.md`, `SECURITY.md`,
      `STATUS.md` all consistent with shipped behaviour.

### Week 3 Definition of Done

- [ ] End-to-end demo: alert in, complete IR report out, reproducible from the README.
- [ ] `scripts/benchmark.py` run committed; README numbers match `data/metrics/benchmark.json`.
- [ ] Measured vs estimated visibly distinguished everywhere.
- [ ] Playbook coverage **and gaps** documented.
- [ ] `STATUS.md` final, all week gates marked met.

---

## Out of Scope

Agreed non-goals. Do not implement without a scope change approved by the user and recorded here.

| Non-goal | Reason |
|---|---|
| Live infrastructure connectors | [`SECURITY.md`](SECURITY.md) §1. The real/simulated line is fixed. |
| Playbook authoring UI | Playbooks are version-controlled YAML. |
| ML-based triage | Severity must be deterministic and explainable. |
| Distributed / multi-tenant execution | Single-node engine by design. No Celery, no Redis. |
| Host memory capture tooling | Never permitted ([`SECURITY.md`](SECURITY.md) §2). |
| More than 4 playbooks | Capped in [`AGENTS.md`](../AGENTS.md) §3; gaps are the deliverable. |
| Third-party SOAR integration | The brief is a custom engine. |