# STATUS.md — Live Progress & Metrics Log

Single source of live progress. Update in the same change that completes an item
([`AGENTS.md`](../AGENTS.md) §5.4). Work order is defined in [`PLAN.md`](PLAN.md).

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

**Last updated:** 2026-10-02 (Weeks 1–2 complete, both gates met)

---

## Overall

| Week | Description | Status |
|---|---|---|
| 1 | Playbook framework | 🟢 Gate met |
| 2 | Forensics & response | 🟢 Gate met |
| 3 | Reporting & documentation | 🔄 In progress — reports pending |

## Setup

- [x] `README.md`
- [x] `AGENTS.md` — ground rules for agents and contributors
- [x] `.gitignore` — created **before** any `git init` ([`AGENTS.md`](../AGENTS.md) §2.5)
- [x] `docker/Dockerfile`, `docker-compose.yml`, `requirements*.txt` — pinned Python 3.11
- [x] `pytest.ini` — `pythonpath = .` so no venv is needed
- [x] [`docs/PLAN.md`](PLAN.md)
- [x] [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
- [x] [`docs/COMPONENTS.md`](COMPONENTS.md)
- [x] [`docs/SECURITY.md`](SECURITY.md)
- [x] [`docs/METRICS.md`](METRICS.md)
- [x] [`docs/STATUS.md`](STATUS.md) — this file

## Week 1 — Playbook framework

- [x] W1.1 Repo skeleton + toolchain
- [x] W1.2 Domain model (`models.py`, `nist.py`)
- [x] W1.3 Severity scoring
- [x] W1.4 Playbook loader + validation
- [x] W1.5 Simulated estate
- [x] W1.6 Execution engine
- [x] W1.7 Persistence (`store.py`)
- [x] W1.8 API skeleton
- [x] W1.9 Four playbooks
- [x] W1.10 Tests
- [x] W1.11 Seed alert fixtures (12 alerts)

### Gate — Week 1 ✅

- [x] `pytest` green, no network — **234 passing**
- [x] Seeded alert runs a full playbook end to end
- [x] **Rollback invariant holds** (estate state restored)
- [x] Timeout, approval gate, 3 failure policies covered
- [x] All playbooks pass schema validation
- [x] `STATUS.md` + README status table updated

## Week 2 — Forensics & response

- [x] W2.1 Evidence collection + chain of custody
- [x] W2.2 Memory forensics (Volatility wrapper)
- [x] W2.3 Volatility fixtures (8 plugins recorded)
- [x] W2.4 IOC extraction
- [x] W2.5 `fetch_memory_image.sh`
- [x] W2.6 Containment connectors
- [x] W2.7 Eradication
- [x] W2.8 Recovery verification
- [x] W2.9 Tests

### Gate — Week 2 ✅

- [x] IOCs from fixtures, fully offline
- [x] Chain-of-custody integrity verified; tampering detected
- [x] Every connector has a tested inverse
- [x] Volatility absent → `skipped`, run still succeeds (`run.incomplete = True`)
- [x] No host memory capture path exists (asserted by `test_forensics.py`)
- [x] `STATUS.md` + README status table updated

## Week 3 — Reporting & documentation

- [ ] W3.1 Report generator ← **next**
- [ ] W3.2 Templates (HTML / Markdown / exec summary)
- [ ] W3.3 Timeline visualisation (timeline JSON endpoint already exists)
- [ ] W3.4 Playbook coverage & gaps — endpoint done, generated doc pending
- [ ] W3.5 Benchmark harness (`scripts/benchmark.py`)
- [ ] W3.6 Metrics with real numbers
- [ ] W3.7 README walkthrough — verified output already captured
- [ ] W3.8 Doc sync

### Gate — Week 3

- [ ] End-to-end demo: alert in, report out
- [ ] Benchmark run committed; README matches `benchmark.json`
- [ ] Measured vs estimated distinguished everywhere
- [ ] Coverage **and gaps** documented
- [ ] All week gates met

---

## Metrics log

**No benchmark has been run.** No performance figure is claimed
([`AGENTS.md`](../AGENTS.md) §4). Per-action timings appear in the README walkthrough as
illustrative single-run output and are explicitly **not** a benchmark result.

<!-- Filled by scripts/benchmark.py at each run; format fixed by METRICS.md §6 -->

| Run date | Commit | n | Mode | Metric | Measured | Target | Source |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | *no runs yet* | — | — |

---

## Known gaps & blockers

| Item | Type | Impact | Notes |
|---|---|---|---|
| Report generation | scope | `GET /incidents/{id}/report` returns `501` | Week 3. Deliberately 501 rather than a placeholder report that could be mistaken for a real one |
| Runs do not survive API restart | limitation | An interrupted run stays `running` in SQLite | In-process thread, no durable queue ([`ARCHITECTURE.md`](ARCHITECTURE.md) §8). Accepted for a single-node engine |
| Volatility memory image | data | Live-image path unexercised | No image available. Fixtures are the default; `scripts/fetch_memory_image.sh` is operator-initiated. Does not block anything |
| Windows symbol tables | data | First `vol` run slow | Cached to a volume. Must be reported separately per [`METRICS.md`](METRICS.md) §3.3 |
| Manual baseline | metric | Comparison is indicative only | Manual figures are ESTIMATES inherited from the brief ([`METRICS.md`](METRICS.md) §5), not measured |
| Action timeouts cannot kill a thread | limitation | A hung connector's thread leaks | Python has no thread kill. The one subprocess enforces its own hard timeout. Documented in `engine.py` |

## Playbook coverage

Produced by `GET /playbooks` (verified live: 9 techniques covered, **7 gaps**).

| Playbook | MITRE techniques | Phases | Status |
|---|---|---|---|
| `ransomware` | T1486, T1490 | 4 | ✅ Written, validated, exercised end to end |
| `credential_theft` | T1003, T1558, T1056 | 4 | ✅ Written, validated |
| `data_exfiltration` | T1041, T1567, T1048 | 4 | ✅ Written, validated |
| `brute_force` | T1110 | 4 | ✅ Written, validated |

### Gaps — uncovered techniques

Reported, not hidden. 3 of the 12 fixture alerts fall into these and correctly return
`playbook_id: None`.

| Technique | Name | Example fixture |
|---|---|---|
| T1489 | Service Stop | `service_stop_critical_service.json` |
| T1566 | Phishing | `phishing_credential_harvest.json` |
| T1190 | Exploit Public-Facing Application | — |
| T1055 | Process Injection | — |
| T1547 | Boot or Logon Autostart Execution | — |
| T1021 | Remote Services | — |
| T1078 | Valid Accounts | — |

`T1046` (Network Service Discovery) is also uncovered —
`port_scan_reconnaissance.json` exercises that path.

---

## Decisions log

Decisions that are not obvious from the code or architecture doc. Newest first.

| Date | Decision | Rationale |
|---|---|---|
| 2026-10-02 | **No severity fallback in playbook selection** | An earlier draft fell back to "most permissive playbook", handing a *phishing* alert to the *ransomware* playbook because both cleared the severity floor. Running the wrong containment procedure is worse than running none. Uncovered techniques now return `None` and surface as gaps |
| 2026-10-02 | **Action timeouts cannot kill a thread** | Python has no thread kill. Documented rather than hidden; the one subprocess has its own hard timeout |
| 2026-10-02 | **`completed` is not terminal for retry** | A run that finished with a failed action (`on_failure: continue`) stays resumable so an operator can retry one step, not re-run containment |
| 2026-10-02 | **`/report` returns 501, not a stub** | A placeholder report could be mistaken for a real one |
| 2026-10-02 | **Absolute evidence paths abort the action** | An absolute or root-escaping path is a malformed playbook, not a missing file. Checked in both POSIX *and* Windows form — the engine runs in Linux where `os.path.isabs("C:/…")` is `False` |
| 2026-10-02 | **Eradication is reversible** | Removed items are recorded, so `remove_persistence` and `quarantine_file` have working inverses. `forward_only` remains supported but nothing shipped needs it |
| 2026-10-02 | **Compensation restores *recorded* prior state** | A naive inverse hard-coding `isolated = False` would un-isolate a host that was already isolated, silently breaking the invariant. Asserted by `test_already_isolated_host_survives_rollback` |
| 2026-10-02 | Containment simulated, forensics real | Hard safety boundary; the real/simulated line is fixed ([`SECURITY.md`](SECURITY.md) §1) |
| 2026-10-02 | Recorded Volatility fixtures as the default input | Tests and demos run offline and deterministically ([`ARCHITECTURE.md`](ARCHITECTURE.md) §7) |
| 2026-10-02 | Severity scoring deterministic, not ML | A responder must be able to audit the score ([`METRICS.md`](METRICS.md) §4) |
| 2026-10-02 | Phase model = rev2 lifecycle + r3 mapping | The brief specifies rev2 phases; r3 (2025) is the current revision, so both dialects are carried ([`ARCHITECTURE.md`](ARCHITECTURE.md) §4) |
| 2026-10-02 | Playbook count capped at 4; gaps documented | Unbounded coverage is scope creep; the gap list is a deliverable ([`AGENTS.md`](../AGENTS.md) §3) |
| 2026-10-02 | No Celery/Redis/SQLAlchemy/matplotlib | YAGNI; stdlib covers it ([`ARCHITECTURE.md`](ARCHITECTURE.md) §9.1) |

## Bugs found and fixed during Week 2

Recorded because each was a case where tests passed but real runs failed — the
reasoning is worth keeping.

| Bug | Symptom | Fix |
|---|---|---|
| `recovery.verify` IOC baseline | `AttributeError: 'str' object has no attribute 'get'` on **every** run | It read `i.get("key")` then unpacked the result. Unit tests supplied no IOCs so the branch was never hit. Added `tests/test_recovery.py` covering each branch |
| `vol` `netscan` remote addresses | C2/exfil IPs never extracted | Field list was missing `ForeignAddr`, Volatility's actual column name — the most important IOC class here |
| Mutex regex rejected real mutexes | `Global\SysUpdateMutex` not reported | Character class omitted `\`; every normal Windows mutex form was rejected |
| `pstree` nested children ignored | Malicious process chain invisible | Read only the top row instead of walking `__children` |
| Engine never substituted `{{ }}` params | `unknown host '{{ alert.asset.id }}'`, runs aborted | Substitution was implemented but never called by the engine |
| Rationale didn't sum to the score | Displayed 92, scored 91 | Rounded display terms; now 1 decimal place so terms reconcile |
| `firewall.unblock` compensation | Recreated rule with subject `restored` | `unblock()` didn't echo the removed rule's definition; now returns zone/subject/action |
| Resume duplicated action rows | Every action logged twice after approval | `execute()` returns cumulative results; the API now persists only the delta |