# COMPONENTS.md — Module Contracts

**Binding.** Per [`AGENTS.md`](../AGENTS.md) §3: do not invent modules, features, or endpoints that
are not listed here. If a contract must change, change it **in the same commit as the code**.

Conventions used below: **pure** = no I/O, no clock, no randomness. **Journaled** = writes to the
engine action journal. Every connector must accept `params: dict` and `ctx: ActionContext`.

---

## `soar/models.py`

Domain dataclasses. Pure.

| Type | Fields (contract) |
|---|---|
| `Incident` | `id`, `alert: dict`, `severity: str`, `score: int`, `rationale: list[str]`, `phase: Phase`, `status: str`, `playbook_id: str \| None`, `created_at`, `updated_at` |
| `Playbook` | `id`, `name`, `description`, `phases: list[Phase]`, `mitre_techniques: list[str]`, `min_severity: str`, `actions: list[Action]` |
| `Action` | `id`, `name`, `phase: Phase`, `connector: str`, `params: dict`, `timeout_seconds: int`, `requires_approval: bool`, `on_failure: str`, `compensates: str \| None`, `forward_only: bool` |
| `ActionResult` | `action_id`, `connector`, `status`, `result: dict`, `error: str \| None`, `started_at`, `ended_at`, `duration_ms: int` |
| `Evidence` | `id`, `incident_id`, `artifact`, `sha256`, `size`, `source`, `collected_at` |
| `Run` | `id`, `incident_id`, `playbook_id`, `status`, `phase_timings: dict`, `started_at`, `ended_at` |

Constraints: `severity` ∈ `low\|medium\|high\|critical`. `on_failure` ∈
`abort\|continue\|compensate`. `status` ∈ `pending\|running\|awaiting_approval\|completed\|failed\|skipped\|aborted`.

## `soar/nist.py`

The SP 800-61 rev2 phase model and its r3 mapping.

- `class Phase(StrEnum)` — `PREPARATION`, `DETECTION`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`.
- `PHASE_ORDER: tuple[Phase, ...]` — canonical ordering.
- `VALID_TRANSITIONS: dict[Phase, set[Phase]]` — per [`ARCHITECTURE.md`](ARCHITECTURE.md) §4.
  Includes `containment → recovery` (false-positive close) and any phase → `aborted`.
- `R3_MAPPING: dict[Phase, dict]` — CSF 2.0 function + subcategories per phase.
- `can_transition(from_: Phase, to: Phase) -> bool`

Constraint: pure. Rejecting an illegal transition is this module's only job.

## `soar/severity.py`

Deterministic alert triage.

- `WEIGHTS: dict[str, float]` — the single config location. Sum normalised in `__init__`.
- `score_alert(alert: dict, context: dict) -> tuple[int, list[str]]`
- `band(score: int) -> str` — `critical ≥ 85`, `high ≥ 70`, `medium ≥ 40`, else `low`.
- `auto_run_allowed(severity: str) -> bool` — drives [`ARCHITECTURE.md`](ARCHITECTURE.md) §5.

**Contract:** deterministic. Same input → same output, always. `rationale` explains every non-zero
term in plain English. No ML, no clock, no randomness ([`AGENTS.md`](../AGENTS.md) §4).

## `soar/playbook_loader.py`

YAML playbook loading, validation, and parameter substitution.

- `load(path: Path) -> Playbook` — parse + validate or raise `PlaybookValidationError`.
- `load_all(dir: Path) -> list[Playbook]`
- `validate(playbook: dict) -> list[str]` — returns the list of problems; empty means valid.
- `select(playbooks: list[Playbook], alert: dict, severity: str) -> Playbook` — best match by MITRE
  technique prefix, then severity band. Falls back to the most permissive playbook.

### `{{ field }}` substitution grammar — permitted and forbidden

Permitted: literal text, `{{ dotted.path }}` resolving against the incident context
(`alert.source.ip`, `incident.id`, `score`, `severity`), and `{{ dotted.path | default }}`.

**Forbidden:** arithmetic, function calls, attribute access beyond the context, any expression that
is not a literal-plus-substitution. A missing path resolves to the empty string or its `default` —
**never an exception mid-run**. See [`SECURITY.md`](SECURITY.md) §5.

Required playbook keys: `id`, `name`, `description`, `phases`, `mitre_techniques`, `actions`. Each
action requires `id`, `phase`, `connector`. `connector` must be a registered name from
[`ARCHITECTURE.md`](ARCHITECTURE.md) §3.1 or validation fails — this is what stops a playbook from
invoking something that does not exist.

## `soar/estate.py`

The **simulated** lab estate. The safety-critical module.

- `class Estate` (abstract) — `snapshot() -> dict`, `restore(snap: dict)`
- `InMemoryEstate(Estate)` — used by tests; snapshot/restore by deep copy.
- `SqliteEstate(Estate)` — runtime persistence.
- Entities: `Host(id, hostname, ip, zone, criticality, isolated)`,
  `Account(id, username, host_id, privileged, locked)`,
  `FirewallRule(id, zone_from, zone_to, action, subject, created_by_action_id)`
- `isolate_host(host_id, action_id)` → `{"host_id", "was_isolated"}`
- `release_host(host_id, action_id)`
- `lock_account(account_id, action_id)` → `{"account_id", "was_locked"}`
- `unlock_account(account_id, action_id)`
- `block_rule(...)` → `{"rule_id"}` · `unblock_rule(rule_id)`
- `journal() -> list[dict]` — ordered mutation record.

### The rollback invariant — enforced contract

> Estate state after any compensated run **must equal** its pre-run state.

Enforced by `snapshot()` deep equality in `tests/test_rollback.py`. This is the core safety
property of the entire project ([`SECURITY.md`](SECURITY.md) §3.1). Forward actions must set
`forward_only: true` explicitly and be excluded with a documented reason.

## `soar/engine.py`

Playbook execution. **All** action execution goes through here
([`AGENTS.md`](../AGENTS.md) §2.7).

- `class Engine` - `class Engine` - `execute(incident, playbook, run, auto_approve=False, prior_results=None, shared=None, approved=None) -> tuple[Run, list[ActionResult]]`
- `registry` - connector registry, keyed by name. `verify=True` asserts it matches
  `REGISTERED_CONNECTORS` in both directions; the test suite passes `verify=False` to inject doubles.
- Internally guarantees, for every action: **journal entry → timeout enforcement → status
  transition → result capture → failure-policy handling → compensation in reverse order on abort.**

Constraints: never bypasses a connector. Never executes a shell command except through a registered
connector (in practice only `forensics.volatility`). `auto_approve` defaults to `False`.
Compensation runs **in reverse action order**, and only for actions that reported `succeeded`.

Additional contract details:

- **Template substitution happens in the engine, before dispatch.** Connectors receive resolved
  params, never literal `{{ }}` text.
- **Return value is CUMULATIVE** (prior results + new). Callers persisting action rows must write
  only the delta after `len(prior_results)`, or every action is logged twice on resume.
- **Resume semantics:** only prior results with status `succeeded` or `awaiting_approval` count as
  done. A `failed` action is **retried**, so `completed` is not a terminal status — `aborted` and
  `failed` are. This lets an operator retry one failed step without re-running containment.
- **Timeouts** are enforced by running the connector on a worker thread and giving up on it. Python
  cannot kill a thread, so a connector that has already started keeps running and its result is
  discarded. The one subprocess enforces its own hard timeout on the child process.

## `soar/connectors/`

| Module | Connectors | Must provide |
|---|---|---|
| `base.py` | `Connector` protocol, `ActionContext`, `ConnectorError` | — |
| `triage.py` | `triage.score` | pure |
| `evidence.py` | `evidence.collect` | read-only copy, SHA-256, custody append |
| `forensics.py` | `forensics.volatility`, `ioc.extract` | timeout; graceful `skipped` |
| `containment.py` | `estate.isolate_host`, `firewall.block`, `identity.lock_account` | `compensate()` + inverse connector |
| `eradication.py` | `eradication.*` | `compensate()` or explicit `forward_only` |
| `recovery.py` | `recovery.verify` | read-only |

Every connector implements `compensate()` unless it is read-only. A containment connector without a
working `compensate()` is incomplete ([`AGENTS.md`](../AGENTS.md) §2.6).

## `soar/evidence.py`

Evidence collection and chain of custody.

- `collect(incident_id: str, artifacts: list[str], dest: Path) -> list[Evidence]` — **read-only**
  copy from source. Never writes to the source.
- `record_custody(incident_id: str, entry: dict) -> None` — **append-only** JSONL. Never rewrites or
  reorders. Corrections are new entries with `supersedes`.
- `verify(incident_id: str) -> dict` - re-hashes every artifact; returns
  `{"ok", "integrity": "PASSED"|"FAILED", "artifacts", "mismatches"}`. A missing artifact and a
  hash mismatch both count as mismatches.
- `manifest(incident_id: str) -> list[dict]`

**Path handling.** An artifact path that is absolute -- POSIX **or** Windows drive/UNC form --
aborts the action with a `ConnectorError`. It is a malformed playbook, not a missing file, and
silently recording it as a failure would let a hostile path pass unnoticed. The Windows check is not
redundant: the engine runs in a Linux container where `os.path.isabs("C:/Windows/System32")` is
`False`. A merely *missing* artifact is recorded as a per-artifact failure and does not abort.

Constraint: custody entries are immutable ([`SECURITY.md`](SECURITY.md) §4). An integrity mismatch
must surface as `integrity: FAILED` in the report — never be swallowed.

## `soar/forensics/memory.py`

The **only** module permitted to spawn a subprocess.

- `available() -> bool` — Volatility importable **and** an image present.
- `analyze(image: Path, plugins: list[str], timeout: int) -> dict[str, list[dict]]` — runs
  `vol -f <image> <plugin> --renderer=json`, returns per-plugin rows.
- `plugins_for(os_profile: str) -> list[str]`

Constraints: **never** captures host memory. Reads only files the operator supplied. Per-plugin
timeout. If `available()` is `False` returns `{"skipped": reason}` — the caller reports the skip.

## `soar/forensics/ioc.py`

IOC extraction — pure, no I/O, so it is exhaustively unit-testable.

- `extract(vol_output: dict, artifacts: list[Evidence] | None) -> list[dict]`
- `INDICATORS` — `ipv4`, `ipv6`, `domain`, `url`, `file_hash`, `mutex`, `process`,
  `persistence`, `registry_key`, `injected_process`

**Contract:** every IOC carries `type`, `value`, `source` (which plugin or artifact it came from),
and `confidence`. No unsourced IOCs. Dedup by `(type, value)` keeping the highest confidence.

## `soar/store.py`

Persistence. Stdlib `sqlite3` only, WAL mode, schema created idempotently at startup.

Tables: `incidents`, `runs`, `actions`, `evidence`, `journal` (see
[`ARCHITECTURE.md`](ARCHITECTURE.md) §6). `journal` is what makes the rollback invariant provable
after the fact. **No ORM** ([`AGENTS.md`](../AGENTS.md) §3).

## `soar/reporting/`

- `generator.py` — `render_html`, `render_markdown`, `render_exec_summary`,
  `render_timeline`; each writes to `reports/` and returns the path.
- `templates/report.html.j2`, `report.md.j2`, `exec_summary.md.j2`

**Contract:** every template labels measured vs estimated figures
([`AGENTS.md`](../AGENTS.md) §4). Timeline renders with Chart.js — **no matplotlib**.

## `soar/api/`

`main.py` (FastAPI app) and `schemas.py` (Pydantic). Endpoints per
[`ARCHITECTURE.md`](ARCHITECTURE.md) §8. `POST /alerts` is the only endpoint that both triages and
selects a playbook. `auto_approve` defaults to `False` on
`POST /incidents/{id}/run`. `GET /playbooks` **must** return an explicit gap list, not just
coverage.

## `scripts/`

| Script | Contract |
|---|---|
| `benchmark.py` | Replays the **entire** `fixtures/alerts/` set. Writes `data/metrics/benchmark.json`. Exclusions require a documented reason ([`AGENTS.md`](../AGENTS.md) §4). |
| `fetch_memory_image.sh` | **Operator-initiated only.** Never automatic. Writes to git-ignored `fixtures/memory/`. Never captures a local host. |
| `seed_incident.py` | Creates a demo incident from a fixture alert. |

## `tests/`

Mandatory coverage ([`AGENTS.md`](../AGENTS.md) §5.5). **No test may require network access.**

| File | Asserts |
|---|---|
| `test_severity.py` | Determinism, band boundaries, rationale completeness |
| `test_engine.py` | Sequencing, timeout, approval gate, all three failure policies |
| `test_rollback.py` | **The rollback invariant**, for every connector |
| `test_playbooks.py` | All 4 YAML files pass schema validation |
| `test_estate.py` | Transition legality, journal integrity |
| `test_ioc.py` | Extraction + dedup + confidence against `fixtures/volatility/` |
| `test_custody.py` | Manifest integrity; tampering is detected; path traversal and absolute paths rejected |
| `test_forensics.py` | Graceful degradation when Volatility is absent; no capture path exists |
| `test_recovery.py` | Every `recovery.verify` check, including IOC-baseline shapes |
| `test_api.py` | Endpoint contracts, `auto_approve` defaults to `False` |