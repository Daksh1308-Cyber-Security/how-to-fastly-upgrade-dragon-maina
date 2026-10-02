# METRICS.md — Definitions, Methodology & Anti-Gaming Rules

Targets and methodology are **fixed here**. Changing this file to make numbers look better is a
violation of [`AGENTS.md`](../AGENTS.md) §4, not an improvement.

---

## 1. The starting point: target ≠ result

The original project brief states:

| Metric | Manual IR | Automated IR |
|---|---|---|
| Mean Time to Respond | 4 hours | 15 minutes |
| Mean Time to Contain | 8 hours | 30 minutes |
| Evidence Collection | Manual (2 hours) | Automated (5 minutes) |
| Report Generation | 4 hours | 5 minutes |

**These are aspirational targets taken from the brief. They are not measurements of this system.**
Nothing in this repository has run a real incident response engagement, so it cannot produce a
credible MTTR or MTTC. Quoting these as results would be fabrication.

Every figure this project publishes is therefore labelled exactly one of:

| Label | Meaning |
|---|---|
| **MEASURED** | Produced by a committed `scripts/benchmark.py` run against `fixtures/alerts/`. Reproducible. |
| **TARGET** | A goal from the brief or this file. Never presented as achieved. |
| **ESTIMATE** | A reasoned projection from a documented manual procedure. Assumptions listed. |

No label means "implied by omission" — an unlabelled number is a bug.

---

## 2. What is actually measurable here

Automation **execution time** on a known input is real and reproducible. Analyst **response time**
is not observable without a real SOC. So the metrics split:

### 2.1 MEASURED — automated execution time

| Metric | Definition |
|---|---|
| **Triage latency** | Alert `POST /alerts` → severity + playbook selected. Target < 2 s. |
| **Time to containment** | Run start → first containment action reports `succeeded`. |
| **Evidence collection time** | `evidence.collect` start → all artifacts hashed and custody entries written. |
| **Memory forensics time** | `forensics.volatility` start → last plugin returns. Gated per plugin. |
| **Report generation time** | Report request → file written. |
| **End-to-end run time** | Run start → run reaches a terminal status. |
| **Rollback correctness** | Runs with compensation where post-run estate state == pre-run state. **Must be 100%.** |
| **Forensic yield** | IOCs extracted per incident, by type. |

### 2.2 ESTIMATE — manual comparison

The manual column is an **estimate**, derived from a documented procedure, not a stopwatch on real
analysts. The estimating procedure and its assumptions must be written into
`data/metrics/benchmark.json` under `baseline_estimate` and reproduced in the README.

Assumptions that must be stated explicitly (see §5 for the seed values):

- Analyst count and role per phase.
- Whether the analyst is already at their desk (shortest case) or paged in (longest case).
- Per-task step counts, e.g. "manually isolate a host = open console, find host, apply rule,
  verify = 4 steps × 90 s".
- Tooling and handoff overhead between analysts.

If an assumption changes, the estimate changes and **the diff must be explained** in the README.
Do not silently revise an estimate to narrow the gap.

---

## 3. Methodology (fixed)

1. **Input set is fixed.** `scripts/benchmark.py` replays **all** files in `fixtures/alerts/`.
   Excluding an incident requires a documented reason in the output file.
2. **Cold start and warm runs are distinguished.** The first run of the process is reported
   separately from subsequent runs. Do not quietly drop the cold run — it is usually the worst
   number and the most honest one.
3. **Volatility symbol download is excluded from forensics timing**, and this must be stated in
   the output. A first-run symbol fetch can take minutes and is not representative of steady-state
   triage. Report it once, labelled, never hidden.
4. **Timings are wall-clock**, measured around the operation, including subprocess overhead. No
   stage is excluded to improve a number.
5. **Sample counts are published.** n = 1 is not a mean. Report `n`, median, min, max, and p95.
   Median is the headline; the mean is reported alongside it.
6. **Environment is recorded** in `benchmark.json`: Python version, container image, CPU count,
   `volatility3` version, whether a real image or fixtures were used.
7. **Every published metric is traceable** to a committed `data/metrics/benchmark.json`. A number
   with no committed run behind it does not get quoted.

---

## 4. Anti-gaming rules

These are hard constraints. Violating any one invalidates the metric.

1. **Never lower a target or alter methodology to improve a result.** Targets may only be revised
   with a documented reason and the user's approval, in the same change as the revision.
2. **Never relabel measured as estimated or vice versa** to make a comparison look better.
3. **Never cherry-pick incidents.** No "best case", no dropping outliers, no excluding a severity
   band that performs badly. If an outlier is excluded, the exclusion is in the output file with a
   reason.
4. **Never simulate to inflate speed.** `auto_approve=true` and fixture-only forensics make runs
   faster; a benchmark using them must say so, and the containment number must also be reported
   with `auto_approve=false`.
5. **Never count a skipped step as a fast step.** A run where `forensics.volatility` returned
   `skipped` must not contribute a suspiciously low forensics time. Report it as `skipped`, not as
   0 s.
6. **Report failures.** If 2 of 12 runs fail, the failure count is part of the result. Success rate
   is a metric, not a footnote.
7. **Honest reporting beats good numbers.** A correctly-reported modest improvement is a stronger
   portfolio artefact than an unsupported 16× claim. A reviewer who catches one fabricated figure
   discounts the entire project.

---

## 5. Seed assumptions for the manual ESTIMATE

Fixed seeds for the Week 3 estimate. Changing one requires updating this section and explaining the
change in the README.

| Parameter | Value | Rationale |
|---|---|---|
| Analyst cost | £45/hour | Blended mid-level SOC analyst |
| Containment elapsed (paged in) | 8 h | Matches the brief's manual MTTC |
| Respond elapsed (paged in) | 4 h | Matches the brief's manual MTTR |
| Evidence collection (manual) | 2 h | Matches the brief |
| Report generation (manual) | 4 h | Matches the brief |
| Analyst throughput | 1 step / 90 s | Conservative single-analyst rate |
| Automation overhead | 0 | Fixed; automation has no per-step analyst cost |

**These manual figures are inherited from the brief and are not independently validated.** They
describe the manual process the project claims to improve on. They must always be labelled
ESTIMATE (inherited), never presented as this project's own measurement.

---

## 6. Metric reporting format

Every published table uses this shape. Deviating from it is a doc-sync violation
([`AGENTS.md`](../AGENTS.md) §5.3).

```markdown
| Metric | Manual (ESTIMATE, §5) | Automated (MEASURED) | n | Median | p95 | Source |
|---|---|---|---|---|---|---|
| Time to contain | 8 h | 41 s | 12 | 39 s | 55 s | benchmark.json#containment |
```

And the disclosure line that must accompany it:

> Automated figures are **measured** by `scripts/benchmark.py` (run `<commit>`, n = 12, fixtures
> only, `auto_approve=false`). Manual figures are **estimates inherited from the project brief**
> (`docs/METRICS.md` §5), not independently measured. The comparison is indicative, not a controlled
> trial.

---

## 7. Rollback correctness is not optional

`Rollback correctness` is the one metric with a **100% hard target** and no tolerance. A run whose
compensations leave the estate in a different state is a **correctness bug**, not a metric miss —
it fails the Week 1 and Week 2 gates ([`PLAN.md`](PLAN.md)) and blocks progress regardless of any
speed figure. Speed never excuses it.