# SECURITY.md — Safety, Containment & Evidence Integrity

Mandatory. Read alongside [`AGENTS.md`](../AGENTS.md) §2 before running anything.

---

## 1. The core safety model

This project automates defensive incident response, which is a dual-use capability. The safety
boundary is drawn as a hard line between what is **real** and what is **simulated**:

| Capability | Boundary | Why |
|---|---|---|
| Alert triage & severity scoring | **Real** | Pure function over input data. No side effects. |
| Evidence collection | **Real** | Reads files the operator placed in `fixtures/`. Read-only. |
| Memory forensics (Volatility) | **Real** | Offline analysis of an operator-supplied image file. |
| IOC extraction | **Real** | Pure function over collected artifacts. |
| Host isolation | **Simulated** | Mutates the estate model, not a network. |
| Firewall rule changes | **Simulated** | Mutates the estate rule set, not a real firewall. |
| Account lockout / disable | **Simulated** | Mutates the estate account table, not a directory. |
| Eradication | **Simulated** | Mutates estate + a virtualised filesystem view. |
| Recovery verification | **Simulated** | Runs health checks against estate state. |

**The boundary is fixed.** Adding a "live" connector, a `--live` flag, or a
`LiveEDRConnector` violates [`AGENTS.md`](../AGENTS.md) §2.2 and will not be merged. This is not a
missing feature to be requested later — it is the design.

## 2. Prohibited operations

Never, in any code path, including tests, scripts, or "temporary" debugging:

- Spawning `powershell`, `pwsh`, `cmd`, `netsh`, `sc`, `reg`, `ssh`, `scp`, `rsync`, `nsenter`.
- Invoking directory APIs: `Disable-ADAccount`, `Set-ADAccountPassword`, `New-NetFirewallRule`,
  `Set-NetFirewallProfile`, `netsh advfirewall`.
- Invoking EDR/cloud APIs (CrowdStrike, Defender, `aws ec2 modify-instance-attribute`,
  `gcloud compute instances`).
- Capturing host memory (`DumpIt`, `LiME`, `winpmem`, `AVML`, `/proc/kcore`, `hiberfil`).
- Scanning or probing hosts on the local network or any real subnet.
- Writing evidence artifacts, memory images, or the custody log outside
  `data/incidents/<incident_id>/`.

A connector implementation that needs any of the above must instead extend the estate model.

## 3. The simulated estate

`soar/estate.py` is a small, explicit model of a network:

- **Hosts** — `id`, `hostname`, `ip`, `zone` (`corp` · `dmz` · `restricted`), `criticality` (1–5),
  `isolated: bool`.
- **Accounts** — `id`, `username`, `host_id`, `privileged: bool`, `locked: bool`.
- **Firewall rules** — `id`, `zone_from`, `zone_to`, `action` (`allow` · `block`), `subject`,
  `created_by_action_id`.
- **Mutations are journalled** — every state change records the `action_id` that caused it, so a
  compensation can be proven correct rather than assumed.

The estate is backed by SQLite for runtime persistence and by an in-memory implementation for
tests. **Isolation is a boolean, not a packet filter.** Nothing in this project touches a real
network stack.

### 3.1 The rollback invariant

This is the most important safety property in the codebase:

> For any playbook run that completes or aborts with compensation, the estate state must be
> **byte-identical** to its pre-run state, unless the playbook explicitly declares a forward-only
> action.

This is asserted in `tests/test_rollback.py` and is a Week 1 Definition of Done gate. A change that
breaks this invariant is a bug even if every test that touches containment "passes" — the assertion
must be on full estate state, not on a subset of fields.

## 4. Evidence integrity & chain of custody

Evidence handling follows the standard forensic principle: **the original is never touched.**

1. Collection **copies** bytes from the source into
   `data/incidents/<incident_id>/evidence/`. The source is opened read-only.
2. The SHA-256 of every copied artifact is computed at collection time.
3. An entry is appended to `chain_of_custody.jsonl`:

   ```json
   {"ts": "2026-10-02T14:31:07Z", "artifact": "memory.raw",
    "sha256": "…", "size": 1048576, "source": "fixtures/memory/sample.raw",
    "collected_by": "evidence.collect", "run_id": "…", "incident_id": "…"}
   ```

4. The log is **append-only**. Never rewrite, reorder, or delete an entry. A correction is a new
   entry with a `supersedes` field.
5. Every artifact is re-hashed on report generation. A mismatch marks the report
   **integrity: FAILED** and must be surfaced to the user — never silently ignored.

Verified by `tests/test_custody.py`.

## 5. Secrets

- No credentials, API keys, or tokens in the repository, fixtures, or playbooks.
- No connector authenticates to anything (see §1 — there is nothing to authenticate to).
- Playbook parameter templating uses `{{ field }}` substitution from the incident context only.
  **Never** implement a template path that evaluates expressions or shell metacharacters. See
  [`COMPONENTS.md`](COMPONENTS.md) → `playbook_loader` for the permitted grammar.

## 6. Containment blast radius

- Containment actions are reversible by construction. If in doubt whether an action is
  reversible, it is containment and it needs a `compensate`.
- Destructive-sounding names (`lock_account`, `isolate_host`, `delete_persistence`) describe
  **estate state transitions**, not host actions. Do not let the naming imply otherwise in docs or
  UI copy.
- The API defaults to `auto_approve=false`. Approval-gated actions block until an analyst approves
  via `POST /incidents/{id}/actions/{action_id}/approve`. Do not flip this default.

## 7. Reporting a concern

If any code path appears capable of touching real infrastructure, stop and raise it with the user
per [`AGENTS.md`](../AGENTS.md) §8. Do not "fix it later" and do not add a feature flag that would
make it easier to enable.