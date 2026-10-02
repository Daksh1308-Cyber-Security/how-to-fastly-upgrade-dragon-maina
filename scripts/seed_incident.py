#!/usr/bin/env python3
"""Seed a demo incident from a fixture alert and (optionally) run its playbook.

Run inside the container:

    docker compose run --rm api python scripts/seed_incident.py \\
        --alert fixtures/alerts/ransomware_finance_host.json

Prints the incident id, score, severity, rationale and selected playbook so the
walkthrough in README.md can be reproduced exactly.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soar.connectors import build_default_registry, verify_registry  # noqa: E402
from soar.engine import Engine  # noqa: E402
from soar.estate import SqliteEstate, seed_demo_estate  # noqa: E402
from soar.models import Incident, Run  # noqa: E402
from soar.nist import Phase  # noqa: E402
from soar.playbook_loader import load_all, select  # noqa: E402
from soar.severity import band, score_alert  # noqa: E402
from soar.store import Store  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed a demo incident.")
    parser.add_argument("--alert", required=True, help="Path to a fixture alert JSON file")
    parser.add_argument("--data-dir", default=str(ROOT / "data"))
    parser.add_argument("--run", action="store_true", help="Execute the playbook after seeding")
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Skip approval gates. Use only for demos; disclosed in every report.",
    )
    parser.add_argument("--playbooks-dir", default=str(ROOT / "playbooks"))
    parser.add_argument("--evidence-roots", default=str(ROOT / "fixtures"))
    args = parser.parse_args()

    alert_path = Path(args.alert)
    if not alert_path.is_file():
        print(f"error: alert file not found: {alert_path}", file=sys.stderr)
        return 1

    alert = json.loads(alert_path.read_text(encoding="utf-8"))
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    # -- triage ---------------------------------------------------------------
    score, rationale = score_alert(alert)
    severity = band(score)
    playbooks = load_all(args.playbooks_dir)
    playbook = select(playbooks, alert, severity)

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    incident = Incident(
        id=f"INC-{uuid.uuid4().hex[:12].upper()}",
        alert=alert,
        severity=severity,
        score=score,
        rationale=rationale,
        phase=Phase.DETECTION,
        status="triaged",
        playbook_id=playbook.id if playbook else None,
        created_at=now,
        updated_at=now,
    )

    # -- persist --------------------------------------------------------------
    store = Store(data_dir / "ir.db")
    store.save_incident(incident)
    estate = seed_demo_estate(SqliteEstate(store.conn))

    print("=" * 68)
    print("TRIAGE")
    print("=" * 68)
    print(f"Incident    : {incident.id}")
    print(f"Alert       : {alert.get('alert_id')} -- {alert.get('name')}")
    print(f"Score       : {score}/100  ->  {severity.upper()}")
    print(f"Technique   : {alert.get('mitre', {}).get('technique_id')} "
          f"({alert.get('mitre', {}).get('technique_name')})")
    print(f"Playbook    : {playbook.id if playbook else 'NONE -- technique not covered (gap)'}")
    print()
    print("Rationale:")
    for line in rationale:
        print(f"  - {line}")

    if not playbook:
        print()
        print("No playbook covers this technique. Recorded as a coverage gap.")
        print("See GET /playbooks for the current gap list.")
        store.close()
        return 0

    if not args.run:
        print()
        print(f"Re-run with --run to execute {playbook.id}.")
        store.close()
        return 0

    # -- execute --------------------------------------------------------------
    registry = build_default_registry()
    verify_registry(registry)
    engine = Engine(
        registry=registry,
        estate=estate,
        data_dir=data_dir,
        evidence_roots=[Path(p) for p in args.evidence_roots.split(",") if p],
    )
    run = Run(
        id=f"RUN-{uuid.uuid4().hex[:12].upper()}",
        incident_id=incident.id,
        playbook_id=playbook.id,
    )
    store.save_run(run)

    before = estate.snapshot()
    run_obj, results = engine.execute(
        incident, playbook, run, auto_approve=args.auto_approve
    )
    store.save_run(run_obj)
    store.save_action_results(run.id, results)
    engine.shutdown()

    print()
    print("=" * 68)
    print("RUN")
    print("=" * 68)
    print(f"Run         : {run.id}")
    print(f"Status      : {run_obj.status}")
    print(f"Incomplete  : {run_obj.incomplete}")
    print()
    for result in results:
        flag = " " if not result.compensation_of else "~"
        detail = f" ({result.duration_ms} ms)" if result.duration_ms else ""
        err = f"  ERROR: {result.error}" if result.error else ""
        print(f" {flag} [{result.status:>18}] {result.action_id}{detail}{err}")

    print()
    print("Estate after run:")
    for host in estate.list_hosts():
        print(f"  {host.hostname:<16} isolated={host.isolated}")
    for account in estate.list_accounts():
        print(f"  {account.username:<16} locked={account.locked}")
    for rule in estate.list_rules():
        print(f"  rule {rule.id}  {rule.zone_from}->{rule.zone_to} {rule.action} {rule.subject}")

    print()
    print("Rollback check:")
    changed = before != estate.snapshot()
    print(f"  Estate changed by this run: {changed}")
    if run_obj.status == "aborted":
        print("  Run aborted, so compensations ran. Compare with the snapshot above.")
    print(f"  Journal entries: {len(estate.journal())}")

    print()
    print(f"Timeline : GET /incidents/{incident.id}/timeline")
    print(f"Report   : GET /incidents/{incident.id}/report  (Week 3 -- returns 501 for now)")

    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())