"""Shared pytest fixtures.

Tests must pass with **no network access** (AGENTS.md section 5.5). Every test
uses the in-memory estate and the recorded Volatility fixtures, so nothing here
reaches the internet or the host filesystem beyond ``fixtures/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soar.connectors import build_default_registry, verify_registry
from soar.engine import Engine
from soar.estate import Account, Host, InMemoryEstate
from soar.models import Incident, Run
from soar.nist import Phase
from soar.playbook_loader import load_all

PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Container mount point. When tests run inside the image the project lives at
#: /app; running pytest against a bind-mounted checkout, ``Path.cwd()`` is the
#: checkout root. Resolving the fixed path first and falling back keeps both
#: working without the caller having to know which context it is in.
_CANDIDATE_ROOTS = (Path("/app"), Path.cwd().resolve(), PROJECT_ROOT)

FIXTURES: Path | None = None
for _root in _CANDIDATE_ROOTS:
    if (_root / "fixtures" / "evidence" / "host-inventory.json").is_file():
        FIXTURES = (_root / "fixtures").resolve()
        break
if FIXTURES is None:  # pragma: no cover - a broken checkout should be loud
    raise RuntimeError(
        "Could not locate fixtures/evidence/host-inventory.json under "
        f"{[str(r) for r in _CANDIDATE_ROOTS]}"
    )

#: The evidence root the engine is permitted to read from. Playbooks reference
#: artifacts as ``evidence/<file>``, so the root is ``fixtures/`` -- NOT
#: ``fixtures/evidence/``.
EVIDENCE = FIXTURES

ALERTS = FIXTURES / "alerts"
EVIDENCE_DIR = FIXTURES / "evidence"
VOLATILITY = FIXTURES / "volatility"

PLAYBOOKS: Path | None = None
for _root in _CANDIDATE_ROOTS:
    if (_root / "playbooks" / "ransomware.yaml").is_file():
        PLAYBOOKS = (_root / "playbooks").resolve()
        break
if PLAYBOOKS is None:  # pragma: no cover
    raise RuntimeError("Could not locate playbooks/ransomware.yaml")


@pytest.fixture(scope="session")
def registry():
    reg = build_default_registry()
    verify_registry(reg)
    return reg


@pytest.fixture
def estate() -> InMemoryEstate:
    """A fresh in-memory estate with the same shape the demo seed produces."""
    return InMemoryEstate(
        hosts=[
            Host("HOST-014", "WS-FIN-014", "10.20.4.31", "corp", 5),
            Host("HOST-022", "WS-ENG-022", "10.20.4.52", "corp", 4),
            Host("HOST-031", "DC-EU-031", "10.20.1.10", "restricted", 5),
            Host("HOST-007", "SRV-FILE-007", "10.20.2.7", "dmz", 4),
            Host("HOST-002", "WKS-ENG-002", "10.20.4.2", "corp", 2),
        ],
        accounts=[
            Account("ACC-JOK", "j.okafor", "HOST-014"),
            Account("ACC-DMS", "d.mensah", "HOST-022"),
            Account("ACC-SVC", "svc-backup", "HOST-031", privileged=True),
            Account("ACC-ADM", "a.renard", "HOST-031", privileged=True),
        ],
    )


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def engine(registry, estate, data_dir) -> Engine:
    eng = Engine(
        registry=registry,
        estate=estate,
        data_dir=data_dir,
        evidence_roots=[EVIDENCE],
    )
    yield eng
    eng.shutdown()


@pytest.fixture(scope="session")
def playbooks():
    return {p.id: p for p in load_all(PLAYBOOKS)}


def load_alert(name: str) -> dict:
    return json.loads((ALERTS / name).read_text(encoding="utf-8"))


@pytest.fixture
def ransomware_alert() -> dict:
    return load_alert("ransomware_finance_host.json")


@pytest.fixture
def port_scan_alert() -> dict:
    return load_alert("port_scan_reconnaissance.json")


@pytest.fixture
def credential_alert() -> dict:
    return load_alert("credential_theft_lsass_dump.json")


@pytest.fixture
def monkey_alert(credential_alert) -> dict:
    """Same alert, but performed by a privileged account."""
    alert = json.loads(json.dumps(credential_alert))
    alert["user"] = {"name": "a.renard", "account_id": "ACC-ADM", "privileged": True}
    return alert


@pytest.fixture
def standard_alert(credential_alert) -> dict:
    """Same alert, performed by a standard account."""
    alert = json.loads(json.dumps(credential_alert))
    alert["user"] = {"name": "d.mensah", "account_id": "ACC-DMS", "privileged": False}
    return alert


@pytest.fixture
def incident(ransomware_alert) -> Incident:
    return Incident(
        id="INC-TEST-0001",
        alert=ransomware_alert,
        severity="critical",
        score=91,
        rationale=["test fixture"],
        phase=Phase.DETECTION,
        status="triaged",
        playbook_id="ransomware",
    )


@pytest.fixture
def run() -> Run:
    return Run(id="RUN-TEST-0001", incident_id="INC-TEST-0001", playbook_id="ransomware")