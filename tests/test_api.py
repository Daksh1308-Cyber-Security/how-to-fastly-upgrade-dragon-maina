"""API surface contracts.

Uses FastAPI's TestClient, which runs in-process -- **no network access**
required (AGENTS.md section 5.5).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from soar.api import main as api_main


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Boot the app against a throwaway data directory.

    ``main.py`` reads its module-level config globals at call time, so patching
    them here redirects state without touching the developer's real ``data/``.
    """
    from tests.conftest import EVIDENCE, PLAYBOOKS

    tmp = tmp_path_factory.mktemp("api")
    api_main.DATA_DIR = tmp / "data"
    api_main.REPORTS_DIR = tmp / "reports"
    api_main.PLAYBOOKS_DIR = PLAYBOOKS
    api_main.EVIDENCE_ROOTS = [EVIDENCE]

    with TestClient(api_main.app) as c:
        yield c


def _post_alert(client, name="ransomware_finance_host.json"):
    from tests.conftest import load_alert

    return client.post("/alerts", json={"alert": load_alert(name)})


# --- health -----------------------------------------------------------------


def test_healthz(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["execution_mode"] == "simulated"
    assert body["playbooks_loaded"] == 4
    assert body["forensic_source"] in {"recorded-fixtures", "live-memory-image", "none"}


# --- triage -----------------------------------------------------------------


def test_alerts_returns_201(client):
    assert _post_alert(client).status_code == 201


def test_alert_is_scored_with_rationale(client):
    body = _post_alert(client).json()
    assert body["score"] > 0
    assert body["rationale"]
    assert body["severity"] in {"low", "medium", "high", "critical"}


def test_alert_selects_its_playbook(client):
    assert _post_alert(client).json()["playbook_id"] == "ransomware"


def test_uncovered_technique_yields_no_playbook(client):
    """A coverage gap must be visible, not papered over with a wrong playbook."""
    body = _post_alert(client, "port_scan_reconnaissance.json").json()
    assert body["playbook_id"] is None


def test_alert_requires_a_payload(client):
    assert client.post("/alerts", json={}).status_code == 422


# --- incidents --------------------------------------------------------------


def test_incidents_listed(client):
    _post_alert(client)
    body = client.get("/incidents").json()
    assert body["total"] >= 1
    assert body["incidents"]


def test_incident_filtered_by_severity(client):
    _post_alert(client)
    body = client.get("/incidents", params={"severity": "critical"}).json()
    assert all(i["severity"] == "critical" for i in body["incidents"])


def test_unknown_incident_is_404(client):
    assert client.get("/incidents/INC-NOPE").status_code == 404


# --- runs -------------------------------------------------------------------


def test_run_is_accepted_and_returns_202(client):
    incident = _post_alert(client).json()
    response = client.post(f"/incidents/{incident['id']}/run", json={})
    assert response.status_code == 202
    assert response.json()["status"] in {"pending", "running", "awaiting_approval"}


def test_run_without_playbook_is_409(client):
    incident = _post_alert(client, "port_scan_reconnaissance.json").json()
    assert client.post(f"/incidents/{incident['id']}/run", json={}).status_code == 409


def test_unknown_playbook_override_is_404(client):
    incident = _post_alert(client).json()
    response = client.post(
        f"/incidents/{incident['id']}/run", json={"playbook_id": "does-not-exist"}
    )
    assert response.status_code == 404


def test_auto_approve_defaults_to_false(client):
    """docs/SECURITY.md section 6 -- the default must not be flipped."""
    from soar.api.schemas import RunRequest

    assert RunRequest().auto_approve is False


def test_critical_run_completes_without_approval(client):
    incident = _post_alert(client).json()
    run = client.post(f"/incidents/{incident['id']}/run", json={}).json()

    import time

    for _ in range(100):
        body = client.get(f"/runs/{run['id']}").json()
        if body["status"] in {"completed", "failed", "aborted"}:
            break
        time.sleep(0.05)

    assert body["status"] == "completed", body
    assert body["results"]


def test_medium_incident_waits_for_approval(client):
    incident = _post_alert(client, "brute_force_rdp.json").json()
    run = client.post(f"/incidents/{incident['id']}/run", json={}).json()

    import time

    for _ in range(100):
        body = client.get(f"/runs/{run['id']}").json()
        if body["status"] == "awaiting_approval":
            break
        time.sleep(0.05)

    assert body["status"] == "awaiting_approval"
    assert body["awaiting_action"]

    action_id = body["awaiting_action"]
    approved = client.post(f"/incidents/{incident['id']}/actions/{action_id}/approve")
    assert approved.status_code == 200

    for _ in range(100):
        body = client.get(f"/runs/{run['id']}").json()
        if body["status"] in {"completed", "failed", "aborted", "awaiting_approval"}:
            break
        time.sleep(0.05)
    assert body["status"] in {"completed", "awaiting_approval"}


def test_approving_unknown_action_is_404(client):
    incident = _post_alert(client, "brute_force_rdp.json").json()
    run = client.post(f"/incidents/{incident['id']}/run", json={}).json()

    import time

    for _ in range(100):
        if client.get(f"/runs/{run['id']}").json()["status"] == "awaiting_approval":
            break
        time.sleep(0.05)

    response = client.post(f"/incidents/{incident['id']}/actions/no-such-action/approve")
    assert response.status_code == 404


def test_approve_without_a_run_is_404(client):
    incident = _post_alert(client).json()
    assert client.post(f"/incidents/{incident['id']}/actions/isolate_affected_host/approve").status_code == 404


def test_unknown_run_is_404(client):
    assert client.get("/runs/RUN-NOPE").status_code == 404


# --- timeline ---------------------------------------------------------------


def test_timeline_returns_events(client):
    incident = _post_alert(client).json()
    run = client.post(f"/incidents/{incident['id']}/run", json={"auto_approve": True}).json()

    import time

    for _ in range(120):
        body = client.get("/incidents/{}/timeline".format(incident["id"])).json()
        if body["events"] and all(e["status"] != "running" for e in body["events"]):
            break
        time.sleep(0.05)

    assert body["run_id"] == run["id"]
    assert body["events"]
    for event in body["events"]:
        assert event["phase"] in {"detection", "containment", "eradication", "recovery", "unknown"}


def test_timeline_for_unrun_incident_is_empty(client):
    incident = _post_alert(client).json()
    body = client.get(f"/incidents/{incident['id']}/timeline").json()
    assert body["run_id"] is None
    assert body["events"] == []


def test_timeline_unknown_incident_is_404(client):
    assert client.get("/incidents/INC-NOPE/timeline").status_code == 404


# --- coverage ---------------------------------------------------------------


def test_coverage_lists_gaps(client):
    """Naming what is NOT covered is the point (PLAN.md W3.4)."""
    body = client.get("/playbooks").json()
    assert body["gap_count"] > 0
    assert body["gaps"]
    assert body["covered_techniques"]
    assert "T1486" in body["covered_techniques"]


def test_coverage_gap_count_matches_list(client):
    body = client.get("/playbooks").json()
    assert body["gap_count"] == len(body["gaps"])


def test_reload_playbooks(client):
    body = client.post("/playbooks/reload").json()
    assert body["count"] == 4


# --- reporting --------------------------------------------------------------


def test_report_defaults_to_html(client):
    incident = _post_alert(client).json()
    resp = client.get(f"/incidents/{incident['id']}/report")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")


def test_report_renders_markdown(client):
    incident = _post_alert(client).json()
    resp = client.get(f"/incidents/{incident['id']}/report", params={"format": "md"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    assert incident["id"] in resp.text


def test_report_renders_exec_summary(client):
    incident = _post_alert(client).json()
    resp = client.get(f"/incidents/{incident['id']}/report", params={"format": "exec"})
    assert resp.status_code == 200
    assert "Executive Summary" in resp.text


def test_report_json_exposes_the_context(client):
    incident = _post_alert(client).json()
    body = client.get(f"/incidents/{incident['id']}/report", params={"format": "json"}).json()
    assert body["incident"]["id"] == incident["id"]
    assert body["metrics"]["label"] == "MEASURED"
    assert body["baseline"]["label"] == "TARGET"


def test_report_for_an_unrun_incident_says_nothing_was_contained(client):
    """A triage-only incident must not read as contained."""
    incident = _post_alert(client).json()
    text = client.get(f"/incidents/{incident['id']}/report", params={"format": "exec"}).text
    assert "Not assessed" in text
    assert "Yes, contained" not in text


def test_report_labels_every_figure_it_renders(client):
    incident = _post_alert(client).json()
    for fmt in ("html", "md", "exec"):
        text = client.get(f"/incidents/{incident['id']}/report", params={"format": fmt}).text
        assert "MEASURED" in text, f"{fmt} report rendered an unlabelled figure"
        assert "TARGET" in text, f"{fmt} report rendered an unlabelled baseline figure"


def test_report_download_sets_attachment_disposition(client):
    incident = _post_alert(client).json()
    resp = client.get(
        f"/incidents/{incident['id']}/report", params={"format": "html", "download": "true"}
    )
    assert "attachment" in resp.headers["content-disposition"]
    assert incident["id"] in resp.headers["content-disposition"]


def test_report_rejects_bad_format(client):
    incident = _post_alert(client).json()
    assert client.get(f"/incidents/{incident['id']}/report", params={"format": "pdf"}).status_code == 422


def test_report_unknown_incident_is_404(client):
    assert client.get("/incidents/INC-NOPE/report").status_code == 404


def test_report_writes_into_the_documented_output_path(client, tmp_path_factory):
    """AGENTS.md section 6: reports/html/<incident_id>.html."""
    from soar.api import main as api_main

    incident = _post_alert(client).json()
    client.get(f"/incidents/{incident['id']}/report", params={"format": "html"})
    client.get(f"/incidents/{incident['id']}/report", params={"format": "md"})
    client.get(f"/incidents/{incident['id']}/report", params={"format": "exec"})

    html_path = api_main.REPORTS_DIR / "html" / f"{incident['id']}.html"
    assert html_path.is_file()
    assert (api_main.REPORTS_DIR / "md" / f"{incident['id']}.md").is_file()
    assert (api_main.REPORTS_DIR / "md" / f"{incident['id']}-exec.md").is_file()
    assert "chart.js" in html_path.read_text(encoding="utf-8").lower()