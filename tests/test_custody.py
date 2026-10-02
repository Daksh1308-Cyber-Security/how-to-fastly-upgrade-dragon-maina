"""Evidence collection and chain-of-custody integrity.

Covers docs/SECURITY.md section 4.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from soar.connectors.base import ActionContext, ConnectorError
from soar.connectors.evidence import (
    EvidenceCollectConnector,
    custody_path,
    manifest,
    read_custody,
    record_custody,
    sha256_file,
    verify,
)
from tests.conftest import EVIDENCE, EVIDENCE_DIR


def _ctx(tmp_path, roots=(EVIDENCE,)) -> ActionContext:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return ActionContext(
        run_id="RUN-C",
        incident_id="INC-C",
        action_id="collect",
        data_dir=data_dir,
        evidence_roots=list(roots),
    )


def test_collects_and_hashes(tmp_path):
    ctx = _ctx(tmp_path)
    result = EvidenceCollectConnector().execute(
        {"artifacts": ["evidence/host-inventory.json"]}, ctx
    )
    assert result["count"] == 1
    entry = result["collected"][0]
    assert len(entry["sha256"]) == 64
    assert entry["size"] > 0


def test_copies_the_file(tmp_path):
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/host-inventory.json"]}, ctx)
    copied = tmp_path / "data" / "incidents" / "INC-C" / "evidence" / "host-inventory.json"
    assert copied.exists()
    assert copied.read_bytes() == (EVIDENCE_DIR / "host-inventory.json").read_bytes()


def test_source_is_not_modified(tmp_path):
    """Evidence handling is read-only; the source must be untouched."""
    source = EVIDENCE_DIR / "host-inventory.json"
    before_bytes = source.read_bytes()
    before_mtime = source.stat().st_mtime_ns

    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/host-inventory.json"]}, ctx)

    assert source.read_bytes() == before_bytes
    assert source.stat().st_mtime_ns == before_mtime


def test_custody_entry_is_complete(tmp_path):
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)
    entries = read_custody(ctx)
    assert len(entries) == 1
    entry = entries[0]
    for key in ("ts", "artifact", "sha256", "size", "source", "collected_by", "run_id", "incident_id"):
        assert entry.get(key) is not None, f"custody entry missing {key}"


def test_custody_log_is_jsonl(tmp_path):
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute(
        {"artifacts": ["evidence/ransom-note.txt", "evidence/host-inventory.json"]}, ctx
    )
    lines = custody_path(ctx).read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # each line must stand alone


def test_append_only(tmp_path):
    """Entries are never rewritten or reordered."""
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)
    first = custody_path(ctx).read_text(encoding="utf-8")

    EvidenceCollectConnector().execute({"artifacts": ["evidence/host-inventory.json"]}, ctx)
    second = custody_path(ctx).read_text(encoding="utf-8")

    assert second.startswith(first), "earlier custody entries were rewritten"


def test_never_overwrites_existing_artifact(tmp_path):
    """A second collection is a new event, not an overwrite."""
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)
    result = EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)

    assert result["count"] == 0
    assert any(f["reason"] == "already collected" for f in result["failures"])


def test_missing_artifact_is_reported_not_fatal(tmp_path):
    ctx = _ctx(tmp_path)
    result = EvidenceCollectConnector().execute(
        {"artifacts": ["evidence/nope.txt", "evidence/ransom-note.txt"]}, ctx
    )
    assert result["count"] == 1
    assert len(result["failures"]) == 1


def test_path_traversal_rejected(tmp_path):
    """A playbook must not be able to read outside the evidence roots."""
    ctx = _ctx(tmp_path)
    result = EvidenceCollectConnector().execute({"artifacts": ["../../../../etc/passwd"]}, ctx)
    assert result["count"] == 0
    assert result["failures"]


def test_absolute_path_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    with pytest.raises(ConnectorError):
        EvidenceCollectConnector().execute({"artifacts": ["C:/Windows/System32/config/SAM"]}, ctx)


def test_empty_artifact_list_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    with pytest.raises(ConnectorError):
        EvidenceCollectConnector().execute({"artifacts": []}, ctx)


# --- integrity verification -------------------------------------------------


def test_verify_passes_on_untouched_evidence(tmp_path):
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)
    result = verify(ctx)
    assert result["ok"] is True
    assert result["integrity"] == "PASSED"
    assert result["mismatches"] == []


def test_verify_detects_tampering(tmp_path):
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)

    target = tmp_path / "data" / "incidents" / "INC-C" / "evidence" / "ransom-note.txt"
    target.write_text("tampered", encoding="utf-8")

    result = verify(ctx)
    assert result["ok"] is False
    assert result["integrity"] == "FAILED"
    assert result["mismatches"][0]["reason"] == "sha256_mismatch"


def test_verify_detects_deletion(tmp_path):
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)

    target = tmp_path / "data" / "incidents" / "INC-C" / "evidence" / "ransom-note.txt"
    target.unlink()

    result = verify(ctx)
    assert result["ok"] is False
    assert result["mismatches"][0]["reason"] == "missing"


def test_verify_on_empty_log_passes(tmp_path):
    assert verify(_ctx(tmp_path))["ok"] is True


def test_manifest_matches_custody_log(tmp_path):
    ctx = _ctx(tmp_path)
    EvidenceCollectConnector().execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)
    assert manifest(ctx) == read_custody(ctx)


def test_sha256_matches_hashlib(tmp_path):
    path = EVIDENCE_DIR / "host-inventory.json"
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    assert sha256_file(path) == expected


def test_compensation_is_a_deliberate_noop(tmp_path):
    """Evidence is append-only; a rollback must not delete it."""
    ctx = _ctx(tmp_path)
    connector = EvidenceCollectConnector()
    result = connector.execute({"artifacts": ["evidence/ransom-note.txt"]}, ctx)
    out = connector.compensate({}, ctx, result)
    assert out["noop"] is True
    assert "append-only" in out["reason"]
    assert (tmp_path / "data" / "incidents" / "INC-C" / "evidence" / "ransom-note.txt").exists()


def test_manual_custody_entry_is_appended(tmp_path):
    ctx = _ctx(tmp_path)
    record_custody(ctx, {"artifact": "manual.txt", "sha256": "c" * 64, "note": "added by analyst"})
    entries = read_custody(ctx)
    assert entries[-1]["artifact"] == "manual.txt"
    assert entries[-1]["note"] == "added by analyst"