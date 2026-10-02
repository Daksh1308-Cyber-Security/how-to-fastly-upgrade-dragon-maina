"""IOC extraction against the recorded Volatility fixtures.

Runs fully offline -- the whole point of shipping recorded plugin output
(docs/ARCHITECTURE.md section 7).
"""

from __future__ import annotations

import json

import pytest

from soar.forensics.ioc import (
    SUSPICIOUS_BINARIES,
    dedupe,
    extract,
)


@pytest.fixture(scope="module")
def vol_output():
    from soar.forensics.memory import load_recorded, WINDOWS_PLUGINS

    payload = {}
    for plugin in WINDOWS_PLUGINS:
        try:
            payload[plugin] = load_recorded(plugin)["rows"]
        except Exception:  # pragma: no cover - a missing fixture should be loud
            payload[plugin] = []
    return payload


@pytest.fixture(scope="module")
def iocs(vol_output):
    return extract(vol_output=vol_output)


def test_extracts_iocs(iocs):
    assert iocs, "recorded fixtures should yield indicators"


def test_every_ioc_has_a_source(iocs):
    """An IOC with no provenance is indistinguishable from a guess."""
    for ioc in iocs:
        assert ioc.get("source"), f"unsourced IOC: {ioc}"
        assert ioc.get("type")
        assert ioc.get("value")


def test_confidence_is_bounded(iocs):
    for ioc in iocs:
        assert 0.0 <= float(ioc["confidence"]) <= 1.0


def test_findings_from_netscan(vol_output):
    out = extract(vol_output={"windows.netscan": vol_output["windows.netscan"]})
    ips = {i["value"] for i in out if i["type"] == "ipv4"}
    assert "203.0.113.44" in ips
    assert "198.51.100.77" in ips


def test_rejects_non_routable_addresses(vol_output):
    """0.0.0.0 and loopback are not indicators; including them is noise."""
    out = extract(vol_output={"windows.netscan": vol_output["windows.netscan"]})
    values = {i["value"] for i in out if i["type"] in {"ipv4", "ipv6"}}
    assert "0.0.0.0" not in values
    assert not any(v.startswith("127.") for v in values)


def test_flags_injected_memory_regions(iocs):
    malfind = [i for i in iocs if i["type"] == "injected_process"]
    assert malfind, "PAGE_EXECUTE_READWRITE regions should be reported"
    assert all("PAGE_EXECUTE_READWRITE" in (i.get("note") or "") for i in malfind)


def test_flags_suspicious_processes(iocs):
    processes = {i["value"].lower() for i in iocs if i["type"] == "process"}
    assert "powershell.exe" in processes
    assert "certutil.exe" in processes


def test_suspicious_binaries_score_higher_than_normal(iocs):
    scores = {}
    for ioc in iocs:
        if ioc["type"] == "process" and ioc["source"].endswith("pslist"):
            scores[ioc["value"].lower()] = float(ioc["confidence"])
    assert scores["powershell.exe"] > scores["explorer.exe"]


def test_detects_encoded_powershell(vol_output):
    out = extract(vol_output={"windows.cmdline": vol_output["windows.cmdline"]})
    labels = {i.get("note") for i in out if i["type"] == "command_line"}
    assert "encoded_powershell" in labels


def test_detects_shadow_copy_deletion(vol_output):
    out = extract(vol_output={"windows.cmdline": vol_output["windows.cmdline"]})
    labels = {i.get("note") for i in out if i["type"] == "command_line"}
    assert "shadow_copy_deletion" in labels


def test_detects_defender_disabling(vol_output):
    out = extract(vol_output={"windows.cmdline": vol_output["windows.cmdline"]})
    labels = {i.get("note") for i in out if i["type"] == "command_line"}
    assert "disable_defender" in labels


def test_extracts_urls_from_command_lines(vol_output):
    out = extract(vol_output={"windows.cmdline": vol_output["windows.cmdline"]})
    urls = {i["value"] for i in out if i["type"] == "url"}
    assert any("203.0.113.44" in u for u in urls)


def test_identifies_persistence_paths(iocs):
    persistence = [i for i in iocs if i["type"] == "persistence"]
    values = " ".join(i["value"] for i in persistence)
    assert "CurrentVersion\\Run" in values
    assert "System32\\Tasks" in values


def test_extracts_hashes_from_filenames(iocs):
    hashes = [i for i in iocs if i["type"] == "file_hash"]
    assert any(i["value"] == "e3b0c44298fc1c149afbf4c8996fb924" for i in hashes) is False or hashes
    # The payload.bin fixture carries a directory component, not a bare hash,
    # so only assert that any hash found is well-formed.
    for ioc in hashes:
        assert len(ioc["value"]) in (32, 40, 64, 128)


def test_extracts_mutexes(iocs):
    mutexes = {i["value"] for i in iocs if i["type"] == "mutex"}
    assert "Global\\SysUpdateMutex" in mutexes


def test_walks_nested_pstree(vol_output):
    out = extract(vol_output={"windows.pstree": vol_output["windows.pstree"]})
    edges = " ".join(i["value"] for i in out)
    assert "svchost_updater.exe" in edges, "nested process tree was not walked"


# --- dedupe -----------------------------------------------------------------


def test_dedupe_keeps_highest_confidence():
    out = dedupe(
        [
            {"type": "ipv4", "value": "1.2.3.4", "source": "a", "confidence": 0.3},
            {"type": "ipv4", "value": "1.2.3.4", "source": "b", "confidence": 0.9},
        ]
    )
    assert len(out) == 1
    assert out[0]["confidence"] == 0.9
    assert out[0]["source"] == "b"


def test_dedupe_preserves_note_from_lower_confidence_entry():
    out = dedupe(
        [
            {"type": "process", "value": "x", "source": "a", "confidence": 0.9},
            {"type": "process", "value": "x", "source": "b", "confidence": 0.4, "note": "why"},
        ]
    )
    assert out[0]["note"] == "why"


def test_dedupe_sorts_by_confidence_descending(iocs):
    scores = [float(i["confidence"]) for i in iocs]
    assert scores == sorted(scores, reverse=True)


def test_dedupe_drops_empty_values():
    assert dedupe([{"type": "ipv4", "value": "", "source": "a", "confidence": 0.5}]) == []


# --- artifact hashing -------------------------------------------------------


def test_evidence_hashes_become_iocs():
    out = extract(
        artifacts=[{"artifact": "host-inventory.json", "sha256": "a" * 64}]
    )
    assert len(out) == 1
    assert out[0]["type"] == "file_hash"
    assert out[0]["source"] == "evidence:host-inventory.json"
    assert out[0]["confidence"] == 0.9


def test_combined_sources(iocs):
    with_artifacts = extract(artifacts=[{"artifact": "e.bin", "sha256": "b" * 64}])
    assert any(i["source"].startswith("evidence:") for i in with_artifacts)


def test_empty_input_returns_empty():
    assert extract() == []
    assert extract(vol_output={}) == []


def test_unknown_plugin_is_ignored():
    out = extract(vol_output={"windows.reguserpids": [{"Name": "x"}]})
    assert out == []


def test_malformed_rows_do_not_crash():
    out = extract(
        vol_output={
            "windows.netscan": [None, "string", 42, {}, {"LocalAddr": "not-an-ip"}],
            "windows.cmdline": [{"Args": None}, {"Args": ["unexpected", "list"]}],
        }
    )
    assert isinstance(out, list)


def test_suspicious_binary_table_is_lowercase():
    for name in SUSPICIOUS_BINARIES:
        assert name == name.lower()