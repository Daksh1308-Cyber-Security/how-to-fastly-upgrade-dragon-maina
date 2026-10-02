"""Volatility wrapper: offline operation and graceful degradation."""

from __future__ import annotations

import json

import pytest

from soar.connectors.base import ActionContext
from soar.connectors.forensics import VolatilityConnector
from soar.forensics import memory as mem


@pytest.fixture
def ctx(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return ActionContext(run_id="RUN-F", incident_id="INC-F", action_id="mem", data_dir=data_dir)


# --- availability -----------------------------------------------------------


def test_recorded_fixtures_are_available():
    """Recorded output is the default input, so the demo works offline."""
    assert mem.find_recorded_dir() is not None
    assert mem.available() is True


def test_no_memory_image_is_shipped():
    """fixtures/memory/ is operator-supplied and git-ignored; nothing is bundled."""
    assert mem.find_image() is None


def test_every_default_plugin_has_recorded_output():
    for plugin in mem.DEFAULT_PLUGINS:
        recorded = mem.load_recorded(plugin)
        assert recorded["rows"], f"{plugin} has no recorded rows"


def test_recorded_payload_shape():
    recorded = mem.load_recorded("windows.pslist")
    assert recorded["plugin"] == "windows.pslist"
    assert isinstance(recorded["rows"], list)


# --- analysis ---------------------------------------------------------------


def test_analyze_returns_plugin_rows():
    result = mem.analyze(prefer_recorded=True)
    assert result["status"] == "ok"
    assert result["source"] == "recorded"
    assert "windows.pslist" in result["plugins"]


def test_analyze_honours_plugin_subset():
    result = mem.analyze(plugins=["windows.netscan"], prefer_recorded=True)
    assert list(result["plugins"]) == ["windows.netscan"]


def test_unknown_plugin_is_skipped_not_fatal():
    result = mem.analyze(plugins=["windows.notaplugin"], prefer_recorded=True)
    assert result["skipped"] == ["windows.notaplugin"]
    assert result["status"] == "partial"


def test_connector_runs_offline(ctx):
    result = VolatilityConnector().execute({"prefer_recorded": True}, ctx)
    assert result["status"] == "ok"
    assert result["plugins"]


def test_connector_compensation_is_noop(ctx):
    connector = VolatilityConnector()
    result = connector.execute({"prefer_recorded": True}, ctx)
    assert connector.compensate({}, ctx, result)["noop"] is True


# --- degradation ------------------------------------------------------------


def test_connector_reports_skipped_when_no_input(ctx, monkeypatch):
    """Silence is not an acceptable substitute for reporting a skipped step."""
    monkeypatch.setattr(mem, "find_image", lambda: None)
    monkeypatch.setattr(mem, "find_recorded_dir", lambda: None)

    result = VolatilityConnector().execute({}, ctx)
    assert result["status"] == "skipped"
    assert "no memory image" in result["reason"]


def test_analyze_raises_when_no_input(monkeypatch):
    monkeypatch.setattr(mem, "find_image", lambda: None)
    monkeypatch.setattr(mem, "find_recorded_dir", lambda: None)
    with pytest.raises(mem.ForensicsUnavailable):
        mem.analyze()


def test_vol_version_is_reported():
    version = mem.vol_version()
    # None when Volatility is not installed -- both outcomes are legitimate.
    assert version is None or isinstance(version, str)


# --- safety -----------------------------------------------------------------


def test_module_cannot_capture_memory():
    """AGENTS.md section 2.3: no host-memory capture path may exist.

    This is a structural assertion, not a behavioural one: the wrapper exposes
    only read-and-analyse operations.
    """
    forbidden = ("capture", "dump_memory", "acquire", "procdump", "winpmem", "lime", "avml")
    public = [n for n in dir(mem) if not n.startswith("_")]
    assert not any(f in n.lower() for f in forbidden for n in public), (
        f"memory module exposes a capture-like name: {public}"
    )


def test_plugin_timeout_is_bounded():
    """METRICS.md section 3.4: a plugin may not stall the run indefinitely."""
    assert 0 < mem.PLUGIN_TIMEOUT_SECONDS <= 600


def test_recorded_output_file_is_read_only_input():
    """Recorded fixtures are never modified by analysis."""
    recorded_dir = mem.find_recorded_dir()
    before = {p.name: p.read_bytes() for p in recorded_dir.glob("*.json")}
    mem.analyze(prefer_recorded=True)
    after = {p.name: p.read_bytes() for p in recorded_dir.glob("*.json")}
    assert before == after