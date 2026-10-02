"""Volatility 3 wrapper.

**The only module in this project permitted to spawn a subprocess**
(docs/SECURITY.md section 2). It runs ``vol`` against a file the operator
supplied and never against the host.

What this module will never do, by construction:

* capture host memory -- there is no capture path here, and adding one is
  forbidden (AGENTS.md section 2.3);
* invoke any shell -- ``shell=False`` and an argument list, always;
* touch anything outside the supplied image path and the symbol cache.

Data source, in order of preference:

1. ``fixtures/memory/`` -- a real memory image the operator deliberately
   placed there. Optional; git-ignored.
2. ``fixtures/volatility/`` -- recorded plugin output. This is the **default**
   and is what the tests and the demo use, so they run offline.

If neither is available, :func:`analyze` returns a ``skipped`` result rather
than pretending it found nothing. Silence is not an acceptable substitute for
reporting a skipped step.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ForensicsUnavailable",
    "DEFAULT_PLUGINS",
    "WINDOWS_PLUGINS",
    "available",
    "find_image",
    "load_recorded",
    "analyze",
    "vol_version",
]

#: Volatility plugins run for a Windows image. Kept short deliberately: every
#: plugin costs wall-clock and is gated by METRICS.md section 3.4.
WINDOWS_PLUGINS: tuple[str, ...] = (
    "windows.info",
    "windows.pslist",
    "windows.cmdline",
    "windows.pstree",
    "windows.netscan",
    "windows.malfind",
    "windows.filescan",
    "windows.handles",
)

DEFAULT_PLUGINS = WINDOWS_PLUGINS

#: Hard ceiling on a single plugin invocation. A plugin that exceeds this is
#: recorded as skipped rather than allowed to stall the whole run.
PLUGIN_TIMEOUT_SECONDS = 120


class ForensicsUnavailable(RuntimeError):
    """Neither a memory image nor recorded plugin output could be found."""


def _fixtures_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "fixtures"


def find_image() -> Path | None:
    """Return the operator-supplied memory image, if any.

    Looks only inside ``fixtures/memory/``. Never probes the host for a live
    image and never suggests capturing one.
    """
    memory_dir = _fixtures_dir() / "memory"
    if not memory_dir.is_dir():
        return None
    for candidate in sorted(memory_dir.iterdir()):
        if candidate.is_file() and candidate.suffix.lower() in {".raw", ".mem", ".vmem", ".dmp", ".lime"}:
            return candidate
    return None


def find_recorded_dir() -> Path | None:
    """Return the recorded-plugin-output directory, if populated."""
    recorded = _fixtures_dir() / "volatility"
    return recorded if recorded.is_dir() and any(recorded.glob("*.json")) else None


def available() -> bool:
    """Whether any forensic input exists (real image or recorded output)."""
    if find_image() is not None:
        return True
    return find_recorded_dir() is not None


def vol_version() -> str | None:
    """Installed Volatility version, or ``None`` if it is not importable."""
    try:
        from volatility3 import framework  # noqa: F401
    except ImportError:
        return None
    import volatility3

    return getattr(volatility3, "__version__", "unknown")


def _plugin_to_filename(plugin: str) -> str:
    return plugin.replace(".", "_") + ".json"


def load_recorded(plugin: str) -> dict[str, Any]:
    """Load recorded output for one plugin.

    Returns the parsed payload, normalised to a list of row dicts under
    ``rows`` so that live and recorded results share one shape.
    """
    recorded_dir = find_recorded_dir()
    if recorded_dir is None:
        raise ForensicsUnavailable("no recorded Volatility output available")

    path = recorded_dir / _plugin_to_filename(plugin)
    if not path.exists():
        # Fall back to any recorded file whose name contains the leaf name, so
        # fixtures do not have to match the full dotted plugin name.
        leaf = plugin.split(".")[-1]
        matches = sorted(recorded_dir.glob(f"*{leaf}*.json"))
        if not matches:
            raise ForensicsUnavailable(f"no recorded output for plugin {plugin!r}")
        path = matches[0]

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ForensicsUnavailable(f"recorded output {path.name} is unreadable: {exc}") from exc

    if isinstance(payload, list):
        return {"source": "recorded", "plugin": plugin, "file": path.name, "rows": payload}
    if isinstance(payload, dict) and "rows" in payload:
        payload.setdefault("source", "recorded")
        payload.setdefault("plugin", plugin)
        return payload
    raise ForensicsUnavailable(f"recorded output {path.name} has an unexpected shape")


@dataclass(slots=True)
class PluginOutcome:
    plugin: str
    status: str  # "ok" | "skipped" | "failed"
    rows: list[dict[str, Any]]
    source: str
    duration_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "status": self.status,
            "source": self.source,
            "duration_ms": self.duration_ms,
            "row_count": len(self.rows),
            "error": self.error,
        }


def _run_live_plugin(image: Path, plugin: str, timeout: int) -> PluginOutcome:
    """Invoke one Volatility plugin. Argument list, no shell, hard timeout."""
    import time

    executable = shutil.which("vol") or shutil.which("python3")
    if executable is None:
        raise ForensicsUnavailable("neither 'vol' nor a python interpreter is on PATH")

    argv = (
        [executable, "-m", "volatility3.cli", "-f", str(image), plugin, "--renderer=json"]
        if executable.endswith("python3") or executable.endswith("python")
        else [executable, "-f", str(image), plugin, "--renderer=json"]
    )

    started = time.perf_counter()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False, the one allowed subprocess
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
            env={"VOLATILITY3_SYMBOL_PATH": str(Path.home() / ".cache" / "volatility3")},
        )
    except subprocess.TimeoutExpired:
        return PluginOutcome(
            plugin=plugin,
            status="skipped",
            rows=[],
            source="live",
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=f"plugin exceeded {timeout}s timeout",
        )

    duration_ms = int((time.perf_counter() - started) * 1000)
    if completed.returncode != 0:
        return PluginOutcome(
            plugin=plugin,
            status="failed",
            rows=[],
            source="live",
            duration_ms=duration_ms,
            error=(completed.stderr or "").strip()[:500],
        )

    try:
        parsed = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        return PluginOutcome(
            plugin=plugin,
            status="failed",
            rows=[],
            source="live",
            duration_ms=duration_ms,
            error=f"could not parse JSON output: {exc}",
        )

    rows = parsed if isinstance(parsed, list) else parsed.get("rows", [])
    return PluginOutcome(plugin=plugin, status="ok", rows=rows, source="live", duration_ms=duration_ms)


def analyze(
    plugins: list[str] | None = None,
    image: Path | None = None,
    timeout: int = PLUGIN_TIMEOUT_SECONDS,
    prefer_recorded: bool = False,
) -> dict[str, Any]:
    """Run or load the requested plugins and return their output.

    Prefers a real image when one is present unless ``prefer_recorded`` is set;
    falls back to recorded output so tests and demos work offline.

    Args:
        plugins: Plugin names. Defaults to :data:`DEFAULT_PLUGINS`.
        image: Explicit image path. Defaults to :func:`find_image`.
        timeout: Per-plugin ceiling in seconds.
        prefer_recorded: Force the recorded path even if an image exists.

    Returns:
        ``{"status", "source", "plugins": {name: [rows]}, "outcomes": [...],
        "image"}``.

    Raises:
        ForensicsUnavailable: when neither input source is available. The
            caller is expected to record a ``skipped`` step, not a failure.
    """
    import time

    plugins = list(plugins or DEFAULT_PLUGINS)
    image = image or find_image()
    recorded_dir = find_recorded_dir()

    if image is None and recorded_dir is None:
        raise ForensicsUnavailable(
            "no memory image in fixtures/memory/ and no recorded output in fixtures/volatility/"
        )

    if image is not None and not prefer_recorded:
        source = "live"
        payload: dict[str, list[dict[str, Any]]] = {}
        outcomes: list[PluginOutcome] = []
        for plugin in plugins:
            outcome = _run_live_plugin(image, plugin, timeout)
            outcomes.append(outcome)
            payload[plugin] = outcome.rows
        status = "ok" if all(o.status == "ok" for o in outcomes) else "partial"
    else:
        source = "recorded"
        payload = {}
        outcomes = []
        for plugin in plugins:
            started = time.perf_counter()
            try:
                recorded = load_recorded(plugin)
            except ForensicsUnavailable as exc:
                outcomes.append(
                    PluginOutcome(
                        plugin=plugin, status="skipped", rows=[], source=source, error=str(exc)
                    )
                )
                payload[plugin] = []
                continue
            rows = list(recorded.get("rows", []))
            payload[plugin] = rows
            outcomes.append(
                PluginOutcome(
                    plugin=plugin,
                    status="ok",
                    rows=rows,
                    source=source,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )
            )
        status = "ok" if all(o.status == "ok" for o in outcomes) else "partial"

    return {
        "status": status,
        "source": source,
        "image": str(image) if image else None,
        "volatility_version": vol_version(),
        "plugins": payload,
        "outcomes": [o.to_dict() for o in outcomes],
        "skipped": [o.plugin for o in outcomes if o.status != "ok"],
    }