"""IOC extraction from Volatility output and collected artifacts.

Pure module: no I/O, no clock, no randomness. Everything is a function of its
inputs, which makes extraction exhaustively unit-testable against the recorded
fixtures in ``fixtures/volatility/`` (docs/COMPONENTS.md -> ``ioc``).

Two rules hold throughout:

* **Every IOC carries a source.** An indicator with no provenance is not
  evidence, and an unattributed IOC in an incident report is indistinguishable
  from a guess.
* **Confidence is explicit** and defaults low. A value seen in ``netscan`` but
  not corroborated elsewhere does not outrank a value confirmed by two plugins.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

__all__ = [
    "extract",
    "dedupe",
    "SUSPICIOUS_BINARIES",
    "SUSPICIOUS_CMD_PATTERNS",
    "PERSISTENCE_PATH_MARKERS",
    "DEFAULT_CONFIDENCE",
]

DEFAULT_CONFIDENCE = 0.5

#: Processes commonly used in post-exploitation. Presence is not proof of
#: compromise -- these get a confidence bump, not a verdict.
SUSPICIOUS_BINARIES: frozenset[str] = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "net.exe",
        "netsh.exe",
        "whoami.exe",
        "schtasks.exe",
        "at.exe",
        "psexec.exe",
        "mimikatz.exe",
    }
)

#: Command-line shapes that warrant a closer look.
SUSPICIOUS_CMD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("encoded_powershell", re.compile(r"powershell[^\s]*\s+.*-e(?:nc|ncodedcommand)\b", re.I)),
    ("download_string", re.compile(r"(?:Invoke-WebRequest|DownloadString|DownloadFile)", re.I)),
    ("in_memory_load", re.compile(r"FromBase64String|Assembly\.Load", re.I)),
    ("shadow_copy_deletion", re.compile(r"vssadmin[^\s]*\s+delete\s+shadows", re.I)),
    ("disable_defender", re.compile(r"Set-MpPreference.*-DisableRealtimeMonitoring", re.I)),
    ("lateral_rpc", re.compile(r"New-PSSession|Invoke-Command|schtasks\s+/s", re.I)),
    ("credential_dump", re.compile(r"lsass|SAM\b|ntds\.dit|mimikatz", re.I)),
)

#: Path fragments that indicate a persistence mechanism.
PERSISTENCE_PATH_MARKERS: tuple[str, ...] = (
    "\\CurrentVersion\\Run",
    "\\CurrentVersion\\RunOnce",
    "\\Start Menu\\Programs\\Startup",
    "\\System32\\Tasks\\",
    "\\Tasks\\",
    "\\services.exe",
    "\\lsass.exe",
    "\\svchost.exe",
    "\\AppData\\Roaming\\",
    "\\ProgramData\\",
)

_HEX_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]{4,}\b", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|info|biz|top|xyz|io|co|uk)\b",
    re.I,
)
#: Mutex / named-object names as Windows actually renders them. Backslash is
#: mandatory: ``Global\Foo``, ``BaseNamedObjects\Bar`` and ``MountPointWrapper{..}``
#: are the normal forms, and a class without ``\\`` rejected all of them.
_MUTEX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\\\-{}$]{2,160}$")


def _row_value(row: Any, *keys: str) -> Any:
    """Fetch the first present key from a Volatility row.

    Volatility's JSON renderer nests data differently per plugin
    (``Offset`` at the top level, some fields under ``__children``), so rows are
    searched recursively rather than by fixed position.
    """
    if not isinstance(row, dict):
        return None
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    for value in row.values():
        if isinstance(value, dict):
            found = _row_value(value, *keys)
            if found is not None:
                return found
    return None


def _iter_nested(row: Any) -> Iterable[Any]:
    """Yield a row and all nested dict values."""
    yield row
    if isinstance(row, dict):
        for value in row.values():
            if isinstance(value, (dict, list)):
                yield from _iter_nested(value)
    elif isinstance(row, list):
        for item in row:
            yield from _iter_nested(item)


def _valid_ip(value: str) -> tuple[str, str] | None:
    """Return ``(type, value)`` for a real IP, or ``None``.

    Rejects unspecified, loopback, link-local, multicast and reserved
    addresses: a self-referencing or broadcast address is not an IOC and
    listing it would pad the report with noise.
    """
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    if (
        parsed.is_unspecified
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
    ):
        return None
    return ("ipv4" if parsed.version == 4 else "ipv6", value)


#: Field names Volatility uses for addresses. ``ForeignAddr`` is the real
#: ``windows.netscan`` column -- missing it meant remote/C2 addresses were
#: never extracted, which is the single most important IOC class here.
_NETSCAN_ADDR_KEYS = ("LocalAddr", "RemoteAddr", "ForeignAddr", "LocalAddress", "ForeignAddress", "IP", "Address")


def _extract_from_netscan(rows: list[Any], out: list[dict[str, Any]]) -> None:
    for row in rows:
        for node in _iter_nested(row):
            if not isinstance(node, dict):
                continue
            for key in _NETSCAN_ADDR_KEYS:
                candidate = node.get(key)
                if isinstance(candidate, str):
                    resolved = _valid_ip(candidate)
                    if resolved:
                        out.append(
                            {
                                "type": resolved[0],
                                "value": resolved[1],
                                "source": "volatility:windows.netscan",
                                "confidence": 0.6,
                            }
                        )
            owner = _row_value(row, "Owner", "Process", "PID")
            if owner:
                out.append(
                    {
                        "type": "process",
                        "value": str(owner),
                        "source": "volatility:windows.netscan",
                        "confidence": 0.4,
                    }
                )


def _extract_from_pslist(rows: list[Any], out: list[dict[str, Any]]) -> None:
    for row in rows:
        name = _row_value(row, "ImageFileName", "Name", "Process")
        if not name:
            continue
        name = str(name)
        confidence = 0.65 if name.lower() in SUSPICIOUS_BINARIES else 0.25
        out.append(
            {
                "type": "process",
                "value": name,
                "source": "volatility:windows.pslist",
                "confidence": confidence,
                "note": "commonly abused binary" if confidence > 0.5 else None,
            }
        )


def _extract_from_cmdline(rows: list[Any], out: list[dict[str, Any]]) -> None:
    for row in rows:
        name = _row_value(row, "Process", "ImageFileName", "Name") or "unknown"
        args = _row_value(row, "Args", "CommandLine", "Cmd")
        if not args:
            continue
        args = str(args)
        for label, pattern in SUSPICIOUS_CMD_PATTERNS:
            if pattern.search(args):
                out.append(
                    {
                        "type": "command_line",
                        "value": f"{name}: {args[:300]}",
                        "source": "volatility:windows.cmdline",
                        "confidence": 0.75,
                        "note": label,
                    }
                )
                break
        for match in _URL_RE.findall(args):
            out.append(
                {"type": "url", "value": match, "source": "volatility:windows.cmdline", "confidence": 0.7}
            )


def _extract_from_malfind(rows: list[Any], out: list[dict[str, Any]]) -> None:
    for row in rows:
        pid = _row_value(row, "PID", "ProcessId")
        start = _row_value(row, "Start VPN", "Start")
        protection = _row_value(row, "Protection", "Type")
        if pid is None:
            continue
        out.append(
            {
                "type": "injected_process",
                "value": f"PID {pid} @ {start}",
                "source": "volatility:windows.malfind",
                "confidence": 0.8,
                "note": f"executable memory region, protection={protection}",
            }
        )


def _extract_from_pstree(rows: list[Any], out: list[dict[str, Any]]) -> None:
    """Walk the tree recursively.

    ``windows.pstree`` nests children under ``__children``; reading only the
    top row found ``System -> ...`` and missed the actual malicious chain.
    """
    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        child = _row_value(node, "Name", "ImageFileName", "Process")
        parent_pid = _row_value(node, "PPID")
        if child and parent_pid is not None:
            out.append(
                {
                    "type": "process_tree_edge",
                    "value": f"{child} (pid {parent_pid}) -> child",
                    "source": "volatility:windows.pstree",
                    "confidence": 0.4,
                }
            )
        children = node.get("__children")
        if children:
            walk(children)

    walk(rows)


def _extract_from_filescan(rows: list[Any], out: list[dict[str, Any]]) -> None:
    for row in rows:
        name = _row_value(row, "Name", "FullName", "FileName")
        if not name:
            continue
        name = str(name)
        lowered = name.lower()
        for marker in PERSISTENCE_PATH_MARKERS:
            if marker.lower() in lowered:
                out.append(
                    {
                        "type": "persistence",
                        "value": name,
                        "source": "volatility:windows.filescan",
                        "confidence": 0.6,
                        "note": f"matches persistence marker {marker}",
                    }
                )
                break
        for match in _HEX_RE.findall(name):
            out.append(
                {
                    "type": "file_hash",
                    "value": match,
                    "source": "volatility:windows.filescan",
                    "confidence": 0.6,
                }
            )


def _extract_from_handles(rows: list[Any], out: list[dict[str, Any]]) -> None:
    for row in rows:
        name = _row_value(row, "Name", "Mutex", "Handle")
        if not name or not _MUTEX_RE.match(str(name)):
            continue
        out.append(
            {
                "type": "mutex",
                "value": str(name),
                "source": "volatility:windows.handles",
                "confidence": 0.35,
            }
        )


_EXTRACTORS = {
    "windows.netscan": _extract_from_netscan,
    "windows.pslist": _extract_from_pslist,
    "windows.cmdline": _extract_from_cmdline,
    "windows.malfind": _extract_from_malfind,
    "windows.pstree": _extract_from_pstree,
    "windows.filescan": _extract_from_filescan,
    "windows.handles": _extract_from_handles,
}


def dedupe(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse IOCs by ``(type, value)``, keeping the highest confidence.

    Also preserves ``note`` from whichever entry carried it, so the strongest
    corroboration survives.
    """
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for ioc in iocs:
        key = (str(ioc.get("type", "")), str(ioc.get("value", "")))
        if not key[1]:
            continue
        existing = best.get(key)
        if existing is None:
            best[key] = dict(ioc)
            continue
        if float(ioc.get("confidence", 0)) > float(existing.get("confidence", 0)):
            if existing.get("note") and not ioc.get("note"):
                ioc["note"] = existing["note"]
            best[key] = dict(ioc)
        elif existing.get("note") is None and ioc.get("note"):
            existing["note"] = ioc["note"]
    return sorted(best.values(), key=lambda i: (-float(i.get("confidence", 0)), i["type"], i["value"]))


def extract(
    vol_output: dict[str, list[Any]] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Extract deduplicated IOCs from Volatility output and evidence artifacts.

    Args:
        vol_output: ``{plugin_name: [rows]}`` as returned by
            :func:`soar.forensics.memory.analyze`.
        artifacts: Evidence manifest entries (dicts with at least ``sha256``
            and ``artifact``). Each ``sha256`` becomes a ``file_hash`` IOC.

    Returns:
        Deduplicated IOCs sorted by descending confidence. Every entry has
        ``type``, ``value``, ``source`` and ``confidence``.
    """
    out: list[dict[str, Any]] = []

    for plugin, rows in (vol_output or {}).items():
        extractor = _EXTRACTORS.get(plugin)
        if extractor is None or not rows:
            continue
        extractor(rows, out)

    for artifact in artifacts or []:
        digest = artifact.get("sha256")
        if digest:
            out.append(
                {
                    "type": "file_hash",
                    "value": str(digest),
                    "source": f"evidence:{artifact.get('artifact', 'unknown')}",
                    "confidence": 0.9,
                }
            )

    return dedupe(out)