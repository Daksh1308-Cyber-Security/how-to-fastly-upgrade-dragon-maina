"""``evidence.collect`` -- real evidence collection with chain of custody.

Real, not simulated. What makes it safe is the direction of travel: bytes are
copied **out of** a read-only fixture tree, never written back to a source, and
every copy is hashed on arrival.

Contract (docs/SECURITY.md section 4):

1. The source is opened read-only. Never modified, never "cleaned".
2. SHA-256 is computed at collection time.
3. An entry is appended to ``chain_of_custody.jsonl``. Append-only: corrections
   are new entries carrying ``supersedes``, never rewrites.
4. ``verify()`` re-hashes on demand; a mismatch must surface as
   ``integrity: FAILED``, never be swallowed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from soar.connectors.base import ActionContext, ConnectorError

__all__ = [
    "EvidenceCollectConnector",
    "sha256_file",
    "record_custody",
    "read_custody",
    "verify",
    "manifest",
    "custody_path",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Streamed SHA-256. Streams because memory images are large and must not
    be loaded into RAM to be hashed."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def incident_dir(ctx: ActionContext) -> Path:
    if ctx.data_dir is None:
        raise ConnectorError("evidence.collect requires a data directory")
    return ctx.data_dir / "incidents" / ctx.incident_id


def custody_path(ctx: ActionContext) -> Path:
    return incident_dir(ctx) / "chain_of_custody.jsonl"


def record_custody(ctx: ActionContext, entry: dict[str, Any]) -> None:
    """Append one custody entry. Never rewrites or reorders existing entries."""
    path = custody_path(ctx)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_custody(ctx: ActionContext) -> list[dict[str, Any]]:
    path = custody_path(ctx)
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def manifest(ctx: ActionContext) -> list[dict[str, Any]]:
    """Return the custody log as a manifest."""
    return read_custody(ctx)


def verify(ctx: ActionContext) -> dict[str, Any]:
    """Re-hash every collected artifact and report integrity.

    Returns ``{"ok": bool, "artifacts": [...], "mismatches": [...]}``. A missing
    artifact or a hash mismatch both count as a mismatch -- silence is not an
    acceptable substitute for reporting a problem.
    """
    entries = read_custody(ctx)
    root = incident_dir(ctx) / "evidence"
    checked: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []

    for entry in entries:
        artifact = root / entry["artifact"]
        if not artifact.exists():
            mismatches.append({"artifact": entry["artifact"], "reason": "missing"})
            checked.append({"artifact": entry["artifact"], "ok": False})
            continue
        actual = sha256_file(artifact)
        ok = actual == entry["sha256"]
        checked.append({"artifact": entry["artifact"], "ok": ok, "sha256": actual})
        if not ok:
            mismatches.append(
                {"artifact": entry["artifact"], "reason": "sha256_mismatch", "expected": entry["sha256"], "actual": actual}
            )

    return {
        "ok": not mismatches,
        "integrity": "PASSED" if not mismatches else "FAILED",
        "artifacts": checked,
        "mismatches": mismatches,
    }


def _resolve_source(ctx: ActionContext, relative: str) -> Path:
    """Resolve a relative artifact path against the read-only evidence roots.

    Path traversal outside the roots is rejected. This is a containment measure:
    a playbook must not be able to ask for ``../../etc/passwd``.

    Absolute paths are rejected in **both** POSIX and Windows form. The engine
    runs in a Linux container, where ``os.path.isabs("C:/Windows/System32")``
    is ``False`` -- a naive POSIX-only check would let a playbook smuggle a
    Windows path straight through and read whatever the bind mount exposes.
    """
    if _looks_absolute(relative):
        # Raised out of execute(), not collected as a per-artifact failure. An
        # absolute path is a malformed playbook, and a playbook asking to read
        # outside its evidence roots must fail loudly rather than be silently
        # downgraded to "artifact not found".
        raise ConnectorError(
            f"artifact path must be relative and inside the evidence roots, got {relative!r}"
        )

    for root in ctx.evidence_roots:
        root = Path(root).resolve()
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue  # escapes this root; try the next
        if candidate.is_file():
            return candidate
    raise ConnectorError(f"artifact {relative!r} not found within configured evidence roots")


#: A drive-letter prefix ("C:", "D:\") -- absolute on Windows even when the
#: engine itself runs in Linux.
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
#: A UNC or backslash-absolute path.
_WINDOWS_ABS_RE = re.compile(r"^(\\\\|/)")


def _looks_absolute(candidate: str) -> bool:
    """True if ``candidate`` is absolute in POSIX or Windows terms."""
    return bool(
        os.path.isabs(candidate)
        or candidate.startswith("\\\\")
        or candidate.startswith("/")
        or _WINDOWS_DRIVE_RE.match(candidate)
        or _WINDOWS_ABS_RE.match(candidate)
    )


class EvidenceCollectConnector:
    name = "evidence.collect"
    phase = "detection"

    def execute(self, params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        artifacts = params.get("artifacts") or []
        if not isinstance(artifacts, list) or not artifacts:
            raise ConnectorError("evidence.collect requires a non-empty 'artifacts' list")

        dest_dir = incident_dir(ctx) / "evidence"
        dest_dir.mkdir(parents=True, exist_ok=True)

        collected: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []

        for relative in artifacts:
            relative = str(relative)
            # An absolute or root-escaping path aborts the whole action. It is a
            # malformed playbook, not a missing file, and silently recording it
            # as a failure would let a hostile path pass unnoticed.
            if _looks_absolute(relative):
                raise ConnectorError(
                    f"artifact path must be relative and inside the evidence roots, got {relative!r}"
                )

            try:
                source = _resolve_source(ctx, relative)
            except ConnectorError as exc:
                failures.append({"artifact": relative, "reason": str(exc)})
                continue

            target = dest_dir / Path(str(relative)).name
            if target.exists():
                # Never overwrite an existing evidence artifact. Collection is a
                # new event with its own custody entry (docs/SECURITY.md section 4).
                failures.append({"artifact": str(relative), "reason": "already collected"})
                continue

            try:
                # shutil.copy2 reads the source; it never writes to it.
                shutil.copy2(source, target)
            except OSError as exc:
                failures.append({"artifact": str(relative), "reason": f"copy failed: {exc}"})
                continue

            digest = sha256_file(target)
            entry = {
                "ts": _now_iso(),
                "artifact": target.name,
                "sha256": digest,
                "size": target.stat().st_size,
                "source": str(source),
                "collected_by": self.name,
                "run_id": ctx.run_id,
                "incident_id": ctx.incident_id,
                "action_id": ctx.action_id,
            }
            record_custody(ctx, entry)
            collected.append(entry)

        return {
            "collected": collected,
            "count": len(collected),
            "failures": failures,
            "evidence_dir": str(dest_dir),
            "custody_log": str(custody_path(ctx)),
        }

    def compensate(self, params: dict[str, Any], ctx: ActionContext, result: dict[str, Any]) -> dict[str, Any]:
        # Evidence is append-only and is never removed by a rollback. Deleting
        # collected evidence to "undo" a run would destroy the forensic record
        # the run exists to produce. Explicitly a no-op, deliberately.
        return {"noop": True, "reason": "evidence is append-only and is never rolled back"}