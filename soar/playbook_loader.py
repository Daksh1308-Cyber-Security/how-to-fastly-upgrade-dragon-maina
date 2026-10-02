"""Playbook loading, validation, parameter substitution and selection.

Permitted ``{{ }}`` grammar (docs/COMPONENTS.md -> ``playbook_loader``,
docs/SECURITY.md section 5):

* literal text
* ``{{ dotted.path }}`` resolved against the action context
* ``{{ dotted.path | default }}``

**Forbidden:** arithmetic, function calls, attribute access outside the context,
or any expression that is not literal-plus-substitution. There is deliberately
no ``eval`` anywhere in this project.

A path that does not resolve yields the default, or the empty string -- it never
raises mid-incident. A playbook that references a connector which is not in
``REGISTERED_CONNECTORS`` fails validation at load time rather than half-way
through a run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

import yaml

from soar.connectors.base import REGISTERED_CONNECTORS
from soar.models import Action, Playbook
from soar.nist import Phase

__all__ = [
    "PlaybookValidationError",
    "load",
    "load_all",
    "validate",
    "select",
    "substitute",
    "SEVERITY_ORDER",
    "PLAYBOOKS_DIR",
]

#: Same ordering as soar.models.SEVERITY_ORDER; duplicated here to keep this
#: module free of a models import cycle at validation time.
SEVERITY_ORDER: tuple[str, ...] = ("low", "medium", "high", "critical")

#: Default playbook directory, overridable via ``SOAR_PLAYBOOKS_DIR``.
PLAYBOOKS_DIR = Path(
    __import__("os").environ.get("SOAR_PLAYBOOKS_DIR", Path(__file__).resolve().parent.parent / "playbooks")
)

_VALID_PHASES = {str(p) for p in Phase}
_VALID_FAILURE_POLICIES = {"abort", "continue", "compensate"}

# {{ path }} or {{ path | default }} -- path is dotted alphanumerics only.
# Anything richer (operators, calls, quotes) simply will not match and is
# therefore left as literal text, which is the safe failure mode.
_TEMPLATE_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\s*(?:\|\s*([^}]*?)\s*)?\}\}")


class PlaybookValidationError(ValueError):
    """A playbook is structurally invalid. Messages list every problem found."""

    def __init__(self, problems: list[str], source: str = "<playbook>") -> None:
        self.problems = problems
        self.source = source
        detail = "; ".join(problems)
        super().__init__(f"{source}: {detail}")


def _resolve(path: str, variables: dict[str, Any]) -> tuple[Any, bool]:
    """Resolve a dotted path. Returns ``(value, found)``.

    Only plain dict traversal is allowed. Lists are addressed by index so a
    playbook can pull ``alert.context.hosts.0`` -- still pure data access, no
    attribute or method access.
    """
    current: Any = variables
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, (list, tuple)):
            try:
                index = int(part)
            except ValueError:
                return None, False
            if -len(current) <= index < len(current):
                current = current[index]
            else:
                return None, False
        else:
            return None, False
    return current, True


def substitute(value: Any, variables: dict[str, Any]) -> Any:
    """Recursively resolve ``{{ }}`` templates inside a params structure.

    Strings are templated. Dicts and lists are walked. Any other type (int,
    bool, None) is returned unchanged, so a numeric timeout or a boolean flag is
    never mangled by string formatting.

    A missing path resolves to its default, or to the empty string when no
    default was given. It does **not** raise.
    """
    if isinstance(value, str):

        def _replace(match: re.Match[str]) -> str:
            path, default = match.group(1), match.group(2)
            resolved, found = _resolve(path, variables)
            if not found or resolved is None:
                return default if default is not None else ""
            if isinstance(resolved, (dict, list)):
                return default if default is not None else ""
            return str(resolved)

        return _TEMPLATE_RE.sub(_replace, value)

    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    return value


def validate(raw: dict[str, Any]) -> list[str]:
    """Return every structural problem found in a raw playbook dict.

    An empty list means valid. Never raises -- the caller decides whether a
    non-empty result is fatal.
    """
    problems: list[str] = []

    if not isinstance(raw, dict):
        return ["playbook root must be a mapping"]

    for key in ("id", "name", "phases", "mitre_techniques", "actions"):
        if key not in raw:
            problems.append(f"missing required key {key!r}")

    for key in ("phases", "mitre_techniques", "actions"):
        value = raw.get(key)
        if key in raw and not isinstance(value, list):
            problems.append(f"{key!r} must be a list")

    min_sev = raw.get("min_severity", "low")
    if min_sev not in SEVERITY_ORDER:
        problems.append(f"min_severity {min_sev!r} not in {SEVERITY_ORDER}")

    for phase in raw.get("phases", []) or []:
        if str(phase) not in _VALID_PHASES:
            problems.append(f"unknown phase {phase!r}")

    seen_ids: set[str] = set()
    actions = raw.get("actions", []) or []
    if not actions:
        problems.append("playbook declares no actions")

    for index, action in enumerate(actions):
        where = f"actions[{index}]"
        if not isinstance(action, dict):
            problems.append(f"{where} must be a mapping")
            continue

        action_id = action.get("id")
        if not action_id:
            problems.append(f"{where} missing required key 'id'")
        elif action_id in seen_ids:
            problems.append(f"duplicate action id {action_id!r}")
        else:
            seen_ids.add(action_id)

        phase = action.get("phase")
        if not phase:
            problems.append(f"{where} missing required key 'phase'")
        elif str(phase) not in _VALID_PHASES:
            problems.append(f"{where} has unknown phase {phase!r}")

        connector = action.get("connector")
        if not connector:
            problems.append(f"{where} missing required key 'connector'")
        elif connector not in REGISTERED_CONNECTORS:
            problems.append(
                f"{where} names connector {connector!r} which is not registered "
                f"(see docs/ARCHITECTURE.md section 3.1)"
            )

        params = action.get("params", {})
        if not isinstance(params, dict):
            problems.append(f"{where} params must be a mapping")

        policy = action.get("on_failure", "abort")
        if policy not in _VALID_FAILURE_POLICIES:
            problems.append(f"{where} on_failure {policy!r} not in {_VALID_FAILURE_POLICIES}")

        timeout = action.get("timeout_seconds", 300)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
            problems.append(f"{where} timeout_seconds must be a positive integer")

        requires_approval = action.get("requires_approval", False)
        if not isinstance(requires_approval, bool):
            problems.append(f"{where} requires_approval must be a boolean")

    # A playbook must be able to reach recovery, or an incident it handles
    # could never be closed (docs/ARCHITECTURE.md section 4).
    phases_used = {str(a.get("phase")) for a in actions if isinstance(a, dict)}
    if actions and str(Phase.RECOVERY) not in phases_used:
        problems.append(
            "playbook has no recovery-phase action; incidents it handles could never be closed"
        )

    return problems


def _to_playbook(raw: dict[str, Any], source: str) -> Playbook:
    actions = [
        Action(
            id=a["id"],
            name=a.get("name", a["id"]),
            phase=Phase(str(a["phase"])),
            connector=a["connector"],
            params=dict(a.get("params", {}) or {}),
            timeout_seconds=int(a.get("timeout_seconds", 300)),
            requires_approval=bool(a.get("requires_approval", False)),
            on_failure=a.get("on_failure", "abort"),
            compensates=a.get("compensates"),
            forward_only=bool(a.get("forward_only", False)),
        )
        for a in raw["actions"]
    ]
    return Playbook(
        id=raw["id"],
        name=raw["name"],
        description=raw.get("description", ""),
        phases=[Phase(str(p)) for p in raw["phases"]],
        mitre_techniques=[str(t) for t in raw["mitre_techniques"]],
        min_severity=raw.get("min_severity", "low"),
        actions=actions,
    )


def load(path: str | Path) -> Playbook:
    """Load and validate a single playbook. Raises :class:`PlaybookValidationError`."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    problems = validate(raw)
    if problems:
        raise PlaybookValidationError(problems, source=path.name)
    return _to_playbook(raw, str(path))


def load_all(directory: str | Path | None = None) -> list[Playbook]:
    """Load every ``*.yaml`` playbook in a directory, sorted by filename.

    A single invalid playbook raises -- a broken playbook on disk should be a
    startup failure, not a surprise during an incident.
    """
    directory = Path(directory) if directory else PLAYBOOKS_DIR
    if not directory.is_dir():
        return []
    playbooks: list[Playbook] = []
    for path in sorted(directory.glob("*.yaml")):
        playbooks.append(load(path))
    return playbooks


def select(playbooks: Iterable[Playbook], alert: dict[str, Any], severity: str) -> Playbook | None:
    """Pick the playbook for an alert, or ``None`` if nothing covers it.

    Matching is by MITRE technique only, in order:

    1. An exact technique match.
    2. A parent-technique match, so ``T1486.001`` selects a ``T1486`` playbook.

    **There is deliberately no severity-based fallback.** An earlier draft fell
    back to "the most permissive playbook available", which handed a phishing
    alert to the ransomware playbook purely because both cleared the severity
    floor. Running the wrong containment procedure during a real incident is
    worse than running none, so an uncovered technique returns ``None``.

    The caller records the incident with ``playbook_id=None`` and it surfaces in
    ``GET /playbooks`` as a gap (``docs/PLAN.md`` W3.4). That is the honest
    outcome: the alert was triaged, and the coverage hole is now visible.

    Args:
        playbooks: Candidate playbooks.
        alert: The alert payload.
        severity: Already-computed severity band. Accepted for signature
            stability and future use; it does not currently affect selection.

    Returns:
        The matching playbook, or ``None`` when the technique is uncovered.
    """
    playbooks = list(playbooks)
    if not playbooks:
        return None

    technique = str(alert.get("mitre", {}).get("technique_id", "") or "").strip()
    if not technique:
        return None

    for playbook in playbooks:
        if technique in playbook.mitre_techniques:
            return playbook

    parent = technique.split(".", 1)[0]
    for playbook in playbooks:
        if any(t.split(".", 1)[0] == parent for t in playbook.mitre_techniques):
            return playbook

    return None