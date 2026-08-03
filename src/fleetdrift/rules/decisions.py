"""The human-approved decision file — where the tool actually "learns".

When unfamiliar software shows up, the optional AI layer can propose a
classification. That proposal is written here with ``status: pending`` and has
**no effect on any finding**. A human changes it to ``approved`` or
``rejected``; only then does it influence a scan.

This is the whole design, and it is deliberate:

* **Deterministic.** Two scans of the same fleet produce the same findings,
  because classification comes from a file, not from a model's mood.
* **Auditable.** ``git log`` on this file is a complete record of who decided
  what about which software, and when. That answers an auditor's question in a
  way "the model classified it" never will.
* **Not injectable.** Software names are attacker-chosen, so a model that
  classified them directly would be taking instructions from the thing it is
  meant to be judging. Here the model only ever proposes, and a human always
  disposes.

The knowledge accumulates in the reviewed file. The model is a drafting aid.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..models import RiskCategory, Severity
from ..validation import ValidationError, normalize_software_name, safe_text

log = logging.getLogger(__name__)

FILE_VERSION = 1
_MAX_DECISIONS = 20000

STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_PENDING = "pending"
_VALID_STATUS = (STATUS_APPROVED, STATUS_REJECTED, STATUS_PENDING)

VERDICT_ALLOW = "allow"
VERDICT_FLAG = "flag"
_VALID_VERDICT = (VERDICT_ALLOW, VERDICT_FLAG)


@dataclass(slots=True)
class Decision:
    """One classification of one piece of software."""

    name: str  # normalised
    status: str = STATUS_PENDING
    verdict: str = VERDICT_FLAG
    category: RiskCategory = RiskCategory.UNKNOWN
    severity: Severity = Severity.MEDIUM
    note: str = ""
    proposed_by: str = "human"
    reviewed_by: str = ""
    updated_at: str = ""

    @property
    def active(self) -> bool:
        """Only an approved decision affects a scan."""
        return self.status == STATUS_APPROVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "verdict": self.verdict,
            "category": self.category.value,
            "severity": self.severity.value,
            "note": self.note,
            "proposed_by": self.proposed_by,
            "reviewed_by": self.reviewed_by,
            "updated_at": self.updated_at,
        }


def _decision_from_mapping(raw: Any, index: int) -> Decision:
    if not isinstance(raw, dict):
        raise ValidationError(f"decision {index} must be a mapping")

    allowed = {
        "name",
        "status",
        "verdict",
        "category",
        "severity",
        "note",
        "proposed_by",
        "reviewed_by",
        "updated_at",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValidationError(f"decision {index} has unknown key(s): {', '.join(unknown)}")

    name = normalize_software_name(raw.get("name", ""))
    if not name:
        raise ValidationError(f"decision {index} has no usable 'name'")

    status = str(raw.get("status", STATUS_PENDING)).strip().lower()
    if status not in _VALID_STATUS:
        raise ValidationError(
            f"decision {index} has status {status!r} (expected one of: {', '.join(_VALID_STATUS)})"
        )

    verdict = str(raw.get("verdict", VERDICT_FLAG)).strip().lower()
    if verdict not in _VALID_VERDICT:
        raise ValidationError(
            f"decision {index} has verdict {verdict!r} (expected one of: {', '.join(_VALID_VERDICT)})"
        )

    try:
        category = RiskCategory(str(raw.get("category", "unknown")).strip().lower())
    except ValueError as exc:
        raise ValidationError(f"decision {index} has an unknown category") from exc

    return Decision(
        name=name,
        status=status,
        verdict=verdict,
        category=category,
        severity=Severity.parse(str(raw.get("severity", "medium"))),
        note=safe_text(raw.get("note") or "", limit=500),
        proposed_by=safe_text(raw.get("proposed_by") or "human", limit=64),
        reviewed_by=safe_text(raw.get("reviewed_by") or "", limit=128),
        updated_at=safe_text(raw.get("updated_at") or "", limit=64),
    )


class DecisionStore:
    """Loads, queries and updates the decision file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self._decisions: dict[str, Decision] = {}
        self._loaded = False

    def load(self) -> dict[str, Decision]:
        if self._loaded:
            return self._decisions
        self._loaded = True

        if not self.path.exists():
            return self._decisions

        if self.path.stat().st_size > 10 * 1024 * 1024:
            raise ValidationError(f"decision file is too large: {self.path}")

        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValidationError(f"decision file is not valid YAML: {exc}") from exc

        if raw is None:
            return self._decisions
        if not isinstance(raw, dict):
            raise ValidationError("decision file must be a mapping with a 'decisions' key")

        version = raw.get("version", FILE_VERSION)
        if version != FILE_VERSION:
            raise ValidationError(
                f"decision file has version {version!r}; this build understands {FILE_VERSION}"
            )

        entries = raw.get("decisions") or []
        if not isinstance(entries, list):
            raise ValidationError("decision file 'decisions' must be a list")
        if len(entries) > _MAX_DECISIONS:
            raise ValidationError(f"decision file has more than {_MAX_DECISIONS} entries")

        for index, item in enumerate(entries):
            decision = _decision_from_mapping(item, index)
            self._decisions[decision.name] = decision

        approved = sum(1 for d in self._decisions.values() if d.active)
        pending = sum(1 for d in self._decisions.values() if d.status == STATUS_PENDING)
        log.info(
            "loaded %d decision(s) from %s (%d approved, %d awaiting review)",
            len(self._decisions),
            self.path,
            approved,
            pending,
        )
        return self._decisions

    def get(self, normalized_name: str) -> Decision | None:
        return self.load().get(normalized_name)

    def active_for(self, normalized_name: str) -> Decision | None:
        decision = self.get(normalized_name)
        return decision if decision and decision.active else None

    def known_names(self) -> set[str]:
        """Every name with a decision, at any status.

        Includes pending and rejected entries deliberately: once a name has been
        seen and written down, it should not be proposed again on every run.
        """
        return set(self.load())

    def add_proposals(self, proposals: list[Decision]) -> int:
        """Record new proposals as ``pending``. Never overwrites an existing entry.

        Returns the number actually added. A name already present — approved,
        rejected, or still pending — is left exactly as it is, so a model cannot
        overturn or re-litigate a human's decision.
        """
        current = self.load()
        added = 0
        for proposal in proposals:
            if proposal.name in current:
                continue
            proposal.status = STATUS_PENDING
            proposal.updated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            current[proposal.name] = proposal
            added += 1

        if added:
            self.save()
        return added

    def save(self) -> None:
        """Write atomically at 0600.

        Atomic because an interrupted write that truncated this file would
        silently discard every classification the team had made.
        """
        payload = {
            "version": FILE_VERSION,
            "decisions": [d.to_dict() for _, d in sorted(self.load().items())],
        }
        serialized = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=100)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".fleetdrift-decisions-", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(_FILE_HEADER)
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        finally:
            # On success os.replace already consumed the temp file; this only
            # fires when the write failed partway and left one behind.
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)


_FILE_HEADER = """\
# fleetdrift decisions
#
# Entries with `status: pending` have NO effect. They are drafts — usually
# proposed by the optional AI triage layer — waiting for a human.
#
# To act on one, set `status: approved` and fill in `reviewed_by`:
#   verdict: allow  -> stop reporting this software
#   verdict: flag   -> report it, using the category and severity below
#
# Set `status: rejected` to dismiss a proposal without deleting it, so it is
# not proposed again.
#
# Commit this file. Its git history is the audit trail for who decided what.
"""
