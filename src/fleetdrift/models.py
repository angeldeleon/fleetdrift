"""Core data model.

Plain dataclasses on purpose: a tool that makes claims about employees' machines
should be auditable by reading it, without the reader having to understand a
validation framework first.

Two types carry the weight. :class:`SoftwareItem` is one installed package on one
host, normalised across the very different shapes osquery returns per platform.
:class:`Finding` is one thing a human should look at, and always names the host
and the software that caused it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .validation import scrub_evidence


class Severity(str, Enum):
    """Finding severity, ordered.

    ``rank`` drives comparisons and exit-code thresholds; the string value is
    what humans and JSON consumers see.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {raw!r} (expected one of: {valid})") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Platform(str, Enum):
    MACOS = "macos"
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, raw: str | None) -> Platform:
        text = (raw or "").strip().lower()
        if text in ("darwin", "macos", "mac os x", "macosx", "apple"):
            return cls.MACOS
        if text.startswith("win"):
            return cls.WINDOWS
        if text in ("linux", "ubuntu", "debian", "rhel", "centos", "fedora", "rocky", "alma", "amzn"):
            return cls.LINUX
        return cls.UNKNOWN


class FindingKind(str, Enum):
    """Why a finding exists.

    POSTURE describes what is on the fleet right now. DRIFT describes a change
    since the previous scan. OPERATIONAL means the tool itself could not
    complete something and is saying so rather than reporting a clean result.
    """

    POSTURE = "posture"
    DRIFT = "drift"
    OPERATIONAL = "operational"


class RiskCategory(str, Enum):
    """Why a piece of software is interesting.

    Categories are deliberately coarse. A security team triages by "is this a
    remote-access tool we didn't deploy", not by a 0-100 score whose derivation
    nobody can reconstruct.
    """

    REMOTE_ACCESS = "remote_access"
    CRYPTOMINER = "cryptominer"
    CREDENTIAL_TOOL = "credential_tool"
    OFFENSIVE_TOOL = "offensive_tool"
    UNSANCTIONED_VPN = "unsanctioned_vpn"
    FILE_SHARING = "file_sharing"
    EOL_SOFTWARE = "eol_software"
    VULNERABLE = "vulnerable"
    UNSIGNED = "unsigned"
    NOT_ALLOWLISTED = "not_allowlisted"
    DENYLISTED = "denylisted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Host:
    """One endpoint.

    ``host_id`` is the stable identifier used for joins and drift. ``display``
    is what a human sees and may be pseudonymised — see :mod:`fleetdrift.privacy`.
    """

    host_id: str
    display: str
    platform: Platform = Platform.UNKNOWN
    os_version: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["platform"] = self.platform.value
        return out


@dataclass(frozen=True, slots=True)
class SoftwareItem:
    """One installed package on one host, normalised across platforms.

    ``key`` is what drift and rules match on. It is derived from the normalised
    name plus the source, deliberately excluding the version so that an upgrade
    reads as a version change rather than as "removed one thing, installed
    another".
    """

    host_id: str
    name: str
    version: str = ""
    source: str = ""  # apps / programs / deb_packages / rpm_packages / chrome_extensions
    publisher: str = ""
    install_path: str = ""
    signed: bool | None = None  # None = unknown, not "unsigned"
    signature_authority: str = ""

    @property
    def key(self) -> str:
        return f"{self.source}::{self.name.strip().lower()}"

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}".strip()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a human should look at."""

    host_display: str
    host_id: str
    software: str
    version: str
    kind: FindingKind
    severity: Severity
    category: RiskCategory
    title: str
    detail: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    references: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        """Stable ID for deduplication and alert suppression.

        Excludes ``detail``, ``version`` and ``evidence`` so that rewording a
        rule, or a routine version bump, does not resurface a finding somebody
        already triaged.
        """
        raw = f"{self.host_id}|{self.software.lower()}|{self.category.value}|{self.kind.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["kind"] = self.kind.value
        out["severity"] = self.severity.value
        out["category"] = self.category.value
        out["references"] = list(self.references)
        # Scrubbed here, at the one place every sink goes through, rather than
        # in each renderer. Evidence carries osquery row fields and an
        # operator's own catalog entries, both of which can name anything.
        out["evidence"] = scrub_evidence(self.evidence)
        out["fingerprint"] = self.fingerprint
        return out


@dataclass(slots=True)
class HostSnapshot:
    """Everything observed about one host in one collection."""

    host: Host
    software: list[SoftwareItem] = field(default_factory=list)

    def software_keys(self) -> set[str]:
        return {item.key for item in self.software}


@dataclass(slots=True)
class Inventory:
    """One complete collection across the fleet."""

    collected_at: str
    source: str
    hosts: list[HostSnapshot] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def software_count(self) -> int:
        return sum(len(h.software) for h in self.hosts)


# Serialisation caps. Both sit far above any healthy run and well below the
# point where a JSON report stops being a file anybody can open.
MAX_SERIALISED_FINDINGS = 2000
MAX_SERIALISED_ERRORS = 200


@dataclass(slots=True)
class ScanReport:
    """Everything one ``fleetdrift scan`` produced."""

    started_at: str
    finished_at: str
    tool_version: str
    source: str
    hosts_scanned: int = 0
    software_seen: int = 0
    findings: list[Finding] = field(default_factory=list)
    baseline_available: bool = False
    collection_errors: list[str] = field(default_factory=list)
    ai_summary: str | None = None
    unknown_software: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def scan_degraded(self) -> bool:
        """True when the collection failed badly enough that "no findings" is a lie.

        A fleet tool that reports a clean result because it could not reach the
        fleet manager is worse than one that fails loudly: the dashboard goes
        green and everyone assumes the estate is healthy.
        """
        return self.hosts_scanned == 0

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def affected_hosts(self) -> int:
        return len({f.host_id for f in self.findings if f.kind is not FindingKind.OPERATIONAL})

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "fleetdrift",
            "tool_version": self.tool_version,
            "source": self.source,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "hosts_scanned": self.hosts_scanned,
            "software_seen": self.software_seen,
            "affected_hosts": self.affected_hosts(),
            "baseline_available": self.baseline_available,
            "scan_degraded": self.scan_degraded,
            "counts_by_severity": self.counts_by_severity(),
            "collection_errors": self.collection_errors[:MAX_SERIALISED_ERRORS],
            # Capped: the Markdown renderer already truncates, and an estate
            # with thousands of unclassified packages would otherwise ship the
            # whole list to a webhook.
            "unknown_software": self.unknown_software[:200],
            "unknown_software_total": len(self.unknown_software),
            # Capped for the same reason unknown_software is: an estate with a
            # bad week can produce more findings than any report reader or
            # webhook receiver will accept, and the run that found the most must
            # not be the one whose output nobody can open. The total stays whole
            # above the cap so a consumer can tell it is reading a subset.
            "findings": [f.to_dict() for f in self.findings[:MAX_SERIALISED_FINDINGS]],
            "findings_total": len(self.findings),
            "findings_truncated": len(self.findings) > MAX_SERIALISED_FINDINGS,
            "ai_summary": self.ai_summary,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
