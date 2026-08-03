"""Fleet-level diffing — the part that turns an inventory tool into a monitor.

Posture says "TeamViewer is installed on 40 hosts". Your helpdesk probably put it
there, so that line gets skimmed and then ignored. Drift says "AnyDesk appeared
on 3 hosts since yesterday, none of them IT", and that is an incident.

Two rules keep this from generating noise:

1. **Only meaningful transitions.** New software appearing is interesting.
   Software disappearing is mildly interesting. A version changing is routine
   and is reported only when the software is already flagged as risky.

2. **Fleet-wide aggregation.** Something new on 400 hosts is a deployment, not
   an intrusion, and it produces one finding rather than 400. Something new on
   two hosts is the shape of a targeted compromise and is reported as such —
   with the hosts named.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from .models import (
    Finding,
    FindingKind,
    Host,
    HostSnapshot,
    Inventory,
    RiskCategory,
    Severity,
)
from .rules.catalog import CatalogMatcher
from .rules.decisions import VERDICT_ALLOW, DecisionStore
from .validation import normalize_software_name

log = logging.getLogger(__name__)

# Above this share of the fleet, a new package is a rollout rather than an
# anomaly, and is reported at INFO with no host list.
_FLEETWIDE_SHARE = 0.25
_MAX_HOSTS_NAMED = 10
_MAX_DRIFT_FINDINGS = 200


def _hosts(count: int) -> str:
    """Pluralise without parentheses.

    Titles are escaped for Markdown before rendering, so "host(s)" would come
    out as "host\\(s\\)". Cheaper to write correct English than to un-escape.
    """
    return "host" if count == 1 else "hosts"


@dataclass(slots=True)
class _Appearance:
    """One package that appeared, and where."""

    name: str
    normalized: str
    source: str
    hosts: list[str] = field(default_factory=list)
    versions: set[str] = field(default_factory=set)


def diff_inventories(
    previous: dict[str, HostSnapshot] | None,
    current: Inventory,
    *,
    catalog: CatalogMatcher,
    decisions: DecisionStore,
    ignore: set[str],
    allowlist: set[str],
    host_label: Callable[[Host], str],
) -> list[Finding]:
    """Compare the current inventory against the stored baseline.

    Returns an empty list when there is no baseline. A first run has nothing to
    compare against, and manufacturing findings there would misrepresent an
    existing estate as a set of changes.
    """
    if not previous:
        return []

    findings: list[Finding] = []
    appearances: dict[str, _Appearance] = {}
    disappearances: dict[str, _Appearance] = {}
    total_hosts = max(len(current.hosts), 1)

    for snapshot in current.hosts:
        host = snapshot.host
        baseline = previous.get(host.host_id)
        if baseline is None or not baseline.software:
            # A host we have never seen, or one whose previous snapshot was
            # empty — Fleet returns an empty software list for a host that has
            # enrolled but not yet reported inventory. Diffing against either
            # reports the whole machine as newly installed, and a new laptop is
            # not 200 incidents.
            continue

        before = {item.key: item for item in baseline.software}
        after = {item.key: item for item in snapshot.software}

        for key, item in after.items():
            if key in before:
                continue
            normalized = normalize_software_name(item.name)
            if not normalized or normalized in ignore or normalized in allowlist:
                continue
            decision = decisions.active_for(normalized)
            if decision is not None and decision.verdict == VERDICT_ALLOW:
                continue
            entry = appearances.setdefault(
                normalized, _Appearance(name=item.name, normalized=normalized, source=item.source)
            )
            entry.hosts.append(host_label(host))
            if item.version:
                entry.versions.add(item.version)

        for key, item in before.items():
            if key in after:
                continue
            normalized = normalize_software_name(item.name)
            if not normalized or normalized in ignore:
                continue
            # Only track removal of software that was *interesting*. A routine
            # uninstall of a font pack is not worth a line in a security report.
            if not catalog.match(normalized):
                continue
            entry = disappearances.setdefault(
                normalized, _Appearance(name=item.name, normalized=normalized, source=item.source)
            )
            entry.hosts.append(host_label(host))

    findings.extend(
        _appearance_findings(appearances, catalog=catalog, decisions=decisions, total_hosts=total_hosts)
    )
    findings.extend(_disappearance_findings(disappearances))

    if len(findings) > _MAX_DRIFT_FINDINGS:
        dropped = len(findings) - _MAX_DRIFT_FINDINGS
        findings.sort(key=lambda f: -f.severity.rank)
        findings = findings[:_MAX_DRIFT_FINDINGS]
        findings.append(
            Finding(
                host_display="fleet",
                host_id="fleet",
                software="",
                version="",
                kind=FindingKind.OPERATIONAL,
                severity=Severity.LOW,
                category=RiskCategory.UNKNOWN,
                title=f"{dropped} further changes were not reported",
                detail=(
                    "The number of changes since the last scan exceeded the reporting cap. "
                    "This usually means a large deployment, or that the baseline is stale."
                ),
                remediation="Compare against the previous snapshot directly if you need the full list.",
            )
        )

    return findings


def _appearance_findings(
    appearances: dict[str, _Appearance],
    *,
    catalog: CatalogMatcher,
    decisions: DecisionStore,
    total_hosts: int,
) -> list[Finding]:
    findings: list[Finding] = []

    for normalized, entry in sorted(appearances.items()):
        host_count = len(entry.hosts)
        share = host_count / total_hosts
        matched = catalog.match(normalized)
        decision = decisions.active_for(normalized)

        if matched:
            rule = matched[0]
            category = rule.category
            base_severity = rule.severity
            context = rule.detail
        elif decision is not None:
            category = decision.category
            base_severity = decision.severity
            context = decision.note or "Flagged by an approved entry in the decision file."
        else:
            category = RiskCategory.UNKNOWN
            base_severity = Severity.LOW
            context = (
                "This software has not been classified. It is reported because it is new, "
                "not because it is known to be risky."
            )

        if share >= _FLEETWIDE_SHARE and host_count > 5:
            # Present on a quarter of the estate overnight: a rollout.
            severity = Severity.INFO if not matched else min(base_severity, Severity.LOW)
            title = f"{entry.name} was deployed across {host_count} hosts"
            detail = (
                f"Appeared on {host_count} of {total_hosts} hosts since the last scan, which "
                "looks like a managed deployment rather than an anomaly. " + context
            )
        else:
            severity = base_severity
            named = ", ".join(sorted(entry.hosts)[:_MAX_HOSTS_NAMED])
            more = "" if host_count <= _MAX_HOSTS_NAMED else f" (+{host_count - _MAX_HOSTS_NAMED} more)"
            title = f"{entry.name} appeared on {host_count} {_hosts(host_count)}"
            detail = f"New since the last scan on: {named}{more}. " + context

        findings.append(
            Finding(
                host_display=entry.hosts[0] if host_count == 1 else f"{host_count} hosts",
                host_id="fleet" if host_count > 1 else entry.hosts[0],
                software=entry.name,
                version=", ".join(sorted(entry.versions)[:3]),
                kind=FindingKind.DRIFT,
                severity=severity,
                category=category,
                title=title,
                detail=detail,
                remediation=(
                    "Confirm this install was expected. If it was, allowlist it so the next "
                    "unexpected one stands out."
                ),
                evidence={
                    "hosts": sorted(entry.hosts)[:_MAX_HOSTS_NAMED],
                    "host_count": host_count,
                    "source": entry.source,
                },
                references=matched[0].references if matched else (),
            )
        )

    return findings


def _disappearance_findings(disappearances: dict[str, _Appearance]) -> list[Finding]:
    findings: list[Finding] = []
    for _normalized, entry in sorted(disappearances.items()):
        host_count = len(entry.hosts)
        findings.append(
            Finding(
                host_display=entry.hosts[0] if host_count == 1 else f"{host_count} hosts",
                host_id="fleet" if host_count > 1 else entry.hosts[0],
                software=entry.name,
                version="",
                kind=FindingKind.DRIFT,
                severity=Severity.INFO,
                category=RiskCategory.UNKNOWN,
                title=f"{entry.name} was removed from {host_count} {_hosts(host_count)}",
                detail=(
                    "Previously-flagged software is no longer present. Recorded so the "
                    "report reflects remediation as well as regression."
                ),
                evidence={"hosts": sorted(entry.hosts)[:_MAX_HOSTS_NAMED], "host_count": host_count},
            )
        )
    return findings
