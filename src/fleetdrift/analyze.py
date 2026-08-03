"""Turning an inventory into findings.

Precedence matters and is fixed here, because the same package can trip several
rules and reporting it three times is how a tool becomes noise:

1. ``policy.ignore`` — never reported, at all.
2. An **approved** decision — the team has already ruled on this, and their
   ruling beats every heuristic below.
3. ``policy.denylist`` — explicitly forbidden by the operator.
4. The catalog — capability-based classification.
5. Everything else — allowlist deviation, signature, vulnerabilities.

Steps 2 and 3 short-circuit. A package the team approved does not also get
flagged by the catalog, and a denylisted package does not need a catalog opinion.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from .config import Config
from .models import (
    Finding,
    FindingKind,
    Host,
    Inventory,
    RiskCategory,
    Severity,
    SoftwareItem,
)
from .rules.catalog import CatalogMatcher
from .rules.decisions import VERDICT_ALLOW, DecisionStore
from .rules.vulns import OSVClient, build_queries
from .validation import normalize_software_name

log = logging.getLogger(__name__)

# Per-host cap. A single misconfigured host must not be able to drown the report
# for the rest of the fleet; the count is reported instead.
MAX_FINDINGS_PER_HOST = 50


class Analyzer:
    """Applies the deterministic rule set to an inventory."""

    def __init__(
        self,
        config: Config,
        *,
        catalog: CatalogMatcher,
        decisions: DecisionStore,
        host_label: Callable[[Host], str],
        identified: bool = False,
    ) -> None:
        self.config = config
        self.catalog = catalog
        self.decisions = decisions
        self.host_label = host_label
        # In pseudonymous mode an install path is a re-identifier: it usually
        # contains the employee's account name, which undoes the pseudonym
        # sitting next to it in the same finding.
        self.identified = identified
        self.unknown_software: set[str] = set()
        self.errors: list[str] = []

    # ------------------------------------------------------------------

    def analyze(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        checks = set(self.config.settings.checks)
        policy = self.config.policy

        ignore = set(policy.ignore)
        allowlist = set(policy.allowlist)
        denylist = set(policy.denylist)

        for snapshot in inventory.hosts:
            host = snapshot.host
            label = self.host_label(host)
            host_findings: list[Finding] = []

            for item in snapshot.software:
                normalized = normalize_software_name(item.name)
                if not normalized or normalized in ignore:
                    continue

                decision = self.decisions.active_for(normalized)
                if decision is not None:
                    if decision.verdict == VERDICT_ALLOW:
                        continue
                    host_findings.append(
                        _finding(
                            host,
                            label,
                            item,
                            severity=decision.severity,
                            category=decision.category,
                            title=f"{item.name} is flagged by local policy",
                            detail=decision.note or "Classified by an approved entry in the decision file.",
                            remediation="Review the decision file entry if this is no longer correct.",
                            evidence={"decision": decision.name, "reviewed_by": decision.reviewed_by},
                        )
                    )
                    continue

                if "denylist" in checks and normalized in denylist:
                    host_findings.append(
                        _finding(
                            host,
                            label,
                            item,
                            severity=Severity.HIGH,
                            category=RiskCategory.DENYLISTED,
                            title=f"{item.name} is on the denylist",
                            detail="This software is explicitly forbidden by policy.",
                            remediation="Remove it, or amend policy.denylist if the policy changed.",
                        )
                    )
                    continue

                matched = False
                if "catalog" in checks or "eol" in checks:
                    for entry in self.catalog.match(normalized)[:1]:
                        # End-of-life entries are gated separately. They are the
                        # noisiest category by a wide margin -- every estate has
                        # some -- and an operator who mutes them should not have
                        # to give up cryptominer and credential-tool rules to do
                        # it. Before this, "eol" was accepted by config
                        # validation and read by nothing, so `checks: [eol]`
                        # produced a permanently green, permanently blind scan.
                        wanted = "eol" if entry.category is RiskCategory.EOL_SOFTWARE else "catalog"
                        if wanted not in checks:
                            continue
                        matched = True
                        host_findings.append(
                            _finding(
                                host,
                                label,
                                item,
                                severity=entry.severity,
                                category=entry.category,
                                title=entry.title,
                                detail=entry.detail,
                                remediation=entry.remediation,
                                evidence={"rule": entry.id, "publisher": item.publisher},
                                references=entry.references,
                            )
                        )

                if "signature" in checks and item.signed is False:
                    host_findings.append(
                        _finding(
                            host,
                            label,
                            item,
                            severity=Severity.MEDIUM,
                            category=RiskCategory.UNSIGNED,
                            title=f"{item.name} is not code-signed",
                            detail=(
                                "The binary carries no valid code signature. Legitimate "
                                "software from a real vendor is signed; unsigned "
                                "applications are either hand-built, tampered with, or "
                                "were never vendor software to begin with."
                            ),
                            remediation="Confirm provenance. Unsigned software on a managed endpoint warrants an explanation.",
                            evidence=({"install_path": item.install_path} if self.identified else {}),
                        )
                    )

                if "allowlist" in checks and policy.enforce_allowlist and normalized not in allowlist:
                    host_findings.append(
                        _finding(
                            host,
                            label,
                            item,
                            severity=Severity.LOW,
                            category=RiskCategory.NOT_ALLOWLISTED,
                            title=f"{item.name} is not on the approved software list",
                            detail="Installed software that does not appear in policy.allowlist.",
                            remediation="Approve it by adding to policy.allowlist, or remove it.",
                        )
                    )

                if (
                    not matched
                    and normalized not in allowlist
                    and normalized not in self.decisions.known_names()
                ):
                    # A candidate for triage. Never a finding on its own —
                    # "software I have not seen before" describes most of a real
                    # estate and says nothing about risk.
                    self.unknown_software.add(normalized)

            if len(host_findings) > MAX_FINDINGS_PER_HOST:
                dropped = len(host_findings) - MAX_FINDINGS_PER_HOST
                host_findings.sort(key=lambda f: -f.severity.rank)
                host_findings = host_findings[:MAX_FINDINGS_PER_HOST]
                host_findings.append(
                    Finding(
                        host_display=label,
                        host_id=label,
                        software="",
                        version="",
                        kind=FindingKind.OPERATIONAL,
                        severity=Severity.LOW,
                        category=RiskCategory.UNKNOWN,
                        title=f"{dropped} further findings on this host were not reported",
                        detail=(
                            f"This host produced more than {MAX_FINDINGS_PER_HOST} findings. "
                            "The most severe are shown; the rest are suppressed so one "
                            "misconfigured machine cannot drown out the fleet."
                        ),
                        remediation="Investigate this host directly rather than through the report.",
                    )
                )

            findings.extend(host_findings)

        if "vulnerabilities" in checks:
            findings.extend(self._vulnerability_findings(inventory))

        return findings

    # ------------------------------------------------------------------

    def _vulnerability_findings(self, inventory: Inventory) -> list[Finding]:
        pairs = [(snapshot.host, snapshot.software) for snapshot in inventory.hosts]
        queries, index, skipped = build_queries(pairs)

        if not queries:
            if skipped:
                self.errors.append(
                    f"vulnerability check: no packages with a determinable ecosystem "
                    f"({skipped} skipped; Linux packages only — see the README)"
                )
            return []

        client = OSVClient(
            timeout=self.config.settings.http_timeout, user_agent=self.config.settings.user_agent
        )
        results, errors = client.query(queries)
        self.errors.extend(errors)

        if skipped:
            self.errors.append(
                f"vulnerability check covered {len(queries)} package(s); {skipped} skipped "
                "because no OSV ecosystem could be determined (macOS and Windows software "
                "is not covered — see the README)"
            )

        findings: list[Finding] = []
        for key, ids in sorted(results.items()):
            for item in index.get(key, []):
                host = next((s.host for s in inventory.hosts if s.host.host_id == item.host_id), None)
                if host is None:  # pragma: no cover - defensive
                    continue
                findings.append(
                    _finding(
                        host,
                        self.host_label(host),
                        item,
                        severity=Severity.MEDIUM,
                        category=RiskCategory.VULNERABLE,
                        title=f"{item.name} {item.version} has {len(ids)} known advisory/advisories",
                        detail=(
                            f"OSV lists {len(ids)} advisory/advisories affecting this package "
                            f"version in the {key[0]} ecosystem. Severity is not differentiated "
                            "here because the batch API does not return it — follow the "
                            "identifiers to triage."
                        ),
                        remediation="Update the package through your normal patch process.",
                        evidence={"advisories": ids, "ecosystem": key[0]},
                        references=tuple(f"https://osv.dev/vulnerability/{i}" for i in ids[:5]),
                    )
                )
        return findings


def _finding(
    host: Host,
    label: str,
    item: SoftwareItem,
    *,
    severity: Severity,
    category: RiskCategory,
    title: str,
    detail: str,
    remediation: str = "",
    evidence: dict | None = None,
    references: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        host_display=label,
        # The pseudonym, not the raw identifier. Findings reach the JSON report
        # and the outbound webhook; the raw id stays in the local 0600 database.
        host_id=label,
        software=item.name,
        version=item.version,
        kind=FindingKind.POSTURE,
        severity=severity,
        category=category,
        title=title,
        detail=detail,
        remediation=remediation,
        evidence={**(evidence or {}), "source": item.source},
        references=references,
    )
