"""Scan orchestration.

Collect, analyse, diff against the baseline, persist, report. Kept out of the
CLI so the whole pipeline can be tested without a process boundary.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from . import __version__
from .analyze import Analyzer
from .config import Config
from .drift import diff_inventories
from .models import Host, Inventory, ScanReport
from .privacy import PrivacyMode, Pseudonymiser
from .rules.catalog import CatalogMatcher, load_catalog
from .rules.decisions import DecisionStore
from .sources import FleetSource, ResultLogSource
from .sources.base import SourceError
from .store import SnapshotStore

log = logging.getLogger(__name__)


def state_scope(config: Config) -> str:
    """A stable namespace for this config's snapshots.

    Derived from the source type and its target so that two configs sharing a
    state file keep separate baselines. Hashed rather than stored plainly
    because a Fleet URL can be an internal hostname.
    """
    if config.source.type == "fleet" and config.source.fleet is not None:
        target = config.source.fleet.url
    elif config.source.resultlog is not None:
        target = str(Path(config.source.resultlog.path).expanduser().resolve())
    else:  # pragma: no cover - config parsing guarantees one of the two
        target = ""
    digest = hashlib.sha256(f"{config.source.type}:{target}".encode()).hexdigest()
    return f"{config.source.type}-{digest[:12]}"


def build_source(config: Config):  # type: ignore[no-untyped-def]
    """Construct the configured source. Read-only by construction."""
    if config.source.type == "fleet":
        if config.source.fleet is None:  # pragma: no cover - guaranteed by config parsing
            raise SourceError("fleet source is selected but not configured")
        return FleetSource(
            config.source.fleet,
            timeout=config.settings.http_timeout,
            user_agent=config.settings.user_agent,
            max_hosts=config.settings.max_hosts,
        )
    if config.source.resultlog is None:  # pragma: no cover - guaranteed by config parsing
        raise SourceError("resultlog source is selected but not configured")
    return ResultLogSource(config.source.resultlog, max_hosts=config.settings.max_hosts)


def collect(config: Config) -> Inventory:
    return build_source(config).collect()


def scan(
    config: Config,
    *,
    inventory: Inventory | None = None,
    store: SnapshotStore | None = None,
    save: bool = True,
) -> ScanReport:
    """Run a full scan and return the report."""
    started = Inventory.now_iso()

    if inventory is None:
        inventory = collect(config)

    pseudonymiser = Pseudonymiser(config.settings.salt_path, mode=config.privacy_mode)

    def host_label(host: Host) -> str:
        return pseudonymiser.host_label(host.host_id, host.display)

    catalog = CatalogMatcher(entries=load_catalog(config.policy.catalog_extra))
    decisions = DecisionStore(config.policy.decisions_path)
    decisions.load()

    analyzer = Analyzer(
        config,
        catalog=catalog,
        decisions=decisions,
        host_label=host_label,
        identified=config.privacy_mode is PrivacyMode.IDENTIFIED,
    )
    findings = analyzer.analyze(inventory)

    baseline_available = False
    baseline_warning: str | None = None
    if store is not None:
        previous_id = store.latest_snapshot_id()
        if previous_id is not None:
            baseline_available = True
            previous = store.load_snapshot(previous_id)
            if (
                previous
                and inventory.hosts
                and not (set(previous) & {s.host.host_id for s in inventory.hosts})
            ):
                # No host in common. Diffing would silently produce nothing
                # while the report claimed a baseline comparison — the failure
                # this tool exists to avoid, applied to itself.
                baseline_warning = (
                    "the stored baseline shares no hosts with this collection, so no drift "
                    "could be computed. This usually means the fleet was re-enrolled or the "
                    "state file belongs to a different config."
                )
                log.warning("%s", baseline_warning)
            findings.extend(
                diff_inventories(
                    previous,
                    inventory,
                    catalog=catalog,
                    decisions=decisions,
                    ignore=set(config.policy.ignore),
                    allowlist=set(config.policy.allowlist),
                    host_label=host_label,
                )
            )

    report = ScanReport(
        started_at=started,
        finished_at=Inventory.now_iso(),
        tool_version=__version__,
        source=inventory.source,
        hosts_scanned=inventory.host_count,
        software_seen=inventory.software_count,
        findings=findings,
        baseline_available=baseline_available,
        collection_errors=[
            *inventory.errors,
            *analyzer.errors,
            *([baseline_warning] if baseline_warning else []),
        ],
        unknown_software=sorted(analyzer.unknown_software),
    )

    report.findings.sort(key=lambda f: (-f.severity.rank, f.kind.value, f.host_display, f.software, f.title))

    # Persist last. A scan that produced a report but could not save is still
    # useful; a scan that saved a baseline it then failed to report on is not.
    if save and store is not None:
        if inventory.host_count == 0:
            # Saving an empty inventory would make the next run report the
            # entire estate as newly installed software.
            log.warning("collection returned no hosts; not updating the baseline")
        else:
            store.save(inventory)

    return report
