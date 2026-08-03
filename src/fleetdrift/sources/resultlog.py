"""Reader for an osquery results log.

For estates that ship osquery results to a file or log pipeline rather than
running Fleet. The log is newline-delimited JSON, one object per scheduled query
result.

Two rules govern what is read:

* **Only queries from the reviewed pack are parsed.** An operator's log will
  contain their own packs too, and those may collect data this tool has no
  business reading. Ignoring them keeps the collection promise in PRIVACY.md
  honest rather than aspirational.
* **Only the most recent snapshot per (host, query) is kept.** A results log is
  append-only and may hold months of history; using anything but the latest
  would report long-uninstalled software as present.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..config import ResultLogSourceConfig
from ..models import Host, HostSnapshot, Inventory, Platform
from ..normalize import MAX_TOTAL_ITEMS, software_list_from_rows
from ..validation import safe_text
from .base import SourceError
from .queries import SOURCE_BY_QUERY, is_known_query, normalize_query_name

log = logging.getLogger(__name__)

# One JSON object per line; a line longer than this is malformed or hostile.
_MAX_LINE_BYTES = 32 * 1024 * 1024
_MAX_LINES = 5_000_000


class ResultLogSource:
    """Collects software inventory from an osquery results log."""

    name = "resultlog"

    def __init__(self, config: ResultLogSourceConfig, *, max_hosts: int = 25000) -> None:
        self.config = config
        self.max_hosts = max_hosts

    def collect(self) -> Inventory:
        inventory = Inventory(collected_at=Inventory.now_iso(), source=self.name)
        path = Path(self.config.path).expanduser()

        if not path.is_file():
            raise SourceError(f"results log not found: {path}")

        size = path.stat().st_size
        if size > self.config.max_bytes:
            raise SourceError(
                f"results log is {size} bytes, above the configured max_bytes "
                f"({self.config.max_bytes}). Rotate the log or raise the limit deliberately."
            )

        truncated_hosts = 0
        empty_hosts = 0
        # (host_id, query) -> (unix_time, rows)
        latest: dict[tuple[str, str], tuple[float, list[Any]]] = {}
        hostnames: dict[str, str] = {}
        platforms: dict[str, Platform] = {}
        malformed = 0
        lines_read = 0

        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    lines_read += 1
                    if lines_read > _MAX_LINES:
                        # A results log is append-only, so stopping here keeps
                        # the OLDEST records — the exact inverse of this
                        # module's rule. Continuing would report months-old
                        # software as currently installed and then persist that
                        # as the baseline. Fail instead.
                        raise SourceError(
                            f"results log exceeds {_MAX_LINES} lines. Reading only the "
                            "beginning would report stale software as current. Rotate the "
                            "log, or point at a rotated segment."
                        )
                    if len(raw_line) > _MAX_LINE_BYTES:
                        malformed += 1
                        continue
                    line = raw_line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                    except ValueError:
                        malformed += 1
                        continue
                    if not isinstance(record, dict):
                        malformed += 1
                        continue

                    query_name = normalize_query_name(record.get("name") or "")
                    if not is_known_query(query_name):
                        continue

                    rows = record.get("snapshot")
                    if not isinstance(rows, list):
                        # Differential results describe a change, not a state.
                        # Reconstructing current inventory from them requires a
                        # complete, gap-free history that a log file cannot
                        # guarantee, so they are skipped rather than guessed at.
                        continue

                    host_id = safe_text(
                        record.get("hostIdentifier") or record.get("host_identifier") or "",
                        limit=128,
                    )
                    if not host_id:
                        malformed += 1
                        continue

                    decorations = record.get("decorations")
                    if isinstance(decorations, dict):
                        hostname = decorations.get("hostname") or decorations.get("host_name")
                        if hostname:
                            hostnames[host_id] = safe_text(hostname, limit=253)
                        platform_hint = decorations.get("platform") or decorations.get("os_name")
                        if platform_hint:
                            platforms[host_id] = Platform.parse(str(platform_hint))

                    try:
                        stamp = float(record.get("unixTime") or record.get("unix_time") or 0)
                    except (TypeError, ValueError):
                        stamp = 0.0

                    key = (host_id, query_name)
                    existing = latest.get(key)
                    if existing is None or stamp >= existing[0]:
                        latest[key] = (stamp, rows)
        except OSError as exc:
            raise SourceError(f"cannot read results log {path}: {exc}") from exc

        if malformed:
            inventory.errors.append(f"{malformed} malformed line(s) in the results log were skipped")

        # Fold per-query results into one snapshot per host.
        by_host: dict[str, list[Any]] = {}
        sources: dict[str, str] = {}
        for (host_id, query_name), (_stamp, rows) in sorted(latest.items()):
            by_host.setdefault(host_id, [])
            source = SOURCE_BY_QUERY.get(query_name, "unknown")
            for row in rows:
                if isinstance(row, dict):
                    tagged = dict(row)
                    tagged.setdefault("source", source)
                    by_host[host_id].append(tagged)
            sources[host_id] = source

        if len(by_host) > self.max_hosts:
            inventory.errors.append(
                f"results log contains more than max_hosts ({self.max_hosts}) hosts; the scan covers a subset"
            )

        total_items = 0
        for host_id in sorted(by_host)[: self.max_hosts]:
            items, truncated = software_list_from_rows(host_id, by_host[host_id])
            if truncated:
                truncated_hosts += 1
                continue
            if not items:
                # A pack result that arrived empty. Recording it would produce
                # a false "software was removed" finding, wipe this host's
                # baseline, and then suppress real drift for a cycle. Same
                # hazard the Fleet source guards against.
                empty_hosts += 1
                continue

            total_items += len(items)
            if total_items > MAX_TOTAL_ITEMS:
                raise SourceError(
                    f"results log yielded more than {MAX_TOTAL_ITEMS} software rows; "
                    "refusing to continue rather than exhaust memory"
                )
            host = Host(
                host_id=host_id,
                display=hostnames.get(host_id, host_id),
                platform=platforms.get(host_id, Platform.UNKNOWN),
            )
            inventory.hosts.append(HostSnapshot(host=host, software=items))

        if empty_hosts:
            inventory.errors.append(
                f"{empty_hosts} host(s) reported an empty software list and were skipped "
                "rather than recorded as having nothing installed"
            )

        if truncated_hosts:
            # Host identifiers are omitted deliberately: for this source the
            # host id IS the hostname, and error strings reach the report and
            # the webhook.
            inventory.errors.append(
                f"{truncated_hosts} host(s) reported more software than the per-host cap "
                "and were skipped rather than recorded partially"
            )

        if not inventory.hosts and not inventory.errors:
            inventory.errors.append(
                "no fleetdrift pack results found in the log. Deploy the pack with "
                "`fleetdrift pack` and confirm the queries are scheduled."
            )

        return inventory
