"""Snapshot persistence in SQLite.

The baseline is the tool's memory: without it every run looks like a first run
and no drift is ever detected. A fleet of 5,000 hosts with 200 packages each is
a million rows, which rules out the single-JSON-file approach — but SQLite is
still one file, with no server and no daemon.

Two properties matter beyond correctness:

* **Restrictive permissions.** This file is a complete software inventory of
  every managed endpoint, which is a useful map for an attacker and personal
  data in several jurisdictions. Created ``0600``.
* **Bounded retention.** Old snapshots are pruned automatically. Keeping
  inventory history forever is a liability, not a feature — see PRIVACY.md.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from .models import Host, HostSnapshot, Inventory, Platform

log = logging.getLogger(__name__)

SCHEMA_VERSION = 2
DEFAULT_STATE_PATH = ".fleetdrift/fleetdrift.db"

# Two snapshots are enough for drift. The rest is kept for short-term context
# when someone asks "when did this appear", and pruned after that.
DEFAULT_RETAIN_SNAPSHOTS = 14


class StateError(Exception):
    """The state database could not be read or written."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at   TEXT NOT NULL,
    source         TEXT NOT NULL,
    scope          TEXT NOT NULL DEFAULT 'default',
    host_count     INTEGER NOT NULL DEFAULT 0,
    software_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_snapshots_scope ON snapshots (scope, id);

CREATE TABLE IF NOT EXISTS hosts (
    snapshot_id INTEGER NOT NULL,
    host_id     TEXT NOT NULL,
    display     TEXT NOT NULL,
    platform    TEXT NOT NULL DEFAULT 'unknown',
    os_version  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, host_id)
);

CREATE TABLE IF NOT EXISTS host_software (
    snapshot_id  INTEGER NOT NULL,
    host_id      TEXT NOT NULL,
    software_key TEXT NOT NULL,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, host_id, software_key)
);

CREATE INDEX IF NOT EXISTS idx_host_software_snapshot ON host_software (snapshot_id);
"""


class SnapshotStore:
    """Reads and writes fleet inventory snapshots."""

    def __init__(
        self,
        path: str | Path = DEFAULT_STATE_PATH,
        *,
        retain: int = DEFAULT_RETAIN_SNAPSHOTS,
        scope: str = "default",
    ) -> None:
        self.path = Path(path).expanduser()
        self.retain = max(2, int(retain))
        # Snapshots are namespaced by scope so that two configs sharing a state
        # file cannot diff against each other's fleet. Without this, every host
        # id misses on lookup, drift silently returns nothing, and the report
        # still claims it compared against a baseline.
        self.scope = scope or "default"

    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Create the file ourselves at 0600 before sqlite touches it.
            # sqlite3.connect() creates at 0644 and chmod-ing afterwards leaves
            # a window in which another local process can open a complete
            # software inventory of every managed endpoint.
            #
            # O_NOFOLLOW has to be checked on EVERY connect, not only when the
            # file appears to be missing. Guarding it with `if not
            # self.path.exists()` was the bug it was meant to prevent:
            # Path.exists() follows symlinks, so a link aimed at an *existing*
            # attacker-owned file returned True, the guarded open was skipped
            # entirely, and sqlite3.connect() followed the link -- writing every
            # hostname on the estate into a file the attacker could read. Only a
            # link to a missing target failed closed.
            try:
                os.close(
                    os.open(
                        self.path,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                        0o600,
                    )
                )
            except FileExistsError:
                self._assert_not_a_symlink()  # the normal path after run one
            connection = sqlite3.connect(self.path, timeout=30.0)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            # Check the recorded version BEFORE applying the schema script.
            # Applying it first means a statement referencing a newer column
            # fails with "no such column: scope", which tells an upgrading
            # operator nothing about what to do.
            self._assert_supported_version(connection)
            connection.executescript(_SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            connection.commit()
            return connection
        except (OSError, sqlite3.Error) as exc:
            raise StateError(f"cannot open state database {self.path}: {exc}") from exc

    def _assert_not_a_symlink(self) -> None:
        """Confirm an existing state file is a real file we can safely open.

        Checked through a descriptor rather than by path: ``os.path.islink``
        followed by ``sqlite3.connect`` is two lookups of the same name and the
        attacker owns what happens in between.
        """
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)  # raises ELOOP on a link
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise StateError(f"state database {self.path} is not a regular file; refusing to open it")
            if info.st_mode & 0o077:
                # Repair through the descriptor, not the path.
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

    @staticmethod
    def _assert_supported_version(connection: sqlite3.Connection) -> None:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'"
        ).fetchone()
        if not exists:
            return  # a fresh database, or one predating the meta table
        row = connection.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        if row and str(row[0]) != str(SCHEMA_VERSION):
            raise StateError(
                f"state database at this path has schema version {row[0]}; this build "
                f"understands {SCHEMA_VERSION}. Move the file aside to start a fresh "
                "baseline (the first run afterwards will report posture only)."
            )

    def check_schema(self) -> None:
        with closing(self._connect()):
            # _connect already asserts the version; this exists so the CLI can
            # fail before doing any collection work.
            pass

    # ------------------------------------------------------------------

    def save(self, inventory: Inventory) -> int:
        """Persist a snapshot and prune old ones. Returns the snapshot id."""
        try:
            with closing(self._connect()) as connection:
                cursor = connection.execute(
                    "INSERT INTO snapshots "
                    "(collected_at, source, scope, host_count, software_count) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        inventory.collected_at,
                        inventory.source,
                        self.scope,
                        inventory.host_count,
                        inventory.software_count,
                    ),
                )
                snapshot_id = int(cursor.lastrowid or 0)

                connection.executemany(
                    "INSERT OR REPLACE INTO hosts "
                    "(snapshot_id, host_id, display, platform, os_version) VALUES (?, ?, ?, ?, ?)",
                    [
                        (
                            snapshot_id,
                            s.host.host_id,
                            s.host.display,
                            s.host.platform.value,
                            s.host.os_version,
                        )
                        for s in inventory.hosts
                    ],
                )

                connection.executemany(
                    "INSERT OR REPLACE INTO host_software "
                    "(snapshot_id, host_id, software_key, name, version, source) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (snapshot_id, item.host_id, item.key, item.name, item.version, item.source)
                        for s in inventory.hosts
                        for item in s.software
                    ],
                )

                connection.commit()
                self._prune(connection)
                connection.commit()
                return snapshot_id
        except sqlite3.Error as exc:
            raise StateError(f"cannot write snapshot: {exc}") from exc

    def _prune(self, connection: sqlite3.Connection) -> None:
        """Delete snapshots beyond the retention limit.

        Expressed as a single id threshold rather than an ``IN (...)`` list so
        that no SQL statement here is built by string formatting. Snapshot ids
        are monotonic, so "older than the Nth newest" is exactly the same set.
        """
        row = connection.execute(
            "SELECT id FROM snapshots WHERE scope = ? ORDER BY id DESC LIMIT 1 OFFSET ?",
            (self.scope, self.retain - 1),
        ).fetchone()
        if row is None:
            return
        oldest_kept = int(row[0])

        connection.execute(
            "DELETE FROM host_software WHERE snapshot_id < ? AND snapshot_id IN "
            "(SELECT id FROM snapshots WHERE scope = ?)",
            (oldest_kept, self.scope),
        )
        connection.execute(
            "DELETE FROM hosts WHERE snapshot_id < ? AND snapshot_id IN "
            "(SELECT id FROM snapshots WHERE scope = ?)",
            (oldest_kept, self.scope),
        )
        cursor = connection.execute(
            "DELETE FROM snapshots WHERE id < ? AND scope = ?", (oldest_kept, self.scope)
        )
        if cursor.rowcount:
            log.info("pruned %d snapshot(s) beyond the retention limit of %d", cursor.rowcount, self.retain)

    # ------------------------------------------------------------------

    def latest_snapshot_id(self, *, before: int | None = None) -> int | None:
        try:
            with closing(self._connect()) as connection:
                if before is None:
                    row = connection.execute(
                        "SELECT MAX(id) FROM snapshots WHERE scope = ?", (self.scope,)
                    ).fetchone()
                else:
                    row = connection.execute(
                        "SELECT MAX(id) FROM snapshots WHERE scope = ? AND id < ?",
                        (self.scope, before),
                    ).fetchone()
                return int(row[0]) if row and row[0] is not None else None
        except sqlite3.Error as exc:
            raise StateError(f"cannot read snapshots: {exc}") from exc

    def load_snapshot(self, snapshot_id: int) -> dict[str, HostSnapshot]:
        """Load one snapshot keyed by host id.

        Software items are returned with name/version/source only — the fields
        drift needs. Signature and path data are not persisted: they are not
        diffed, and storing less is the right default for an inventory of
        employees' machines.
        """
        from .models import SoftwareItem

        try:
            with closing(self._connect()) as connection:
                hosts: dict[str, HostSnapshot] = {}
                for host_id, display, platform, os_version in connection.execute(
                    "SELECT host_id, display, platform, os_version FROM hosts WHERE snapshot_id = ?",
                    (snapshot_id,),
                ):
                    hosts[host_id] = HostSnapshot(
                        host=Host(
                            host_id=host_id,
                            display=display,
                            platform=Platform.parse(platform),
                            os_version=os_version,
                        )
                    )

                for host_id, name, version, source in connection.execute(
                    "SELECT host_id, name, version, source FROM host_software WHERE snapshot_id = ?",
                    (snapshot_id,),
                ):
                    snapshot = hosts.get(host_id)
                    if snapshot is None:
                        continue
                    snapshot.software.append(
                        SoftwareItem(host_id=host_id, name=name, version=version, source=source)
                    )

                return hosts
        except sqlite3.Error as exc:
            raise StateError(f"cannot read snapshot {snapshot_id}: {exc}") from exc

    def snapshot_count(self) -> int:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT COUNT(*) FROM snapshots WHERE scope = ?", (self.scope,)
                ).fetchone()
                return int(row[0]) if row else 0
        except sqlite3.Error as exc:
            raise StateError(f"cannot count snapshots: {exc}") from exc
