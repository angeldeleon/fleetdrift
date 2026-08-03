"""The fixed osquery query pack.

**This is the most security-sensitive file in the project. Read it before
changing it.**

osquery is not a software-inventory API — it is a SQL interface to the entire
endpoint. ``SELECT * FROM file WHERE path LIKE '/Users/%/.ssh/%'`` is valid, so
is reading browser history, so is ``carve``-ing a file off the disk. A tool that
accepted a query from configuration would therefore be a fleet-wide arbitrary
read primitive wearing a monitoring tool's clothes — and the config file is
usually the least-protected artefact in the whole deployment.

So the queries live here, in-tree, reviewed, and there is no code path that
constructs, interpolates into, or accepts one from outside. Every query below:

* reads only software-inventory tables, never ``file``, ``users``,
  ``shell_history``, ``process_events`` or anything else;
* selects named columns, never ``*``, so a schema change cannot silently widen
  what is collected;
* is a snapshot query, so results describe current state rather than a stream of
  events that would need retention.

If you add a query, add it here and say in the pull request exactly what new
data it collects and why the finding it enables is worth that collection. That
trade is the whole point of the review.
"""

from __future__ import annotations

from dataclasses import dataclass

PACK_NAME = "fleetdrift"

# Daily is the right cadence for software inventory: it changes slowly, and a
# tighter interval multiplies endpoint cost for no extra signal.
DEFAULT_INTERVAL_SECONDS = 86400


@dataclass(frozen=True, slots=True)
class PackQuery:
    """One reviewed query."""

    name: str
    sql: str
    platform: str
    source: str
    description: str
    interval: int = DEFAULT_INTERVAL_SECONDS


# ---------------------------------------------------------------------------
# The pack
# ---------------------------------------------------------------------------

_QUERIES: tuple[PackQuery, ...] = (
    PackQuery(
        name="fleetdrift_macos_apps",
        platform="darwin",
        source="apps",
        description=(
            "Installed macOS applications, with code-signing authority. The join "
            "against `signature` is what makes unsigned-binary detection possible; "
            "it reads signing metadata only, never file contents."
        ),
        sql=(
            "SELECT a.name AS name, "
            "a.bundle_short_version AS version, "
            "a.bundle_identifier AS publisher, "
            "a.path AS install_path, "
            "s.authority AS signature_authority, "
            "s.signed AS signed "
            "FROM apps a LEFT JOIN signature s ON s.path = a.path;"
        ),
    ),
    PackQuery(
        name="fleetdrift_windows_programs",
        platform="windows",
        source="programs",
        description="Installed Windows programs as reported by the uninstall registry.",
        sql=(
            "SELECT name AS name, "
            "version AS version, "
            "publisher AS publisher, "
            "install_location AS install_path "
            "FROM programs;"
        ),
    ),
    PackQuery(
        name="fleetdrift_linux_deb",
        platform="linux",
        source="deb_packages",
        description="Installed Debian/Ubuntu packages.",
        sql=(
            "SELECT name AS name, version AS version, "
            "maintainer AS publisher, '' AS install_path "
            "FROM deb_packages;"
        ),
    ),
    PackQuery(
        name="fleetdrift_linux_rpm",
        platform="linux",
        source="rpm_packages",
        description="Installed RPM packages.",
        sql=(
            "SELECT name AS name, version AS version, "
            "vendor AS publisher, '' AS install_path "
            "FROM rpm_packages;"
        ),
    ),
    PackQuery(
        name="fleetdrift_browser_extensions",
        platform="all",
        source="chrome_extensions",
        description=(
            "Chromium-family browser extensions. Extensions are a common and "
            "under-monitored route for data exfiltration, and they install "
            "without administrator rights."
        ),
        sql=(
            "SELECT name AS name, version AS version, "
            "identifier AS publisher, path AS install_path "
            "FROM chrome_extensions;"
        ),
    ),
)

QUERIES: dict[str, PackQuery] = {query.name: query for query in _QUERIES}

# Query names this tool will consume from a results log. Anything else in the
# log is ignored rather than parsed: an operator's own packs may collect data
# fleetdrift has no business reading, and silently ingesting it would break the
# collection promise made in PRIVACY.md.
KNOWN_QUERY_NAMES: frozenset[str] = frozenset(QUERIES)

# Maps a results-log query name to the normalised source label.
SOURCE_BY_QUERY: dict[str, str] = {query.name: query.source for query in _QUERIES}


def is_known_query(name: str) -> bool:
    """True if *name* is one of the reviewed queries.

    Results-log lines are matched against this. A pack name may be prefixed by
    osquery (``pack/fleetdrift/fleetdrift_macos_apps``), so the trailing segment
    is what gets compared.
    """
    return normalize_query_name(name) in KNOWN_QUERY_NAMES


def normalize_query_name(name: str) -> str:
    """Strip any ``pack/<pack>/`` prefix osquery may have added."""
    return str(name).strip().rsplit("/", 1)[-1]


def render_pack() -> dict:
    """Return the pack as a dict, ready to serialise as osquery pack JSON.

    Emitted by ``fleetdrift pack`` so an operator can review the exact SQL
    before deploying it, rather than taking the tool's word for what it reads.
    """
    return {
        "queries": {
            query.name: {
                "query": query.sql,
                "interval": query.interval,
                "platform": query.platform,
                "snapshot": True,
                "description": query.description,
            }
            for query in _QUERIES
        }
    }
