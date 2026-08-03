"""Normalising software rows into a single shape.

The unglamorous part. macOS reports ``AnyDesk.app`` with a bundle identifier and
a code-signing authority; Windows reports ``AnyDesk`` with a publisher string
from the uninstall registry; Debian reports ``anydesk`` with a maintainer. All
three are the same product, and a rule that matches only one of them is a rule
an attacker evades by choosing a different installer.

Everything is sanitised here, at ingestion, because the values are chosen by
whatever is installed on the endpoint. In the scenario this tool exists to
detect, that includes the attacker — so a package named
``Zoom\\n\\n:white_check_mark: all clear`` must not be able to forge a line in a
Slack alert. Sanitising at the boundary means no downstream consumer has to
remember to.
"""

from __future__ import annotations

import logging
from typing import Any

from .models import Platform, SoftwareItem
from .validation import safe_text

log = logging.getLogger(__name__)

# A host reporting more than this is either broken or trying to exhaust us.
MAX_ITEMS_PER_HOST = 5000

# Aggregate ceiling across the whole collection. Per-host caps alone leave
# max_hosts x MAX_ITEMS_PER_HOST as the real bound, which is over 100M objects
# on a large estate — enough for a broken or hostile fleet manager to OOM the
# scanner rather than merely produce a wrong answer.
MAX_TOTAL_ITEMS = 2_000_000

_SOURCE_ALIASES = {
    "apps": "apps",
    "macos_apps": "apps",
    "programs": "programs",
    "windows_programs": "programs",
    "deb_packages": "deb_packages",
    "rpm_packages": "rpm_packages",
    "chrome_extensions": "chrome_extensions",
    "browser_extensions": "chrome_extensions",
    "firefox_addons": "chrome_extensions",
    "safari_extensions": "chrome_extensions",
    "package": "package",
    "": "unknown",
}


def normalize_source(raw: Any) -> str:
    text = safe_text(raw, limit=64).lower().strip()
    return _SOURCE_ALIASES.get(text, text or "unknown")


def _parse_signed(raw: Any) -> bool | None:
    """Interpret osquery's signed column.

    Returns ``None`` for anything unrecognised. That distinction matters: a
    platform which simply does not report signing must not be reported as
    *unsigned*, which would flag every Linux package on the estate.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes", "signed"):
        return True
    if text in ("0", "false", "no", "unsigned"):
        return False
    return None


def software_from_row(host_id: str, row: dict[str, Any], *, source: str = "") -> SoftwareItem | None:
    """Build a :class:`SoftwareItem` from one osquery/Fleet row.

    Returns ``None`` for a row with no usable name rather than inventing a
    placeholder — a nameless entry cannot be matched, reported or acted on, and
    keeping it would only inflate counts.
    """
    if not isinstance(row, dict):
        return None

    name = safe_text(row.get("name") or row.get("bundle_name") or "", limit=200)
    if not name:
        return None

    version = safe_text(
        row.get("version") or row.get("bundle_short_version") or row.get("bundle_version") or "",
        limit=64,
    )

    return SoftwareItem(
        host_id=host_id,
        name=name,
        version=version,
        source=normalize_source(source or row.get("source") or row.get("type") or ""),
        publisher=safe_text(
            row.get("publisher") or row.get("vendor") or row.get("maintainer") or "", limit=200
        ),
        install_path=safe_text(row.get("install_path") or row.get("path") or "", limit=512),
        signed=_parse_signed(row.get("signed")),
        signature_authority=safe_text(
            row.get("signature_authority") or row.get("authority") or "", limit=200
        ),
    )


def software_list_from_rows(
    host_id: str, rows: list[Any], *, source: str = ""
) -> tuple[list[SoftwareItem], bool]:
    """Normalise many rows, deduplicating and capping.

    Returns ``(items, truncated)``. ``truncated`` is propagated rather than
    swallowed: a partial inventory that looks complete would read as "software
    was uninstalled" on the next run, which is the false-positive class this
    project exists to avoid.
    """
    items: list[SoftwareItem] = []
    seen: set[tuple[str, str]] = set()
    truncated = False

    for row in rows:
        if len(items) >= MAX_ITEMS_PER_HOST:
            truncated = True
            log.warning(
                "host %s reported more than %d software rows; truncating",
                host_id,
                MAX_ITEMS_PER_HOST,
            )
            break
        item = software_from_row(host_id, row, source=source)
        if item is None:
            continue
        # The same package can appear twice (a Fleet host detail listing both a
        # bundle and its installer, say). Same name+version is the same thing.
        identity = (item.key, item.version)
        if identity in seen:
            continue
        seen.add(identity)
        items.append(item)

    # Sort for determinism: source order varies between API pages and log lines,
    # and unsorted output would look like drift on every single run.
    items.sort(key=lambda i: (i.source, i.name.lower(), i.version))
    return items, truncated


def platform_from_fleet(raw: Any) -> Platform:
    return Platform.parse(str(raw or ""))
