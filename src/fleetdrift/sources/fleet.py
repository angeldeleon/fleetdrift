"""Read-only client for a Fleet (fleetdm.com) server.

Fleet is the most widely deployed open-source osquery manager, so consuming its
API means the tool works on day one in most estates without deploying anything
new to a single endpoint.

Only two endpoints are used, both GET:

* ``/api/v1/fleet/hosts`` — the host list, paginated
* ``/api/v1/fleet/hosts/{id}`` — host detail, for software, when the list
  response does not already include it

Nothing here writes, schedules a query, or issues a live query. A Fleet API
token can be scoped to a read-only observer role, and this client is designed so
that such a token is sufficient — if you find yourself needing more privilege,
something is wrong.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode, urljoin

from ..config import FleetSourceConfig
from ..httpclient import HTTPError, safe_request
from ..models import Host, HostSnapshot, Inventory, Platform
from ..normalize import MAX_TOTAL_ITEMS, platform_from_fleet, software_list_from_rows
from ..validation import ValidationError, safe_text
from .base import SourceError

log = logging.getLogger(__name__)

# Bounds on what we will accept from the server. A compromised or simply broken
# Fleet must not be able to make this process allocate without limit.
_MAX_PAGES = 2000
_MAX_DETAIL_FETCHES = 5000


class FleetSource:
    """Collects software inventory from a Fleet server."""

    name = "fleet"

    def __init__(
        self,
        config: FleetSourceConfig,
        *,
        timeout: float = 30.0,
        user_agent: str = "fleetdrift",
        max_hosts: int = 25000,
    ) -> None:
        self.config = config
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_hosts = max_hosts

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        token = self.config.api_token()
        if not token:
            raise SourceError(f"no Fleet API token: set the {self.config.api_token_env} environment variable")
        return {"Authorization": f"Bearer {token}"}

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        query = ""
        if params:
            # urlencode, not f-strings: every value here is an int or a bounded
            # literal today, but building query strings by concatenation is how
            # that stops being true later.
            query = "?" + urlencode({k: v for k, v in params.items() if v is not None})

        # urljoin rather than concatenation: a configured base URL carrying a
        # query string or fragment would otherwise swallow the API path.
        url = urljoin(self.config.url + "/", path.lstrip("/")) + query

        try:
            response = safe_request(
                "GET",
                url,
                timeout=self.timeout,
                headers=self._headers(),
                user_agent=self.user_agent,
                allow_internal=self.config.allow_internal,
                verify=self.config.verify_tls,
            )
        except (HTTPError, ValidationError) as exc:
            raise SourceError(f"Fleet request failed: {exc}") from exc

        if response.status_code == 401:
            raise SourceError("Fleet rejected the API token (HTTP 401)")
        if response.status_code == 403:
            raise SourceError("Fleet API token lacks permission for this endpoint (HTTP 403)")
        if response.status_code != 200:
            raise SourceError(f"Fleet returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError(f"Fleet returned a non-JSON response: {exc}") from exc
        if not isinstance(payload, dict):
            raise SourceError("Fleet returned an unexpected payload shape")
        return payload

    # ------------------------------------------------------------------
    # collection
    # ------------------------------------------------------------------

    def collect(self) -> Inventory:
        inventory = Inventory(collected_at=Inventory.now_iso(), source=self.name)

        raw_hosts = self._list_hosts(inventory)
        detail_fetches = 0
        # Counters rather than per-host messages: host identifiers reach the
        # report and the outbound webhook, and this source's identifiers are
        # real hostnames.
        detail_failures = 0
        missing_inventory = 0
        truncated_hosts = 0
        total_items = 0

        for raw in raw_hosts:
            host = self._host_from_payload(raw)
            software_rows = _extract_software(raw)

            if software_rows is None and detail_fetches < _MAX_DETAIL_FETCHES:
                # Older Fleet versions omit software from the list response.
                detail_fetches += 1
                try:
                    # int() rather than interpolating the raw value: the id is
                    # server-supplied and goes into a URL path.
                    numeric_id = int(raw.get("id"))  # type: ignore[arg-type]
                    detail = self._get(f"/api/v1/fleet/hosts/{numeric_id}")
                except (SourceError, TypeError, ValueError):
                    detail_failures += 1
                    software_rows = None
                else:
                    software_rows = _extract_software(detail.get("host") or detail)

            if software_rows is None:
                # No inventory for this host. Recording it with an empty list
                # would read as "everything was uninstalled" on the next scan.
                missing_inventory += 1
                continue

            items, truncated = software_list_from_rows(host.host_id, software_rows)
            if truncated:
                truncated_hosts += 1
                continue

            if not items:
                # Fleet returns an empty software array for a host that has
                # enrolled but not yet reported inventory. Persisting that would
                # make the next run report the entire machine as newly installed.
                missing_inventory += 1
                continue

            total_items += len(items)
            if total_items > MAX_TOTAL_ITEMS:
                raise SourceError(
                    f"Fleet returned more than {MAX_TOTAL_ITEMS} software rows; "
                    "refusing to continue rather than exhaust memory"
                )

            inventory.hosts.append(HostSnapshot(host=host, software=items))

        if missing_inventory:
            inventory.errors.append(
                f"{missing_inventory} host(s) had no software inventory available and were skipped"
            )
        if detail_failures:
            inventory.errors.append(f"{detail_failures} host detail request(s) failed")
        if truncated_hosts:
            inventory.errors.append(
                f"{truncated_hosts} host(s) reported more software than the per-host cap "
                "and were skipped rather than recorded partially"
            )

        return inventory

    def _list_hosts(self, inventory: Inventory) -> list[dict[str, Any]]:
        hosts: list[dict[str, Any]] = []
        page = 0

        while page < _MAX_PAGES and len(hosts) < self.max_hosts:
            payload = self._get(
                "/api/v1/fleet/hosts",
                {
                    "page": page,
                    "per_page": self.config.page_size,
                    "team_id": self.config.team_id,
                    "label_id": self.config.label_id,
                    # Ask for software inline. Fleet versions that don't know
                    # this parameter ignore it, and the per-host fallback covers
                    # them.
                    "populate_software": "true",
                },
            )
            batch = payload.get("hosts")
            if not isinstance(batch, list) or not batch:
                break
            hosts.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < self.config.page_size:
                break
            page += 1

        # `>=`, not `>`. The loop stops as soon as len(hosts) reaches max_hosts,
        # so when max_hosts is a multiple of page_size it lands exactly on the
        # cap and a `>` test never fires -- and the shipped defaults are exactly
        # that case (25000 / 100). The result was a fleet silently truncated at
        # the cap while the report asserted a complete scan. Landing on the cap
        # is indistinguishable from a fleet that is precisely that size, so this
        # reports the ambiguity rather than guessing which it was.
        if len(hosts) >= self.max_hosts:
            inventory.errors.append(
                f"host listing reached the max_hosts cap ({self.max_hosts}); if the fleet is "
                "larger than that, this scan covers only a subset. Raise max_hosts to be sure."
            )
            hosts = hosts[: self.max_hosts]

        if page >= _MAX_PAGES:
            inventory.errors.append("stopped paginating at the page limit; results are incomplete")

        return hosts

    @staticmethod
    def _host_from_payload(raw: dict[str, Any]) -> Host:
        host_id = str(raw.get("uuid") or raw.get("id") or raw.get("hostname") or "unknown")
        hostname = safe_text(
            raw.get("hostname") or raw.get("computer_name") or raw.get("display_name") or host_id,
            limit=253,
        )
        platform = platform_from_fleet(raw.get("platform"))
        if platform is Platform.UNKNOWN:
            platform = platform_from_fleet(raw.get("os_version"))
        return Host(
            host_id=safe_text(host_id, limit=128),
            display=hostname,
            platform=platform,
            os_version=safe_text(raw.get("os_version") or "", limit=128),
            last_seen=safe_text(raw.get("seen_time") or raw.get("updated_at") or "", limit=64),
        )


def _extract_software(raw: Any) -> list[Any] | None:
    """Pull the software array out of a Fleet host payload.

    Returns ``None`` when the payload carries no software key at all — which
    means "not collected", not "nothing installed". An empty list, by contrast,
    is a real answer and is returned as such.
    """
    if not isinstance(raw, dict):
        return None
    software = raw.get("software")
    if software is None:
        return None
    if not isinstance(software, list):
        return None
    return software
