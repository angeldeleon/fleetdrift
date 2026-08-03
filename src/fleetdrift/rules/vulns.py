"""Known-vulnerability matching via OSV.dev.

**Scope, stated up front because it is the honest part:** this covers Linux
distribution packages only. OSV indexes package ecosystems — Debian, Ubuntu,
Rocky, Alma, Red Hat — where a name and version map unambiguously to advisories.
It does not index macOS ``.app`` bundles or Windows uninstall-registry entries.

The obvious alternative for those is CPE matching against NVD, and it is
deliberately not implemented. CPE names collide badly (``Adobe Reader`` vs
``Adobe Acrobat Reader DC`` vs a dozen vendor spellings), and a vulnerability
report with a high false-positive rate is worse than none: it trains the team to
dismiss the whole category. macOS and Windows coverage comes from the catalog,
end-of-life detection, signature checks and drift instead.

If the ecosystem cannot be determined the package is skipped and the skip is
reported, rather than guessed at.
"""

from __future__ import annotations

import logging

from ..httpclient import HTTPError, safe_request
from ..models import Host, Platform, SoftwareItem
from ..validation import ValidationError, safe_text

log = logging.getLogger(__name__)

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"

# OSV accepts up to 1000 queries per batch; 100 keeps individual requests small
# and failures cheap to retry.
_BATCH_SIZE = 100
_MAX_BATCHES = 200
_MAX_IDS_REPORTED = 10


def ecosystem_for(host: Host, item: SoftwareItem) -> str | None:
    """Map a package to an OSV ecosystem, or ``None`` if it cannot be determined.

    Returning ``None`` is a first-class answer. Guessing an ecosystem produces
    advisories for a different distribution's package of the same name, which is
    exactly the false-positive class this module exists to avoid.
    """
    if host.platform is not Platform.LINUX and item.source not in ("deb_packages", "rpm_packages"):
        return None

    os_version = (host.os_version or "").lower()

    if item.source == "deb_packages":
        if "ubuntu" in os_version:
            return "Ubuntu"
        if "debian" in os_version or not os_version:
            return "Debian"
        return "Debian"

    if item.source == "rpm_packages":
        if "rocky" in os_version:
            return "Rocky Linux"
        if "alma" in os_version:
            return "AlmaLinux"
        if "red hat" in os_version or "rhel" in os_version:
            return "Red Hat"
        # SUSE, Amazon Linux and others exist in OSV under names we cannot infer
        # reliably from an os_version string, so we decline rather than guess.
        return None

    return None


class OSVClient:
    """Batch lookups against OSV.dev.

    OSV is a free community service with no SLA. Every failure path here returns
    partial results with an error string rather than raising: a scan must not
    fail because a third-party API is slow, and it must not silently report
    "no vulnerabilities" when it simply could not ask.
    """

    def __init__(self, *, timeout: float = 30.0, user_agent: str = "fleetdrift") -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def query(
        self, packages: list[tuple[str, str, str]]
    ) -> tuple[dict[tuple[str, str, str], list[str]], list[str]]:
        """Look up ``(ecosystem, name, version)`` triples.

        Returns ``(vulnerabilities, errors)`` where the mapping holds only
        packages with at least one advisory.
        """
        results: dict[tuple[str, str, str], list[str]] = {}
        errors: list[str] = []

        unique = sorted(set(packages))
        if not unique:
            return results, errors

        batches = [unique[i : i + _BATCH_SIZE] for i in range(0, len(unique), _BATCH_SIZE)]
        if len(batches) > _MAX_BATCHES:
            errors.append(
                f"vulnerability lookup covered {_MAX_BATCHES * _BATCH_SIZE} of "
                f"{len(unique)} unique packages; the rest were skipped"
            )
            batches = batches[:_MAX_BATCHES]

        for batch in batches:
            payload = {
                "queries": [
                    {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                    for ecosystem, name, version in batch
                ]
            }
            try:
                response = safe_request(
                    "POST",
                    OSV_BATCH_ENDPOINT,
                    timeout=self.timeout,
                    json_body=payload,
                    user_agent=self.user_agent,
                )
            except (HTTPError, ValidationError) as exc:
                errors.append(f"OSV lookup failed: {exc}")
                break

            if response.status_code != 200:
                errors.append(f"OSV returned HTTP {response.status_code}")
                break

            try:
                body = response.json()
            except ValueError as exc:
                errors.append(f"OSV returned non-JSON: {exc}")
                break

            batch_results = body.get("results") if isinstance(body, dict) else None
            if not isinstance(batch_results, list) or len(batch_results) != len(batch):
                # A response that does not line up positionally with the request
                # cannot be attributed to the right package. Attributing it
                # anyway would report advisories against the wrong software.
                errors.append("OSV response did not align with the request; batch discarded")
                continue

            for key, entry in zip(batch, batch_results, strict=False):
                if not isinstance(entry, dict):
                    continue
                vulns = entry.get("vulns")
                if not isinstance(vulns, list) or not vulns:
                    continue
                ids = sorted(
                    {safe_text(v.get("id"), limit=64) for v in vulns if isinstance(v, dict) and v.get("id")}
                )
                if ids:
                    results[key] = ids[:_MAX_IDS_REPORTED]

        return results, errors


def build_queries(
    hosts: list[tuple[Host, list[SoftwareItem]]],
) -> tuple[list[tuple[str, str, str]], dict[tuple[str, str, str], list[SoftwareItem]], int]:
    """Collect the lookups to perform, and the items each result maps back to.

    Returns ``(queries, index, skipped)``. ``skipped`` counts packages whose
    ecosystem could not be determined, so the report can say how much of the
    estate the check actually covered rather than implying it covered all of it.
    """
    index: dict[tuple[str, str, str], list[SoftwareItem]] = {}
    skipped = 0

    for host, items in hosts:
        for item in items:
            if not item.version:
                skipped += 1
                continue
            ecosystem = ecosystem_for(host, item)
            if ecosystem is None:
                skipped += 1
                continue
            key = (ecosystem, item.name, item.version)
            index.setdefault(key, []).append(item)

    return sorted(index), index, skipped
