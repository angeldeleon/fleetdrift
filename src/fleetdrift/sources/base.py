"""Source protocol.

A source is anything that can produce an :class:`~fleetdrift.models.Inventory`.
Every source is **read-only by construction** — it fetches or reads, and has no
API for writing to an endpoint or a fleet manager. That is the property that
makes this tool safe to point at production, and it should stay true of any
source added later.
"""

from __future__ import annotations

from typing import Protocol

from ..models import Inventory


class SourceError(Exception):
    """The source could not be read.

    Raised for genuine failures — unreachable server, unreadable file, bad
    credentials. Never raised for "the fleet is empty", which is a legitimate
    (if surprising) answer that the caller handles separately.
    """


class Source(Protocol):
    """Produces an inventory snapshot."""

    name: str

    def collect(self) -> Inventory: ...
