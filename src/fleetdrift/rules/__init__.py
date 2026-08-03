"""Risk rules.

Every rule in this package is deterministic: same inventory in, same findings
out. Nothing here consults a model. The optional AI layer proposes entries for
:mod:`fleetdrift.rules.decisions`, and those only take effect once a human
approves them.
"""

from __future__ import annotations

from .catalog import BUILTIN_CATALOG, CatalogEntry, CatalogMatcher, load_catalog
from .decisions import Decision, DecisionStore

__all__ = [
    "BUILTIN_CATALOG",
    "CatalogEntry",
    "CatalogMatcher",
    "load_catalog",
    "Decision",
    "DecisionStore",
]
