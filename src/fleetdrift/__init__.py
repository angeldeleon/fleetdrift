"""fleetdrift — endpoint software drift detection for security teams.

Read-only by construction. It consumes osquery inventory that a fleet already
collects, compares it against a stored baseline, and reports what changed. It
deploys nothing to endpoints, requires no privilege on them, and has no code
path that writes to a managed machine.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
