"""Pseudonymisation of endpoint identifiers.

Software inventory is workplace monitoring data. In the EU and UK it is personal
data under GDPR the moment it can be tied to a named employee, and in several
jurisdictions deploying it without consultation is a labour-law problem rather
than a technical one.

So identifiers are pseudonymised by default. The security team still gets what
it needs — "the same three machines keep showing this" — because the mapping is
*stable*, and can resolve a specific pseudonym back to a hostname through the
fleet manager when an investigation actually warrants it.

The mechanism is HMAC-SHA256 under a locally generated salt:

* **Deterministic**, so drift detection works across runs.
* **Not reversible** by anyone holding the report but not the salt, which
  matters because reports get pasted into tickets and chat.
* **Not enumerable**, unlike a plain hash — a 100k-host estate has a small
  enough hostname space to brute-force a bare SHA256 in seconds.

The salt lives beside the database at ``0600``. Deleting it makes every previous
pseudonym unresolvable and resets the baseline, which is the correct behaviour
for a "forget this fleet" operation.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import stat
import tempfile
from enum import Enum
from hashlib import sha256
from pathlib import Path

log = logging.getLogger(__name__)

_SALT_BYTES = 32
_PSEUDONYM_HEX = 12


class PrivacyMode(str, Enum):
    """How host identifiers appear in output.

    ``PSEUDONYMOUS`` is the default. ``IDENTIFIED`` is a deliberate choice an
    operator makes with knowledge of their own legal position, not something the
    tool should quietly assume.
    """

    PSEUDONYMOUS = "pseudonymous"
    IDENTIFIED = "identified"

    @classmethod
    def parse(cls, raw: str) -> PrivacyMode:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(f"unknown privacy mode {raw!r} (expected one of: {valid})") from exc


class Pseudonymiser:
    """Maps identifiers to stable, non-reversible labels."""

    def __init__(self, salt_path: str | Path, *, mode: PrivacyMode = PrivacyMode.PSEUDONYMOUS) -> None:
        self.mode = mode
        self.salt_path = Path(salt_path).expanduser()
        self._salt: bytes | None = None

    @property
    def salt(self) -> bytes:
        if self._salt is None:
            self._salt = self._load_or_create_salt()
        return self._salt

    def _load_or_create_salt(self) -> bytes:
        """Read the salt, or create one.

        Every filesystem operation goes through a file descriptor opened with
        ``O_NOFOLLOW``, never through the path. Following a symlink here would
        let anyone who can write the state directory (plausible when this runs
        as root from cron) point the salt at a file of their choosing: they
        would learn the salt, making every pseudonym in every past report
        enumerable, and the "tighten permissions" branch would chmod their
        target to 0600 — ``chmod 600 /etc/passwd`` is a working denial of
        service.
        """
        try:
            fd = os.open(self.salt_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return self._create_salt()
        except OSError as exc:
            raise ValueError(f"cannot read salt file {self.salt_path}: {exc}") from exc

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"salt path {self.salt_path} is not a regular file")
            data = os.read(fd, _SALT_BYTES * 4)
            if len(data) < 16:
                raise ValueError(
                    f"salt file {self.salt_path} is too short to be usable; "
                    "delete it to regenerate (this resets all pseudonyms and the baseline)"
                )
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o077:
                # A group- or world-readable salt lets anyone on the box
                # re-identify every host in every report ever produced.
                log.warning(
                    "salt file %s is readable by others (mode %o); tightening to 0600",
                    self.salt_path,
                    mode,
                )
                os.fchmod(fd, 0o600)
            return data
        finally:
            os.close(fd)

    def _create_salt(self) -> bytes:
        """Create the salt atomically.

        Written to a temporary file and linked into place, rather than
        ``O_CREAT|O_EXCL`` followed by a write. The naive version leaves a
        window in which the file exists but is empty: a concurrent run reads
        zero bytes and fails, and if the process is killed inside that window
        the empty file persists and *every* subsequent run fails forever — with
        the only advertised remedy being to delete it, which destroys every
        pseudonym and the baseline with it.
        """
        self.salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(_SALT_BYTES)

        fd, tmp_name = tempfile.mkstemp(prefix=".fleetdrift-salt-", dir=str(self.salt_path.parent))
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, salt)
            os.fsync(fd)
        finally:
            os.close(fd)

        try:
            # link() is atomic and fails if the target exists, so a concurrent
            # creator cannot be clobbered. rename() would silently overwrite,
            # leaving two running scans with different salts in memory.
            os.link(tmp_name, self.salt_path)
        except FileExistsError:
            os.unlink(tmp_name)
            return self._load_or_create_salt()
        except OSError:
            # Filesystems without hard links (some network mounts). rename is
            # still atomic; it just cannot detect a lost race.
            os.replace(tmp_name, self.salt_path)
            log.info("generated a new pseudonymisation salt at %s", self.salt_path)
            return salt
        else:
            os.unlink(tmp_name)

        log.info("generated a new pseudonymisation salt at %s", self.salt_path)
        return salt

    def host_label(self, identifier: str, hostname: str) -> str:
        """Return the label a human sees for this host."""
        if self.mode is PrivacyMode.IDENTIFIED:
            return hostname or identifier
        return self.pseudonym("host", identifier or hostname)

    def pseudonym(self, namespace: str, value: str) -> str:
        """Stable pseudonym for *value* within *namespace*.

        The namespace stops the same string colliding across contexts — a
        hostname and a username that happen to match should not produce the
        same label.
        """
        digest = hmac.new(self.salt, f"{namespace}:{value}".encode(), sha256).hexdigest()
        return f"{namespace}-{digest[:_PSEUDONYM_HEX]}"
