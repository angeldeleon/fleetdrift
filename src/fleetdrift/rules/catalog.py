"""The curated software risk catalog.

Matching is token-based, not substring: a pattern matches when its tokens appear
as a contiguous run inside the normalised software name. ``anydesk`` therefore
matches ``AnyDesk``, ``AnyDesk 8.0.8`` and ``AnyDesk.app``, but not
``manydesks``. Substring matching would produce exactly the kind of confident
false positive that gets a tool switched off.

Severity here reflects **what the software can do**, not whether it is
authorised — the catalog cannot know that. A remote-access tool your helpdesk
deployed is HIGH by capability and completely fine in context; the way to say so
is to allowlist it, which is one line of config. What genuinely deserves
attention is the *drift* finding when one appears somewhere new.

Entries are deliberately conservative. A catalog that flags ``nmap`` on a
security engineer's laptop as HIGH teaches the team to ignore it, and then the
cryptominer gets ignored too.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import RiskCategory, Severity
from ..validation import ValidationError, normalize_software_name, read_text_file, safe_text

log = logging.getLogger(__name__)

_MAX_CATALOG_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """One rule matching a family of software."""

    id: str
    patterns: tuple[str, ...]
    category: RiskCategory
    severity: Severity
    title: str
    detail: str
    remediation: str = ""
    references: tuple[str, ...] = ()
    source: str = "builtin"

    def matches(self, normalized_name: str) -> bool:
        tokens = normalized_name.split()
        return any(_contains_tokens(tokens, pattern.split()) for pattern in self.patterns)


def _contains_tokens(haystack: list[str], needle: list[str]) -> bool:
    """True when *needle* appears as a contiguous run of tokens in *haystack*."""
    if not needle or len(needle) > len(haystack):
        return False
    first = needle[0]
    for index in range(len(haystack) - len(needle) + 1):
        if haystack[index] == first and haystack[index : index + len(needle)] == needle:
            return True
    return False


_REMOTE_ACCESS_DETAIL = (
    "Remote-access and RMM software allows interactive control of the endpoint. "
    "It is legitimate when IT deploys it and a serious problem when it arrives "
    "any other way — it is the most common persistence mechanism in hands-on "
    "intrusions precisely because it looks like normal admin tooling."
)
_REMOTE_ACCESS_FIX = (
    "If IT deployed this, add it to policy.allowlist so it stops being reported. "
    "If not, treat the host as suspect: establish who installed it and when."
)

BUILTIN_CATALOG: tuple[CatalogEntry, ...] = (
    # ---------------- remote access / RMM ----------------
    CatalogEntry(
        id="remote-access.commercial",
        patterns=(
            "teamviewer",
            "anydesk",
            "screenconnect",
            "connectwise control",
            "connectwise screenconnect",
            "splashtop",
            "logmein",
            "gotomypc",
            "ammyy admin",
            "remote utilities",
            "radmin",
            "supremo",
            "ultraviewer",
            "rustdesk",
            "dwservice",
            "chrome remote desktop",
        ),
        category=RiskCategory.REMOTE_ACCESS,
        severity=Severity.HIGH,
        title="Remote-access software installed",
        detail=_REMOTE_ACCESS_DETAIL,
        remediation=_REMOTE_ACCESS_FIX,
        references=("https://attack.mitre.org/techniques/T1219/",),
    ),
    CatalogEntry(
        id="remote-access.rmm",
        patterns=(
            "atera",
            "ninjarmm",
            "ninja rmm",
            "syncro",
            "kaseya",
            "pulseway",
            "action1",
            "tacticalrmm",
            "tactical rmm",
            "meshcentral",
            "meshagent",
            "level io",
            "itarian",
            "comodo one",
        ),
        category=RiskCategory.REMOTE_ACCESS,
        severity=Severity.HIGH,
        title="Remote monitoring and management (RMM) agent installed",
        detail=(
            "RMM agents provide unattended remote control and software deployment. "
            "Ransomware operators routinely install a second, unmanaged RMM agent "
            "for persistence because it survives credential resets and blends in "
            "with legitimate IT tooling."
        ),
        remediation=_REMOTE_ACCESS_FIX,
        references=("https://attack.mitre.org/techniques/T1219/",),
    ),
    CatalogEntry(
        id="remote-access.vnc",
        patterns=("realvnc", "tightvnc", "ultravnc", "tigervnc", "vnc viewer", "vnc server"),
        category=RiskCategory.REMOTE_ACCESS,
        severity=Severity.MEDIUM,
        title="VNC remote-desktop software installed",
        detail=(
            "VNC exposes interactive desktop access. Historically it is often "
            "deployed with weak or absent authentication, and older builds "
            "carry known authentication-bypass flaws."
        ),
        remediation=_REMOTE_ACCESS_FIX,
        references=("https://attack.mitre.org/techniques/T1219/",),
    ),
    # ---------------- cryptominers ----------------
    CatalogEntry(
        id="cryptominer.known",
        patterns=(
            "xmrig",
            "nicehash",
            "phoenixminer",
            "cgminer",
            "bfgminer",
            "claymore",
            "t rex miner",
            "trex miner",
            "gminer",
            "lolminer",
            "ethminer",
            "cudo miner",
            "minergate",
            "nbminer",
            "srbminer",
            "xmr stak",
        ),
        category=RiskCategory.CRYPTOMINER,
        severity=Severity.CRITICAL,
        title="Cryptocurrency miner installed",
        detail=(
            "A cryptocurrency miner on a corporate endpoint is either an insider "
            "misusing company hardware or, far more often, the payload of an "
            "intrusion. Either way it means something reached the machine that "
            "should not have."
        ),
        remediation=(
            "Isolate the host and investigate how it arrived. Miners are frequently "
            "dropped alongside a loader that also establishes persistence, so "
            "removing the miner alone is not remediation."
        ),
        references=("https://attack.mitre.org/techniques/T1496/",),
    ),
    # ---------------- credential tooling ----------------
    CatalogEntry(
        id="credential.dumper",
        patterns=(
            "mimikatz",
            "lazagne",
            "pwdump",
            "gsecdump",
            "wce windows credentials editor",
            "webbrowserpassview",
            "mail passview",
            "protected storage passview",
            "网络密码",  # NirSoft tools ship localised names in some bundles
        ),
        category=RiskCategory.CREDENTIAL_TOOL,
        severity=Severity.CRITICAL,
        title="Credential-dumping tool installed",
        detail=(
            "This software exists to extract stored credentials from memory, "
            "browsers or the OS credential store. There is no benign reason for "
            "it to be installed on a general-purpose endpoint."
        ),
        remediation=(
            "Treat as an active incident. Assume credentials used on this host "
            "are compromised and rotate them."
        ),
        references=("https://attack.mitre.org/techniques/T1003/",),
    ),
    CatalogEntry(
        id="credential.cracker",
        patterns=("hashcat", "john the ripper", "cain abel", "ophcrack", "hydra thc", "thc hydra"),
        category=RiskCategory.CREDENTIAL_TOOL,
        severity=Severity.HIGH,
        title="Password-cracking tool installed",
        detail=(
            "Offline password cracking software. Legitimate on an authorised "
            "red-team or forensics workstation, and a strong signal anywhere else."
        ),
        remediation="Confirm the host belongs to someone whose role requires it; allowlist if so.",
        references=("https://attack.mitre.org/techniques/T1110/002/",),
    ),
    # ---------------- offensive tooling ----------------
    CatalogEntry(
        id="offensive.c2",
        patterns=(
            "cobalt strike",
            "cobaltstrike",
            "sliver",
            "brute ratel",
            "havoc c2",
            "powersploit",
            "empire",
            "covenant",
            "metasploit",
        ),
        category=RiskCategory.OFFENSIVE_TOOL,
        severity=Severity.CRITICAL,
        title="Command-and-control or exploitation framework installed",
        detail=(
            "Adversary-emulation frameworks provide implant generation, C2 and "
            "post-exploitation tooling. Outside a sanctioned red-team host, "
            "presence usually means the machine is already being operated by "
            "someone else."
        ),
        remediation="Verify against your authorised red-team asset list; treat as an incident otherwise.",
        references=("https://attack.mitre.org/software/S0154/",),
    ),
    CatalogEntry(
        id="offensive.recon",
        patterns=("bloodhound", "sharphound", "rubeus", "impacket", "responder", "sqlmap", "crackmapexec"),
        category=RiskCategory.OFFENSIVE_TOOL,
        severity=Severity.HIGH,
        title="Active Directory or network attack tooling installed",
        detail=(
            "Tooling for enumerating and abusing directory services or capturing "
            "network authentication. Expected on a penetration-testing host, "
            "notable on anything else."
        ),
        remediation="Confirm the host is an authorised testing machine; allowlist if so.",
        references=("https://attack.mitre.org/techniques/T1087/",),
    ),
    CatalogEntry(
        id="dual-use.network-tools",
        patterns=("nmap", "zenmap", "wireshark", "burp suite", "angry ip scanner", "advanced ip scanner"),
        category=RiskCategory.OFFENSIVE_TOOL,
        severity=Severity.LOW,
        title="Network analysis tooling installed",
        detail=(
            "Standard equipment for IT and security staff, and equally standard "
            "for an intruder mapping the network. Reported at LOW because the "
            "base rate on engineering machines is high — the signal is a new "
            "install on a host that has no reason for one."
        ),
        remediation="Allowlist for teams that need it, so a genuinely unusual install stands out.",
        references=("https://attack.mitre.org/techniques/T1046/",),
    ),
    # ---------------- unsanctioned VPN / anonymisers ----------------
    CatalogEntry(
        id="vpn.consumer",
        patterns=(
            "nordvpn",
            "expressvpn",
            "protonvpn",
            "surfshark",
            "cyberghost",
            "windscribe",
            "tunnelbear",
            "mullvad",
            "hola vpn",
            "psiphon",
            "ultrasurf",
            "hotspot shield",
            "tor browser",
        ),
        category=RiskCategory.UNSANCTIONED_VPN,
        severity=Severity.MEDIUM,
        title="Consumer VPN or anonymiser installed",
        detail=(
            "Consumer VPN clients tunnel traffic outside corporate egress, "
            "bypassing DNS filtering, DLP and network monitoring. Some free "
            "providers have been documented reselling user bandwidth as exit nodes."
        ),
        remediation="Confirm against acceptable-use policy; allowlist a corporate VPN client.",
        references=("https://attack.mitre.org/techniques/T1090/",),
    ),
    # ---------------- file sharing ----------------
    CatalogEntry(
        id="filesharing.p2p",
        patterns=(
            "utorrent",
            "bittorrent",
            "qbittorrent",
            "transmission",
            "deluge",
            "vuze",
            "frostwire",
            "limewire",
            "emule",
            "bitcomet",
        ),
        category=RiskCategory.FILE_SHARING,
        severity=Severity.MEDIUM,
        title="Peer-to-peer file-sharing client installed",
        detail=(
            "P2P clients create inbound network exposure, are a common vector for "
            "trojanised software, and carry obvious copyright-liability risk on "
            "company hardware."
        ),
        remediation="Confirm against acceptable-use policy and remove if unsanctioned.",
    ),
    # ---------------- end of life ----------------
    CatalogEntry(
        id="eol.unsupported",
        patterns=(
            "adobe flash player",
            "adobe shockwave",
            "microsoft silverlight",
            "quicktime",
            "adobe air",
            "internet explorer",
        ),
        category=RiskCategory.EOL_SOFTWARE,
        severity=Severity.HIGH,
        title="End-of-life software installed",
        detail=(
            "This software is no longer supported and receives no security "
            "updates. Known vulnerabilities in it will never be fixed, which "
            "makes it a permanent, reliable foothold."
        ),
        remediation="Uninstall. There is no patched version to move to.",
    ),
)


def _entry_from_mapping(raw: Any, index: int, source: str) -> CatalogEntry:
    if not isinstance(raw, dict):
        raise ValidationError(f"catalog entry {index} must be a mapping")

    allowed = {
        "id",
        "patterns",
        "category",
        "severity",
        "title",
        "detail",
        "remediation",
        "references",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValidationError(
            f"catalog entry {index} has unknown key(s): {', '.join(unknown)} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )

    patterns_raw = raw.get("patterns")
    if not isinstance(patterns_raw, list) or not patterns_raw:
        raise ValidationError(f"catalog entry {index} needs a non-empty 'patterns' list")

    patterns: list[str] = []
    for pattern in patterns_raw:
        normalized = normalize_software_name(pattern)
        if not normalized:
            raise ValidationError(f"catalog entry {index} has a pattern that normalises to nothing")
        if len(normalized) < 4:
            # A three-character pattern will match half the estate. Rejecting it
            # here beats debugging a flood of false positives later.
            raise ValidationError(
                f"catalog entry {index} pattern {pattern!r} is too short to match safely "
                "(4 characters minimum after normalisation)"
            )
        patterns.append(normalized)

    try:
        category = RiskCategory(str(raw.get("category", "unknown")).strip().lower())
    except ValueError as exc:
        raise ValidationError(f"catalog entry {index} has an unknown category") from exc

    return CatalogEntry(
        id=safe_text(raw.get("id") or f"custom.{index}", limit=64),
        patterns=tuple(patterns),
        category=category,
        severity=Severity.parse(str(raw.get("severity", "medium"))),
        title=safe_text(raw.get("title") or "Software flagged by local policy", limit=200),
        detail=safe_text(raw.get("detail") or "", limit=1000),
        remediation=safe_text(raw.get("remediation") or "", limit=500),
        references=tuple(safe_text(r, limit=300) for r in (raw.get("references") or [])),
        source=source,
    )


def load_catalog(extra_path: str | Path | None = None) -> tuple[CatalogEntry, ...]:
    """Return the built-in catalog, optionally extended from a YAML file."""
    entries = list(BUILTIN_CATALOG)
    if not extra_path:
        return tuple(entries)

    path = Path(extra_path).expanduser()
    # Read through a descriptor: the path comes from the config and usually
    # points inside the repository the scan runs from, so is_file() followed by
    # read_text() checked one name and read another. See
    # :func:`fleetdrift.validation.read_text_file`.
    text = read_text_file(path, max_bytes=_MAX_CATALOG_BYTES, what="catalog file")

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValidationError(f"catalog file is not valid YAML: {exc}") from exc

    if raw is None:
        return tuple(entries)
    if isinstance(raw, dict):
        raw = raw.get("entries")
    if not isinstance(raw, list):
        raise ValidationError("catalog file must contain a list of entries (or an 'entries' key)")
    if len(raw) > 5000:
        raise ValidationError("catalog file has more than 5000 entries")

    for index, item in enumerate(raw):
        entries.append(_entry_from_mapping(item, index, source=str(path)))

    log.info("loaded %d catalog entries (%d from %s)", len(entries), len(raw), path)
    return tuple(entries)


@dataclass(slots=True)
class CatalogMatcher:
    """Matches normalised software names against the catalog."""

    entries: tuple[CatalogEntry, ...] = field(default_factory=lambda: BUILTIN_CATALOG)

    def match(self, normalized_name: str) -> list[CatalogEntry]:
        """Return every entry matching *normalized_name*, most severe first."""
        if not normalized_name:
            return []
        hits = [entry for entry in self.entries if entry.matches(normalized_name)]
        hits.sort(key=lambda e: (-e.severity.rank, e.id))
        return hits
