"""Input validation and outbound-request guards.

This module is the trust boundary. Everything externally influenced — a Fleet
server URL from config, a webhook URL from the environment, a software name
returned by an endpoint — passes through here before the tool acts on it.

Three threats drive the design:

1. **SSRF.** ``fleetdrift`` runs on a management network with reach into
   internal systems, and posts to operator-supplied webhooks. A webhook of
   ``http://169.254.169.254/latest/meta-data/`` must not be followed.
   :func:`assert_public_http_url` resolves the host and rejects anything outside
   public unicast space; the HTTP client re-checks after every redirect.

2. **Injection via inventory data.** Software names, publishers and paths are
   chosen by whatever is installed on the endpoint — which, in the scenario this
   tool exists to detect, includes the attacker. Those strings reach Slack
   messages, Markdown reports and an LLM prompt, so they are sanitised here at
   the boundary rather than at each sink.

3. **Aiming the tool inward.** A Fleet URL pointing at an internal host is a
   legitimate enterprise case, unlike a webhook — so it is permitted, but only
   when the operator opts in explicitly.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from urllib.parse import urlsplit

__all__ = [
    "ValidationError",
    "assert_public_http_url",
    "assert_http_url",
    "resolve_public_ips",
    "is_public_address",
    "safe_text",
    "normalize_software_name",
    "validate_env_var_name",
]


class ValidationError(ValueError):
    """Raised when untrusted input fails validation."""


# Anything outside this is either a broken agent or a deliberate injection.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_FIELD_LENGTH = 256

# Characters that are invisible but change how the text around them is read.
# A name ending in U+202E RIGHT-TO-LEFT OVERRIDE followed by "gpn.exe" displays
# to an analyst as "...exe.npg" -- the Trojan Source trick, and the same class
# of forgery as smuggling in a newline. The rest are zero-width or bidi-isolate
# characters used to split a name so it reads as one thing and matches another.
#
# Written as escapes on purpose. A literal U+202E in this file would be exactly
# the problem it describes -- bandit's B613 flags it, correctly -- and it would
# render this comment unreadable in an editor.
_INVISIBLE_RE = re.compile(
    "[\u200b-\u200f\u061c\u00ad\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]"
)

# json.loads() happily produces lone surrogates from "\ud800". Every subsequent
# encode -- writing the report, hashing a fingerprint, the SQLite driver --
# raises UnicodeEncodeError, so one crafted name from a hostile fleet manager
# denies scanning of the whole estate.
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


def safe_text(value: object, *, limit: int = _MAX_FIELD_LENGTH) -> str:
    """Neutralise an endpoint-supplied string for storage and rendering.

    Collapses control characters (a newline lets a crafted software name forge
    an extra line in a Slack alert or a Markdown report), drops invisible and
    direction-changing characters, replaces unpaired surrogates so nothing
    downstream can fail to encode, and caps length. Applied at ingestion so no
    downstream consumer has to remember to do it.
    """
    text = _SURROGATE_RE.sub("�", str(value))
    text = _CONTROL_CHARS_RE.sub(" ", text)
    text = _INVISIBLE_RE.sub("", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def normalize_software_name(value: object) -> str:
    """Canonical form used for rule matching and drift keys.

    Lowercased, control characters stripped, and the decorations vendors add to
    installer names removed — ``AnyDesk.app``, ``AnyDesk (64-bit)`` and
    ``AnyDesk 8.0.8`` must all match the same rule, or a catalog entry can be
    evaded by installing the same product from a different package.

    Two properties matter beyond tidiness, because this function decides both
    what a rule matches and what a drift key is:

    * **NFKC first.** Without it, ``ＡｎｙＤｅｓｋ`` in fullwidth characters is a
      different string from ``AnyDesk`` and matches no rule.
    * **Unicode-aware separator stripping.** The previous ``[^a-z0-9]`` reduced
      any name written in a non-Latin script to the empty string, and callers
      skip empty names — so ``网络密码`` was not flagged, not listed as
      unclassified, and produced no drift finding. A one-character rename bought
      total invisibility, which for a tool whose input is chosen by malware is
      the worst possible failure mode.
    * **Never empty for a name that has any content.** The separator strip is
      the right rule for letters and digits and the wrong one for a name made
      only of punctuation, symbols or emoji: ``+++`` and ``🔒`` reduced to ``""``
      and hit the same "skip empty names" branch, which bought the same total
      invisibility by a different spelling. Falling back to the sanitised text
      keeps such an item visible to every check and to drift; it is still
      case- and width-folded, so it is still a stable key.
    """
    text = unicodedata.normalize("NFKC", safe_text(value)).casefold()
    text = re.sub(r"\.(app|exe|msi|pkg|dmg)$", "", text)
    text = re.sub(r"\((?:x?64|32|64-bit|32-bit|x86|arm64)[^)]*\)", " ", text)
    text = re.sub(r"\bversion\b", " ", text)
    # Trailing version numbers: "AnyDesk 8.0.8" -> "anydesk"
    text = re.sub(r"[\s\-_]+v?\d+(?:\.\d+)*\s*$", "", text)
    # \w is Unicode-aware, so this keeps letters and digits in every script and
    # drops punctuation. Underscore is a \w character but reads as a separator.
    stripped = " ".join(re.sub(r"[\W_]+", " ", text).split())
    if stripped:
        return stripped
    # Nothing but separators survived. The version and decoration strips above
    # have already run, so "+++ 1.0" and "+++ 2.0" still collapse to one key.
    return " ".join(text.split())


def validate_env_var_name(name: str, *, where: str) -> str:
    """Confirm a config field holds an environment variable *name*, not a secret."""
    text = str(name).strip()
    if "://" in text or "/" in text:
        raise ValidationError(f"{where} must be the NAME of an environment variable, not a URL or path")
    if not text or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        raise ValidationError(f"{where} is not a valid environment variable name: {name!r}")
    return text


def is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally-routable unicast addresses.

    ``is_global`` alone is insufficient: it does not exclude multicast, and IPv6
    handling around mapped and translated addresses has had gaps. The explicit
    checks below are cheap insurance.
    """
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        # ::ffff:169.254.169.254 and 2002::/16 are IPv6 spellings of IPv4
        # addresses. Unwrap and re-check rather than trusting the v6 flags.
        mapped = ip.ipv4_mapped or getattr(ip, "sixtofour", None)
        if mapped is not None:
            return is_public_address(mapped)
        if ip.is_site_local:
            return False

    return ip.is_global


def resolve_public_ips(host: str, *, port: int = 443) -> list[str]:
    """Resolve *host*, raising unless every address is public.

    Fails closed on a mixed result: a host resolving to one public and one
    private address is the classic DNS-rebinding shape, and there is no safe way
    to "use the good one" — the client may pick the other at connect time.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationError(f"cannot resolve host {host!r}: {exc}") from exc

    # sockaddr is (host, port) for IPv4 and a 4-tuple for IPv6; element 0 is the
    # address string in both cases.
    addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        raise ValidationError(f"host {host!r} resolved to no addresses")

    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise ValidationError(f"host {host!r} resolved to unparseable address {address!r}") from exc
        if not is_public_address(parsed):
            raise ValidationError(
                f"refusing to connect to {host!r}: resolves to non-public address {address}"
            )

    return addresses


def assert_http_url(
    url: str,
    *,
    require_https: bool = True,
    allow_internal: bool = False,
    resolve: bool = True,
) -> str:
    """Validate an outbound URL.

    With ``allow_internal=False`` (the default, and the only setting used for
    webhooks) the host must resolve entirely to public address space.

    ``allow_internal=True`` exists for one case: an on-premises Fleet server,
    which legitimately lives on RFC1918. It is opt-in per config field and never
    applies to notification destinations.

    ``resolve=False`` checks the URL's *shape* only — scheme, credentials, host,
    port — without touching DNS. Config parsing uses it so that ``fleetdrift
    validate`` works offline and does not fail on a host that happens to be
    unreachable at the moment. Nothing is weakened by this: the address check
    that actually matters runs at connect time in
    :func:`fleetdrift.httpclient.safe_request`, where it is the last thing
    before a socket is opened.

    Even then the check is time-of-check/time-of-use — DNS can change between
    validation and connection. It raises the bar substantially against
    accidental and opportunistic SSRF without claiming to be airtight.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("URL is empty")

    parts = urlsplit(url.strip())

    allowed_schemes = ("https",) if require_https else ("https", "http")
    if parts.scheme not in allowed_schemes:
        raise ValidationError(
            f"URL scheme {parts.scheme!r} is not allowed (expected one of: {', '.join(allowed_schemes)})"
        )

    if parts.username or parts.password:
        raise ValidationError("URLs with embedded credentials are not allowed")

    host = parts.hostname
    if not host:
        raise ValidationError("URL has no host")

    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError(f"URL has an invalid port: {exc}") from exc

    if allow_internal:
        return url.strip()

    # A literal IP needs no DNS, so it is checked even in shape-only mode:
    # catching `https://10.0.0.5` when the config is parsed is far better
    # feedback than catching it on the first scheduled run at 3am.
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public_address(literal):
            raise ValidationError(f"refusing to connect to non-public address {host}")
        return url.strip()

    if not resolve:
        return url.strip()

    effective_port = port or (443 if parts.scheme == "https" else 80)
    resolve_public_ips(host, port=effective_port)
    return url.strip()


def assert_public_http_url(url: str, *, require_https: bool = True) -> str:
    """Validate an outbound URL and require it to point somewhere public."""
    return assert_http_url(url, require_https=require_https, allow_internal=False)
