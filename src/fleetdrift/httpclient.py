"""Guarded HTTP client for every outbound request this tool makes.

Everything goes through :func:`safe_request`, which:

* validates the URL and confirms the host resolves to public address space
  before connecting — except for an explicitly opted-in internal Fleet server;
* re-validates after each redirect, because an allowed URL redirecting to
  ``http://169.254.169.254/`` is the standard SSRF bypass;
* **drops credential-bearing headers and the request body when a redirect
  crosses origins**, so a 302 cannot forward your Fleet token, your API key, or
  your fleet's software inventory to a third party;
* streams the response and aborts once the size cap is exceeded, rather than
  buffering an unbounded body first — a fleet API can legitimately return a lot
  of data, and an untrusted one can return far more;
* redacts URLs in every error message, because for a webhook the path *is* the
  credential.

There is no code path in ``fleetdrift`` that makes an unguarded HTTP request.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from .validation import ValidationError, assert_http_url

log = logging.getLogger(__name__)

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

# Headers that authenticate the request and must never survive a hop to a
# different origin. Compared lowercase.
_CREDENTIAL_HEADERS = frozenset(
    {
        "authorization",
        "x-api-key",
        "proxy-authorization",
        "cookie",
        "api-key",
        "x-auth-token",
        "x-fleet-token",
    }
)


class HTTPError(Exception):
    """A guarded request failed."""


def safe_request(
    method: str,
    url: str,
    *,
    timeout: float = 30.0,
    headers: Mapping[str, str] | None = None,
    json_body: Any | None = None,
    user_agent: str = "fleetdrift",
    allow_http: bool = False,
    allow_internal: bool = False,
    verify: bool = True,
) -> httpx.Response:
    """Perform an SSRF-guarded HTTP request.

    Redirects are followed manually so each hop can be re-validated. Raises
    :class:`HTTPError` on transport failure and :class:`ValidationError` if any
    URL in the chain fails validation.
    """
    current = assert_http_url(url, require_https=not allow_http, allow_internal=allow_internal)

    request_headers = {
        "User-Agent": user_agent,
        "Accept": "application/json, text/plain;q=0.8, */*;q=0.5",
    }
    if headers:
        for key, value in headers.items():
            # Header injection guard: a newline in a value can split the
            # request. httpx blocks most of this, but failing loudly beats
            # depending on a library's internals.
            if any(c in str(value) for c in "\r\n") or any(c in str(key) for c in "\r\n"):
                raise ValidationError(f"illegal newline in header {key!r}")
            request_headers[str(key)] = str(value)

    current_method = method.upper()
    current_headers = dict(request_headers)
    current_body = json_body

    try:
        with httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            verify=verify,
            trust_env=False,  # ignore ambient HTTP(S)_PROXY, which could redirect traffic
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as client:
            for hop in range(MAX_REDIRECTS + 1):
                request = client.build_request(
                    current_method, current, headers=current_headers, json=current_body
                )
                response = client.send(request, stream=True)

                try:
                    location = response.headers.get("location") if response.is_redirect else None
                    if location:
                        if hop >= MAX_REDIRECTS:
                            raise HTTPError(f"too many redirects (>{MAX_REDIRECTS}) for {redact_url(url)}")

                        candidate = urljoin(current, location)
                        # allow_internal exists for one case: an on-prem Fleet
                        # server the operator named. It must not extend to
                        # wherever that server points us next — otherwise a
                        # compromised (or on-path, since verify_tls can be
                        # disabled) Fleet can redirect the scanner to any
                        # internal endpoint and have the response parsed as
                        # inventory and forwarded to Slack.
                        same_origin = _origin(candidate) == _origin(current)
                        next_url = assert_http_url(
                            candidate,
                            require_https=not allow_http,
                            allow_internal=allow_internal and same_origin,
                        )

                        if _origin(next_url) != _origin(current):
                            # httpx strips Authorization on cross-host redirects
                            # when it follows them itself; following manually
                            # means we must, and for the same reason. The body
                            # goes too — it carries the inventory payload.
                            current_headers = {
                                k: v
                                for k, v in current_headers.items()
                                if k.lower() not in _CREDENTIAL_HEADERS
                            }
                            current_body = None
                            log.debug("dropping credentials and body across origin change")

                        if response.status_code in (301, 302, 303) and current_method != "GET":
                            # RFC 9110 §15.4: these turn a POST into a GET.
                            current_method = "GET"
                            current_body = None

                        current = next_url
                        continue

                    content = _read_capped(response, current)
                finally:
                    response.close()

                # Rebuild as a non-streaming response so callers can use
                # .json() normally. iter_bytes() already decompressed, so the
                # original Content-Encoding must go: leaving it makes httpx
                # decode the plaintext a second time and fail on every gzipped
                # response — which is very nearly all of them.
                rebuilt = httpx.Headers(response.headers)
                rebuilt.pop("content-encoding", None)
                rebuilt["content-length"] = str(len(content))
                return httpx.Response(
                    status_code=response.status_code,
                    headers=rebuilt,
                    content=content,
                    request=request,
                )

            raise HTTPError(f"redirect handling fell through for {redact_url(url)}")  # pragma: no cover
    except httpx.HTTPError as exc:
        raise HTTPError(f"request to {redact_url(url)} failed: {exc}") from exc


def _read_capped(response: httpx.Response, url: str) -> bytes:
    """Read the body, aborting as soon as the cap is exceeded.

    ``Content-Length`` alone is not enough: a chunked response omits it, and a
    non-streaming read would buffer the whole body before any check could run.
    """
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise HTTPError(f"response from {redact_url(url)} declares more than {MAX_RESPONSE_BYTES} bytes")

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise HTTPError(f"response from {redact_url(url)} exceeds {MAX_RESPONSE_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    default_port = 443 if parts.scheme == "https" else 80
    try:
        port = parts.port or default_port
    except ValueError:  # pragma: no cover - validated upstream
        port = default_port
    return (parts.scheme, (parts.hostname or "").lower(), port)


def redact_url(url: str) -> str:
    """Strip everything after the host.

    For most webhook providers the secret lives in the URL *path*, not a query
    string, so logging a full URL on error leaks the credential into a CI log.
    """
    try:
        parts = urlsplit(url)
        if not parts.scheme or not parts.hostname:
            return "<redacted url>"
        return f"{parts.scheme}://{parts.hostname}/<redacted>"
    except Exception:  # pragma: no cover - defensive
        return "<redacted url>"
