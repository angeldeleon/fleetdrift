"""End-to-end tests for the guarded HTTP client.

Run against throwaway loopback servers. The SSRF guard is patched out for the
transport tests — it would (correctly) refuse to talk to 127.0.0.1, and what is
under test here is everything *after* the guard.

This file exists because the alternative failed. The redirect-scope regression
test used to assert that a particular string appeared in the function's source,
which would have passed even if that expression were dead code. Behaviour has to
be exercised, not inspected.
"""

from __future__ import annotations

import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import fleetdrift.httpclient as hc
from fleetdrift.httpclient import MAX_RESPONSE_BYTES, HTTPError, safe_request
from fleetdrift.validation import ValidationError

RECEIVED: list[dict] = []
_OTHER_PORT = 0


class _Handler(BaseHTTPRequestHandler):
    """Serves the transfer shapes a real endpoint might return."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # noqa: A002 - silence test output
        pass

    def _record(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        RECEIVED.append(
            {
                "path": self.path,
                "method": self.command,
                "port": self.server.server_address[1],
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("utf-8", "replace"),
            }
        )

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._record()
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self._record()
        self._dispatch()

    def _dispatch(self) -> None:
        path = self.path
        if path.startswith("/plain"):
            self._send(json.dumps({"ok": True}).encode())
        elif path.startswith("/gzip"):
            payload = gzip.compress(json.dumps({"ok": True, "encoding": "gzip"}).encode())
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-encoding", "gzip")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif path.startswith("/chunked"):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for piece in (b'{"ok"', b":true", b"}"):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif path.startswith("/huge"):
            self.send_response(200)
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            block = b"A" * 65536
            try:
                for _ in range((MAX_RESPONSE_BYTES // len(block)) + 8):
                    self.wfile.write(f"{len(block):x}\r\n".encode() + block + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass  # the client aborted, which is the point
        elif path.startswith("/redirect-cross-307"):
            self._redirect(307, f"http://127.0.0.1:{_OTHER_PORT}/plain")
        elif path.startswith("/redirect-cross"):
            self._redirect(302, f"http://127.0.0.1:{_OTHER_PORT}/plain")
        elif path.startswith("/redirect-metadata"):
            self._redirect(302, "http://169.254.169.254/latest/meta-data/")
        elif path.startswith("/redirect-same"):
            self._redirect(302, "/plain")
        elif path.startswith("/redirect-loop"):
            self._redirect(302, "/redirect-loop")
        else:
            self._send(b"{}", status=404)

    def _redirect(self, status: int, location: str) -> None:
        self.send_response(status)
        self.send_header("location", location)
        self.send_header("content-length", "0")
        self.end_headers()

    def _send(self, payload: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _QuietServer(ThreadingHTTPServer):
    """Suppresses the broken-pipe traceback the size-cap test deliberately causes."""

    def handle_error(self, request, client_address) -> None:
        pass


def _start() -> ThreadingHTTPServer:
    server = _QuietServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture(scope="module")
def servers():
    global _OTHER_PORT
    primary = _start()
    secondary = _start()
    _OTHER_PORT = secondary.server_address[1]
    yield primary, secondary
    primary.shutdown()
    secondary.shutdown()


@pytest.fixture
def allow_loopback(monkeypatch):
    """Bypass the address check so the transport behind it can be exercised.

    Only the *address* portion is stubbed; scheme, credential and redirect
    handling all still run. The real guard is tested in test_validation.py and
    again, unstubbed, in TestGuardStillApplies below.
    """
    monkeypatch.setattr(hc, "assert_http_url", lambda url, require_https=True, allow_internal=False: url)
    RECEIVED.clear()


def _url(server, path: str) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}{path}"


class TestTransferEncodings:
    def test_plain(self, servers, allow_loopback) -> None:
        primary, _ = servers
        assert safe_request("GET", _url(primary, "/plain"), allow_http=True).json() == {"ok": True}

    def test_gzip(self, servers, allow_loopback) -> None:
        """Streaming decompresses, so the rebuilt response must drop content-encoding."""
        primary, _ = servers
        response = safe_request("GET", _url(primary, "/gzip"), allow_http=True)
        assert response.json()["encoding"] == "gzip"

    def test_chunked(self, servers, allow_loopback) -> None:
        primary, _ = servers
        assert safe_request("GET", _url(primary, "/chunked"), allow_http=True).json() == {"ok": True}

    def test_oversized_chunked_body_is_aborted(self, servers, allow_loopback) -> None:
        primary, _ = servers
        with pytest.raises(HTTPError, match="exceeds"):
            safe_request("GET", _url(primary, "/huge"), allow_http=True, timeout=30.0)


class TestRedirects:
    def test_same_origin_redirect_is_followed(self, servers, allow_loopback) -> None:
        primary, _ = servers
        assert safe_request("GET", _url(primary, "/redirect-same"), allow_http=True).json() == {"ok": True}

    def test_redirect_loop_is_capped(self, servers, allow_loopback) -> None:
        primary, _ = servers
        with pytest.raises(HTTPError, match="too many redirects"):
            safe_request("GET", _url(primary, "/redirect-loop"), allow_http=True)

    def test_credentials_and_body_dropped_across_origins(self, servers, allow_loopback) -> None:
        primary, secondary = servers
        safe_request(
            "POST",
            _url(primary, "/redirect-cross-307"),
            headers={"x-api-key": "SECRET-KEY", "authorization": "Bearer SECRET"},
            json_body={"inventory": "sensitive"},
            allow_http=True,
        )
        hop = [r for r in RECEIVED if r["port"] == secondary.server_address[1]]
        assert hop, "the redirect was not followed"
        assert "x-api-key" not in hop[0]["headers"]
        assert "authorization" not in hop[0]["headers"]
        assert "sensitive" not in hop[0]["body"]

    def test_credentials_survive_a_same_origin_redirect(self, servers, allow_loopback) -> None:
        primary, _ = servers
        safe_request(
            "GET",
            _url(primary, "/redirect-same"),
            headers={"x-api-key": "SECRET-KEY"},
            allow_http=True,
        )
        final = [r for r in RECEIVED if r["path"] == "/plain"]
        assert final and final[0]["headers"].get("x-api-key") == "SECRET-KEY"

    def test_post_downgrades_to_get_on_302(self, servers, allow_loopback) -> None:
        primary, _ = servers
        safe_request("POST", _url(primary, "/redirect-same"), json_body={"a": 1}, allow_http=True)
        final = [r for r in RECEIVED if r["path"] == "/plain"]
        assert final and final[0]["method"] == "GET" and final[0]["body"] == ""


class TestGuardStillApplies:
    """These run WITHOUT the address-check stub — the guard must actually fire."""

    def test_internal_targets_are_refused(self) -> None:
        for url in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1/", "http://10.0.0.1/"):
            with pytest.raises(ValidationError):
                safe_request("GET", url, allow_http=True)

    def test_allow_internal_does_not_survive_a_cross_origin_redirect(self, servers) -> None:
        """The fix this test exists for: an on-prem Fleet must not be able to
        redirect the scanner to an arbitrary internal endpoint."""
        RECEIVED.clear()
        primary, secondary = servers
        # allow_internal lets us reach the loopback server at all...
        with pytest.raises(ValidationError):
            # ...but the cross-origin hop to the metadata service is refused.
            safe_request(
                "GET",
                _url(primary, "/redirect-metadata"),
                allow_http=True,
                allow_internal=True,
            )

    def test_allow_internal_still_permits_a_same_origin_redirect(self, servers) -> None:
        RECEIVED.clear()
        primary, _ = servers
        response = safe_request("GET", _url(primary, "/redirect-same"), allow_http=True, allow_internal=True)
        assert response.json() == {"ok": True}

    def test_allow_internal_does_not_permit_a_cross_origin_internal_hop(self, servers) -> None:
        RECEIVED.clear()
        primary, secondary = servers
        with pytest.raises(ValidationError):
            safe_request("GET", _url(primary, "/redirect-cross"), allow_http=True, allow_internal=True)
        assert not [r for r in RECEIVED if r["port"] == secondary.server_address[1]]


class TestHeaderInjection:
    def test_newline_in_header_is_rejected(self, servers, allow_loopback) -> None:
        primary, _ = servers
        with pytest.raises(ValidationError, match="newline"):
            safe_request(
                "GET",
                _url(primary, "/plain"),
                headers={"x-api-key": "a\r\nX-Injected: 1"},
                allow_http=True,
            )
