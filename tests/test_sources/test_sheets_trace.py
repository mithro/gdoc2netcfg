"""fetch_sheet records a per-hop trace, and a failure says where it stalled.

These run against a real local HTTP server so the http.client / urllib code
paths that production uses (redirects, response parsing, socket timeouts)
are exercised, not mocked.  Production fetches are HTTPS; the tracing is
shared by the HTTP and HTTPS connection classes, and only the TLS step is
HTTPS-specific.
"""

from __future__ import annotations

import http.server
import threading
import urllib.error

import pytest

from gdoc2netcfg.sources.sheets import SheetFetchError, fetch_sheet

_BODY = b"Machine,MAC\ndesk,aa:bb:cc:dd:ee:ff\n"


class _Handler(http.server.BaseHTTPRequestHandler):
    release: threading.Event  # set on the server class by the fixture

    def log_message(self, *args):
        pass

    def _send_body(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/csv":
            self._send_body(_BODY)
        elif self.path.startswith("/redirect/"):
            self.send_response(307)
            self.send_header("Location", self.path[len("/redirect"):])
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/stall-headers":
            self.release.wait(10)
        elif self.path == "/stall-body":
            self.send_response(200)
            self.send_header("Content-Length", str(len(_BODY) * 4))
            self.end_headers()
            self.wfile.write(_BODY)
            self.wfile.flush()
            self.release.wait(10)
        elif self.path == "/bad-request":
            body = b"<html>Bad Request</html>"
            self.send_response(400)
            self.send_header("Server", "test-esf")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)


@pytest.fixture
def server():
    release = threading.Event()
    handler = type("Handler", (_Handler,), {"release": release})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    release.set()
    srv.shutdown()
    srv.server_close()


def test_success_records_one_hop(server):
    data = fetch_sheet("network", f"{server}/csv", timeout=5)
    assert data.csv_text == _BODY.decode()
    (hop,) = data.trace.hops
    assert hop.host == "127.0.0.1"
    assert hop.peer == "127.0.0.1"
    assert hop.status == 200
    assert hop.phase == "done"
    assert hop.bytes_in > len(_BODY)  # response headers + body
    assert hop.connected is not None and hop.request_sent is not None and hop.headers is not None
    assert hop.tls_done is None  # plain HTTP: no TLS step


def test_success_through_a_redirect_records_both_hops(server):
    data = fetch_sheet("network", f"{server}/redirect/csv", timeout=5)
    assert data.csv_text == _BODY.decode()
    first, second = data.trace.hops
    assert (first.status, first.phase) == (307, "done")
    assert first.location.endswith("/csv")
    assert (second.status, second.phase) == (200, "done")
    text = data.trace.describe()
    assert "HTTP 307" in text and "HTTP 200" in text


def test_stall_waiting_for_headers_names_the_hop_and_phase(server):
    with pytest.raises(SheetFetchError) as info:
        fetch_sheet("network", f"{server}/redirect/stall-headers", timeout=0.5)
    err = info.value
    assert isinstance(err.__cause__, TimeoutError)
    first, second = err.trace.hops
    assert first.phase == "done" and first.status == 307
    assert second.phase == "headers" and second.status is None
    assert second.request_sent is not None
    msg = str(err)
    # Original error first, so existing log greps still match.
    assert msg.startswith(str(err.__cause__))
    assert "waiting for response headers" in msg
    assert "hop 2" in msg


def test_stall_mid_body_reports_the_bytes_that_arrived(server):
    with pytest.raises(SheetFetchError) as info:
        fetch_sheet("network", f"{server}/stall-body", timeout=0.5)
    (hop,) = info.value.trace.hops
    assert hop.status == 200
    assert hop.phase == "body"
    # The partial body arrived before the stall and must be counted, even
    # though the buffered read that timed out discarded it.
    assert hop.bytes_in > len(_BODY)
    assert "reading the body" in str(info.value)
    assert f"{hop.bytes_in} B received" in str(info.value)


def test_http_error_names_the_hop_that_returned_it(server):
    with pytest.raises(SheetFetchError) as info:
        fetch_sheet("network", f"{server}/redirect/bad-request", timeout=5)
    err = info.value
    assert isinstance(err.__cause__, urllib.error.HTTPError)
    assert err.__cause__.code == 400
    first, second = err.trace.hops
    assert first.status == 307
    assert (second.status, second.phase) == (400, "http-error")
    assert "test-esf" in second.server  # BaseHTTPRequestHandler adds its own Server header too
    assert "hop 2" in str(err) and "HTTP 400" in str(err)


def test_connect_failure_is_reported_in_the_connect_phase():
    # Port 9 on loopback is (essentially) never listening: connection refused.
    with pytest.raises(SheetFetchError) as info:
        fetch_sheet("network", "http://127.0.0.1:9/csv", timeout=2)
    (hop,) = info.value.trace.hops
    assert hop.phase == "connect"
    assert hop.connected is None
    assert "connecting" in str(info.value)
