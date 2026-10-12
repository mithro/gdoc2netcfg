"""Source: fetch CSV data from Google Sheets published URLs."""

from __future__ import annotations

import functools
import http.client
import io
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

#: Socket timeout (seconds) for one published-CSV request: connect and every
#: recv().  Without it a stalled TLS connection hangs the process forever —
#: monarto's cron fetch sat 6 days 16 h on an ESTABLISHED socket to Google
#: holding the fetch lock (2026-09-05), so no fetch ran at all.
SHEET_FETCH_TIMEOUT_SECONDS = 60.0


# ---------------------------------------------------------------------------
# Per-hop fetch trace
# ---------------------------------------------------------------------------
#
# A published-CSV fetch is two HTTP requests: docs.google.com answers 307 with
# a signed doc-*-sheets.googleusercontent.com URL, which serves the CSV.  When
# a fetch fails, "The read operation timed out" alone cannot say which of the
# two stalled, against which server address, or how far it got — so every
# request ("hop") records its milestones and the failure message carries them.

#: What a hop was doing when it stopped, as used in failure messages.
_PHASE_TEXT = {
    "connect": "connecting (DNS + TCP)",
    "tls": "doing the TLS handshake",
    "send": "sending the request",
    "headers": "waiting for response headers",
    "body": "reading the body",
}


@dataclass
class HopTrace:
    """Milestones of one HTTP request (one per redirect hop).

    Times are ``time.monotonic()`` values.  ``phase`` is what the hop was
    doing last: connect → tls (HTTPS only) → send → headers → body → done,
    or ``http-error`` when the response status was >= 400.
    ``bytes_in`` counts every application byte received on the connection
    (response headers, body and chunked-encoding framing; after TLS
    decryption) — an indicator of progress, not the CSV size.
    """

    host: str
    port: int
    started: float
    phase: str = "connect"
    peer: str | None = None
    connected: float | None = None
    tls_done: float | None = None
    request_sent: float | None = None
    headers: float | None = None
    status: int | None = None
    location: str | None = None
    server: str | None = None
    bytes_in: int = 0
    last_byte: float | None = None
    ended: float | None = None

    def describe(self, now: float) -> str:
        where = f"{self.host}[{self.peer}]" if self.peer else self.host
        parts: list[str] = []
        prev = self.started
        for label, at in (("tcp", self.connected), ("tls", self.tls_done),
                          ("sent", self.request_sent), ("headers", self.headers)):
            if at is not None:
                parts.append(f"{label} +{at - prev:.2f}s")
                prev = at
        if self.status is not None:
            status = f"HTTP {self.status}"
            if self.location:
                status += f" -> {urllib.parse.urlsplit(self.location).hostname}"
            if self.server:
                status += f" (server {self.server})"
            parts.append(status)
        if self.phase == "done":
            end = self.ended if self.ended is not None else now
            parts.append(f"{self.bytes_in} B received, {end - self.started:.2f}s total")
        elif self.phase == "http-error":
            parts.append(f"{now - self.started:.2f}s total")
        else:
            last = max(prev, self.last_byte or prev)
            parts.append(
                f"FAILED while {_PHASE_TEXT.get(self.phase, self.phase)}: "
                f"no progress for {now - last:.2f}s, {self.bytes_in} B received"
            )
        return f"{where} " + ", ".join(parts)


@dataclass
class FetchTrace:
    """Every hop of one fetch_sheet() call, in order."""

    started: float = field(default_factory=time.monotonic)
    hops: list[HopTrace] = field(default_factory=list)

    def describe(self, now: float | None = None) -> str:
        now = time.monotonic() if now is None else now
        if not self.hops:
            return f"no connection attempted, {now - self.started:.2f}s"
        return "; ".join(f"hop {i}: {hop.describe(now)}" for i, hop in enumerate(self.hops, 1))


class SheetFetchError(Exception):
    """A sheet fetch failed.  ``__cause__`` is the original exception (so
    callers can still classify timeouts, HTTP errors, DNS failures …) and
    ``trace`` says which hop failed, where, and in which phase.

    ``str()`` is the original error followed by the trace, so log lines that
    used to read ``The read operation timed out`` still start that way.
    """

    def __init__(self, name: str, cause: BaseException, trace: FetchTrace):
        self.name = name
        self.cause = cause
        self.trace = trace
        self._now = time.monotonic()
        super().__init__(name, cause)
        self.__cause__ = cause

    def __str__(self) -> str:
        return f"{self.cause} [{self.trace.describe(self._now)}]"


class _CountingRaw(io.RawIOBase):
    """Raw socket reader that time-stamps and counts every recv.

    Counting happens below the BufferedReader on purpose: a buffered
    ``read(n)`` that times out discards the partial data it already had, so
    a counter above the buffer would report 0 bytes for a body that stalled
    half-way.
    """

    def __init__(self, raw, hop: HopTrace):
        super().__init__()
        self._raw = raw
        self._hop = hop

    def readable(self) -> bool:
        return True

    def readinto(self, buf):
        n = self._raw.readinto(buf)
        if n:
            self._hop.bytes_in += n
            self._hop.last_byte = time.monotonic()
        return n

    def fileno(self) -> int:
        return self._raw.fileno()

    def close(self) -> None:
        if not self.closed:
            self._raw.close()
        super().close()


class _TracingResponse(http.client.HTTPResponse):
    def __init__(self, sock, *args, hop: HopTrace, **kwargs):
        super().__init__(sock, *args, **kwargs)
        # Swap HTTPResponse's buffered socket file for one built on a
        # counting raw reader.  makefile() keeps the socket's io refcount
        # right for both files; closing the original drops its reference.
        buffered = self.fp
        self.fp = io.BufferedReader(_CountingRaw(sock.makefile("rb", buffering=0), hop))
        buffered.close()


class _TracingConnectionMixin:
    """Records a HopTrace for each connection urllib opens.

    Hooks only public-ish seams of http.client: the ``_create_connection``
    factory (TCP connect, includes DNS), ``connect`` (TLS for HTTPS),
    ``request``, ``getresponse`` and ``response_class``.
    """

    def __init__(self, host, *args, trace: FetchTrace, **kwargs):
        super().__init__(host, *args, **kwargs)
        now = time.monotonic()
        # urllib reads and closes a redirect's body before opening the next
        # hop, so an earlier hop still in "body" has finished.
        for earlier in trace.hops:
            if earlier.phase == "body":
                earlier.phase, earlier.ended = "done", now
        hop = HopTrace(host=self.host, port=self.port, started=now)
        trace.hops.append(hop)
        self._hop = hop
        create = self._create_connection

        def traced_create(address, *a, **kw):
            sock = create(address, *a, **kw)
            hop.connected = time.monotonic()
            hop.peer = sock.getpeername()[0]
            hop.phase = "tls" if isinstance(self, http.client.HTTPSConnection) else "send"
            return sock

        self._create_connection = traced_create
        self.response_class = functools.partial(_TracingResponse, hop=hop)

    def connect(self):
        super().connect()
        if isinstance(self, http.client.HTTPSConnection):
            self._hop.tls_done = time.monotonic()
            self._hop.phase = "send"

    def request(self, *args, **kwargs):
        super().request(*args, **kwargs)
        self._hop.request_sent = time.monotonic()
        self._hop.phase = "headers"

    def getresponse(self):
        response = super().getresponse()
        hop = self._hop
        hop.headers = time.monotonic()
        hop.status = response.status
        hop.location = response.getheader("Location")
        hop.server = response.getheader("Server")
        hop.phase = "http-error" if response.status >= 400 else "body"
        return response


class _TracingHTTPConnection(_TracingConnectionMixin, http.client.HTTPConnection):
    pass


class _TracingHTTPSConnection(_TracingConnectionMixin, http.client.HTTPSConnection):
    pass


class _TracingHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, trace: FetchTrace):
        super().__init__()
        self._trace = trace

    def http_open(self, req):
        return self.do_open(functools.partial(_TracingHTTPConnection, trace=self._trace), req)


class _TracingHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, trace: FetchTrace):
        super().__init__()
        self._trace = trace

    def https_open(self, req):
        kwargs = {"context": self._context}
        if hasattr(self, "_check_hostname"):  # Python 3.11 still passes it through
            kwargs["check_hostname"] = self._check_hostname
        return self.do_open(
            functools.partial(_TracingHTTPSConnection, trace=self._trace), req, **kwargs)


@dataclass
class SheetData:
    """Raw CSV data fetched from a Google Sheets published URL."""

    name: str
    csv_text: str
    trace: FetchTrace | None = None


def fetch_sheet(
    name: str, url: str, *, timeout: float = SHEET_FETCH_TIMEOUT_SECONDS,
) -> SheetData:
    """Fetch CSV data from a Google Sheets published URL.

    Uses urllib exactly as ``urlopen()`` would (same redirect, proxy and TLS
    handling) but with connections that record a per-hop FetchTrace.

    Args:
        name: Human-readable sheet name (e.g. 'Network', 'IoT')
        url: Published CSV URL from Google Sheets
        timeout: Socket timeout in seconds for the connect and each read.
            Never None/0 — a fetch must not be able to hang.

    Returns:
        SheetData with the raw CSV text content and the fetch's trace.

    Raises:
        SheetFetchError: If the fetch fails for any reason; ``__cause__`` is
            the original exception (``urllib.error.URLError``,
            ``TimeoutError`` …) and ``trace`` says where it failed.
        ValueError: If *timeout* is not a positive number.
    """
    if not timeout or timeout <= 0:
        raise ValueError(f"fetch_sheet timeout must be > 0, got {timeout!r}")
    trace = FetchTrace()
    opener = urllib.request.build_opener(_TracingHTTPHandler(trace), _TracingHTTPSHandler(trace))
    try:
        with opener.open(url, timeout=timeout) as response:
            csv_text = response.read().decode("utf-8")
    except Exception as exc:
        raise SheetFetchError(name, exc, trace) from exc
    if trace.hops and trace.hops[-1].phase == "body":
        trace.hops[-1].phase, trace.hops[-1].ended = "done", time.monotonic()
    return SheetData(name=name, csv_text=csv_text, trace=trace)


def fetch_all_sheets(
    sheets: list[tuple[str, str]],
) -> list[SheetData]:
    """Fetch CSV data from all configured sheets.

    Args:
        sheets: List of (name, url) pairs.

    Returns:
        List of SheetData, one per sheet. Sheets that fail to fetch are
        skipped with a warning printed to stderr.
    """
    results = []
    for name, url in sheets:
        try:
            data = fetch_sheet(name, url)
            results.append(data)
        except Exception as e:
            import sys

            print(f"Warning: failed to fetch sheet {name!r}: {e}", file=sys.stderr)
    return results
