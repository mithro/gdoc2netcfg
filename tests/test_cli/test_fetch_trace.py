"""cmd_fetch prints each sheet's fetch trace, on success and on failure."""

from __future__ import annotations

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import FetchTrace, HopTrace, SheetData, SheetFetchError
from tests.test_cli.test_fetch_credentials import fetch_config  # noqa: F401

_CSV = "Machine,MAC Address,IP,Interface\ndesk,aa:bb:cc:dd:ee:ff,10.1.10.5,eth0\n"


def _trace(status: int, phase: str) -> FetchTrace:
    trace = FetchTrace(started=100.0)
    trace.hops.append(HopTrace(
        host="doc-10-4o-sheets.googleusercontent.com", port=443, started=100.0,
        peer="2404:6800:4013:409::84", connected=100.02, tls_done=100.17,
        request_sent=100.18, headers=103.1 if status else None, status=status or None,
        phase=phase, bytes_in=65696, ended=103.2,
    ))
    return trace


def test_success_line_carries_the_trace(fetch_config, monkeypatch, capsys):  # noqa: F811
    config, _ = fetch_config

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=_CSV, trace=_trace(200, "done"))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)
    assert cli.main(["-c", str(config), "fetch"]) == 0
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if "network: fetched" in ln)
    assert f"({len(_CSV)} bytes)" in line
    assert "doc-10-4o-sheets.googleusercontent.com[2404:6800:4013:409::84]" in line
    assert "HTTP 200" in line


def test_success_without_a_trace_still_prints(fetch_config, monkeypatch, capsys):  # noqa: F811
    config, _ = fetch_config

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=_CSV)

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)
    assert cli.main(["-c", str(config), "fetch"]) == 0
    assert f"network: fetched ({len(_CSV)} bytes)" in capsys.readouterr().out


def test_failure_line_carries_the_trace(fetch_config, monkeypatch, capsys):  # noqa: F811
    config, _ = fetch_config

    def failing_fetch(name, url, timeout=None):
        raise SheetFetchError(name, TimeoutError("The read operation timed out"),
                              _trace(0, "headers"))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", failing_fetch, raising=True)
    assert cli.main(["-c", str(config), "fetch"]) == 1
    err = capsys.readouterr().err
    line = next(ln for ln in err.splitlines() if "network: FAILED" in ln)
    assert "The read operation timed out" in line
    assert "FAILED while waiting for response headers" in line
