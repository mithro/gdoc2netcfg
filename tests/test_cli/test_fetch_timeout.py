"""cmd_fetch runs its sheet fetches under one wall-clock deadline."""

from __future__ import annotations

import time

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import SHEET_FETCH_TIMEOUT_SECONDS, SheetData
from tests.test_cli.test_fetch_credentials import fetch_config  # noqa: F401

_CSV = "Machine,MAC Address,IP,Interface\ndesk,aa:bb:cc:dd:ee:ff,10.1.10.5,eth0\n"


def _two_sheets(config):
    config.write_text(config.read_text().replace(
        'network = "https://example.com/network"',
        'network = "https://example.com/network"\niot = "https://example.com/iot"',
    ))


def test_each_request_gets_at_most_the_socket_timeout(fetch_config, monkeypatch):  # noqa: F811
    config, cache_dir = fetch_config
    seen: list[float] = []

    def fake_fetch(name, url, timeout=None):
        seen.append(timeout)
        return SheetData(name=name, csv_text=_CSV)

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    assert cli.main(["-c", str(config), "fetch"]) == 0
    assert seen == [SHEET_FETCH_TIMEOUT_SECONDS]


def test_sheets_past_the_job_deadline_fail_loud_and_are_not_attempted(
    fetch_config, monkeypatch, capsys,  # noqa: F811
):
    """First sheet eats the whole budget; the second must be reported FAILED
    (deadline) without a request, and the run exits 1 so cron mails it —
    while the sheet that did arrive is still cached."""
    config, cache_dir = fetch_config
    _two_sheets(config)
    monkeypatch.setattr(cli, "FETCH_JOB_DEADLINE_SECONDS", 0.2)
    attempted: list[tuple[str, float]] = []

    def slow_fetch(name, url, timeout=None):
        attempted.append((name, timeout))
        time.sleep(0.3)
        return SheetData(name=name, csv_text=_CSV)

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", slow_fetch, raising=True)

    rc = cli.main(["-c", str(config), "fetch"])

    assert rc == 1
    assert [n for n, _ in attempted] == ["network"]
    assert attempted[0][1] <= 0.2            # capped by the time left, not 60 s
    err = capsys.readouterr().err
    assert "iot: FAILED" in err and "deadline" in err
    assert (cache_dir / "network.csv").exists()
    assert not (cache_dir / "iot.csv").exists()
