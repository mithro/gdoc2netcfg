"""fetch must refuse to cache a sheet set that fails validation."""

from __future__ import annotations

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import SheetData
from tests.test_cli.test_fetch_credentials import fetch_config  # noqa: F401


def test_fetch_refuses_sheet_with_unmarked_missing_mac(fetch_config, monkeypatch, capsys):  # noqa: F811
    config, cache_dir = fetch_config

    # Seed the cache with a known-good CSV first, so the test proves the
    # headline property: a refused fetch leaves the previous cached copy
    # completely untouched (not just "no file was created").
    good_csv = "Machine,MAC Address,IP,Interface\nswitch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(good_csv)

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\n"
            "ten64,none,10.98.5.1,wg-desktop\n"          # marked: fine
            "power9-b,,10.1.11.184,enP5p1s0f0\n"         # unmarked: ERROR
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    rc = cli.main(["-c", str(config), "fetch"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "missing_mac" in err
    assert "power9-b" in err
    assert "network:3" in err or "row 3" in err
    assert "Nothing was stored" in err
    assert (cache_dir / "network.csv").read_text() == good_csv
    assert not (cache_dir / "config.db").exists()


def test_fetch_caches_sheet_when_dns_only_rows_are_marked(fetch_config, monkeypatch):  # noqa: F811
    config, cache_dir = fetch_config

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\n"
            "ten64,none,10.98.5.1,wg-desktop\n"
            "desk,aa:bb:cc:dd:ee:ff,10.1.10.5,eth0\n"
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    assert cli.main(["-c", str(config), "fetch"]) == 0
    assert (cache_dir / "network.csv").exists()


def test_fetch_validates_against_cached_copy_of_a_sheet_that_failed_to_fetch(
    fetch_config, monkeypatch, tmp_path,  # noqa: F811
):
    """Partial fetch: the post-write cache = fetched sheets + the cached copy
    of the failed ones.  Validate exactly that set, so a cross-reference
    row whose owner lives in the failed sheet is still recognised."""
    config, cache_dir = fetch_config
    config.write_text(config.read_text().replace(
        'network = "https://example.com/network"',
        'network = "https://example.com/network"\niot = "https://example.com/iot"',
    ))
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\nplug-1,aa:bb:cc:dd:ee:01,10.1.90.10,\n"
    )

    def fake_fetch(name, url, timeout=None):
        if name == "network":
            raise RuntimeError("HTTP 503")
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\nplug-1,,10.1.90.10,\n"   # xref of cached owner
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    # network's own live fetch genuinely failed (HTTP 503) — cmd_fetch keeps
    # its pre-existing "any per-sheet fetch failure -> rc 1" convention (see
    # test_fetch_credentials.py::test_failed_credential_sheet_fetch_does_not_wipe_store
    # and cmd_tasmota_configure's identical `1 if fail > 0` rule) so that
    # transient fetch problems are never silently swallowed. What this test
    # verifies is narrower: the validation gate must not treat iot's
    # MAC-less cross-reference row as an error just because its owner
    # ('network') came from the fetch-failure's cached copy rather than a
    # fresh fetch, and iot's own successful, valid data must still be cached.
    assert cli.main(["-c", str(config), "fetch"]) == 1
    assert (cache_dir / "iot.csv").exists()


def test_fetch_refuses_sheet_set_failing_a_cross_host_check(fetch_config, monkeypatch, capsys):  # noqa: F811
    """fetch runs the FULL validation, not just the per-row field checks:
    two hosts sharing one IP is only visible once hosts are built, and
    must keep that data out of the cache just like a missing MAC does."""
    config, cache_dir = fetch_config

    good_csv = "Machine,MAC Address,IP,Interface\nswitch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(good_csv)

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\n"
            "sw-old,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
            "sw-new,aa:bb:cc:dd:ee:02,10.1.30.1,\n"
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    rc = cli.main(["-c", str(config), "fetch"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "ip_multiple_hosts" in err
    assert "sw-old" in err and "sw-new" in err
    assert "Nothing was stored" in err
    assert (cache_dir / "network.csv").read_text() == good_csv
    assert not (cache_dir / "config.db").exists()


def test_refused_fetch_leaves_the_credential_store_untouched(fetch_config, monkeypatch, capsys):  # noqa: F811
    """The gate runs before ANY write, the root-only credential store
    included: a refused fetch must not record (or tombstone) a secret."""
    from gdoc2netcfg.storage.credentials_db import CredentialsDB

    config, cache_dir = fetch_config
    sheet = {"csv": "Machine,MAC Address,IP,Interface,Password\n"
                    "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,,secret1\n"}

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=sheet["csv"])

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)
    assert cli.main(["-c", str(config), "fetch"]) == 0
    with CredentialsDB(cache_dir / "credentials.db", read_only=True) as db:
        before = db.load_latest_credentials()
    assert before

    sheet["csv"] = (
        "Machine,MAC Address,IP,Interface,Password\n"
        "sw-old,aa:bb:cc:dd:ee:01,10.1.30.1,,secret2\n"
        "sw-new,aa:bb:cc:dd:ee:02,10.1.30.1,,secret3\n"
    )
    capsys.readouterr()
    assert cli.main(["-c", str(config), "fetch"]) == 1
    err = capsys.readouterr().err
    assert "ip_multiple_hosts" in err
    assert "secret2" not in err and "secret3" not in err
    with CredentialsDB(cache_dir / "credentials.db", read_only=True) as db:
        assert db.load_latest_credentials() == before


def test_fetch_caches_a_sheet_set_with_only_warnings(fetch_config, monkeypatch, capsys):  # noqa: F811
    """Full validation still gates on ERRORS only: production carries
    hundreds of warnings, and blocking on them would stop every fetch.
    Warnings are not printed either (cron mails any output)."""
    from gdoc2netcfg.cli.main import _build_sheet_model
    from gdoc2netcfg.config import load_config
    from gdoc2netcfg.constraints.validators import validate_all

    config, cache_dir = fetch_config
    csv_text = (
        "Machine,MAC Address,IP,Interface,IPv6 x\n"
        "desk,aa:bb:cc:dd:ee:01,10.1.10.5,,yes\n"   # ipv6_unknown_prefix
        "spare,,,,\n"                               # missing_ip etc.
    )
    result = validate_all(*_build_sheet_model(load_config(config), [("network", csv_text)]))
    assert result.warnings and not result.errors  # not vacuous

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=csv_text)

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)
    assert cli.main(["-c", str(config), "fetch"]) == 0
    assert (cache_dir / "network.csv").read_text() == csv_text
    captured = capsys.readouterr()
    for v in result.warnings:
        assert v.code not in captured.err and v.code not in captured.out


def test_fetch_refuses_conflict_with_the_cached_copy_of_a_failed_sheet(
    fetch_config, monkeypatch, capsys,  # noqa: F811
):
    """Partial fetch, refuse direction: the conflicting owner exists only
    in the cached copy of the sheet that failed to fetch."""
    config, cache_dir = fetch_config
    config.write_text(config.read_text().replace(
        'network = "https://example.com/network"',
        'network = "https://example.com/network"\niot = "https://example.com/iot"',
    ))
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\nsw-old,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
    )

    def fake_fetch(name, url, timeout=None):
        if name == "network":
            raise RuntimeError("HTTP 503")
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\nsw-new,aa:bb:cc:dd:ee:02,10.1.30.1,\n"
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)
    assert cli.main(["-c", str(config), "fetch"]) == 1
    err = capsys.readouterr().err
    assert "ip_multiple_hosts" in err
    assert not (cache_dir / "iot.csv").exists()
    assert not (cache_dir / "config.db").exists()


def _with_wifi_sheet(config):
    config.write_text(config.read_text().replace(
        'network = "https://example.com/network"',
        'network = "https://example.com/network"\nwifi = "https://example.com/wifi"',
    ))


_NETWORK_CSV = "Machine,MAC Address,IP,Interface\nswitch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"


def test_fetch_stores_nothing_when_building_hosts_raises(fetch_config, monkeypatch):  # noqa: F811
    """Host building runs at fetch now, so its fail-loud raises (here a
    puck whose '#' names another machine) stop the fetch before any
    write instead of being cached for every later generate to crash on."""
    import pytest

    config, cache_dir = fetch_config
    _with_wifi_sheet(config)

    def fake_fetch(name, url, timeout=None):
        if name == "wifi":
            return SheetData(name=name, csv_text=(
                "Machine,MAC Address,IP,Interface,#,Serial\n"
                "puck03,aa:bb:cc:dd:ee:11,10.1.4.103,wan,2,S1\n"
                "puck03,aa:bb:cc:dd:ee:12,10.1.4.103,lan,2,S1\n"
            ))
        return SheetData(name=name, csv_text=_NETWORK_CSV)

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)
    with pytest.raises(ValueError, match="puck02"):
        cli.main(["-c", str(config), "fetch"])
    assert not (cache_dir / "wifi.csv").exists()
    assert not (cache_dir / "network.csv").exists()
    assert not (cache_dir / "config.db").exists()
    assert not (cache_dir / "credentials.db").exists()


def test_build_sheet_model_attaches_wifi_identity(fetch_config):  # noqa: F811
    """_build_sheet_model is the one host builder shared by fetch and
    generate; dropping its WiFi enrichment would silently empty pucks.json."""
    from gdoc2netcfg.cli.main import _build_pipeline
    from gdoc2netcfg.config import load_config
    from gdoc2netcfg.models.host import WifiData

    config, cache_dir = fetch_config
    _with_wifi_sheet(config)
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(_NETWORK_CSV)
    (cache_dir / "wifi.csv").write_text(
        "Machine,MAC Address,IP,Interface,#,Serial\n"
        "puck01,aa:bb:cc:dd:ee:11,10.1.4.101,wan,1,S1\n"
        "puck01,aa:bb:cc:dd:ee:12,10.1.4.101,lan,1,\n"
    )
    _, hosts, inventory, _ = _build_pipeline(load_config(config))
    by_name = {h.hostname: h for h in inventory.hosts}
    assert by_name["puck01.wifi"].wifi_data == WifiData(number=1, serial="S1")
    assert by_name["switch1"].wifi_data is None


def test_fetch_validates_the_credential_free_text_it_caches(fetch_config, monkeypatch, capsys):  # noqa: F811
    """A row one cell short of a trailing credential column is skipped by
    the parser in the raw CSV, but parses once the column is stripped —
    so the gate must check the text that is cached, not the raw text."""
    config, cache_dir = fetch_config
    good_csv = "Machine,MAC Address,IP,Interface\nsw-old,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(good_csv)

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface,Password\n"
            "sw-old,aa:bb:cc:dd:ee:01,10.1.30.1,,secret1\n"
            "sw-new,aa:bb:cc:dd:ee:02,10.1.30.1,\n"   # short: no Password cell
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)
    assert cli.main(["-c", str(config), "fetch"]) == 1
    assert "ip_multiple_hosts" in capsys.readouterr().err
    assert (cache_dir / "network.csv").read_text() == good_csv


import pytest  # noqa: E402

_GOOD_CSV = "Machine,MAC Address,IP,Interface\nswitch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"


@pytest.mark.parametrize("fetched,expect", [
    ("<!DOCTYPE html>\n<html><body>Sorry, unable to open the file.</body></html>\n",
     "no header row"),
    ("Host,MAC Address,IP\nswitch1,aa:bb:cc:dd:ee:01,10.1.30.1\n", "no header row"),
    ("Machine,MAC Address,Address\nswitch1,aa:bb:cc:dd:ee:01,10.1.30.1\n",
     "no IP column"),
    ("Machine,MAC Address,IP,Interface\n", "no device rows"),
    ("Machine,MAC Address,IP,Interface,Site\nsw,aa:bb:cc:dd:ee:01,10.2.30.1,,monarto\n",
     "no rows for site 'test'"),
])
def test_fetch_refuses_a_device_sheet_it_cannot_read(
    fetch_config, monkeypatch, capsys, fetched, expect,  # noqa: F811
):
    """#84 D: each of these used to be cached with 0 errors while every
    host on the sheet vanished from DNS."""
    config, cache_dir = fetch_config
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(_GOOD_CSV)

    def fake_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=fetched)

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    assert cli.main(["-c", str(config), "fetch"]) == 1
    err = capsys.readouterr().err
    assert expect in err
    assert "network" in err
    assert "Nothing was stored" in err
    assert (cache_dir / "network.csv").read_text() == _GOOD_CSV
    assert not (cache_dir / "config.db").exists()
