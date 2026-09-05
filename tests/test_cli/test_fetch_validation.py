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

    def fake_fetch(name, url):
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

    def fake_fetch(name, url):
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

    def fake_fetch(name, url):
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
