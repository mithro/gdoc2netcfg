"""_load_cached_csvs: read the validated cache, never fetch (#84 H)."""

from __future__ import annotations

import pytest

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import SheetData
from tests.test_cli.test_fetch_credentials import fetch_config  # noqa: F401


def _config(config_path):
    return cli._load_config(type("A", (), {"config": str(config_path)})())


def test_configured_sheet_with_no_cache_raises_and_never_fetches(
    fetch_config, monkeypatch,  # noqa: F811
):
    """Only `fetch` may download a sheet: it is the one path that validates
    the data and strips the credential columns before caching. Before, a
    missing cache made generate/validate fetch the sheet themselves and
    write the RAW text (passwords included) into the world-readable cache;
    a failed fetch then dropped the sheet with only a warning."""
    config_path, cache_dir = fetch_config
    calls = []

    def recording_fetch(name, url, timeout=None):
        calls.append(name)
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface,Password\n"
            "sw,aa:bb:cc:dd:ee:01,10.1.30.1,,secret1\n"
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", recording_fetch, raising=True)

    with pytest.raises(RuntimeError, match="'network'.*no cached copy.*gdoc2netcfg fetch"):
        cli._load_cached_csvs(_config(config_path))
    assert calls == []
    assert not (cache_dir / "network.csv").exists()


def test_cached_sheet_is_read(fetch_config):  # noqa: F811
    config_path, cache_dir = fetch_config
    csv_text = "Machine,MAC Address,IP\nsw,aa:bb:cc:dd:ee:01,10.1.30.1\n"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(csv_text)

    assert cli._load_cached_csvs(_config(config_path)) == [("network", csv_text)]
