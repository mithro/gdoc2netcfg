"""_fetch_or_load_csvs must not drop a configured sheet (#84 H)."""

from __future__ import annotations

import pytest

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import SheetData
from tests.test_cli.test_fetch_credentials import fetch_config  # noqa: F401


def test_configured_sheet_with_no_cache_and_failed_fetch_raises(
    fetch_config, monkeypatch,  # noqa: F811
):
    """Before, this warned and returned without the sheet, so generate
    built (and could deploy) an inventory missing every host on it."""
    config_path, _cache_dir = fetch_config

    def bad_fetch(name, url, timeout=None):
        raise RuntimeError("HTTP 503")

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", bad_fetch, raising=True)
    config = cli._load_config(type("A", (), {"config": str(config_path)})())

    with pytest.raises(RuntimeError, match="'network'.*no cached copy"):
        cli._fetch_or_load_csvs(config, use_cache=True)


def test_configured_sheet_with_no_cache_is_fetched(fetch_config, monkeypatch):  # noqa: F811
    config_path, cache_dir = fetch_config
    csv_text = "Machine,MAC Address,IP\nsw,aa:bb:cc:dd:ee:01,10.1.30.1\n"

    def good_fetch(name, url, timeout=None):
        return SheetData(name=name, csv_text=csv_text)

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", good_fetch, raising=True)
    config = cli._load_config(type("A", (), {"config": str(config_path)})())

    assert cli._fetch_or_load_csvs(config, use_cache=True) == [("network", csv_text)]
