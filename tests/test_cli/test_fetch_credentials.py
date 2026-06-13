"""Tests for credential stripping during fetch."""

from __future__ import annotations

import textwrap

import pytest

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import SheetData
from gdoc2netcfg.storage.credentials_db import CredentialsDB


@pytest.fixture()
def fetch_config(tmp_path):
    cache_dir = tmp_path / ".cache"
    config = tmp_path / "gdoc2netcfg.toml"
    config.write_text(textwrap.dedent(f"""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]
        network = "https://example.com/network"

        [cache]
        directory = "{cache_dir}"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [generators]
        enabled = []
    """))
    return config, cache_dir


def _fake_network_csv() -> str:
    return (
        "Machine,MAC Address,IP,Interface,Password,Notes\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,,secret1,hi\n"
    )


def test_fetch_strips_password_from_cache_and_stores_it(
    fetch_config, monkeypatch,
):
    config, cache_dir = fetch_config

    def fake_fetch(name, url):
        return SheetData(name=name, csv_text=_fake_network_csv())

    monkeypatch.setattr(
        "gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True,
    )

    rc = cli.main(["-c", str(config), "fetch"])
    assert rc == 0

    # Cache CSV is credential-free.
    cached = (cache_dir / "network.csv").read_text()
    assert "secret1" not in cached
    assert "Password" not in cached

    # Credential is in the root-only store, keyed by hostname.
    with CredentialsDB(cache_dir / "credentials.db", read_only=True) as db:
        creds = db.load_latest_credentials()
    assert creds is not None
    assert any(v == {"Password": "secret1"} for v in creds.values())


def test_fetch_creates_credentials_db_0600(fetch_config, monkeypatch):
    import os
    import stat

    config, cache_dir = fetch_config

    def fake_fetch(name, url):
        return SheetData(name=name, csv_text=_fake_network_csv())

    monkeypatch.setattr(
        "gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True,
    )
    cli.main(["-c", str(config), "fetch"])

    mode = stat.S_IMODE(os.stat(cache_dir / "credentials.db").st_mode)
    assert oct(mode) == oct(0o600)
