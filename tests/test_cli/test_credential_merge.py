"""Credential re-hydration for scan commands.

The credential columns (Password, SNMP Community) are stripped from the
world-readable cache at fetch time and live only in the root-only
credentials.db.  Any scan that authenticates to a device — BMC IPMI or SNMP —
must merge them back onto ``host.extra`` before scanning.  These tests cover
the shared ``_load_stored_credentials`` / ``_merge_credentials_into_hosts``
helpers and assert every credential-consuming scan command actually calls the
merge before it scans (the regression guard for the snmp-host/-switch/bridge
gap).
"""

import argparse
import sqlite3
import textwrap

import pytest

import gdoc2netcfg.cli.main as cli_main
from gdoc2netcfg.config import CacheConfig, PipelineConfig
from gdoc2netcfg.models.host import Host
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.storage.credentials_db import CredentialsDB


def _config(tmp_path) -> PipelineConfig:
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    return PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=cache_dir),
    )


def _populate(config, mapping) -> None:
    with CredentialsDB(config.cache.credentials_db_path) as db:
        scan_id = db.begin_scan("csv_credentials")
        changed = db.save_credentials(scan_id, mapping)
        db.finish_scan(scan_id, host_count=len(mapping), changed_count=changed)


# --- _load_stored_credentials ----------------------------------------------

class TestLoadStoredCredentials:
    def test_returns_latest_mapping(self, tmp_path):
        config = _config(tmp_path)
        _populate(config, {"switch1": {"Password": "p", "SNMP Community": "c"}})
        stored = cli_main._load_stored_credentials(config)
        assert stored == {"switch1": {"Password": "p", "SNMP Community": "c"}}

    def test_missing_store_raises_filenotfound(self, tmp_path):
        config = _config(tmp_path)  # no credentials.db written
        with pytest.raises(FileNotFoundError):
            cli_main._load_stored_credentials(config)


# --- _merge_credentials_into_hosts -----------------------------------------

class TestMergeCredentialsIntoHosts:
    def test_merges_onto_matching_host_by_hostname(self, tmp_path):
        config = _config(tmp_path)
        _populate(config, {"switch1": {"Password": "sw1", "SNMP Community": "comm"}})
        switch1 = Host(machine_name="switch1", hostname="switch1", extra={})
        other = Host(machine_name="other", hostname="other", extra={"Driver": "x"})

        cli_main._merge_credentials_into_hosts([switch1, other], config)

        assert switch1.extra["Password"] == "sw1"
        assert switch1.extra["SNMP Community"] == "comm"
        # A host absent from the store keeps its existing extra untouched.
        assert other.extra == {"Driver": "x"}

    def test_missing_store_warns_and_continues(self, tmp_path, capsys):
        config = _config(tmp_path)  # no store on disk
        host = Host(machine_name="switch1", hostname="switch1", extra={})

        cli_main._merge_credentials_into_hosts([host], config)  # must not raise

        assert host.extra == {}
        err = capsys.readouterr().err.lower()
        assert "credential store" in err
        assert "fetch" in err

    def test_unreadable_store_warns_and_continues(
        self, tmp_path, capsys, monkeypatch,
    ):
        config = _config(tmp_path)

        def _raise(_config):
            raise sqlite3.OperationalError("unable to open database file")

        monkeypatch.setattr(cli_main, "_load_stored_credentials", _raise)
        host = Host(machine_name="switch1", hostname="switch1", extra={})

        cli_main._merge_credentials_into_hosts([host], config)  # must not raise

        assert host.extra == {}
        err = capsys.readouterr().err.lower()
        assert "sudo" in err or "root-only" in err


# --- Wiring: every credential-consuming scan command merges first ----------

class _StopForTest(Exception):
    """Sentinel: short-circuit a command right at the merge call so the test
    never reaches network I/O (reachability/scan)."""


@pytest.fixture
def scan_config(tmp_path):
    """A config file + credential-free CSV cache + populated credentials.db,
    enough to drive a scan command up to its credential-merge call."""
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
        "big-storage,aa:bb:cc:dd:ee:04,10.1.10.7,\n"
        "big-storage,aa:bb:cc:dd:ee:05,10.1.10.8,bmc\n"
    )
    with CredentialsDB(cache_dir / "credentials.db") as db:
        scan_id = db.begin_scan("csv_credentials")
        changed = db.save_credentials(scan_id, {
            "switch1": {"Password": "sw1pass", "SNMP Community": "comm"},
            "bmc.big-storage": {"Password": "ADMIN:secret"},
        })
        db.finish_scan(scan_id, host_count=2, changed_count=changed)

    config = tmp_path / "gdoc2netcfg.toml"
    config.write_text(textwrap.dedent(f"""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]
        network = "https://example.com/not-used"

        [cache]
        directory = "{cache_dir}"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [vlans]
        10 = {{ name = "int", subdomain = "int" }}
        30 = {{ name = "net", subdomain = "net" }}

        [network_subdomains]
        10 = "int"
        30 = "net"

        [generators]
        enabled = []
    """))
    return config


@pytest.mark.parametrize("cmd_name", [
    "cmd_snmp_host",
    "cmd_snmp_switch",
    "cmd_bridge_scan",
    "cmd_bmc_firmware",
])
def test_scan_command_merges_credentials_before_scanning(
    scan_config, monkeypatch, cmd_name,
):
    """Each credential-consuming scan command must hand its built hosts to
    ``_merge_credentials_into_hosts`` before any scan runs."""
    captured = {}

    def fake_merge(hosts, config):
        captured["hosts"] = hosts
        raise _StopForTest

    monkeypatch.setattr(cli_main, "_merge_credentials_into_hosts", fake_merge)
    cmd = getattr(cli_main, cmd_name)
    args = argparse.Namespace(config=str(scan_config), force=True)

    with pytest.raises(_StopForTest):
        cmd(args)

    assert captured.get("hosts"), f"{cmd_name} did not merge credentials"
    assert any(h.hostname == "switch1" for h in captured["hosts"])
