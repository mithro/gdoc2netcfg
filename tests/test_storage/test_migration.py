"""Tests for flat-file to SQLite migration."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gdoc2netcfg.storage import open_databases
from gdoc2netcfg.storage.config_db import ConfigDB
from gdoc2netcfg.storage.discovery_db import DiscoveryDB
from gdoc2netcfg.storage.migration import import_flat_files


@pytest.fixture()
def cache_dir(tmp_path: Path) -> Path:
    """Create a cache directory with sample flat files."""
    cache = tmp_path / ".cache"
    cache.mkdir()
    return cache


def _write_json(path: Path, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f)


# -- import_flat_files -----------------------------------------------------

class TestImportFlatFiles:
    def test_imports_csv_files(self, cache_dir: Path):
        (cache_dir / "network.csv").write_text("Machine,MAC\ndesktop,aa:bb")
        (cache_dir / "iot.csv").write_text("Machine,MAC\nplug1,cc:dd")

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        results = import_flat_files(cache_dir, config_db, discovery_db)

        assert "network.csv" in results
        assert "iot.csv" in results
        assert config_db.load_latest_csv("network") == "Machine,MAC\ndesktop,aa:bb"
        assert config_db.load_latest_csv("iot") == "Machine,MAC\nplug1,cc:dd"

        config_db.close()
        discovery_db.close()

    def test_imports_ssh_host_keys(self, cache_dir: Path):
        _write_json(cache_dir / "ssh_host_keys.json", {
            "server1": [
                "server1 ssh-ed25519 AAAA",
                "server1 ssh-rsa BBBB",
            ],
        })

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        results = import_flat_files(cache_dir, config_db, discovery_db)

        assert results["ssh_host_keys.json"] == 1
        loaded = discovery_db.load_latest_ssh_host_keys()
        assert "server1" in loaded
        assert len(loaded["server1"]) == 2

        config_db.close()
        discovery_db.close()

    def test_imports_reachability_v2(self, cache_dir: Path):
        _write_json(cache_dir / "reachability.json", {
            "version": 2,
            "hosts": {
                "server1": {
                    "interfaces": [[
                        {"ip": "10.1.10.1", "transmitted": 10,
                         "received": 10, "rtt_avg_ms": 5.2},
                    ]],
                },
            },
        })

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        results = import_flat_files(cache_dir, config_db, discovery_db)

        assert results["reachability.json"] == 1
        loaded = discovery_db.load_latest_reachability()
        assert "server1" in loaded
        assert loaded["server1"]["interfaces"][0][0]["ip"] == "10.1.10.1"

        config_db.close()
        discovery_db.close()

    def test_reachability_v1_raises(self, cache_dir: Path):
        """v1 reachability format raises an error (fail loud)."""
        _write_json(cache_dir / "reachability.json", {
            "server1": ["10.1.10.1"],
        })

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        with pytest.raises(ValueError, match="unsupported format"):
            import_flat_files(cache_dir, config_db, discovery_db)

        config_db.close()
        discovery_db.close()

    def test_imports_ssl_certs(self, cache_dir: Path):
        _write_json(cache_dir / "ssl_certs.json", {
            "server1": {
                "issuer": "Let's Encrypt",
                "self_signed": False,
                "valid": True,
                "expiry": "2025-12-31",
                "sans": ["server1.example.com"],
            },
        })

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        results = import_flat_files(cache_dir, config_db, discovery_db)

        assert results["ssl_certs.json"] == 1
        loaded = discovery_db.load_latest_ssl_certs()
        assert loaded["server1"]["issuer"] == "Let's Encrypt"

        config_db.close()
        discovery_db.close()

    def test_imports_bmc_firmware(self, cache_dir: Path):
        _write_json(cache_dir / "bmc_firmware.json", {
            "bmc.server1": {
                "product_name": "X11SPM-TF",
                "firmware_revision": "1.35.07",
                "ipmi_version": "2.0",
                "series": 11,
                "snmp_capable": True,
            },
        })

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        results = import_flat_files(cache_dir, config_db, discovery_db)

        assert results["bmc_firmware.json"] == 1
        loaded = discovery_db.load_latest_bmc_firmware()
        assert loaded["bmc.server1"]["product_name"] == "X11SPM-TF"

        config_db.close()
        discovery_db.close()

    def test_imports_json_blob_types(self, cache_dir: Path):
        for name in ("snmp", "bridge", "nsdp", "tasmota"):
            _write_json(cache_dir / f"{name}.json", {
                "host1": {"key": f"{name}_value"},
            })

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        results = import_flat_files(cache_dir, config_db, discovery_db)

        for name in ("snmp", "bridge", "nsdp", "tasmota"):
            assert f"{name}.json" in results
            load_fn = getattr(discovery_db, f"load_latest_{name}")
            loaded = load_fn()
            assert loaded["host1"]["key"] == f"{name}_value"

        config_db.close()
        discovery_db.close()

    def test_handles_missing_files(self, cache_dir: Path):
        """Missing files are skipped gracefully."""
        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        results = import_flat_files(cache_dir, config_db, discovery_db)

        assert results == {}  # nothing to import

        config_db.close()
        discovery_db.close()

    def test_preserves_file_mtime(self, cache_dir: Path):
        """Scan timestamps use the flat file's mtime."""
        csv_path = cache_dir / "network.csv"
        csv_path.write_text("Machine,MAC\ndesktop,aa:bb")
        # Set mtime to a known time (2025-01-15 12:00:00 UTC)
        known_time = 1736942400.0
        os.utime(csv_path, (known_time, known_time))

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        import_flat_files(cache_dir, config_db, discovery_db)

        history = config_db.scan_history(scan_type="csv_fetch")
        assert len(history) == 1
        assert "2025-01-15" in history[0]["started_at"]

        config_db.close()
        discovery_db.close()

    def test_corrupt_json_raises(self, cache_dir: Path):
        """Corrupt JSON files raise an error (fail loud)."""
        (cache_dir / "snmp.json").write_text("{invalid json")

        config_db = ConfigDB(cache_dir / "config.db")
        discovery_db = DiscoveryDB(cache_dir / "discovery.db")
        with pytest.raises(json.JSONDecodeError):
            import_flat_files(cache_dir, config_db, discovery_db)

        config_db.close()
        discovery_db.close()


# -- open_databases --------------------------------------------------------

class TestOpenDatabases:
    def test_creates_both_databases(self, cache_dir: Path):
        pair = open_databases(cache_dir)
        assert (cache_dir / "config.db").exists()
        assert (cache_dir / "discovery.db").exists()
        pair.close()

    def test_reopen_preserves_data(self, cache_dir: Path):
        pair = open_databases(cache_dir)
        scan_id = pair.config.begin_scan("csv_fetch")
        pair.config.save_csv(scan_id, "test", "data")
        pair.config.finish_scan(scan_id, host_count=1, changed_count=1)
        pair.close()

        pair2 = open_databases(cache_dir)
        assert pair2.config.load_latest_csv("test") == "data"
        pair2.close()

    def test_migrate_imports_flat_files(self, cache_dir: Path):
        (cache_dir / "network.csv").write_text("Machine,MAC\ndesktop,aa:bb")
        _write_json(cache_dir / "snmp.json", {"sw1": {"sysName": "switch1"}})

        pair = open_databases(cache_dir, migrate=True)
        assert pair.config.load_latest_csv("network") is not None
        assert pair.discovery.load_latest_snmp() is not None
        pair.close()

    def test_no_migrate_by_default(self, cache_dir: Path):
        (cache_dir / "network.csv").write_text("data")

        pair = open_databases(cache_dir)  # migrate=False by default
        assert pair.config.load_latest_csv("network") is None
        pair.close()

    def test_database_pair_close(self, cache_dir: Path):
        pair = open_databases(cache_dir)
        pair.close()
        # Both connections should be closed
        with pytest.raises(Exception):
            pair.config.connection.execute("SELECT 1")
