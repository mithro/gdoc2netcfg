"""cmd_zigbee_* read from and persist to discovery.db only (#8).

Zigbee data is stored as one document per site ({"bridge": ...,
"devices": {ieee: ...}}), mirroring the per-site cache files it
replaced.
"""

import argparse
from unittest.mock import patch

import pytest

from gdoc2netcfg.cli.main import (
    cmd_zigbee_scan,
    cmd_zigbee_show,
    cmd_zigbee_update_sheet,
)
from gdoc2netcfg.config import (
    CacheConfig,
    PipelineConfig,
    SheetsConfig,
    ZigbeeConfig,
    ZigbeeSiteConfig,
)
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.storage import open_databases
from gdoc2netcfg.supplements.zigbee import ZigbeeScanError


def _config(tmp_path, *site_names: str) -> PipelineConfig:
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    return PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        spreadsheet_url="https://docs.google.com/spreadsheets/d/x/edit",
        cache=CacheConfig(directory=cache_dir),
        sheets_config=SheetsConfig(credentials_file="client_secret.json"),
        zigbee=ZigbeeConfig(
            sites=[
                ZigbeeSiteConfig(name=name, mqtt_host=f"mqtt.{name}.example")
                for name in (site_names or ("welland",))
            ],
        ),
    )


def _device(site: str, ieee: str, **overrides) -> dict:
    d = {
        "site": site,
        "ieee_address": ieee,
        "friendly_name": "kitchen_temp",
        "object_id": "kitchen_temp",
        "device_type": "EndDevice",
        "model_id": "WSDCGQ12LM",
        "manufacturer": "Xiaomi",
        "model": "Aqara temperature sensor",
        "power_source": "Battery",
        "software_build_id": "100",
        "date_code": "",
        "last_seen": None,
        "link_quality": 80,
        "availability": "online",
        "network_address": 1234,
    }
    d.update(overrides)
    return d


def _site_doc(site: str, *devices: dict, bridge: bool = True) -> dict:
    bridge_info = {
        "site": site,
        "z2m_version": "1.38.0",
        "coordinator_ieee": "0x00aa",
        "coordinator_type": "ConBee II",
        "channel": 15,
        "pan_id": "0x1a62",
    }
    return {
        "bridge": bridge_info if bridge else None,
        "devices": {d["ieee_address"]: d for d in devices},
    }


def _seed_db(config: PipelineConfig, data: dict) -> None:
    dbs = open_databases(config.cache.directory)
    scan_id = dbs.discovery.begin_scan("zigbee")
    changed = dbs.discovery.save_zigbee(scan_id, data)
    dbs.discovery.finish_scan(
        scan_id, host_count=len(data), changed_count=changed,
    )
    dbs.close()


def _load_db(config: PipelineConfig) -> dict | None:
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    with DiscoveryDB(config.cache.discovery_db_path, read_only=True) as db:
        return db.load_latest_zigbee()


class TestZigbeeScan:
    def test_fresh_db_scan_is_reused(self, tmp_path, capsys):
        config = _config(tmp_path)
        _seed_db(config, {
            "welland": _site_doc("welland", _device("welland", "0x01")),
        })
        args = argparse.Namespace(config=None, force=False)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee.scan_zigbee_site",
                 side_effect=AssertionError("must not scan when fresh"),
             ):
            rc = cmd_zigbee_scan(args)

        assert rc == 0
        out = capsys.readouterr()
        assert "Using cached zigbee scan" in out.err
        assert "Found 1 Zigbee device(s) across 1 site(s)." in out.out

    def test_live_scan_persists_to_db(self, tmp_path):
        config = _config(tmp_path)
        data = {"welland": _site_doc("welland", _device("welland", "0x01"))}
        args = argparse.Namespace(config=None, force=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee.scan_zigbee",
                 return_value=(data, []),
             ):
            rc = cmd_zigbee_scan(args)

        assert rc == 0
        assert _load_db(config) == data

    def test_partial_failure_persists_then_fails_loud(self, tmp_path):
        config = _config(tmp_path)
        data = {"welland": _site_doc("welland", _device("welland", "0x01"))}
        args = argparse.Namespace(config=None, force=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee.scan_zigbee",
                 return_value=(data, ["monarto: timeout"]),
             ), pytest.raises(ZigbeeScanError, match="monarto"):
            cmd_zigbee_scan(args)

        # The successful site's data was saved before the raise.
        assert _load_db(config) == data

    def test_no_sites_configured_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        config.zigbee.sites = []
        args = argparse.Namespace(config=None, force=False)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_scan(args)

        assert rc == 1
        assert "No zigbee sites configured" in capsys.readouterr().err


class TestZigbeeShow:
    def test_show_reads_db(self, tmp_path, capsys):
        config = _config(tmp_path)
        _seed_db(config, {
            "welland": _site_doc("welland", _device("welland", "0x01")),
        })
        args = argparse.Namespace(config=None)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_show(args)

        assert rc == 0
        out = capsys.readouterr().out
        assert "Site: welland" in out
        assert "kitchen_temp" in out
        assert "ConBee II" in out

    def test_show_without_data_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        args = argparse.Namespace(config=None)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_show(args)

        assert rc == 1
        assert "No Zigbee data cached" in capsys.readouterr().out


class TestZigbeeUpdateSheet:
    def test_update_sheet_reads_db(self, tmp_path):
        config = _config(tmp_path)
        _seed_db(config, {
            "welland": _site_doc("welland", _device("welland", "0x01")),
        })
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee_sheet.update_zigbee_sheet",
                 return_value=1,
             ) as mock_update:
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 0
        mock_update.assert_called_once()
        _, devices, bridge_infos = mock_update.call_args.args[:3]
        assert [d.ieee_address for d in devices] == ["0x01"]
        assert bridge_infos["welland"].coordinator_type == "ConBee II"

    def test_update_sheet_one_row_per_site(self, tmp_path):
        """A device in both configured sites' registries becomes one
        sheet row PER SITE — no cross-site projection."""
        config = _config(tmp_path, "welland", "monarto")
        _seed_db(config, {
            "welland": _site_doc(
                "welland",
                _device("welland", "0x01", availability="offline"),
            ),
            "monarto": _site_doc(
                "monarto",
                _device("monarto", "0x01", availability="online"),
            ),
        })
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee_sheet.update_zigbee_sheet",
                 return_value=2,
             ) as mock_update:
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 0
        _, devices, _bridge_infos = mock_update.call_args.args[:3]
        assert sorted((d.site, d.ieee_address) for d in devices) == [
            ("monarto", "0x01"), ("welland", "0x01"),
        ]

    def test_update_sheet_skips_unconfigured_site(self, tmp_path, capsys):
        """DB data for a site no longer in config (stale, pre-tombstone)
        contributes no rows."""
        config = _config(tmp_path, "welland")
        _seed_db(config, {
            "welland": _site_doc("welland", _device("welland", "0x01")),
            "monarto": _site_doc("monarto", _device("monarto", "0x02")),
        })
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee_sheet.update_zigbee_sheet",
                 return_value=1,
             ) as mock_update:
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 0
        _, devices, _ = mock_update.call_args.args[:3]
        assert [d.ieee_address for d in devices] == ["0x01"]
        assert "monarto" in capsys.readouterr().err

    def test_update_sheet_no_sites_configured_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        config.zigbee.sites = []
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 1
        assert "No zigbee sites configured" in capsys.readouterr().err

    def test_update_sheet_without_data_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 1
        assert "No Zigbee data to write" in capsys.readouterr().out
