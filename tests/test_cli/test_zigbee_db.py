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
    cmd_zigbee_topology,
    cmd_zigbee_update_sheet,
)
from gdoc2netcfg.config import (
    CacheConfig,
    HomeAssistantConfig,
    MqttBrokerConfig,
    PipelineConfig,
    SheetsConfig,
    ZigbeeConfig,
)
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.storage import open_databases
from gdoc2netcfg.supplements.zigbee import ZigbeeScanError


def _config(tmp_path, site_name: str = "welland") -> PipelineConfig:
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    return PipelineConfig(
        site=Site(name=site_name, domain="test.example.com"),
        spreadsheet_url="https://docs.google.com/spreadsheets/d/x/edit",
        cache=CacheConfig(directory=cache_dir),
        sheets_config=SheetsConfig(credentials_file="client_secret.json"),
        homeassistant=HomeAssistantConfig(
            mqtt=MqttBrokerConfig(host="mqtt.example"),
        ),
        zigbee=ZigbeeConfig(enabled=True),
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
        "description": "",
        "definition_description": "",
        "connected_via": "",
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

    def test_no_zigbee_section_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        config.zigbee.enabled = False
        args = argparse.Namespace(config=None, force=False)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_scan(args)

        assert rc == 1
        assert "No [zigbee] section configured" in capsys.readouterr().err


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
        _, devices = mock_update.call_args.args[:2]
        assert [d.ieee_address for d in devices] == ["0x01"]

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
        _, devices = mock_update.call_args.args[:2]
        assert [d.ieee_address for d in devices] == ["0x01"]
        assert "Skipping site 'monarto'" in capsys.readouterr().err

    def test_update_sheet_no_zigbee_section_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        config.zigbee.enabled = False
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 1
        assert "No [zigbee] section configured" in capsys.readouterr().err

    def test_update_sheet_without_data_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 1
        assert "No Zigbee data to write" in capsys.readouterr().out


class TestZigbeeTopology:
    """cmd_zigbee_topology scans fresh, persists, then renders."""

    def _args(self, fmt="text", output_dir="."):
        return argparse.Namespace(
            config=None, format=fmt, output_dir=output_dir,
        )

    def test_text_format_renders_to_stdout_and_persists(
        self, tmp_path, capsys,
    ):
        config = _config(tmp_path)
        data = {"welland": _site_doc("welland", _device("welland", "0x01"))}

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee.scan_zigbee",
                 return_value=(data, []),
             ):
            rc = cmd_zigbee_topology(self._args(fmt="text"))

        assert rc == 0
        out = capsys.readouterr().out
        assert "Zigbee Mesh - welland" in out
        assert "kitchen_temp" in out
        # The fresh scan was persisted before rendering.
        assert _load_db(config) == data

    def test_text_format_writes_no_files(self, tmp_path, capsys):
        config = _config(tmp_path)
        data = {"welland": _site_doc("welland", _device("welland", "0x01"))}
        out_dir = tmp_path / "diagrams"

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee.scan_zigbee",
                 return_value=(data, []),
             ):
            rc = cmd_zigbee_topology(
                self._args(fmt="text", output_dir=str(out_dir)),
            )

        assert rc == 0
        assert not out_dir.exists()

    def test_svg_format_renders_each_site(self, tmp_path, capsys):
        config = _config(tmp_path)
        data = {"welland": _site_doc("welland", _device("welland", "0x01"))}
        out_dir = tmp_path / "diagrams"

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee.scan_zigbee",
                 return_value=(data, []),
             ), patch(
                 "gdoc2netcfg.supplements.zigbee_topology.render_dot",
             ) as mock_render:
            rc = cmd_zigbee_topology(
                self._args(fmt="svg", output_dir=str(out_dir)),
            )

        assert rc == 0
        mock_render.assert_called_once()
        _dot, out_path = mock_render.call_args.args[:2]
        assert out_path == out_dir / "zigbee_welland.svg"
        assert "Wrote" in capsys.readouterr().out

    def test_scan_failure_renders_stale_baseline_then_raises(
        self, tmp_path, capsys,
    ):
        """A failed site still renders its baseline, labelled stale, and
        the command fails loud afterwards."""
        config = _config(tmp_path)
        baseline = {
            "welland": _site_doc("welland", _device("welland", "0x01")),
        }
        _seed_db(config, baseline)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee.scan_zigbee",
                 return_value=(baseline, ["welland: Networkmap timed out"]),
             ), pytest.raises(ZigbeeScanError, match="Networkmap timed out"):
            cmd_zigbee_topology(self._args(fmt="text"))

        out = capsys.readouterr().out
        assert "Zigbee Mesh - welland" in out
        assert "WARNING: this scan failed" in out
        # The stale baseline document is still the DB's latest view.
        assert _load_db(config) == baseline

    def test_no_zigbee_section_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        config.zigbee.enabled = False

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_topology(self._args())

        assert rc == 1
        assert "No [zigbee] section configured" in capsys.readouterr().err
