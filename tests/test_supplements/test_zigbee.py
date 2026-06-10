"""Tests for the zigbee supplement's scan/merge behaviour.

scan_zigbee_site (the MQTT layer) is mocked; these tests cover the
baseline-merge semantics: per-site authoritative replace, failed sites
keeping their baseline entries, and the persist-then-fail-loud error
contract.
"""

from __future__ import annotations

import pytest

from gdoc2netcfg.config import ZigbeeConfig, ZigbeeSiteConfig
from gdoc2netcfg.supplements import zigbee
from gdoc2netcfg.supplements.zigbee import (
    ZigbeeBridgeInfo,
    ZigbeeDevice,
    ZigbeeScanError,
    bridge_key,
    is_bridge_key,
    raise_for_zigbee_errors,
    scan_zigbee,
)


def _device(site: str, ieee: str, **overrides) -> ZigbeeDevice:
    fields = {
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
        "date_code": "2023-10-15",
        "last_seen": 1000,
        "link_quality": 80,
        "availability": "online",
        "network_address": 1234,
    }
    fields.update(overrides)
    return ZigbeeDevice(**fields)


def _bridge(site: str) -> ZigbeeBridgeInfo:
    return ZigbeeBridgeInfo(
        site=site,
        z2m_version="1.38.0",
        coordinator_ieee="0x00aa",
        coordinator_type="ConBee II",
        channel=15,
        pan_id="0x1a62",
    )


def _config(*site_names: str) -> ZigbeeConfig:
    return ZigbeeConfig(sites=[
        ZigbeeSiteConfig(name=name, mqtt_host=f"mqtt.{name}.example")
        for name in site_names
    ])


class TestBridgeKey:
    def test_roundtrip(self):
        assert bridge_key("welland") == "_bridge/welland"
        assert is_bridge_key("_bridge/welland")
        assert not is_bridge_key("0x00124b0001020304")


class TestScanZigbee:
    def test_no_sites_configured_fails_loud(self):
        with pytest.raises(RuntimeError, match="No zigbee sites"):
            scan_zigbee(ZigbeeConfig(), None)

    def test_missing_mqtt_host_fails_loud(self):
        config = ZigbeeConfig(sites=[ZigbeeSiteConfig(name="welland")])
        with pytest.raises(RuntimeError, match="No mqtt_host"):
            scan_zigbee(config, None)

    def test_scan_builds_keyed_data(self, monkeypatch):
        monkeypatch.setattr(
            zigbee, "scan_zigbee_site",
            lambda name, cfg, verbose=False: (
                [_device("welland", "0x01")], _bridge("welland"),
            ),
        )
        data, errors = scan_zigbee(_config("welland"), None)
        assert errors == []
        assert set(data) == {"0x01", "_bridge/welland"}
        assert data["0x01"]["object_id"] == "kitchen_temp"
        assert data["_bridge/welland"]["z2m_version"] == "1.38.0"

    def test_scan_without_bridge_info(self, monkeypatch):
        monkeypatch.setattr(
            zigbee, "scan_zigbee_site",
            lambda name, cfg, verbose=False: (
                [_device("welland", "0x01")], None,
            ),
        )
        data, errors = scan_zigbee(_config("welland"), None)
        assert set(data) == {"0x01"}

    def test_successful_site_replaces_its_baseline(self, monkeypatch):
        """A removed device drops out; other sites' entries survive."""
        baseline = {
            "0x01": {"site": "welland", "ieee_address": "0x01"},
            "0x02": {"site": "welland", "ieee_address": "0x02"},
            "_bridge/welland": {"site": "welland", "z2m_version": "1.0"},
            "0x99": {"site": "monarto", "ieee_address": "0x99"},
        }
        monkeypatch.setattr(
            zigbee, "scan_zigbee_site",
            lambda name, cfg, verbose=False: (
                [_device("welland", "0x01")], _bridge("welland"),
            ),
        )
        data, errors = scan_zigbee(_config("welland"), baseline)
        assert errors == []
        # 0x02 was removed from Z2M; 0x99 (monarto, unscanned) survives.
        assert set(data) == {"0x01", "_bridge/welland", "0x99"}

    def test_failed_site_keeps_baseline_and_reports(self, monkeypatch):
        baseline = {
            "0x01": {"site": "welland", "ieee_address": "0x01"},
            "0x99": {"site": "monarto", "ieee_address": "0x99"},
        }

        def fake_scan(name, cfg, verbose=False):
            if name == "monarto":
                raise RuntimeError("Timeout waiting for bridge/devices")
            return [_device("welland", "0x01")], _bridge("welland")

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland", "monarto"), baseline)
        assert len(errors) == 1
        assert "monarto" in errors[0]
        assert "0x99" in data  # baseline retained for the failed site

    def test_connection_oserror_is_collected(self, monkeypatch):
        def fake_scan(name, cfg, verbose=False):
            raise ConnectionRefusedError("connection refused")

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland"), None)
        assert data == {}
        assert len(errors) == 1


class TestCrossSiteDuplicates:
    """A device in two Z2M registries (moved without cleanup) resolves
    deterministically: online wins, then newest last_seen — loudly."""

    def test_online_view_wins(self, monkeypatch, capsys):
        def fake_scan(name, cfg, verbose=False):
            if name == "welland":
                return [_device("welland", "0x01", availability="offline")], None
            return [_device("monarto", "0x01", availability="online")], None

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland", "monarto"), None)
        assert errors == []
        assert data["0x01"]["site"] == "monarto"
        err = capsys.readouterr().err
        assert "both welland and monarto" in err
        assert "remove the stale welland entry" in err

    def test_online_wins_regardless_of_site_order(self, monkeypatch):
        def fake_scan(name, cfg, verbose=False):
            if name == "welland":
                return [_device("welland", "0x01", availability="online")], None
            return [_device("monarto", "0x01", availability="offline")], None

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, _ = scan_zigbee(_config("welland", "monarto"), None)
        assert data["0x01"]["site"] == "welland"

    def test_newest_last_seen_wins_when_both_offline(self, monkeypatch):
        def fake_scan(name, cfg, verbose=False):
            if name == "welland":
                return [_device("welland", "0x01", availability="offline",
                                last_seen=5000)], None
            return [_device("monarto", "0x01", availability="offline",
                            last_seen=2000)], None

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, _ = scan_zigbee(_config("welland", "monarto"), None)
        assert data["0x01"]["site"] == "welland"

    def test_baseline_entry_defended_when_its_site_fails(self, monkeypatch):
        """A stale ghost must not clobber the failed site's good baseline."""
        from dataclasses import asdict

        baseline = {
            "0x01": asdict(_device("monarto", "0x01", availability="online",
                                   last_seen=9000)),
        }

        def fake_scan(name, cfg, verbose=False):
            if name == "monarto":
                raise RuntimeError("Timeout")
            return [_device("welland", "0x01", availability="offline",
                            last_seen=100)], None

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland", "monarto"), baseline)
        assert len(errors) == 1
        assert data["0x01"]["site"] == "monarto"  # baseline view kept


class TestRaiseForZigbeeErrors:
    def test_no_errors_is_noop(self):
        raise_for_zigbee_errors([])

    def test_errors_raise(self):
        with pytest.raises(ZigbeeScanError, match="1 zigbee site scan error"):
            raise_for_zigbee_errors(["welland: timeout"])
