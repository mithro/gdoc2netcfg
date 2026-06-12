"""Tests for the zigbee supplement's scan/merge behaviour.

scan_zigbee_site (the MQTT layer) is mocked; these tests cover the
per-site document semantics: each site's document is independent and
replaced wholesale by its own scan, failed sites keep their baseline
document, and the persist-then-fail-loud error contract.
"""

from __future__ import annotations

from dataclasses import asdict

import pytest

from gdoc2netcfg.config import ZigbeeConfig, ZigbeeSiteConfig
from gdoc2netcfg.supplements import zigbee
from gdoc2netcfg.supplements.zigbee import (
    ZigbeeBridgeInfo,
    ZigbeeDevice,
    ZigbeeScanError,
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


def _site_doc(site: str, *devices: ZigbeeDevice, bridge: bool = True) -> dict:
    return {
        "bridge": asdict(_bridge(site)) if bridge else None,
        "devices": {d.ieee_address: asdict(d) for d in devices},
    }


def _config(*site_names: str) -> ZigbeeConfig:
    return ZigbeeConfig(sites=[
        ZigbeeSiteConfig(name=name, mqtt_host=f"mqtt.{name}.example")
        for name in site_names
    ])


class TestScanZigbee:
    def test_no_sites_configured_fails_loud(self):
        with pytest.raises(RuntimeError, match="No zigbee sites"):
            scan_zigbee(ZigbeeConfig(), None)

    def test_missing_mqtt_host_fails_loud(self):
        config = ZigbeeConfig(sites=[ZigbeeSiteConfig(name="welland")])
        with pytest.raises(RuntimeError, match="No mqtt_host"):
            scan_zigbee(config, None)

    def test_scan_builds_one_document_per_site(self, monkeypatch):
        def fake_scan(name, cfg, verbose=False):
            return [_device(name, f"0x{name}")], _bridge(name)

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland", "monarto"), None)
        assert errors == []
        assert set(data) == {"welland", "monarto"}
        assert set(data["welland"]["devices"]) == {"0xwelland"}
        assert data["welland"]["bridge"]["z2m_version"] == "1.38.0"
        assert set(data["monarto"]["devices"]) == {"0xmonarto"}

    def test_scan_without_bridge_info(self, monkeypatch):
        monkeypatch.setattr(
            zigbee, "scan_zigbee_site",
            lambda name, cfg, verbose=False: (
                [_device("welland", "0x01")], None,
            ),
        )
        data, errors = scan_zigbee(_config("welland"), None)
        assert data["welland"]["bridge"] is None
        assert set(data["welland"]["devices"]) == {"0x01"}

    def test_site_scan_replaces_only_its_own_document(self, monkeypatch):
        """A removed device drops out of its site's document; the other
        site's document is rebuilt from its own scan alone."""
        baseline = {
            "welland": _site_doc(
                "welland",
                _device("welland", "0x01"),
                _device("welland", "0x02"),
            ),
            "monarto": _site_doc("monarto", _device("monarto", "0x99")),
        }

        def fake_scan(name, cfg, verbose=False):
            if name == "welland":
                # 0x02 has been removed from welland's Z2M registry.
                return [_device("welland", "0x01")], _bridge("welland")
            return [_device("monarto", "0x99")], _bridge("monarto")

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland", "monarto"), baseline)
        assert errors == []
        assert set(data["welland"]["devices"]) == {"0x01"}
        assert data["monarto"] == baseline["monarto"]

    def test_failed_site_keeps_baseline_and_reports(self, monkeypatch):
        baseline = {
            "monarto": _site_doc("monarto", _device("monarto", "0x99")),
        }

        def fake_scan(name, cfg, verbose=False):
            if name == "monarto":
                raise RuntimeError("Timeout waiting for bridge/devices")
            return [_device("welland", "0x01")], _bridge("welland")

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland", "monarto"), baseline)
        assert len(errors) == 1
        assert "monarto" in errors[0]
        assert data["monarto"] == baseline["monarto"]  # retained
        assert set(data["welland"]["devices"]) == {"0x01"}

    def test_unconfigured_baseline_site_is_dropped(self, monkeypatch):
        """A site removed from the config drops out (the save then
        tombstones it) — as do pre-site-keyed legacy entries."""
        baseline = {
            "welland": _site_doc("welland", _device("welland", "0x01")),
            "oldsite": _site_doc("oldsite", _device("oldsite", "0x42")),
        }
        monkeypatch.setattr(
            zigbee, "scan_zigbee_site",
            lambda name, cfg, verbose=False: (
                [_device("welland", "0x01")], _bridge("welland"),
            ),
        )
        data, _ = scan_zigbee(_config("welland"), baseline)
        assert set(data) == {"welland"}

    def test_device_in_both_registries_keeps_both_views(self, monkeypatch):
        """A device moved between sites without removing the old Z2M
        entry appears in both site documents — sites are independent."""
        def fake_scan(name, cfg, verbose=False):
            avail = "online" if name == "monarto" else "offline"
            return [_device(name, "0x01", availability=avail)], None

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, _ = scan_zigbee(_config("welland", "monarto"), None)
        assert data["welland"]["devices"]["0x01"]["availability"] == "offline"
        assert data["monarto"]["devices"]["0x01"]["availability"] == "online"

    def test_connection_oserror_is_collected(self, monkeypatch):
        def fake_scan(name, cfg, verbose=False):
            raise ConnectionRefusedError("connection refused")

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee(_config("welland"), None)
        assert data == {}
        assert len(errors) == 1


class TestRaiseForZigbeeErrors:
    def test_no_errors_is_noop(self):
        raise_for_zigbee_errors([])

    def test_errors_raise(self):
        with pytest.raises(ZigbeeScanError, match="1 zigbee site scan error"):
            raise_for_zigbee_errors(["welland: timeout"])
