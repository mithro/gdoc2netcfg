"""Tests for the zigbee supplement's scan/merge behaviour.

scan_zigbee_site (the MQTT layer) is mocked; these tests cover the
single-site document semantics: the site's document is replaced
wholesale by its own scan, a failed scan keeps the baseline document,
any other site's stale baseline is dropped, and the persist-then-fail-
loud error contract.
"""

from __future__ import annotations

from dataclasses import asdict

import pytest

from gdoc2netcfg.config import MqttBrokerConfig
from gdoc2netcfg.supplements import zigbee
from gdoc2netcfg.supplements.zigbee import (
    ZigbeeBridgeInfo,
    ZigbeeDevice,
    ZigbeeScanError,
    raise_for_zigbee_errors,
    scan_zigbee,
)

_MQTT = MqttBrokerConfig(host="mqtt.example", port=1883)


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


class TestScanZigbee:
    def test_missing_mqtt_host_fails_loud(self):
        with pytest.raises(RuntimeError, match=r"\[homeassistant.mqtt\] host"):
            scan_zigbee("welland", MqttBrokerConfig(), None)

    def test_scan_builds_document_for_site(self, monkeypatch):
        def fake_scan(name, cfg, verbose=False):
            return [_device(name, f"0x{name}")], _bridge(name)

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee("welland", _MQTT, None)
        assert errors == []
        assert set(data) == {"welland"}
        assert set(data["welland"]["devices"]) == {"0xwelland"}
        assert data["welland"]["bridge"]["z2m_version"] == "1.38.0"

    def test_scan_without_bridge_info(self, monkeypatch):
        monkeypatch.setattr(
            zigbee, "scan_zigbee_site",
            lambda name, cfg, verbose=False: ([_device("welland", "0x01")], None),
        )
        data, errors = scan_zigbee("welland", _MQTT, None)
        assert data["welland"]["bridge"] is None
        assert set(data["welland"]["devices"]) == {"0x01"}

    def test_scan_replaces_its_own_document(self, monkeypatch):
        """A device removed from the Z2M registry drops out of the
        wholesale-replaced document."""
        baseline = {
            "welland": _site_doc(
                "welland",
                _device("welland", "0x01"),
                _device("welland", "0x02"),
            ),
        }

        # 0x02 has been removed from welland's Z2M registry.
        monkeypatch.setattr(
            zigbee, "scan_zigbee_site",
            lambda name, cfg, verbose=False: (
                [_device("welland", "0x01")], _bridge("welland"),
            ),
        )
        data, errors = scan_zigbee("welland", _MQTT, baseline)
        assert errors == []
        assert set(data["welland"]["devices"]) == {"0x01"}

    def test_failed_scan_keeps_baseline_and_reports(self, monkeypatch):
        baseline = {
            "welland": _site_doc("welland", _device("welland", "0x99")),
        }

        def fake_scan(name, cfg, verbose=False):
            raise RuntimeError("Timeout waiting for bridge/devices")

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee("welland", _MQTT, baseline)
        assert len(errors) == 1
        assert "welland" in errors[0]
        assert data["welland"] == baseline["welland"]  # retained

    def test_other_site_baseline_is_dropped(self, monkeypatch):
        """A document for another site (e.g. legacy/pre-split data) drops
        out — the save then tombstones it."""
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
        data, _ = scan_zigbee("welland", _MQTT, baseline)
        assert set(data) == {"welland"}

    def test_connection_oserror_is_collected(self, monkeypatch):
        def fake_scan(name, cfg, verbose=False):
            raise ConnectionRefusedError("connection refused")

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        data, errors = scan_zigbee("welland", _MQTT, None)
        assert data == {}
        assert len(errors) == 1


class TestRaiseForZigbeeErrors:
    def test_no_errors_is_noop(self):
        raise_for_zigbee_errors([])

    def test_errors_raise(self):
        with pytest.raises(ZigbeeScanError, match="1 zigbee site scan error"):
            raise_for_zigbee_errors(["welland: timeout"])
