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


class FakeMqttMessage:
    def __init__(self, topic: str, payload: bytes):
        self.topic = topic
        self.payload = payload


class FakeMqttClient:
    """Minimal paho stand-in: records subscription order and delivers
    retained messages per subscription, in subscription order — like a
    broker whose retained deliveries all succeed."""

    retained: dict[str, bytes] = {}
    last_instance = None

    def __init__(self, api_version):
        self.subscriptions: list[str] = []
        self.on_connect = None
        self.on_message = None
        FakeMqttClient.last_instance = self

    def username_pw_set(self, user, password):
        pass

    def connect(self, host, port, keepalive=30):
        pass

    def loop_start(self):
        self.on_connect(self, None, None, 0, None)
        for pattern in list(self.subscriptions):
            for topic, payload in self.retained.items():
                if self._matches(pattern, topic):
                    self.on_message(self, None, FakeMqttMessage(topic, payload))

    @staticmethod
    def _matches(pattern: str, topic: str) -> bool:
        p_parts = pattern.split("/")
        t_parts = topic.split("/")
        if len(p_parts) != len(t_parts):
            return False
        return all(p in ("+", t) for p, t in zip(p_parts, t_parts))

    def subscribe(self, topic, qos=0):
        self.subscriptions.append(topic)

    def publish(self, topic, payload):
        pass

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


def _networkmap_response(
    nodes: list | None = None, links: list | None = None,
) -> dict:
    """A minimal valid raw-networkmap response envelope."""
    if nodes is None:
        nodes = [{"ieeeAddr": "0xc0", "friendlyName": "Coordinator"}]
    return {
        "status": "ok",
        "data": {"value": {"nodes": nodes, "links": links or []}},
    }


class TestScanZigbeeSiteSubscribeOrder:
    """bridge/devices must be subscribed LAST: its huge retained payload
    chokes the connection, and Mosquitto drops retained deliveries for
    any subscription made after it (observed on welland — devices
    arrived, bridge/info and all availability silently missing)."""

    def _run_scan(self, monkeypatch):
        import json as _json

        import paho.mqtt.client as paho_mqtt

        FakeMqttClient.retained = {
            "zigbee2mqtt/bridge/info": _json.dumps({
                "version": "2.9.2",
                "coordinator": {"ieee_address": "0x00aa", "type": "EmberZNet"},
                "network": {"channel": 11, "pan_id": 0x189E},
            }).encode(),
            "zigbee2mqtt/kitchen_temp/availability": _json.dumps(
                {"state": "online"}
            ).encode(),
            "zigbee2mqtt/bridge/devices": _json.dumps([
                {
                    "type": "EndDevice",
                    "ieee_address": "0x01",
                    "friendly_name": "kitchen_temp",
                },
            ]).encode(),
        }
        monkeypatch.setattr(paho_mqtt, "Client", FakeMqttClient)
        monkeypatch.setattr(
            zigbee, "_request_networkmap",
            lambda *a, **kw: _networkmap_response(),
        )
        devices, bridge = zigbee.scan_zigbee_site(
            "welland", _MQTT, availability_collect_s=0.0,
        )
        return devices, bridge, FakeMqttClient.last_instance

    def test_devices_subscription_is_last(self, monkeypatch):
        _devices, _bridge, client = self._run_scan(monkeypatch)
        assert client.subscriptions[-1] == "zigbee2mqtt/bridge/devices"
        assert set(client.subscriptions) == {
            "zigbee2mqtt/bridge/info",
            "zigbee2mqtt/+/availability",
            "zigbee2mqtt/bridge/devices",
        }

    def test_bridge_info_and_availability_are_captured(self, monkeypatch):
        devices, bridge, _client = self._run_scan(monkeypatch)
        assert bridge is not None
        assert bridge.z2m_version == "2.9.2"
        assert len(devices) == 1
        assert devices[0].availability == "online"

    def test_networkmap_supplies_parent_and_link_quality(self, monkeypatch):
        """bridge/devices no longer reports link_quality in Z2M 2.x —
        the parent link's LQI from the networkmap fills it."""
        import json as _json

        import paho.mqtt.client as paho_mqtt

        FakeMqttClient.retained = {
            "zigbee2mqtt/bridge/devices": _json.dumps([
                {
                    "type": "EndDevice",
                    "ieee_address": "0x01",
                    "friendly_name": "kitchen_temp",
                },
            ]).encode(),
        }
        monkeypatch.setattr(paho_mqtt, "Client", FakeMqttClient)
        monkeypatch.setattr(
            zigbee, "_request_networkmap",
            lambda *a, **kw: _networkmap_response(
                nodes=[
                    {"ieeeAddr": "0xc0", "friendlyName": "Coordinator"},
                    {"ieeeAddr": "0x01", "friendlyName": "kitchen_temp"},
                ],
                links=[
                    {
                        "relationship": 1,
                        "sourceIeeeAddr": "0x01",
                        "targetIeeeAddr": "0xc0",
                        "linkquality": 237,
                    },
                ],
            ),
        )
        devices, _bridge = zigbee.scan_zigbee_site(
            "welland", _MQTT, availability_collect_s=0.0,
        )
        assert devices[0].connected_via == "Coordinator"
        assert devices[0].link_quality == 237

    def test_networkmap_failure_propagates(self, monkeypatch):
        """A failed networkmap must fail the site scan — continuing with
        empty connected_via would erase previously-recorded parents."""
        import paho.mqtt.client as paho_mqtt

        monkeypatch.setattr(paho_mqtt, "Client", FakeMqttClient)

        def raise_timeout(*a, **kw):
            raise RuntimeError("Networkmap timed out after 600s for welland")

        monkeypatch.setattr(zigbee, "_request_networkmap", raise_timeout)
        with pytest.raises(RuntimeError, match="Networkmap timed out"):
            zigbee.scan_zigbee_site(
                "welland", _MQTT, availability_collect_s=0.0,
            )


class TestRequestNetworkmap:
    """_request_networkmap fails loud on error responses — a failed
    networkmap must never reduce to "no parents"."""

    def _request(self, monkeypatch, payload: bytes):
        import paho.mqtt.client as paho_mqtt

        FakeMqttClient.retained = {
            "zigbee2mqtt/bridge/response/networkmap": payload,
        }
        monkeypatch.setattr(paho_mqtt, "Client", FakeMqttClient)
        return zigbee._request_networkmap(_MQTT, "welland", timeout=1.0)

    def test_ok_response_returns_envelope(self, monkeypatch):
        import json as _json

        response = _networkmap_response()
        envelope = self._request(
            monkeypatch, _json.dumps(response).encode(),
        )
        assert envelope == response

    def test_error_status_raises(self, monkeypatch):
        import json as _json

        payload = _json.dumps(
            {"status": "error", "error": "Failed to generate network map"}
        ).encode()
        with pytest.raises(RuntimeError, match="status='error'"):
            self._request(monkeypatch, payload)

    def test_undecodable_payload_raises(self, monkeypatch):
        with pytest.raises(RuntimeError, match="not valid JSON"):
            self._request(monkeypatch, b"\xff\xfe not json")

    def test_non_dict_response_raises(self, monkeypatch):
        with pytest.raises(RuntimeError, match="unexpected type"):
            self._request(monkeypatch, b"[1, 2, 3]")

    def test_timeout_raises(self, monkeypatch):
        import paho.mqtt.client as paho_mqtt

        FakeMqttClient.retained = {}  # no response ever arrives
        monkeypatch.setattr(paho_mqtt, "Client", FakeMqttClient)
        with pytest.raises(RuntimeError, match="timed out"):
            zigbee._request_networkmap(_MQTT, "welland", timeout=0.1)


class TestBuildParentMap:
    """Parent + link-LQI extraction from the raw Z2M networkmap."""

    def test_missing_value_raises(self):
        with pytest.raises(RuntimeError, match="missing data.value"):
            zigbee._build_parent_map({"status": "ok", "data": {}})

    def test_missing_nodes_raises(self):
        with pytest.raises(RuntimeError, match="missing nodes/links"):
            zigbee._build_parent_map(
                {"data": {"value": {"links": []}}},
            )

    def test_empty_nodes_raises(self):
        """A raw map always includes the coordinator — an empty node
        list is an invalid response, not an empty mesh."""
        with pytest.raises(RuntimeError, match="no nodes"):
            zigbee._build_parent_map(
                {"data": {"value": {"nodes": [], "links": []}}},
            )

    def _networkmap(self, links: list) -> dict:
        return {
            "data": {
                "value": {
                    "nodes": [
                        {"ieeeAddr": "0xc0", "friendlyName": "Coordinator"},
                        {"ieeeAddr": "0x01", "friendlyName": "Z1"},
                        {"ieeeAddr": "0x02", "friendlyName": "T1"},
                    ],
                    "links": links,
                },
            },
        }

    def test_is_child_link_maps_parent_and_lqi(self):
        nm = self._networkmap([
            {
                "relationship": 1,
                "sourceIeeeAddr": "0x02",
                "targetIeeeAddr": "0x01",
                "linkquality": 237,
            },
        ])
        assert zigbee._build_parent_map(nm) == {"0x02": ("Z1", 237)}

    def test_is_parent_link_fills_gaps_only(self):
        nm = self._networkmap([
            {
                "relationship": 1,
                "sourceIeeeAddr": "0x02",
                "targetIeeeAddr": "0xc0",
                "linkquality": 200,
            },
            {   # rel=0: source parent of target — must not override rel=1
                "relationship": 0,
                "sourceIeeeAddr": "0x01",
                "targetIeeeAddr": "0x02",
                "linkquality": 40,
            },
            {   # rel=0 for a device with no rel=1 link — fills the gap
                "relationship": 0,
                "sourceIeeeAddr": "0xc0",
                "targetIeeeAddr": "0x01",
                "linkquality": 150,
            },
        ])
        assert zigbee._build_parent_map(nm) == {
            "0x02": ("Coordinator", 200),
            "0x01": ("Coordinator", 150),
        }

    def test_sibling_links_ignored(self):
        nm = self._networkmap([
            {
                "relationship": 2,
                "sourceIeeeAddr": "0x01",
                "targetIeeeAddr": "0x02",
                "linkquality": 99,
            },
        ])
        assert zigbee._build_parent_map(nm) == {}

    def test_missing_linkquality_is_none(self):
        nm = self._networkmap([
            {
                "relationship": 1,
                "sourceIeeeAddr": "0x02",
                "targetIeeeAddr": "0x01",
            },
        ])
        assert zigbee._build_parent_map(nm) == {"0x02": ("Z1", None)}


class TestValidateParents:
    """EndDevices can only hang under Routers or the Coordinator."""

    def test_router_and_coordinator_parents_pass(self):
        devices = [
            _device("welland", "0x01", friendly_name="Z1",
                    device_type="Router", connected_via="Coordinator"),
            _device("welland", "0x02", friendly_name="T1",
                    connected_via="Z1"),
        ]
        zigbee._validate_parents("welland", devices)  # must not raise

    def test_end_device_parent_fails_loud(self):
        devices = [
            _device("welland", "0x01", friendly_name="T1",
                    connected_via="Coordinator"),
            _device("welland", "0x02", friendly_name="T2",
                    connected_via="T1"),
        ]
        with pytest.raises(RuntimeError, match=(
            r"T2 claims parent T1 which is a EndDevice"
        )):
            zigbee._validate_parents("welland", devices)

    def test_unknown_parent_name_is_left_alone(self):
        devices = [
            _device("welland", "0x01", friendly_name="T1",
                    connected_via="RenamedRouter"),
        ]
        zigbee._validate_parents("welland", devices)  # must not raise

    def test_all_violations_reported(self):
        devices = [
            _device("welland", "0x01", friendly_name="T1"),
            _device("welland", "0x02", friendly_name="T2",
                    connected_via="T1"),
            _device("welland", "0x03", friendly_name="T3",
                    connected_via="T1"),
        ]
        with pytest.raises(RuntimeError) as excinfo:
            zigbee._validate_parents("welland", devices)
        message = str(excinfo.value)
        assert "T2 claims parent T1" in message
        assert "T3 claims parent T1" in message

    def test_scan_collects_corrupt_networkmap_as_site_error(self, monkeypatch):
        """The validation error keeps the baseline and surfaces through
        scan_zigbee's per-site error contract."""
        def fake_scan(name, cfg, verbose=False):
            raise RuntimeError(
                f"[{name}] Networkmap reports non-router parent(s)"
            )

        monkeypatch.setattr(zigbee, "scan_zigbee_site", fake_scan)
        baseline = {"welland": _site_doc("welland", _device("welland", "0x01"))}
        data, errors = scan_zigbee("welland", _MQTT, baseline)
        assert data == baseline  # baseline document kept
        assert len(errors) == 1
        assert "non-router parent" in errors[0]
