"""Tests for the MQTT HA discovery publisher."""

import json
from unittest.mock import MagicMock, patch

import pytest

from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, TasmotaData
from gdoc2netcfg.supplements.mqtt_ha import (
    BRIDGE_AVAIL_TOPIC,
    DISCOVERY_PREFIX,
    HOST_CONNECTIVITY,
    HOST_STACK_MODE,
    HOST_TRACKER,
    ORIGIN,
    STATE_PREFIX,
    EntityDef,
    _availability_list,
    _device_dict,
    _iface_entities,
    _iface_entity_state_topic,
    _iface_slug,
    _node_id,
    build_host_state,
    build_interface_state,
    discovery_payload,
    discovery_topic,
    publish_all_hosts,
)
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    InterfaceReachability,
    PingResult,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_host(
    machine_name: str = "big-storage",
    hostname: str = "big-storage",
    ip: str = "10.1.5.10",
    mac: str = "aa:bb:cc:dd:ee:ff",
    iface_name: str | None = None,
    extra: dict | None = None,
) -> Host:
    """Build a minimal Host for testing."""
    return Host(
        machine_name=machine_name,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=iface_name,
                mac=MACAddress(mac),
                ip_addresses=(
                    IPv4Address(ip),
                    IPv6Address("2404:e80:a137:105::10", "2404:e80:a137:"),
                ),
            ),
        ],
        extra=extra or {},
    )


def _make_multi_iface_host() -> Host:
    """Build a host with two interfaces."""
    return Host(
        machine_name="dual-nic",
        hostname="dual-nic",
        interfaces=[
            NetworkInterface(
                name="eth0",
                mac=MACAddress("aa:bb:cc:00:00:01"),
                ip_addresses=(
                    IPv4Address("10.1.5.20"),
                    IPv6Address("2404:e80:a137:105::20", "2404:e80:a137:"),
                ),
            ),
            NetworkInterface(
                name="eth1",
                mac=MACAddress("aa:bb:cc:00:00:02"),
                ip_addresses=(
                    IPv4Address("10.1.10.20"),
                    IPv6Address("2404:e80:a137:110::20", "2404:e80:a137:"),
                ),
            ),
        ],
    )


def _make_reachability(
    hostname: str = "big-storage",
    ip: str = "10.1.5.10",
    ipv6: str = "2404:e80:a137:105::10",
    received_v4: int = 10,
    received_v6: int = 10,
    rtt_v4: float | None = 1.2,
    rtt_v6: float | None = 2.3,
) -> HostReachability:
    """Build a HostReachability with one interface."""
    pings = [
        (ip, PingResult(10, received_v4, rtt_v4)),
        (ipv6, PingResult(10, received_v6, rtt_v6)),
    ]
    ir = InterfaceReachability(pings=tuple(pings))
    active = [addr for addr, pr in pings if pr]
    return HostReachability(
        hostname=hostname,
        active_ips=tuple(active),
        interfaces=(ir,),
    )


# ---------------------------------------------------------------------------
# node_id and slug helpers
# ---------------------------------------------------------------------------

class TestNodeId:
    def test_simple_hostname(self):
        assert _node_id("big-storage") == "big_storage"

    def test_bmc_hostname(self):
        assert _node_id("bmc.big-storage") == "bmc_big_storage"

    def test_already_underscored(self):
        assert _node_id("my_host") == "my_host"

    def test_uppercase_lowered(self):
        assert _node_id("MyHost") == "myhost"

    def test_dots_and_hyphens(self):
        assert _node_id("sw.rack-1.unit-2") == "sw_rack_1_unit_2"


class TestIfaceSlug:
    def test_named_interface(self):
        host = _make_host(iface_name="eth0")
        vi = host.virtual_interfaces[0]
        assert _iface_slug(vi) == "eth0"

    def test_none_interface(self):
        host = _make_host(iface_name=None)
        vi = host.virtual_interfaces[0]
        assert _iface_slug(vi) == "default"


# ---------------------------------------------------------------------------
# Entity definitions
# ---------------------------------------------------------------------------

class TestEntityDefs:
    def test_host_connectivity_is_main_entity(self):
        assert HOST_CONNECTIVITY.name is None
        assert HOST_CONNECTIVITY.component == "binary_sensor"
        assert HOST_CONNECTIVITY.device_class == "connectivity"

    def test_host_tracker(self):
        assert HOST_TRACKER.component == "device_tracker"
        assert HOST_TRACKER.source_type == "router"
        assert HOST_TRACKER.payload_home == "home"

    def test_host_stack_mode(self):
        assert HOST_STACK_MODE.component == "sensor"
        assert HOST_STACK_MODE.entity_category == "diagnostic"

    def test_iface_entities_count(self):
        entities = _iface_entities("eth0", "eth0")
        assert len(entities) == 5  # connectivity, stack_mode, ipv4, mac, rtt

    def test_iface_rtt_has_measurement(self):
        entities = _iface_entities("eth0", "eth0")
        rtt = [e for e in entities if e.suffix == "eth0_rtt"][0]
        assert rtt.device_class == "duration"
        assert rtt.state_class == "measurement"
        assert rtt.unit == "ms"
        assert rtt.suggested_display_precision == 1


# ---------------------------------------------------------------------------
# Device dict
# ---------------------------------------------------------------------------

class TestDeviceDict:
    def test_basic_device(self):
        host = _make_host()
        d = _device_dict(host)
        assert d["identifiers"] == ["gdoc2netcfg_big_storage"]
        assert d["name"] == "big-storage"  # hostname == machine_name in this fixture
        assert d["connections"] == [["mac", "aa:bb:cc:dd:ee:ff"]]
        assert d["configuration_url"] == "http://10.1.5.10"

    def test_suggested_area_from_extra(self):
        host = _make_host(extra={"Physical Location": "Back Shed"})
        d = _device_dict(host)
        assert d["suggested_area"] == "Back Shed"

    def test_no_suggested_area_when_empty(self):
        host = _make_host()
        d = _device_dict(host)
        assert "suggested_area" not in d

    def test_multi_mac(self):
        host = _make_multi_iface_host()
        d = _device_dict(host)
        assert len(d["connections"]) == 2
        assert d["connections"][0] == ["mac", "aa:bb:cc:00:00:01"]
        assert d["connections"][1] == ["mac", "aa:bb:cc:00:00:02"]

    def test_bmc_gets_unique_identifiers(self):
        """BMC host must get different identifiers from its parent.

        BMC hosts share machine_name with their parent (both are
        "big-storage"), but have different hostnames ("bmc.big-storage"
        vs "big-storage").  Using hostname for node_id avoids collision.
        """
        parent = _make_host(
            machine_name="big-storage",
            hostname="big-storage",
            ip="10.1.10.1",
        )
        bmc = _make_host(
            machine_name="big-storage",  # same machine_name!
            hostname="bmc.big-storage",  # different hostname
            ip="10.1.5.150",
            mac="11:22:33:44:55:66",
        )

        parent_d = _device_dict(parent)
        bmc_d = _device_dict(bmc)

        assert parent_d["identifiers"] == ["gdoc2netcfg_big_storage"]
        assert bmc_d["identifiers"] == ["gdoc2netcfg_bmc_big_storage"]
        assert parent_d["identifiers"] != bmc_d["identifiers"]

        assert parent_d["name"] == "big-storage"
        assert bmc_d["name"] == "bmc.big-storage"

    def test_hostname_with_subdomain(self):
        """Hosts with VLAN subdomain in hostname get correct node_id."""
        host = _make_host(
            machine_name="au-plug-1",
            hostname="au-plug-1.iot",
        )
        d = _device_dict(host)
        assert d["identifiers"] == ["gdoc2netcfg_au_plug_1_iot"]
        assert d["name"] == "au-plug-1.iot"


# ---------------------------------------------------------------------------
# Availability list
# ---------------------------------------------------------------------------

class TestAvailabilityList:
    def test_base_availability(self):
        host = _make_host()
        avail, mode = _availability_list(host)
        assert len(avail) == 1
        assert avail[0]["topic"] == BRIDGE_AVAIL_TOPIC
        assert mode is None

    def test_power_plug_linkage(self):
        """When a Tasmota device controls this host, add plug's POWER topic."""
        controlled_host = _make_host(machine_name="server1", hostname="server1")

        plug_host = Host(
            machine_name="au-plug-17",
            hostname="au-plug-17.iot",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress("11:22:33:44:55:66"),
                    ip_addresses=(IPv4Address("10.1.30.17"),),
                ),
            ],
            tasmota_data=TasmotaData(
                device_name="au-plug-17",
                friendly_name="au-plug-17",
                hostname="au-plug-17",
                firmware_version="14.4.1",
                mqtt_host="ha.welland.mithis.com",
                mqtt_port=1883,
                mqtt_topic="au-plug-17",
                mqtt_client="au-plug-17",
                mac="11:22:33:44:55:66",
                ip="10.1.30.17",
                controls=("server1",),
            ),
        )

        hosts_by_name = {
            "server1": controlled_host,
            "au-plug-17": plug_host,
        }

        avail, mode = _availability_list(controlled_host, hosts_by_name)
        assert len(avail) == 2
        assert avail[1]["topic"] == "stat/au-plug-17/POWER"
        assert avail[1]["payload_available"] == "ON"
        assert mode == "all"

    def test_no_linkage_without_tasmota(self):
        host = _make_host()
        other = _make_host(machine_name="other", hostname="other", ip="10.1.5.11")
        hosts_by_name = {"big-storage": host, "other": other}
        avail, mode = _availability_list(host, hosts_by_name)
        assert len(avail) == 1
        assert mode is None


# ---------------------------------------------------------------------------
# Discovery payload
# ---------------------------------------------------------------------------

class TestDiscoveryPayload:
    def test_binary_sensor_connectivity(self):
        host = _make_host()
        dev = _device_dict(host)
        avail, mode = _availability_list(host)
        nid = _node_id(host.hostname)
        state_topic = f"{STATE_PREFIX}/{nid}/connectivity/state"

        payload = discovery_payload(
            HOST_CONNECTIVITY, nid, dev, avail, mode, state_topic,
        )

        assert payload["unique_id"] == "gdoc2netcfg_big_storage_connectivity"
        assert payload["default_entity_id"] == (
            "binary_sensor.gdoc2netcfg_big_storage_connectivity"
        )
        assert payload["name"] is None  # Main entity
        assert payload["device_class"] == "connectivity"
        assert payload["payload_on"] == "ON"
        assert payload["payload_off"] == "OFF"
        assert payload["expire_after"] == 600
        assert payload["state_topic"] == state_topic
        assert payload["device"]["identifiers"] == ["gdoc2netcfg_big_storage"]
        assert payload["origin"] == ORIGIN
        assert "availability_mode" not in payload

    def test_device_tracker(self):
        host = _make_host()
        dev = _device_dict(host)
        avail, mode = _availability_list(host)
        nid = _node_id(host.hostname)

        payload = discovery_payload(
            HOST_TRACKER, nid, dev, avail, mode,
            f"{STATE_PREFIX}/{nid}/tracker/state",
            json_attr_topic=f"{STATE_PREFIX}/{nid}/tracker/attributes",
        )

        assert payload["unique_id"] == "gdoc2netcfg_big_storage_tracker"
        assert payload["default_entity_id"] == (
            "device_tracker.gdoc2netcfg_big_storage_tracker"
        )
        assert payload["source_type"] == "router"
        assert payload["payload_home"] == "home"
        assert payload["payload_not_home"] == "not_home"
        assert payload["json_attributes_topic"] == f"{STATE_PREFIX}/{nid}/tracker/attributes"

    def test_sensor_stack_mode(self):
        host = _make_host()
        dev = _device_dict(host)
        avail, mode = _availability_list(host)
        nid = _node_id(host.hostname)

        payload = discovery_payload(
            HOST_STACK_MODE, nid, dev, avail, mode,
            f"{STATE_PREFIX}/{nid}/stack_mode/state",
        )

        assert payload["unique_id"] == "gdoc2netcfg_big_storage_stack_mode"
        assert payload["entity_category"] == "diagnostic"
        assert payload["icon"] == "mdi:ip-network"
        assert "device_class" not in payload
        assert "state_class" not in payload

    def test_interface_rtt_entity(self):
        entities = _iface_entities("eth0", "eth0")
        rtt = [e for e in entities if e.suffix == "eth0_rtt"][0]

        host = _make_host()
        dev = _device_dict(host)
        avail, mode = _availability_list(host)
        nid = _node_id(host.hostname)

        payload = discovery_payload(
            rtt, nid, dev, avail, mode,
            f"{STATE_PREFIX}/{nid}/eth0/rtt/state",
            json_attr_topic=f"{STATE_PREFIX}/{nid}/eth0/rtt/attributes",
        )

        assert payload["device_class"] == "duration"
        assert payload["state_class"] == "measurement"
        assert payload["unit_of_measurement"] == "ms"
        assert payload["suggested_display_precision"] == 1
        assert payload["entity_category"] == "diagnostic"

    def test_availability_mode_included_when_set(self):
        host = _make_host()
        dev = _device_dict(host)
        avail = [
            {"topic": BRIDGE_AVAIL_TOPIC, "payload_available": "online",
             "payload_not_available": "offline"},
            {"topic": "stat/plug/POWER", "payload_available": "ON",
             "payload_not_available": "OFF"},
        ]
        nid = _node_id(host.hostname)

        payload = discovery_payload(
            HOST_CONNECTIVITY, nid, dev, avail, "all",
            f"{STATE_PREFIX}/{nid}/connectivity/state",
        )

        assert payload["availability_mode"] == "all"


# ---------------------------------------------------------------------------
# Discovery topic
# ---------------------------------------------------------------------------

class TestDiscoveryTopic:
    def test_binary_sensor_topic(self):
        nid = _node_id("big-storage")
        topic = discovery_topic(HOST_CONNECTIVITY, nid)
        expected = (
            f"{DISCOVERY_PREFIX}/binary_sensor/gdoc2netcfg_big_storage/"
            f"gdoc2netcfg_big_storage_connectivity/config"
        )
        assert topic == expected

    def test_device_tracker_topic(self):
        nid = _node_id("big-storage")
        topic = discovery_topic(HOST_TRACKER, nid)
        assert "/device_tracker/" in topic
        assert topic.endswith("/config")

    def test_sensor_topic(self):
        nid = _node_id("big-storage")
        topic = discovery_topic(HOST_STACK_MODE, nid)
        assert "/sensor/" in topic


# ---------------------------------------------------------------------------
# State builders
# ---------------------------------------------------------------------------

class TestBuildHostState:
    def test_reachable_host(self):
        host = _make_host()
        hr = _make_reachability()
        states = build_host_state(host, hr)

        nid = _node_id(host.hostname)
        assert states[f"{STATE_PREFIX}/{nid}/connectivity/state"] == "ON"
        assert states[f"{STATE_PREFIX}/{nid}/tracker/state"] == "home"
        assert states[f"{STATE_PREFIX}/{nid}/stack_mode/state"] == "dual-stack"

    def test_unreachable_host(self):
        host = _make_host()
        hr = _make_reachability(received_v4=0, received_v6=0, rtt_v4=None, rtt_v6=None)
        states = build_host_state(host, hr)

        nid = _node_id(host.hostname)
        assert states[f"{STATE_PREFIX}/{nid}/connectivity/state"] == "OFF"
        assert states[f"{STATE_PREFIX}/{nid}/tracker/state"] == "not_home"
        assert states[f"{STATE_PREFIX}/{nid}/stack_mode/state"] == "unreachable"

    def test_ipv4_only(self):
        host = _make_host()
        hr = _make_reachability(received_v6=0, rtt_v6=None)
        states = build_host_state(host, hr)

        nid = _node_id(host.hostname)
        assert states[f"{STATE_PREFIX}/{nid}/stack_mode/state"] == "ipv4-only"

    def test_tracker_attributes_json(self):
        host = _make_host()
        hr = _make_reachability()
        states = build_host_state(host, hr)

        nid = _node_id(host.hostname)
        attrs_json = states[f"{STATE_PREFIX}/{nid}/tracker/attributes"]
        attrs = json.loads(attrs_json)
        assert attrs["host_name"] == "big-storage"
        assert attrs["ip"] == "10.1.5.10"
        assert attrs["mac"] == "aa:bb:cc:dd:ee:ff"


class TestBuildInterfaceState:
    def test_reachable_interface(self):
        host = _make_host(iface_name="eth0")
        vi = host.virtual_interfaces[0]
        ir = InterfaceReachability(pings=(
            ("10.1.5.10", PingResult(10, 10, 1.5)),
            ("2404:e80:a137:105::10", PingResult(10, 10, 2.0)),
        ))

        states = build_interface_state(host, vi, ir)

        nid = _node_id(host.hostname)
        assert states[f"{STATE_PREFIX}/{nid}/eth0/connectivity/state"] == "ON"
        assert states[f"{STATE_PREFIX}/{nid}/eth0/stack_mode/state"] == "dual-stack"
        assert states[f"{STATE_PREFIX}/{nid}/eth0/ipv4/state"] == "10.1.5.10"
        assert states[f"{STATE_PREFIX}/{nid}/eth0/mac/state"] == "aa:bb:cc:dd:ee:ff"
        # RTT should be the best (lowest) RTT
        assert states[f"{STATE_PREFIX}/{nid}/eth0/rtt/state"] == "1.5"

    def test_unreachable_interface(self):
        host = _make_host(iface_name="eth0")
        vi = host.virtual_interfaces[0]
        ir = InterfaceReachability(pings=(
            ("10.1.5.10", PingResult(10, 0)),
            ("2404:e80:a137:105::10", PingResult(10, 0)),
        ))

        states = build_interface_state(host, vi, ir)

        nid = _node_id(host.hostname)
        assert states[f"{STATE_PREFIX}/{nid}/eth0/connectivity/state"] == "OFF"
        assert states[f"{STATE_PREFIX}/{nid}/eth0/rtt/state"] == ""

    def test_rtt_attributes_json(self):
        host = _make_host(iface_name="eth0")
        vi = host.virtual_interfaces[0]
        ir = InterfaceReachability(pings=(
            ("10.1.5.10", PingResult(10, 10, 1.5)),
        ))

        states = build_interface_state(host, vi, ir)

        nid = _node_id(host.hostname)
        attrs = json.loads(states[f"{STATE_PREFIX}/{nid}/eth0/rtt/attributes"])
        assert "10.1.5.10" in attrs
        assert attrs["10.1.5.10"]["transmitted"] == 10
        assert attrs["10.1.5.10"]["received"] == 10
        assert attrs["10.1.5.10"]["rtt_avg_ms"] == 1.5


# ---------------------------------------------------------------------------
# Publisher (mock paho client)
# ---------------------------------------------------------------------------

class TestPublishAllHosts:
    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_publishes_discovery_retained(self, mock_client_cls):
        """Discovery config topics must be published with retain=True."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()
        hr = _make_reachability()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        publish_all_hosts([host], {"big-storage": hr}, mqtt_config)

        # Collect all publish calls
        pub_calls = client.publish.call_args_list

        # Find discovery calls (topic starts with "homeassistant/")
        discovery_calls = [
            c for c in pub_calls
            if c.args[0].startswith("homeassistant/")
        ]
        assert len(discovery_calls) > 0

        # All discovery calls must have retain=True
        for c in discovery_calls:
            assert c.kwargs.get("retain", c.args[2] if len(c.args) > 2 else None) is True, (
                f"Discovery topic {c.args[0]} not retained"
            )

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_publishes_state_not_retained(self, mock_client_cls):
        """State topics must NOT be retained."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()
        hr = _make_reachability()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        publish_all_hosts([host], {"big-storage": hr}, mqtt_config)

        pub_calls = client.publish.call_args_list

        # Find state calls (topic starts with "gdoc2netcfg/" but not bridge avail)
        state_calls = [
            c for c in pub_calls
            if c.args[0].startswith(f"{STATE_PREFIX}/")
            and c.args[0] != BRIDGE_AVAIL_TOPIC
        ]
        assert len(state_calls) > 0

        for c in state_calls:
            retain = c.kwargs.get("retain", c.args[2] if len(c.args) > 2 else None)
            assert retain is False, f"State topic {c.args[0]} should not be retained"

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_bridge_availability_retained(self, mock_client_cls):
        """Bridge availability topic must be retained."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()
        hr = _make_reachability()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        publish_all_hosts([host], {"big-storage": hr}, mqtt_config)

        pub_calls = client.publish.call_args_list
        bridge_calls = [c for c in pub_calls if c.args[0] == BRIDGE_AVAIL_TOPIC]
        assert len(bridge_calls) >= 1
        # The last bridge call should be "online", retained
        last = bridge_calls[-1]
        assert last.args[1] == "online"
        assert last.kwargs.get("retain", last.args[2] if len(last.args) > 2 else None) is True

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_lwt_set_before_connect(self, mock_client_cls):
        """LWT must be set before connecting."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()
        hr = _make_reachability()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        publish_all_hosts([host], {"big-storage": hr}, mqtt_config)

        # will_set must be called
        client.will_set.assert_called_once_with(
            BRIDGE_AVAIL_TOPIC, "offline", retain=True,
        )

        # will_set must come before connect
        all_calls = client.method_calls
        will_idx = next(
            i for i, c in enumerate(all_calls)
            if c[0] == "will_set"
        )
        connect_idx = next(
            i for i, c in enumerate(all_calls)
            if c[0] == "connect"
        )
        assert will_idx < connect_idx

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_returns_host_count(self, mock_client_cls):
        """publish_all_hosts returns the number of hosts published."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()
        hr = _make_reachability()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        count = publish_all_hosts([host], {"big-storage": hr}, mqtt_config)
        assert count == 1

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_discovery_payload_valid_json(self, mock_client_cls):
        """Discovery payloads must be valid JSON with required fields."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()
        hr = _make_reachability()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        publish_all_hosts([host], {"big-storage": hr}, mqtt_config)

        pub_calls = client.publish.call_args_list
        discovery_calls = [
            c for c in pub_calls
            if c.args[0].startswith("homeassistant/")
        ]

        for c in discovery_calls:
            payload = json.loads(c.args[1])
            assert "unique_id" in payload, f"Missing unique_id in {c.args[0]}"
            assert "device" in payload, f"Missing device in {c.args[0]}"
            assert "state_topic" in payload, f"Missing state_topic in {c.args[0]}"
            assert "origin" in payload, f"Missing origin in {c.args[0]}"
            assert "availability" in payload, f"Missing availability in {c.args[0]}"

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_multi_interface_host_entities(self, mock_client_cls):
        """Multi-interface host should produce per-interface entities."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_multi_iface_host()
        # Build reachability with two interfaces
        ir1 = InterfaceReachability(pings=(
            ("10.1.5.20", PingResult(10, 10, 1.0)),
            ("2404:e80:a137:105::20", PingResult(10, 10, 2.0)),
        ))
        ir2 = InterfaceReachability(pings=(
            ("10.1.10.20", PingResult(10, 10, 1.5)),
            ("2404:e80:a137:110::20", PingResult(10, 10, 2.5)),
        ))
        hr = HostReachability(
            hostname="dual-nic",
            active_ips=("10.1.5.20", "2404:e80:a137:105::20",
                        "10.1.10.20", "2404:e80:a137:110::20"),
            interfaces=(ir1, ir2),
        )

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        publish_all_hosts([host], {"dual-nic": hr}, mqtt_config)

        pub_calls = client.publish.call_args_list
        discovery_calls = [
            c for c in pub_calls
            if c.args[0].startswith("homeassistant/")
        ]

        # Should have: 3 host-level + 5 per-interface * 2 interfaces = 13
        assert len(discovery_calls) == 13

        # Check eth0 and eth1 entities exist
        topics = [c.args[0] for c in discovery_calls]
        eth0_topics = [t for t in topics if "eth0" in t]
        eth1_topics = [t for t in topics if "eth1" in t]
        assert len(eth0_topics) == 5  # connectivity, stack_mode, ipv4, mac, rtt
        assert len(eth1_topics) == 5

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_disconnects_on_completion(self, mock_client_cls):
        """Client must be disconnected after publishing."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()
        hr = _make_reachability()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        publish_all_hosts([host], {"big-storage": hr}, mqtt_config)

        client.disconnect.assert_called_once()
        client.loop_stop.assert_called_once()

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_raises_on_missing_reachability(self, mock_client_cls):
        """Publish must raise KeyError if host has no reachability entry."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_host()

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        # Empty reachability dict — host is missing
        with pytest.raises(KeyError, match="big-storage"):
            publish_all_hosts([host], {}, mqtt_config)

    @patch("gdoc2netcfg.supplements.mqtt_ha.mqtt.Client")
    def test_raises_on_interface_count_mismatch(self, mock_client_cls):
        """Publish must raise ValueError if interface counts don't match."""
        client = MagicMock()
        mock_client_cls.return_value = client

        host = _make_multi_iface_host()  # 2 interfaces
        # Reachability with only 1 interface
        ir1 = InterfaceReachability(pings=(
            ("10.1.5.20", PingResult(10, 10, 1.0)),
        ))
        hr = HostReachability(
            hostname="dual-nic",
            active_ips=("10.1.5.20",),
            interfaces=(ir1,),  # Only 1, host has 2
        )

        from gdoc2netcfg.config import TasmotaConfig

        mqtt_config = TasmotaConfig(
            mqtt_host="broker", mqtt_port=1883,
            mqtt_user="user", mqtt_password="pass",
        )

        with pytest.raises(ValueError, match="data consistency bug"):
            publish_all_hosts([host], {"dual-nic": hr}, mqtt_config)


# ---------------------------------------------------------------------------
# _iface_entity_state_topic helper
# ---------------------------------------------------------------------------

class TestIfaceEntityStateTopic:
    def test_connectivity_suffix(self):
        entities = _iface_entities("eth0", "eth0")
        conn = [e for e in entities if e.suffix == "eth0_connectivity"][0]
        st, ja = _iface_entity_state_topic(conn, "big_storage", "eth0")
        assert st == f"{STATE_PREFIX}/big_storage/eth0/connectivity/state"
        assert ja is None

    def test_rtt_suffix_has_attributes(self):
        entities = _iface_entities("eth0", "eth0")
        rtt = [e for e in entities if e.suffix == "eth0_rtt"][0]
        st, ja = _iface_entity_state_topic(rtt, "big_storage", "eth0")
        assert st == f"{STATE_PREFIX}/big_storage/eth0/rtt/state"
        assert ja == f"{STATE_PREFIX}/big_storage/eth0/rtt/attributes"

    def test_unknown_suffix_raises(self):
        bad_entity = EntityDef(
            component="sensor", suffix="eth0_unknown",
        )
        with pytest.raises(ValueError, match="Unknown entity suffix"):
            _iface_entity_state_topic(bad_entity, "x", "eth0")


class TestEntityDefImport:
    """Verify EntityDef is importable for test_unknown_suffix_raises."""
    pass
