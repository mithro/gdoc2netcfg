"""Tests for the bridge SNMP supplement."""

from unittest.mock import patch

import pytest

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.bridge import (
    _BRIDGE_TABLE_OIDS,
    BRIDGE_CAPABLE_HARDWARE,
    _collect_bridge_data,
    _format_hex_mac,
    _format_octet_string,
    _parse_port_statistics,
    enrich_hosts_with_bridge_data,
    parse_bridge_port_map,
    parse_if_aliases,
    parse_if_names,
    parse_lldp_neighbors,
    parse_mac_table,
    parse_poe_status,
    parse_port_pvids,
    parse_port_status,
    parse_vlan_egress_ports,
    parse_vlan_names,
    parse_vlan_untagged_ports,
    scan_bridge,
)
from gdoc2netcfg.supplements.reachability import HostReachability


def _make_switch(hostname="sw-test", ip="10.1.5.10"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name="manage",
                mac=MACAddress.parse("08:bd:43:6b:b8:d8"),
                ip_addresses=(IPv4Address(ip),),
                dhcp_name=hostname,
            ),
        ],
        hardware_type="netgear-switch",
        extra={},
    )


class TestParseMacTable:
    """Parse dot1qTpFdbTable walk results into (mac, vlan, port, name) tuples."""

    def test_parses_mac_vlan_port(self):
        # OID: .1.3.6.1.2.1.17.7.1.2.2.1.2.<VLAN>.<M1>.<M2>.<M3>.<M4>.<M5>.<M6>
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.8.189.67.107.184.216", "313"),
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.31.228.95.1.141.247.23", "3"),
        ]
        bridge_to_if = {313: 313, 3: 3}
        if_names = {313: "CPU Interface:  0/5/1", 3: "1/g3"}
        result = parse_mac_table(walk, bridge_to_if, if_names)
        assert len(result) == 2
        assert result[0] == ("08:BD:43:6B:B8:D8", 5, 313, "CPU Interface:  0/5/1")
        assert result[1] == ("E4:5F:01:8D:F7:17", 31, 3, "1/g3")

    def test_empty_walk(self):
        assert parse_mac_table([], {}, {}) == []

    def test_unknown_bridge_port_keeps_empty_name(self):
        """Bridge ports with no dot1dBasePortIfIndex entry (LAG/CPU ports
        on e.g. Cisco small-business switches) have no resolvable name —
        the name stays empty rather than being fabricated, and the
        bridge_port number is preserved."""
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.170.187.204.221.238.255", "99"),
        ]
        result = parse_mac_table(walk, {}, {})
        assert len(result) == 1
        assert result[0] == ("AA:BB:CC:DD:EE:FF", 5, 99, "")

    def test_skips_malformed_oid(self):
        """OID with wrong number of components should be silently skipped."""
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.170.187", "99"),
        ]
        result = parse_mac_table(walk, {}, {})
        assert len(result) == 0

    def test_multiple_vlans_same_mac(self):
        """Same MAC can appear on different VLANs."""
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.170.187.204.221.238.255", "3"),
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.10.170.187.204.221.238.255", "3"),
        ]
        result = parse_mac_table(walk, {3: 3}, {3: "1/g3"})
        assert len(result) == 2
        assert result[0][1] == 5   # VLAN 5
        assert result[1][1] == 10  # VLAN 10


class TestParseIfNames:
    def test_parses_if_names(self):
        walk = [
            ("1.3.6.1.2.1.31.1.1.1.1.1", "1/g1"),
            ("1.3.6.1.2.1.31.1.1.1.1.49", "1/xg49"),
        ]
        result = parse_if_names(walk)
        assert result == {1: "1/g1", 49: "1/xg49"}

    def test_empty(self):
        assert parse_if_names([]) == {}

    def test_multi_digit_index(self):
        walk = [
            ("1.3.6.1.2.1.31.1.1.1.1.314", "CPU Interface:  0/5/1"),
        ]
        result = parse_if_names(walk)
        assert result == {314: "CPU Interface:  0/5/1"}


class TestParseBridgePortMap:
    def test_parses_mapping(self):
        walk = [
            ("1.3.6.1.2.1.17.1.4.1.2.1", "1"),
            ("1.3.6.1.2.1.17.1.4.1.2.50", "50"),
            ("1.3.6.1.2.1.17.1.4.1.2.314", "314"),
        ]
        result = parse_bridge_port_map(walk)
        assert result == {1: 1, 50: 50, 314: 314}

    def test_empty(self):
        assert parse_bridge_port_map([]) == {}


class TestParseVlanNames:
    def test_parses_names(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.1", "Default"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.10", "int"),
        ]
        result = parse_vlan_names(walk)
        assert result == [(1, "Default"), (5, "net"), (10, "int")]

    def test_empty(self):
        assert parse_vlan_names([]) == []


class TestParsePortPvids:
    def test_parses_pvids(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.5.1.1.1", "31"),
            ("1.3.6.1.2.1.17.7.1.4.5.1.1.40", "5"),
        ]
        result = parse_port_pvids(walk)
        assert result == [(1, 31), (40, 5)]

    def test_empty(self):
        assert parse_port_pvids([]) == []


class TestParsePortStatus:
    def test_parses_status_and_speed(self):
        oper_walk = [
            ("1.3.6.1.2.1.2.2.1.8.1", "2"),   # down
            ("1.3.6.1.2.1.2.2.1.8.3", "1"),   # up
        ]
        speed_walk = [
            ("1.3.6.1.2.1.31.1.1.1.15.1", "0"),
            ("1.3.6.1.2.1.31.1.1.1.15.3", "1000"),
        ]
        result = parse_port_status(oper_walk, speed_walk)
        assert (1, 2, 0) in result
        assert (3, 1, 1000) in result

    def test_missing_speed(self):
        """Port with oper status but no speed data gets speed 0."""
        oper_walk = [
            ("1.3.6.1.2.1.2.2.1.8.5", "1"),
        ]
        speed_walk = []
        result = parse_port_status(oper_walk, speed_walk)
        assert (5, 1, 0) in result

    def test_empty(self):
        assert parse_port_status([], []) == []


class TestParseLldpNeighbors:
    def test_parses_neighbors(self):
        walk = [
            # lldpRemChassisIdSubtype (OID .4)
            ("1.0.8802.1.1.2.1.4.1.1.4.97.50.1", "4"),
            # lldpRemChassisId (OID .5) - hex MAC
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xc80084897170"),
            # lldpRemPortId (OID .7)
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "gi24"),
            # lldpRemSysName (OID .9)
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "sw-cisco-shed"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0] == (50, "sw-cisco-shed", "gi24", "C8:00:84:89:71:70")

    def test_multiple_neighbors(self):
        walk = [
            # Neighbor 1
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xaabbccddeeff"),
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "gi24"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "switch-a"),
            # Neighbor 2
            ("1.0.8802.1.1.2.1.4.1.1.5.97.51.2", "0x112233445566"),
            ("1.0.8802.1.1.2.1.4.1.1.7.97.51.2", "eth0"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.51.2", "switch-b"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 2

    def test_empty(self):
        assert parse_lldp_neighbors([]) == []

    def test_non_hex_chassis_id(self):
        """Chassis ID that is not hex MAC format should be preserved as-is."""
        walk = [
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "some-string-id"),
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "gi24"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "neighbor"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0][3] == "some-string-id"

    def test_raw_binary_port_id_6_bytes(self):
        """Port ID as raw 6-byte binary (MAC) should be formatted as hex."""
        walk = [
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xc80084897170"),
            # Raw binary port ID: 0C:C4:7A:16:3B:4A
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "\x0c\xc4\x7a\x16\x3b\x4a"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "neighbor"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0][2] == "0C:C4:7A:16:3B:4A"

    def test_raw_binary_port_id_4_bytes(self):
        """Port ID as raw 4-byte binary should be formatted as hex."""
        walk = [
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xc80084897170"),
            # Raw binary port ID: C4:7A:3B:4A (4 bytes, not a MAC)
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "\xc4\x7a\x3b\x4a"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "neighbor"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0][2] == "C4:7A:3B:4A"


class TestFormatHexMac:
    """Tests for _format_hex_mac() which normalises chassis IDs to XX:XX:XX:XX:XX:XX."""

    def test_format_hex_mac_raw_bytes(self):
        """Raw 6-byte binary string (pysnmp OCTET STRING via str()) → formatted MAC."""
        raw = "\xc8\x00\x84\x89\x71\x70"
        assert _format_hex_mac(raw) == "C8:00:84:89:71:70"

    def test_format_hex_mac_raw_bytes_all_zeros(self):
        """Raw 6-byte binary string of all zeros."""
        raw = "\x00\x00\x00\x00\x00\x00"
        assert _format_hex_mac(raw) == "00:00:00:00:00:00"

    def test_format_hex_mac_0x_prefix(self):
        """0x-prefixed 12-hex-digit string → formatted MAC."""
        assert _format_hex_mac("0xc80084897170") == "C8:00:84:89:71:70"

    def test_format_hex_mac_12_hex_digits(self):
        """12 hex digits without 0x prefix → formatted MAC."""
        assert _format_hex_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_format_hex_mac_passthrough(self):
        """Non-MAC strings returned unchanged."""
        assert _format_hex_mac("some-string-id") == "some-string-id"
        assert _format_hex_mac("") == ""
        assert _format_hex_mac("short") == "short"


class TestFormatOctetString:
    """Tests for _format_octet_string() which formats arbitrary binary for display."""

    def test_printable_ascii_unchanged(self):
        """Printable ASCII strings are returned as-is."""
        assert _format_octet_string("gi24") == "gi24"
        assert _format_octet_string("1/xg50") == "1/xg50"
        assert _format_octet_string("eth0") == "eth0"

    def test_binary_formatted_as_hex(self):
        """Non-printable binary is formatted as colon-separated hex."""
        assert _format_octet_string("\xc4\x7a\x3b\x4a") == "C4:7A:3B:4A"
        assert _format_octet_string("\x0c\xc4\x7a\x16\x3b\x4a") == "0C:C4:7A:16:3B:4A"

    def test_empty_string(self):
        """Empty string returns empty."""
        assert _format_octet_string("") == ""

    def test_mixed_with_control_chars(self):
        """String with control characters is formatted as hex."""
        # Contains newline and null
        assert _format_octet_string("\x00\x0a") == "00:0A"


class TestParseVlanEgressPorts:
    def test_parses_egress(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.3.1.2.5", "0xffc00000"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.2.10", "0xff000000"),
        ]
        result = parse_vlan_egress_ports(walk)
        assert result == [(5, "0xffc00000"), (10, "0xff000000")]

    def test_empty(self):
        assert parse_vlan_egress_ports([]) == []


class TestParseVlanUntaggedPorts:
    def test_parses_untagged(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.3.1.4.5", "0xff800000"),
        ]
        result = parse_vlan_untagged_ports(walk)
        assert result == [(5, "0xff800000")]

    def test_empty(self):
        assert parse_vlan_untagged_ports([]) == []


class TestParsePortStatistics:
    """Tests for parsing IF-MIB interface statistics OIDs."""

    def test_parses_port_statistics(self):
        """Parse ifHCInOctets, ifHCOutOctets, and ifInErrors into tuples."""
        raw = {
            "ifHCInOctets": [
                ("1.3.6.1.2.1.31.1.1.1.6.1", "1000"),
                ("1.3.6.1.2.1.31.1.1.1.6.2", "2000"),
            ],
            "ifHCOutOctets": [
                ("1.3.6.1.2.1.31.1.1.1.10.1", "500"),
                ("1.3.6.1.2.1.31.1.1.1.10.2", "1000"),
            ],
            "ifInErrors": [
                ("1.3.6.1.2.1.2.2.1.14.1", "5"),
                ("1.3.6.1.2.1.2.2.1.14.2", "0"),
            ],
        }
        result = _parse_port_statistics(raw)

        assert len(result) == 2
        assert result[0] == (1, 1000, 500, 5)
        assert result[1] == (2, 2000, 1000, 0)

    def test_empty_raw_data(self):
        """Empty input returns empty tuple."""
        result = _parse_port_statistics({})
        assert result == ()

    def test_missing_out_octets(self):
        """Port with in octets but no out octets defaults out to 0."""
        raw = {
            "ifHCInOctets": [
                ("1.3.6.1.2.1.31.1.1.1.6.5", "9999"),
            ],
            "ifInErrors": [
                ("1.3.6.1.2.1.2.2.1.14.5", "3"),
            ],
        }
        result = _parse_port_statistics(raw)

        assert len(result) == 1
        assert result[0] == (5, 9999, 0, 3)

    def test_missing_in_octets(self):
        """Port with out octets but no in octets defaults in to 0."""
        raw = {
            "ifHCOutOctets": [
                ("1.3.6.1.2.1.31.1.1.1.10.3", "7777"),
            ],
        }
        result = _parse_port_statistics(raw)

        assert len(result) == 1
        assert result[0] == (3, 0, 7777, 0)

    def test_missing_errors(self):
        """Port with octets but no errors defaults errors to 0."""
        raw = {
            "ifHCInOctets": [
                ("1.3.6.1.2.1.31.1.1.1.6.1", "1000"),
            ],
            "ifHCOutOctets": [
                ("1.3.6.1.2.1.31.1.1.1.10.1", "500"),
            ],
        }
        result = _parse_port_statistics(raw)

        assert len(result) == 1
        assert result[0] == (1, 1000, 500, 0)

    def test_large_counter_values(self):
        """64-bit counter values are handled correctly."""
        raw = {
            "ifHCInOctets": [
                ("1.3.6.1.2.1.31.1.1.1.6.1", "18446744073709551615"),   # 2^64 - 1
            ],
            "ifHCOutOctets": [
                ("1.3.6.1.2.1.31.1.1.1.10.1", "9223372036854775807"),  # 2^63 - 1
            ],
        }
        result = _parse_port_statistics(raw)

        assert len(result) == 1
        assert result[0] == (1, 18446744073709551615, 9223372036854775807, 0)

    def test_sorted_by_ifindex(self):
        """Results are sorted by ifIndex."""
        raw = {
            "ifHCInOctets": [
                ("1.3.6.1.2.1.31.1.1.1.6.10", "100"),
                ("1.3.6.1.2.1.31.1.1.1.6.3", "300"),
                ("1.3.6.1.2.1.31.1.1.1.6.7", "700"),
            ],
        }
        result = _parse_port_statistics(raw)

        assert len(result) == 3
        assert result[0][0] == 3
        assert result[1][0] == 7
        assert result[2][0] == 10


class TestParsePoeStatus:
    def test_parses_real_walk_layout(self):
        # Layout captured live from sw-netgear-gsm7252ps-s1 (GSM7252PS):
        # pethPsePortEntry exposes columns 3-14. RFC 3621 columns 1-2
        # (group/port index) are not-accessible and never appear in walks.
        # Port 1 is delivering power, port 43 has a self-powered device
        # attached (admin on, detection searching).
        walk = []
        for col, port1, port43 in [
            (3, "1", "1"),   # pethPsePortAdminEnable: both enabled
            (4, "1", "1"),   # pethPsePortPowerPairsControlAbility
            (5, "1", "1"),   # pethPsePortPowerPairs
            (6, "3", "2"),   # pethPsePortDetectionStatus: delivering / searching
            (7, "3", "3"),   # pethPsePortPowerPriority
            (8, "0", "0"),   # pethPsePortMPSAbsentCounter
            (9, "1", "1"),   # pethPsePortType
            (11, "0", "0"),  # pethPsePortInvalidSignatureCounter
            (12, "0", "0"),
            (13, "0", "0"),
            (14, "0", "0"),
        ]:
            walk.append((f"1.3.6.1.2.1.105.1.1.1.{col}.1.1", port1))
            walk.append((f"1.3.6.1.2.1.105.1.1.1.{col}.1.43", port43))

        assert parse_poe_status(walk) == [(1, 1, 3), (43, 1, 2)]

    def test_empty(self):
        # Non-PoE switches return nothing for the pethPsePortTable walk.
        assert parse_poe_status([]) == []

    def test_missing_admin_column_raises(self):
        walk = [("1.3.6.1.2.1.105.1.1.1.6.1.1", "3")]
        with pytest.raises(ValueError, match="missing admin"):
            parse_poe_status(walk)

    def test_missing_detection_column_raises(self):
        walk = [("1.3.6.1.2.1.105.1.1.1.3.1.1", "1")]
        with pytest.raises(ValueError, match="missing detection"):
            parse_poe_status(walk)

    def test_non_integer_value_raises(self):
        walk = [
            ("1.3.6.1.2.1.105.1.1.1.3.1.1", "1"),
            ("1.3.6.1.2.1.105.1.1.1.6.1.1", "bogus"),
        ]
        with pytest.raises(ValueError, match="non-integer"):
            parse_poe_status(walk)


class TestParseIfAliases:
    def test_parses_aliases(self):
        # Values captured live from sw-netgear-gsm7252ps-s1: operator-set
        # port descriptions naming the attached host.  Unset aliases are
        # empty strings and are kept.
        walk = [
            ("1.3.6.1.2.1.31.1.1.1.18.1", "eth0.rpi5-pmod"),
            ("1.3.6.1.2.1.31.1.1.1.18.2", ""),
            ("1.3.6.1.2.1.31.1.1.1.18.48", "gi28.sw-cisco-shed"),
        ]
        assert parse_if_aliases(walk) == {
            1: "eth0.rpi5-pmod",
            2: "",
            48: "gi28.sw-cisco-shed",
        }

    def test_ignores_other_oids(self):
        walk = [("1.3.6.1.2.1.31.1.1.1.1.1", "1/g1")]  # ifName, not ifAlias
        assert parse_if_aliases(walk) == {}

    def test_empty(self):
        assert parse_if_aliases([]) == {}


class TestCollectBridgeData:
    def test_walks_if_alias(self):
        assert _BRIDGE_TABLE_OIDS["if_alias"] == "1.3.6.1.2.1.31.1.1.1.18"

    @patch("gdoc2netcfg.supplements.bridge.try_snmp_credentials")
    def test_collects_port_aliases(self, mock_try):
        mock_try.return_value = {
            "if_name": [("1.3.6.1.2.1.31.1.1.1.1.1", "1/g1")],
            "if_alias": [("1.3.6.1.2.1.31.1.1.1.18.1", "eth0.rpi5-pmod")],
        }
        doc = _collect_bridge_data("10.1.5.22", _make_switch())
        assert doc["port_names"] == [(1, "1/g1")]
        assert doc["port_aliases"] == [(1, "eth0.rpi5-pmod")]

    @patch("gdoc2netcfg.supplements.bridge.try_snmp_credentials")
    def test_no_alias_support_yields_empty_list(self, mock_try):
        """A switch that answers nothing for ifAlias still produces the
        key — present-and-empty, distinct from pre-capture history."""
        mock_try.return_value = {
            "if_name": [("1.3.6.1.2.1.31.1.1.1.1.1", "1/g1")],
        }
        doc = _collect_bridge_data("10.1.5.22", _make_switch())
        assert doc["port_aliases"] == []


class TestBridgeCapableHardware:
    def test_includes_netgear_switch(self):
        assert "netgear-switch" in BRIDGE_CAPABLE_HARDWARE

    def test_includes_cisco_switch(self):
        assert "cisco-switch" in BRIDGE_CAPABLE_HARDWARE

    def test_excludes_netgear_switch_plus(self):
        assert "netgear-switch-plus" not in BRIDGE_CAPABLE_HARDWARE


class TestEnrichHostsWithBridgeData:
    def test_enriches_switch_hosts(self):
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
                "vlan_names": [[1, "Default"], [5, "net"]],
                "port_pvids": [[1, 31]],
                "port_names": [[1, "1/g1"]],
                "port_aliases": [[1, "eth0.rpi5-pmod"]],
                "port_status": [[1, 2, 0]],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)
        assert host.bridge_data is not None
        assert len(host.bridge_data.mac_table) == 1
        assert host.bridge_data.mac_table[0] == ("AA:BB:CC:DD:EE:FF", 5, 3, "1/g3")
        assert len(host.bridge_data.vlan_names) == 2
        assert host.bridge_data.vlan_names[0] == (1, "Default")
        assert host.bridge_data.vlan_names[1] == (5, "net")
        assert host.bridge_data.port_aliases == ((1, "eth0.rpi5-pmod"),)

    def test_no_data_for_host(self):
        host = _make_switch()
        enrich_hosts_with_bridge_data([host], {})
        assert host.bridge_data is None

    def test_bridge_data_is_frozen(self):
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [],
                "vlan_names": [],
                "port_pvids": [],
                "port_names": [],
                "port_status": [],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)
        assert host.bridge_data is not None
        try:
            host.bridge_data.mac_table = ()
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_missing_keys_use_defaults(self):
        """Cache entries missing some keys should still work with empty defaults."""
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
                # Missing all other keys
            }
        }
        enrich_hosts_with_bridge_data([host], cache)
        assert host.bridge_data is not None
        assert len(host.bridge_data.mac_table) == 1
        assert host.bridge_data.vlan_names == ()
        assert host.bridge_data.port_pvids == ()
        assert host.bridge_data.port_aliases == ()


class TestScanBridge:
    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_collects_from_switch(self, mock_collect, tmp_path):
        mock_collect.return_value = {
            "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
            "vlan_names": [[5, "net"]],
            "port_pvids": [],
            "port_names": [],
            "port_status": [],
            "lldp_neighbors": [],
            "vlan_egress_ports": [],
            "vlan_untagged_ports": [],
            "poe_status": [],
        }
        host = _make_switch()
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=("10.1.5.10",)),
        }
        result = scan_bridge([host], {}, reachability=reachability)
        assert "sw-test" in result
        mock_collect.assert_called_once()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_non_switches(self, mock_collect, tmp_path):
        host = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.10.5"),),
                ),
            ],
            hardware_type=None,
        )
        reachability = {
            "desktop": HostReachability(hostname="desktop", active_ips=("10.1.10.5",)),
        }
        result = scan_bridge([host], {}, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_unreachable(self, mock_collect, tmp_path):
        host = _make_switch()
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=()),
        }
        result = scan_bridge([host], {}, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_merges_baseline(self, mock_collect):
        """Fresh results merge over the baseline; unscanned hosts persist."""
        mock_collect.return_value = {
            "mac_table": [], "vlan_names": [], "port_pvids": [],
            "port_names": [], "port_status": [], "lldp_neighbors": [],
            "vlan_egress_ports": [], "vlan_untagged_ports": [], "poe_status": [],
        }
        host = _make_switch()
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=("10.1.5.10",)),
        }
        baseline = {"sw-other": {"mac_table": []}}

        result = scan_bridge([host], baseline, reachability=reachability)

        assert "sw-test" in result
        assert result["sw-other"] == {"mac_table": []}
        # The input baseline is not mutated.
        assert "sw-test" not in baseline

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_no_snmp_response(self, mock_collect, tmp_path):
        mock_collect.return_value = None
        host = _make_switch()
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=("10.1.5.10",)),
        }
        result = scan_bridge([host], {}, reachability=reachability)
        assert "sw-test" not in result

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_includes_hosts_with_snmp_data(self, mock_collect, tmp_path):
        """Hosts with existing snmp_data (not bridge-capable hardware type)
        should also be scanned, since SNMP proved reachable."""
        from gdoc2netcfg.models.host import SNMPData

        host = Host(
            machine_name="bmc-server",
            hostname="bmc-server",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("00:25:90:aa:bb:cc"),
                    ip_addresses=(IPv4Address("10.1.5.20"),),
                    dhcp_name="bmc-server",
                ),
            ],
            hardware_type="supermicro-bmc",
            snmp_data=SNMPData(snmp_version="v2c"),
        )
        mock_collect.return_value = {
            "mac_table": [], "vlan_names": [], "port_pvids": [],
            "port_names": [], "port_status": [], "lldp_neighbors": [],
            "vlan_egress_ports": [], "vlan_untagged_ports": [], "poe_status": [],
        }
        reachability = {
            "bmc-server": HostReachability(hostname="bmc-server", active_ips=("10.1.5.20",)),
        }
        result = scan_bridge([host], {}, reachability=reachability)
        assert "bmc-server" in result
        mock_collect.assert_called_once()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_without_reachability(self, mock_collect, tmp_path):
        """Without reachability data, hosts are skipped."""
        host = _make_switch()
        result = scan_bridge([host], {}, reachability=None)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_netgear_switch_plus(self, mock_collect, tmp_path):
        """netgear-switch-plus models lack SNMP and should be skipped."""
        host = Host(
            machine_name="gs110emx-rack1",
            hostname="gs110emx-rack1",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("08:bd:43:aa:bb:cc"),
                    ip_addresses=(IPv4Address("10.1.5.30"),),
                ),
            ],
            hardware_type="netgear-switch-plus",
        )
        reachability = {
            "gs110emx-rack1": HostReachability(
                hostname="gs110emx-rack1", active_ips=("10.1.5.30",)
            ),
        }
        result = scan_bridge([host], {}, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()


class TestScanBridgeMultiIP:
    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_tries_all_ips_until_success(self, mock_collect, tmp_path):
        """Should try SNMP bridge on each reachable IP until one succeeds."""
        mock_collect.side_effect = [
            None,
            {"mac_table": [], "vlan_names": []},
        ]
        host = _make_switch()
        reachability = {
            "sw-test": HostReachability(
                hostname="sw-test",
                active_ips=("10.1.5.10", "2001:db8::10"),
            ),
        }
        result = scan_bridge(
            [host], {}, reachability=reachability,
        )

        assert "sw-test" in result
        # Both IPs tried
        assert mock_collect.call_count == 2

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_stops_on_first_success(self, mock_collect, tmp_path):
        """Should stop trying IPs after first SNMP success."""
        mock_collect.return_value = {"mac_table": [], "vlan_names": []}
        host = _make_switch()
        reachability = {
            "sw-test": HostReachability(
                hostname="sw-test",
                active_ips=("10.1.5.10", "2001:db8::10"),
            ),
        }
        scan_bridge(
            [host], {}, reachability=reachability,
        )

        # Should only try first IP since it succeeded
        mock_collect.assert_called_once()


class TestBridgeToSwitchData:
    """Tests for the bridge_to_switch_data converter function."""

    def test_basic_conversion(self):
        """Convert basic BridgeData with port status and PVIDs."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.models.switch_data import SwitchDataSource
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            port_status=((1, 1, 1000), (2, 2, 0)),  # (ifIndex, oper_status, speed)
            port_names=((1, "ge-0/0/1"), (2, "ge-0/0/2")),
            port_pvids=((1, 10), (2, 20)),
        )
        result = bridge_to_switch_data(bridge, model="GS724T")

        assert result.source == SwitchDataSource.SNMP
        assert result.model == "GS724T"
        assert len(result.port_status) == 2
        assert result.port_status[0].port_id == 1
        assert result.port_status[0].is_up is True  # oper_status 1 = up
        assert result.port_status[0].speed_mbps == 1000
        assert result.port_status[0].port_name == "ge-0/0/1"
        assert result.port_status[1].port_id == 2
        assert result.port_status[1].is_up is False  # oper_status 2 = down
        assert result.port_status[1].speed_mbps == 0
        assert result.port_pvids == ((1, 10), (2, 20))

    def test_vlan_conversion(self):
        """Convert VLAN data from egress/untagged port bitmaps."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            vlan_names=((1, "default"), (10, "mgmt")),
            # VLAN 1: ports 1-8 egress (0xff = 11111111)
            # VLAN 10: ports 1,2 egress (0xc0 = 11000000)
            # Raw byte strings as stored from SNMP OctetStrings via JSON
            vlan_egress_ports=((1, "\xff"), (10, "\xc0")),
            # VLAN 1: ports 3-8 untagged (0x3f = 00111111)
            # VLAN 10: ports 1,2 untagged (0xc0 = 11000000)
            vlan_untagged_ports=((1, "\x3f"), (10, "\xc0")),
        )
        result = bridge_to_switch_data(bridge)

        assert len(result.vlans) == 2

        vlan1 = next(v for v in result.vlans if v.vlan_id == 1)
        assert vlan1.name == "default"
        assert vlan1.member_ports == frozenset({1, 2, 3, 4, 5, 6, 7, 8})
        # tagged = egress - untagged = {1,2,3,4,5,6,7,8} - {3,4,5,6,7,8} = {1,2}
        assert vlan1.tagged_ports == frozenset({1, 2})
        assert vlan1.untagged_ports == frozenset({3, 4, 5, 6, 7, 8})

        vlan10 = next(v for v in result.vlans if v.vlan_id == 10)
        assert vlan10.name == "mgmt"
        assert vlan10.member_ports == frozenset({1, 2})
        # All untagged (tagged = egress - untagged = empty)
        assert vlan10.tagged_ports == frozenset()
        assert vlan10.untagged_ports == frozenset({1, 2})

    def test_mac_table_passthrough(self):
        """MAC table is passed through unchanged."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            mac_table=(("AA:BB:CC:DD:EE:FF", 1, 5, "port5"),),
        )
        result = bridge_to_switch_data(bridge)

        assert result.mac_table is not None
        assert result.mac_table == (("AA:BB:CC:DD:EE:FF", 1, 5, "port5"),)

    def test_lldp_neighbors_passthrough(self):
        """LLDP neighbors are passed through unchanged."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            lldp_neighbors=((1, "switch-a", "port24", "AA:BB:CC:DD:EE:FF"),),
        )
        result = bridge_to_switch_data(bridge)

        assert result.lldp_neighbors is not None
        assert result.lldp_neighbors == ((1, "switch-a", "port24", "AA:BB:CC:DD:EE:FF"),)

    def test_poe_status_passthrough(self):
        """PoE status is passed through unchanged."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            poe_status=((1, 1, 3), (2, 2, 1)),
        )
        result = bridge_to_switch_data(bridge)

        assert result.poe_status is not None
        assert result.poe_status == ((1, 1, 3), (2, 2, 1))

    def test_empty_poe_status(self):
        """Empty PoE status results in empty tuple (not None).

        None means "source doesn't support this field" (e.g., NSDP).
        Empty tuple means "source supports it but no data collected".
        """
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            poe_status=(),
        )
        result = bridge_to_switch_data(bridge)

        assert result.poe_status == ()

    def test_model_defaults_to_none(self):
        """Model defaults to None if not provided."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData()
        result = bridge_to_switch_data(bridge)

        assert result.model is None

    def test_empty_bridge_data(self):
        """Empty BridgeData converts to minimal SwitchData.

        SNMP-only fields are empty tuples (not None) to distinguish
        "no data collected" from "source doesn't support this field".
        """
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.models.switch_data import SwitchDataSource
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData()
        result = bridge_to_switch_data(bridge)

        assert result.source == SwitchDataSource.SNMP
        assert result.port_status == ()
        assert result.port_pvids == ()
        assert result.vlans == ()
        assert result.mac_table == ()  # Empty tuple, not None
        assert result.lldp_neighbors == ()
        assert result.poe_status == ()

    def test_multi_byte_bitmap(self):
        """Handle multi-byte bitmaps spanning multiple octets."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        # 2-byte bitmap: 0xc0 0x80 = ports 1,2 (from byte 0) + port 9 (from byte 1)
        bridge = BridgeData(
            vlan_names=((5, "test"),),
            vlan_egress_ports=((5, "\xc0\x80"),),
            vlan_untagged_ports=((5, "\xc0\x80"),),
        )
        result = bridge_to_switch_data(bridge)

        vlan5 = result.vlans[0]
        assert vlan5.member_ports == frozenset({1, 2, 9})

    def test_empty_bitmap(self):
        """Empty bitmap string results in empty port set."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            vlan_names=((5, "test"),),
            vlan_egress_ports=((5, ""),),
            vlan_untagged_ports=((5, ""),),
        )
        result = bridge_to_switch_data(bridge)

        vlan5 = result.vlans[0]
        assert vlan5.member_ports == frozenset()


class TestEnrichHostsWithBridgeDataSetsSwitch:
    """Tests that enrich_hosts_with_bridge_data also sets switch_data."""

    def test_sets_switch_data(self):
        """enrich_hosts_with_bridge_data should also set host.switch_data."""
        from gdoc2netcfg.models.switch_data import SwitchDataSource

        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
                "vlan_names": [[1, "Default"], [5, "net"]],
                "port_pvids": [[1, 31]],
                "port_names": [[1, "1/g1"]],
                "port_status": [[1, 1, 1000]],  # port 1 up at 1Gbps
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)

        assert host.bridge_data is not None
        assert host.switch_data is not None
        assert host.switch_data.source == SwitchDataSource.SNMP
        assert len(host.switch_data.port_status) == 1
        assert host.switch_data.port_status[0].is_up is True
        assert host.switch_data.port_status[0].speed_mbps == 1000

    def test_no_switch_data_when_no_bridge_data(self):
        """switch_data should remain None when no bridge data exists."""
        host = _make_switch()
        enrich_hosts_with_bridge_data([host], {})

        assert host.bridge_data is None
        assert host.switch_data is None


class TestBridgeDataPortStatistics:
    """Tests for port_statistics field in BridgeData."""

    def test_bridge_data_with_port_statistics(self):
        """BridgeData can store port statistics tuples."""
        from gdoc2netcfg.models.host import BridgeData

        bridge = BridgeData(
            port_statistics=((1, 1000, 500, 5), (2, 2000, 1000, 0)),
        )

        assert len(bridge.port_statistics) == 2
        assert bridge.port_statistics[0] == (1, 1000, 500, 5)
        assert bridge.port_statistics[1] == (2, 2000, 1000, 0)

    def test_bridge_data_default_empty_port_statistics(self):
        """BridgeData defaults to empty port_statistics."""
        from gdoc2netcfg.models.host import BridgeData

        bridge = BridgeData()

        assert bridge.port_statistics == ()


class TestBridgeToSwitchDataWithStats:
    """Tests for bridge_to_switch_data converting port_statistics to port_stats."""

    def test_converts_port_statistics_to_port_stats(self):
        """bridge_to_switch_data converts port_statistics to PortTrafficStats."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData(
            port_statistics=((1, 1000, 500, 5), (2, 2000, 1000, 0)),
        )
        result = bridge_to_switch_data(bridge)

        assert len(result.port_stats) == 2
        assert result.port_stats[0].port_id == 1
        assert result.port_stats[0].bytes_rx == 1000
        assert result.port_stats[0].bytes_tx == 500
        assert result.port_stats[0].errors == 5
        assert result.port_stats[1].port_id == 2
        assert result.port_stats[1].bytes_rx == 2000
        assert result.port_stats[1].bytes_tx == 1000
        assert result.port_stats[1].errors == 0

    def test_empty_port_statistics_gives_empty_port_stats(self):
        """Empty port_statistics results in empty port_stats tuple."""
        from gdoc2netcfg.models.host import BridgeData
        from gdoc2netcfg.supplements.bridge import bridge_to_switch_data

        bridge = BridgeData()
        result = bridge_to_switch_data(bridge)

        assert result.port_stats == ()


class TestEnrichWithPortStatistics:
    """Tests for enrich_hosts_with_bridge_data handling port_statistics."""

    def test_enriches_with_port_statistics(self):
        """enrich_hosts_with_bridge_data includes port_statistics from cache."""
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [],
                "vlan_names": [],
                "port_pvids": [],
                "port_names": [],
                "port_status": [],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
                "port_statistics": [[1, 1000, 500, 5], [2, 2000, 1000, 0]],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)

        assert host.bridge_data is not None
        assert len(host.bridge_data.port_statistics) == 2
        assert host.bridge_data.port_statistics[0] == (1, 1000, 500, 5)

    def test_enriches_switch_data_with_port_stats(self):
        """enrich_hosts_with_bridge_data sets switch_data.port_stats from port_statistics."""
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [],
                "vlan_names": [],
                "port_pvids": [],
                "port_names": [],
                "port_status": [],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
                "port_statistics": [[1, 1000, 500, 5]],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)

        assert host.switch_data is not None
        assert len(host.switch_data.port_stats) == 1
        assert host.switch_data.port_stats[0].port_id == 1
        assert host.switch_data.port_stats[0].bytes_rx == 1000

    def test_missing_port_statistics_key(self):
        """Cache entry without port_statistics key defaults to empty."""
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [],
                "vlan_names": [],
                "port_pvids": [],
                "port_names": [],
                "port_status": [],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
                # No port_statistics key
            }
        }
        enrich_hosts_with_bridge_data([host], cache)

        assert host.bridge_data is not None
        assert host.bridge_data.port_statistics == ()
        assert host.switch_data.port_stats == ()
