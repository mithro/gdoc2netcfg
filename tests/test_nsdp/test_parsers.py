"""Tests for NSDP TLV value parsers."""

import struct

import pytest

from nsdp.parsers import (
    parse_discovery_response,
    parse_igmp_snooping,
    parse_ipv4,
    parse_mac,
    parse_port_mirroring,
    parse_port_pvid,
    parse_port_qos,
    parse_port_statistics,
    parse_port_status,
    parse_vlan_members,
)
from nsdp.protocol import NSDPPacket, Op, Tag
from nsdp.types import LinkSpeed


class TestParseIPv4:
    def test_loopback(self):
        assert parse_ipv4(b"\x7f\x00\x00\x01") == "127.0.0.1"

    def test_private(self):
        assert parse_ipv4(b"\x0a\x01\x14\x01") == "10.1.20.1"

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="4 bytes"):
            parse_ipv4(b"\x0a\x01")


class TestParseMAC:
    def test_normal(self):
        assert parse_mac(b"\x00\x09\x5b\xaa\xbb\xcc") == "00:09:5b:aa:bb:cc"

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="6 bytes"):
            parse_mac(b"\x00\x09")


class TestParsePortStatus:
    def test_gigabit(self):
        ps = parse_port_status(b"\x01\x05\x01")
        assert ps.port_id == 1
        assert ps.speed is LinkSpeed.GIGABIT

    def test_down(self):
        ps = parse_port_status(b"\x03\x00\x01")
        assert ps.port_id == 3
        assert ps.speed is LinkSpeed.DOWN

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="3 bytes"):
            parse_port_status(b"\x01\x05")


class TestParsePortStatistics:
    def test_basic(self):
        data = b"\x01"  # port_id=1
        data += struct.pack(">Q", 1000)  # bytes_received
        data += struct.pack(">Q", 500)   # bytes_sent
        data += struct.pack(">Q", 0)     # crc_errors
        data += b"\x00" * 24             # 6 unknown uint64 fields
        ps = parse_port_statistics(data)
        assert ps.port_id == 1
        assert ps.bytes_received == 1000
        assert ps.bytes_sent == 500
        assert ps.crc_errors == 0

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="49 bytes"):
            parse_port_statistics(b"\x01\x02")


class TestParsePortPVID:
    def test_basic(self):
        pp = parse_port_pvid(b"\x05\x00\x64")  # port=5, vlan=100
        assert pp.port_id == 5
        assert pp.vlan_id == 100

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="3 bytes"):
            parse_port_pvid(b"\x05")


class TestParseVLANMembers:
    def test_basic_8_port(self):
        """8-port switch: 1-byte member bitmap, 1-byte tagged bitmap."""
        data = struct.pack(">H", 100)  # vlan_id=100
        data += bytes([0b11110000])    # ports 1-4 are members
        data += bytes([0b00010000])    # port 4 is tagged
        vm = parse_vlan_members(data, port_count=8)
        assert vm.vlan_id == 100
        assert vm.member_ports == frozenset({1, 2, 3, 4})
        assert vm.tagged_ports == frozenset({4})

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="4 bytes"):
            parse_vlan_members(b"\x00", port_count=8)


class TestParseDiscoveryResponse:
    def test_full_response(self):
        """Build a synthetic NSDP read response and parse it."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.HOSTNAME, b"switch-1")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.IP_ADDRESS, b"\x0a\x01\x14\x01")
        pkt.add_tlv(Tag.NETMASK, b"\xff\xff\xff\x00")
        pkt.add_tlv(Tag.GATEWAY, b"\x0a\x01\x14\xfe")
        pkt.add_tlv(Tag.FIRMWARE_VER_1, b"V2.06.24GR")
        pkt.add_tlv(Tag.DHCP_MODE, b"\x01")
        pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
        pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")  # port 1, 1G
        pkt.add_tlv(Tag.PORT_STATUS, b"\x02\x00\x01")  # port 2, down

        device = parse_discovery_response(pkt)
        assert device.model == "GS110EMX"
        assert device.hostname == "switch-1"
        assert device.mac == "00:09:5b:aa:bb:cc"
        assert device.ip == "10.1.20.1"
        assert device.netmask == "255.255.255.0"
        assert device.gateway == "10.1.20.254"
        assert device.firmware_version == "V2.06.24GR"
        assert device.dhcp_enabled is True
        assert device.port_count == 10
        assert len(device.port_status) == 2
        assert device.port_status[0].speed is LinkSpeed.GIGABIT
        assert device.port_status[1].speed is LinkSpeed.DOWN


class TestParseSerialNumber:
    """Serial number TLV (0x7800): one 0x01 prefix byte, then ASCII serial.

    Wire format captured live from a GS110EMX (raw=b'\\x0153H6025EA0083').
    """

    def _packet_with_serial(self, raw: bytes) -> NSDPPacket:
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.SERIAL_NUMBER, raw)
        return pkt

    def test_prefix_byte_stripped(self):
        pkt = self._packet_with_serial(b"\x0153H6025EA0083")
        device = parse_discovery_response(pkt)
        assert device.serial_number == "53H6025EA0083"

    def test_unexpected_prefix_raises(self):
        pkt = self._packet_with_serial(b"\x0253H6025EA0083")
        with pytest.raises(ValueError, match="prefix byte 0x02"):
            parse_discovery_response(pkt)

    def test_empty_value_raises(self):
        pkt = self._packet_with_serial(b"")
        with pytest.raises(ValueError, match="SERIAL_NUMBER"):
            parse_discovery_response(pkt)

    def test_non_ascii_serial_raises(self):
        pkt = self._packet_with_serial(b"\x0153H\xc8\x84A0083")
        with pytest.raises(ValueError):
            parse_discovery_response(pkt)


class TestParsePortQoS:
    def test_valid(self):
        result = parse_port_qos(b"\x01\x08")
        assert result.port_id == 1
        assert result.priority == 8

    def test_port_2_priority_3(self):
        result = parse_port_qos(b"\x02\x03")
        assert result.port_id == 2
        assert result.priority == 3

    def test_invalid_length_too_short(self):
        with pytest.raises(ValueError, match="2 bytes"):
            parse_port_qos(b"\x01")

    def test_invalid_length_too_long(self):
        with pytest.raises(ValueError, match="2 bytes"):
            parse_port_qos(b"\x01\x02\x03")


class TestParsePortMirroring:
    def test_disabled(self):
        result = parse_port_mirroring(b"\x00\x00\x00\x00")
        assert result.destination_port == 0
        assert result.source_ports == frozenset()

    def test_enabled_single_source(self):
        # Dest port 10, source port 1 (bitmap 0x80 = 10000000)
        result = parse_port_mirroring(b"\x0a\x80\x00\x00")
        assert result.destination_port == 10
        assert result.source_ports == frozenset({1})

    def test_enabled_multiple_sources(self):
        # Dest port 10, source ports 1,2 (bitmap 0xC0 = 11000000)
        result = parse_port_mirroring(b"\x0a\xc0\x00\x00")
        assert result.destination_port == 10
        assert result.source_ports == frozenset({1, 2})

    def test_enabled_many_sources(self):
        # Dest port 5, source ports 1,2,3,4,5,6,7,8 (bitmap 0xFF 0x00 0x00)
        result = parse_port_mirroring(b"\x05\xff\x00\x00")
        assert result.destination_port == 5
        assert result.source_ports == frozenset({1, 2, 3, 4, 5, 6, 7, 8})

    def test_invalid_length_too_short(self):
        with pytest.raises(ValueError, match="4 bytes"):
            parse_port_mirroring(b"\x0a\xc0")

    def test_invalid_length_too_long(self):
        with pytest.raises(ValueError, match="4 bytes"):
            parse_port_mirroring(b"\x0a\xc0\x00\x00\x00")


class TestParseIGMPSnooping:
    def test_enabled(self):
        result = parse_igmp_snooping(b"\x00\x01\x00\x01")
        assert result.enabled is True

    def test_disabled(self):
        result = parse_igmp_snooping(b"\x00\x00\x00\x00")
        assert result.enabled is False

    def test_enabled_with_vlan(self):
        # enabled, vlan_id = 10 in byte 3
        result = parse_igmp_snooping(b"\x00\x01\x00\x0a")
        assert result.enabled is True
        assert result.vlan_id == 10

    def test_enabled_no_vlan(self):
        # enabled, vlan_id = 0 means None
        result = parse_igmp_snooping(b"\x00\x01\x00\x00")
        assert result.enabled is True
        assert result.vlan_id is None

    def test_invalid_length_too_short(self):
        with pytest.raises(ValueError, match="2 bytes"):
            parse_igmp_snooping(b"\x00")


class TestParseDiscoveryResponseNewTags:
    """Tests for parse_discovery_response with new QoS, mirroring, and IGMP tags."""

    def test_qos_engine(self):
        """Test parsing QOS_ENGINE tag."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.QOS_ENGINE, b"\x02")  # 802.1p mode

        device = parse_discovery_response(pkt)
        assert device.qos_engine == 2

    def test_port_qos_priority(self):
        """Test parsing PORT_QOS_PRIORITY tags (repeated)."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.PORT_QOS_PRIORITY, b"\x01\x08")  # port 1, priority 8
        pkt.add_tlv(Tag.PORT_QOS_PRIORITY, b"\x02\x04")  # port 2, priority 4

        device = parse_discovery_response(pkt)
        assert len(device.port_qos) == 2
        assert device.port_qos[0].port_id == 1
        assert device.port_qos[0].priority == 8
        assert device.port_qos[1].port_id == 2
        assert device.port_qos[1].priority == 4

    def test_port_mirroring(self):
        """Test parsing PORT_MIRRORING tag."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        # Dest port 10, source ports 1,2 (bitmap 0xC0)
        pkt.add_tlv(Tag.PORT_MIRRORING, b"\x0a\xc0\x00\x00")

        device = parse_discovery_response(pkt)
        assert device.port_mirroring is not None
        assert device.port_mirroring.destination_port == 10
        assert device.port_mirroring.source_ports == frozenset({1, 2})

    def test_igmp_snooping(self):
        """Test parsing IGMP_SNOOPING tag."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.IGMP_SNOOPING, b"\x00\x01\x00\x0a")  # enabled, vlan=10

        device = parse_discovery_response(pkt)
        assert device.igmp_snooping is not None
        assert device.igmp_snooping.enabled is True
        assert device.igmp_snooping.vlan_id == 10

    def test_broadcast_filtering(self):
        """Test parsing BROADCAST_FILTERING tag."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.BROADCAST_FILTERING, b"\x01")  # enabled

        device = parse_discovery_response(pkt)
        assert device.broadcast_filtering is True

    def test_loop_detection(self):
        """Test parsing LOOP_DETECTION tag."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.LOOP_DETECTION, b"\x00")  # disabled

        device = parse_discovery_response(pkt)
        assert device.loop_detection is False

    def test_all_new_tags_together(self):
        """Test parsing all new tags in a single response."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")  # 10 ports
        pkt.add_tlv(Tag.QOS_ENGINE, b"\x01")  # port-based
        pkt.add_tlv(Tag.PORT_QOS_PRIORITY, b"\x01\x08")
        pkt.add_tlv(Tag.PORT_MIRRORING, b"\x05\x80\x00\x00")  # dest=5, source=1
        pkt.add_tlv(Tag.IGMP_SNOOPING, b"\x00\x01\x00\x00")  # enabled, no vlan
        pkt.add_tlv(Tag.BROADCAST_FILTERING, b"\x01")
        pkt.add_tlv(Tag.LOOP_DETECTION, b"\x01")

        device = parse_discovery_response(pkt)
        assert device.qos_engine == 1
        assert len(device.port_qos) == 1
        assert device.port_mirroring.destination_port == 5
        assert device.igmp_snooping.enabled is True
        assert device.broadcast_filtering is True
        assert device.loop_detection is True
