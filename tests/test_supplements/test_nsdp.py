"""Tests for the NSDP supplement."""

from gdoc2netcfg.cli.main import main
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NSDPData
from gdoc2netcfg.models.switch_data import SwitchDataSource
from gdoc2netcfg.supplements.nsdp import (
    enrich_hosts_with_nsdp,
    nsdp_to_switch_data,
)


class TestNSDPCLIRegistration:
    """Test that the 'nsdp' CLI subcommand is registered."""

    def test_nsdp_subcommand_in_help(self, capsys):
        """The nsdp subcommand should be registered in argparse."""
        try:
            main(["nsdp", "--help"])
        except SystemExit as e:
            # Should exit 0 with help output, not exit 2 with error
            assert e.code == 0, f"Expected exit 0 for --help, got exit {e.code}"
        captured = capsys.readouterr()
        # The help output should describe what nsdp does
        assert "nsdp" in captured.out.lower() or "netgear" in captured.out.lower()


def _make_host(hostname="gs110emx", ip="10.1.20.1", hardware_type="netgear-switch-plus"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("00:09:5b:aa:bb:cc"),
                ip_addresses=(IPv4Address(ip),),
                dhcp_name=hostname,
            ),
        ],
        hardware_type=hardware_type,
    )


class TestEnrichHostsWithNSDP:
    def test_enrich_from_cache(self):
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "firmware_version": "V2.06.24GR",
                "port_count": 10,
                "port_status": [(1, 5), (2, 0)],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.nsdp_data.model == "GS110EMX"
        assert host.nsdp_data.firmware_version == "V2.06.24GR"
        assert host.nsdp_data.port_count == 10
        assert len(host.nsdp_data.port_status) == 2

    def test_no_cache_entry(self):
        host = _make_host()
        enrich_hosts_with_nsdp([host], {})
        assert host.nsdp_data is None

    def test_skip_non_netgear(self):
        host = _make_host(hardware_type=None)
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        # Still enriches — cache is hostname-keyed, not hardware-type filtered
        assert host.nsdp_data is not None

    def test_enrich_with_vlan_engine(self):
        """Test that vlan_engine is loaded from cache."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "vlan_engine": 4,
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.nsdp_data.vlan_engine == 4

    def test_enrich_with_vlan_members(self):
        """Test that vlan_members is loaded from cache."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "vlan_members": [
                    [1, [1, 2, 3], [3]],
                    [10, [1, 2], [1, 2]],
                ],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert len(host.nsdp_data.vlan_members) == 2
        # Check first VLAN
        assert host.nsdp_data.vlan_members[0][0] == 1  # vlan_id
        assert host.nsdp_data.vlan_members[0][1] == frozenset({1, 2, 3})  # members
        assert host.nsdp_data.vlan_members[0][2] == frozenset({3})  # tagged
        # Check second VLAN
        assert host.nsdp_data.vlan_members[1][0] == 10  # vlan_id
        assert host.nsdp_data.vlan_members[1][1] == frozenset({1, 2})  # members
        assert host.nsdp_data.vlan_members[1][2] == frozenset({1, 2})  # tagged

    def test_enrich_with_port_statistics(self):
        """Test that port_statistics is loaded from cache."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "port_statistics": [
                    [1, 1000, 500, 0],
                    [2, 2000, 1000, 5],
                ],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert len(host.nsdp_data.port_statistics) == 2
        assert host.nsdp_data.port_statistics[0] == (1, 1000, 500, 0)
        assert host.nsdp_data.port_statistics[1] == (2, 2000, 1000, 5)

    def test_enrich_with_all_new_fields(self):
        """Test enrichment with all new VLAN/stats fields together."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "vlan_engine": 4,
                "vlan_members": [[1, [1, 2], [2]]],
                "port_statistics": [[1, 100, 50, 0]],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.nsdp_data.vlan_engine == 4
        assert len(host.nsdp_data.vlan_members) == 1
        assert len(host.nsdp_data.port_statistics) == 1

    def test_enrich_sets_switch_data(self):
        """Test that enrichment also sets switch_data from nsdp_data."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "firmware_version": "V2.06.24GR",
                "port_count": 10,
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.switch_data is not None
        assert host.switch_data.source == SwitchDataSource.NSDP
        assert host.switch_data.model == "GS110EMX"


class TestNSDPToSwitchData:
    """Tests for the nsdp_to_switch_data converter function."""

    def test_basic_conversion(self):
        """Test conversion of basic NSDP fields to SwitchData."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            firmware_version="1.0.1.4",
            port_count=10,
            serial_number="ABC123",
        )
        result = nsdp_to_switch_data(nsdp)

        assert result.source == SwitchDataSource.NSDP
        assert result.model == "GS110EMX"
        assert result.firmware_version == "1.0.1.4"
        assert result.port_count == 10
        assert result.serial_number == "ABC123"

    def test_port_status_conversion(self):
        """Test conversion of port_status tuples to PortLinkStatus objects."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            port_status=(
                (1, 5),   # port 1, gigabit (LinkSpeed.GIGABIT = 0x05)
                (2, 0),   # port 2, down (LinkSpeed.DOWN = 0x00)
                (3, 4),   # port 3, 100M full (LinkSpeed.FULL_100M = 0x04)
                (4, 0xFF),  # port 4, 10G (LinkSpeed.TEN_GIGABIT = 0xFF)
            ),
        )
        result = nsdp_to_switch_data(nsdp)

        assert len(result.port_status) == 4
        # Port 1: gigabit, up
        assert result.port_status[0].port_id == 1
        assert result.port_status[0].is_up is True
        assert result.port_status[0].speed_mbps == 1000
        assert result.port_status[0].port_name is None  # NSDP has no port names
        # Port 2: down
        assert result.port_status[1].port_id == 2
        assert result.port_status[1].is_up is False
        assert result.port_status[1].speed_mbps == 0
        # Port 3: 100M
        assert result.port_status[2].port_id == 3
        assert result.port_status[2].is_up is True
        assert result.port_status[2].speed_mbps == 100
        # Port 4: 10G
        assert result.port_status[3].port_id == 4
        assert result.port_status[3].is_up is True
        assert result.port_status[3].speed_mbps == 10000

    def test_port_pvids_passthrough(self):
        """Test that port_pvids tuple is passed through unchanged."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            port_pvids=((1, 10), (2, 20), (3, 1)),
        )
        result = nsdp_to_switch_data(nsdp)

        assert result.port_pvids == ((1, 10), (2, 20), (3, 1))

    def test_port_statistics_conversion(self):
        """Test conversion of port_statistics to PortTrafficStats objects."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            port_statistics=(
                (1, 1000, 500, 0),    # port 1: 1000 rx, 500 tx, 0 errors
                (2, 2000, 1000, 5),   # port 2: 2000 rx, 1000 tx, 5 CRC errors
            ),
        )
        result = nsdp_to_switch_data(nsdp)

        assert len(result.port_stats) == 2
        assert result.port_stats[0].port_id == 1
        assert result.port_stats[0].bytes_rx == 1000
        assert result.port_stats[0].bytes_tx == 500
        assert result.port_stats[0].errors == 0
        assert result.port_stats[1].port_id == 2
        assert result.port_stats[1].bytes_rx == 2000
        assert result.port_stats[1].bytes_tx == 1000
        assert result.port_stats[1].errors == 5

    def test_vlan_members_conversion(self):
        """Test conversion of vlan_members to VLANInfo objects."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            vlan_members=(
                (1, frozenset({1, 2, 3}), frozenset({3})),  # VLAN 1: all 3, port 3 tagged
                (10, frozenset({1, 2}), frozenset({1, 2})),  # VLAN 10: 1,2 both tagged
                (20, frozenset({4, 5}), frozenset()),  # VLAN 20: 4,5 untagged
            ),
        )
        result = nsdp_to_switch_data(nsdp)

        assert len(result.vlans) == 3
        # VLAN 1
        assert result.vlans[0].vlan_id == 1
        assert result.vlans[0].name is None  # NSDP has no VLAN names
        assert result.vlans[0].member_ports == frozenset({1, 2, 3})
        assert result.vlans[0].tagged_ports == frozenset({3})
        assert result.vlans[0].untagged_ports == frozenset({1, 2})
        # VLAN 10
        assert result.vlans[1].vlan_id == 10
        assert result.vlans[1].member_ports == frozenset({1, 2})
        assert result.vlans[1].tagged_ports == frozenset({1, 2})
        assert result.vlans[1].untagged_ports == frozenset()
        # VLAN 20
        assert result.vlans[2].vlan_id == 20
        assert result.vlans[2].member_ports == frozenset({4, 5})
        assert result.vlans[2].tagged_ports == frozenset()
        assert result.vlans[2].untagged_ports == frozenset({4, 5})

    def test_vlan_engine_and_qos_engine(self):
        """Test that vlan_engine and qos_engine are separate fields."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            vlan_engine=4,  # Advanced 802.1Q
            qos_engine=2,  # 802.1p priority
        )
        result = nsdp_to_switch_data(nsdp)

        # vlan_engine (VLAN mode) and qos_engine (QoS mode) are separate
        assert result.vlan_engine == 4
        assert result.qos_engine == 2

    def test_empty_collections(self):
        """Test that empty collections are handled correctly."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            # All collections empty by default
        )
        result = nsdp_to_switch_data(nsdp)

        assert result.port_status == ()
        assert result.port_pvids == ()
        assert result.port_stats == ()
        assert result.vlans == ()

    def test_snmp_fields_are_none(self):
        """Test that SNMP-only fields remain None for NSDP source."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
        )
        result = nsdp_to_switch_data(nsdp)

        # SNMP-only fields should be None
        assert result.mac_table is None
        assert result.lldp_neighbors is None
        assert result.poe_status is None

    def test_full_conversion(self):
        """Integration test with all fields populated."""
        nsdp = NSDPData(
            model="GS110EMX",
            mac="aa:bb:cc:dd:ee:ff",
            firmware_version="V2.06.24GR",
            port_count=10,
            serial_number="XYZ789",
            port_status=((1, 5), (2, 0)),
            port_pvids=((1, 10), (2, 20)),
            vlan_engine=4,
            vlan_members=((1, frozenset({1, 2}), frozenset({2})),),
            port_statistics=((1, 100, 50, 0),),
        )
        result = nsdp_to_switch_data(nsdp)

        assert result.source == SwitchDataSource.NSDP
        assert result.model == "GS110EMX"
        assert result.firmware_version == "V2.06.24GR"
        assert result.port_count == 10
        assert result.serial_number == "XYZ789"
        assert len(result.port_status) == 2
        assert result.port_pvids == ((1, 10), (2, 20))
        assert result.vlan_engine == 4  # vlan_engine, not qos_engine
        assert len(result.vlans) == 1
        assert len(result.port_stats) == 1
