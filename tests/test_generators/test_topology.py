"""Tests for the Graphviz network topology generator."""

from gdoc2netcfg.generators.topology import generate_topology
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import (
    BridgeData,
    Host,
    NetworkInterface,
    NetworkInventory,
)
from gdoc2netcfg.models.network import Site

SITE = Site(name="welland", domain="welland.mithis.com")


def _iface(mac="AA:BB:CC:DD:EE:01", ip="10.1.5.1", name=None):
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(mac),
        ip_addresses=(IPv4Address(ip),),
    )


def _switch(hostname, ip, mac="AA:BB:CC:DD:EE:01", bridge_data=None):
    """Create a switch host with bridge_data."""
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[_iface(mac=mac, ip=ip)],
        bridge_data=bridge_data or BridgeData(),
    )


def _host(hostname, ip, mac="AA:BB:CC:DD:EE:02"):
    """Create a regular host (no bridge_data)."""
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[_iface(mac=mac, ip=ip)],
    )


class TestTopologyEmpty:
    def test_empty_inventory_returns_valid_dot(self):
        inv = NetworkInventory(site=SITE, hosts=[])
        output = generate_topology(inv)
        assert "digraph network_topology" in output
        assert "{" in output
        assert "}" in output

    def test_no_switches_returns_minimal_dot(self):
        """Non-switch hosts (no bridge_data) produce no edges."""
        hosts = [_host("desktop", "10.1.10.1")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert "digraph network_topology" in output
        # No edges since there are no switches
        assert "->" not in output


class TestTopologySwitchNodes:
    def test_switch_with_bridge_data_appears_as_node(self):
        hosts = [_switch("sw-core", "10.1.5.1")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert '"sw-core"' in output
        assert "shape=box" in output

    def test_multiple_switches_appear(self):
        hosts = [
            _switch("sw-core", "10.1.5.1", mac="AA:BB:CC:DD:E1:01"),
            _switch("sw-floor1", "10.1.5.2", mac="AA:BB:CC:DD:E2:01"),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert '"sw-core"' in output
        assert '"sw-floor1"' in output


class TestTopologyLLDPEdges:
    def test_lldp_edge_between_switches(self):
        """Two switches connected via LLDP produce a bold bidirectional edge."""
        sw1_bridge = BridgeData(
            port_names=((1, "0/1"),),
            lldp_neighbors=((1, "sw-floor1", "0/2", "AA:BB:CC:DD:E2:01", ""),),
        )
        sw2_bridge = BridgeData(
            port_names=((1, "0/2"),),
            lldp_neighbors=((1, "sw-core", "0/1", "AA:BB:CC:DD:E1:01", ""),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", mac="AA:BB:CC:DD:E1:01",
                    bridge_data=sw1_bridge),
            _switch("sw-floor1", "10.1.5.2", mac="AA:BB:CC:DD:E2:01",
                    bridge_data=sw2_bridge),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        # Should have exactly one edge (deduplicated from both directions)
        assert "dir=both" in output
        assert "style=bold" in output

    def test_lldp_bidirectional_dedup(self):
        """Both sides of an LLDP link produce only one edge."""
        sw1_bridge = BridgeData(
            port_names=((1, "0/1"),),
            lldp_neighbors=((1, "sw-floor1", "0/2", "AA:BB:CC:DD:E2:01", ""),),
        )
        sw2_bridge = BridgeData(
            port_names=((1, "0/2"),),
            lldp_neighbors=((1, "sw-core", "0/1", "AA:BB:CC:DD:E1:01", ""),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", mac="AA:BB:CC:DD:E1:01",
                    bridge_data=sw1_bridge),
            _switch("sw-floor1", "10.1.5.2", mac="AA:BB:CC:DD:E2:01",
                    bridge_data=sw2_bridge),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        # Count edges with dir=both — should be exactly 1
        assert output.count("dir=both") == 1

    def test_lldp_edge_labels_include_port_names(self):
        sw_bridge = BridgeData(
            port_names=((5, "0/5"),),
            lldp_neighbors=((5, "sw-floor1", "0/10", "AA:BB:CC:DD:E2:01", ""),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", mac="AA:BB:CC:DD:E1:01",
                    bridge_data=sw_bridge),
            _switch("sw-floor1", "10.1.5.2", mac="AA:BB:CC:DD:E2:01"),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert "0/5" in output


class TestTopologyMACEdges:
    def test_mac_learned_edge_to_known_host(self):
        """A host's MAC in a switch's MAC table produces a dashed edge."""
        desktop_mac = "11:22:33:44:55:66"
        sw_bridge = BridgeData(
            port_names=((1, "0/1"),),
            mac_table=((desktop_mac, 10, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", mac="AA:BB:CC:DD:E1:01",
                    bridge_data=sw_bridge),
            _host("desktop", "10.1.10.1", mac=desktop_mac),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert "style=dashed" in output
        assert '"desktop"' in output

    def test_mac_learned_edge_skips_switch_self_mac(self):
        """A switch's own MAC in its MAC table should not produce an edge."""
        switch_mac = "AA:BB:CC:DD:E1:01"
        sw_bridge = BridgeData(
            port_names=((1, "0/1"),),
            mac_table=((switch_mac, 10, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", mac=switch_mac,
                    bridge_data=sw_bridge),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert "->" not in output

    def test_mac_learned_edge_skips_laa_macs(self):
        """Locally administered MACs (bit 1 of first octet set) are skipped."""
        # BA:BE:xx:xx:xx:xx is locally administered (0xBA = 10111010, bit 1 set)
        laa_mac = "BA:BE:00:11:22:33"
        sw_bridge = BridgeData(
            port_names=((1, "0/1"),),
            mac_table=((laa_mac, 10, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", bridge_data=sw_bridge),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv, show_unknown_macs=True)
        # LAA MACs should be skipped entirely, even with show_unknown_macs
        assert "BA:BE" not in output


class TestTopologyUnknownMACs:
    def test_unknown_macs_hidden_by_default(self):
        """MACs not in inventory are not shown by default."""
        # Use non-LAA MAC so it isn't filtered before the unknown check
        unknown_mac = "00:EE:DD:CC:BB:AA"
        sw_bridge = BridgeData(
            port_names=((1, "0/1"),),
            mac_table=((unknown_mac, 10, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", bridge_data=sw_bridge),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert unknown_mac not in output

    def test_unknown_macs_shown_when_enabled(self):
        """When show_unknown_macs=True, unknown MACs appear as point nodes."""
        # Use non-LAA MAC (first octet bit 1 clear) so it isn't filtered
        unknown_mac = "00:EE:DD:CC:BB:AA"
        sw_bridge = BridgeData(
            port_names=((1, "0/1"),),
            mac_table=((unknown_mac, 10, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", bridge_data=sw_bridge),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv, show_unknown_macs=True)
        assert unknown_mac in output
        assert "shape=point" in output


class TestTopologyLLDPMACOverlap:
    def test_mac_edge_skipped_when_lldp_covers_link(self):
        """If LLDP already connects two nodes, MAC edge is redundant."""
        # Use non-LAA MACs (first octet bit 1 clear) so the test
        # actually exercises the LLDP-overlap filter, not the LAA filter.
        floor1_mac = "00:BB:CC:DD:E2:01"
        sw1_bridge = BridgeData(
            port_names=((1, "0/1"),),
            lldp_neighbors=((1, "sw-floor1", "0/2", floor1_mac, ""),),
            mac_table=((floor1_mac, 1, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", mac="00:BB:CC:DD:E1:01",
                    bridge_data=sw1_bridge),
            _switch("sw-floor1", "10.1.5.2", mac=floor1_mac),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        # Should have LLDP edge (bold, dir=both)
        assert "dir=both" in output
        # Should NOT have a dashed MAC edge (check edges specifically)
        edge_lines = [line for line in output.splitlines() if "->" in line]
        for line in edge_lines:
            assert "style=dashed" not in line


class TestTopologyDOTFormat:
    def test_rankdir_lr(self):
        inv = NetworkInventory(site=SITE, hosts=[])
        output = generate_topology(inv)
        assert "rankdir=LR" in output

    def test_switch_subgraph(self):
        hosts = [_switch("sw-core", "10.1.5.1")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert "cluster_switches" in output

    def test_host_subgraph(self):
        desktop_mac = "11:22:33:44:55:66"
        sw_bridge = BridgeData(
            port_names=((1, "0/1"),),
            mac_table=((desktop_mac, 10, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", bridge_data=sw_bridge),
            _host("desktop", "10.1.10.1", mac=desktop_mac),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        assert "cluster_hosts" in output

    def test_mac_edge_includes_vlan_label(self):
        desktop_mac = "11:22:33:44:55:66"
        sw_bridge = BridgeData(
            port_names=((1, "0/1"),),
            mac_table=((desktop_mac, 42, 1, "0/1"),),
        )
        hosts = [
            _switch("sw-core", "10.1.5.1", bridge_data=sw_bridge),
            _host("desktop", "10.1.10.1", mac=desktop_mac),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_topology(inv)
        # Edge label should contain port name and VLAN
        assert "0/1" in output
        assert "42" in output
