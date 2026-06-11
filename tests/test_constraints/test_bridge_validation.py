"""Tests for bridge/topology validation constraints."""

from gdoc2netcfg.constraints.bridge_validation import (
    validate_lldp_topology,
    validate_mac_connectivity,
    validate_vlan_names,
)
from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import (
    BridgeData,
    Host,
    NetworkInterface,
    NetworkInventory,
)
from gdoc2netcfg.models.network import VLAN, Site


def _make_site_with_vlans():
    return Site(
        name="test",
        domain="test.example.com",
        vlans={
            1: VLAN(id=1, name="tmp", subdomain="tmp", third_octets=(1,)),
            5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
            10: VLAN(id=10, name="int", subdomain="int", third_octets=(10,)),
        },
    )


def _make_switch_with_bridge(hostname, vlan_names, **kwargs):
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name="manage",
                mac=MACAddress.parse("08:bd:43:6b:b8:d8"),
                ip_addresses=(IPv4Address("10.1.5.11"),),
            ),
        ],
        hardware_type="netgear-switch",
        bridge_data=BridgeData(
            vlan_names=tuple(vlan_names),
            **kwargs,
        ),
    )
    return host


class TestValidateVlanNames:
    def test_matching_names_no_violations(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "net"), (10, "int")])
        result = validate_vlan_names([host], site)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_mismatched_name_produces_warning(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "wrong-name")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "wrong-name" in result.warnings[0].message
        assert "net" in result.warnings[0].message
        assert result.warnings[0].severity == Severity.WARNING
        assert result.warnings[0].code == "bridge_vlan_name_mismatch"

    def test_unknown_vlan_on_switch_produces_warning(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(4089, "Auto-Video")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "4089" in result.warnings[0].message
        assert result.warnings[0].code == "bridge_unknown_vlan"

    def test_skips_hosts_without_bridge_data(self):
        site = _make_site_with_vlans()
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
        )
        result = validate_vlan_names([host], site)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_default_vlan_1_name_ignored(self):
        """VLAN 1 named 'Default' on switch but 'tmp' in spreadsheet is OK."""
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(1, "Default")])
        result = validate_vlan_names([host], site)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_vlan_1_non_default_name_still_compared(self):
        """VLAN 1 named something other than 'Default' IS compared."""
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(1, "custom-name")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "custom-name" in result.warnings[0].message
        assert "tmp" in result.warnings[0].message

    def test_multiple_switches_aggregate_warnings(self):
        """Warnings from multiple switches are all collected."""
        site = _make_site_with_vlans()
        sw1 = _make_switch_with_bridge("sw-1", [(99, "mystery")])
        sw2 = _make_switch_with_bridge("sw-2", [(5, "wrong")])
        result = validate_vlan_names([sw1, sw2], site)
        assert len(result.warnings) == 2
        record_ids = {w.record_id for w in result.warnings}
        assert record_ids == {"sw-1", "sw-2"}

    def test_warnings_are_not_errors(self):
        """VLAN name issues are warnings, not errors -- is_valid stays True."""
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "wrong"), (999, "bogus")])
        result = validate_vlan_names([host], site)
        assert result.is_valid  # warnings don't fail validation
        assert len(result.warnings) == 2


# --- Helpers for inventory-level tests ---


def _make_inventory_with_switch(switch_host, other_hosts, site):
    all_hosts = [switch_host] + other_hosts
    return NetworkInventory(
        site=site,
        hosts=all_hosts,
        ip_to_hostname={},
        ip_to_macs={},
    )


# --- Task 6: MAC connectivity discovery ---


class TestValidateMacConnectivity:
    def test_known_mac_on_switch_no_violation(self):
        """A MAC in the spreadsheet should not produce a warning."""
        site = _make_site_with_vlans()
        desktop = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.10.5"),),
                    vlan_id=10,
                ),
            ],
        )
        switch = _make_switch_with_bridge(
            "sw-test", [],
            mac_table=(("AA:BB:CC:DD:EE:FF", 10, 3, "1/g3"),),
        )
        inventory = _make_inventory_with_switch(switch, [desktop], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_unknown_mac_produces_warning(self):
        """A MAC not in any host interface should produce a warning."""
        site = _make_site_with_vlans()
        # Use a globally unique MAC (bit 1 of first octet NOT set)
        switch = _make_switch_with_bridge(
            "sw-test", [],
            mac_table=(("C0:FF:EE:00:00:01", 5, 3, "1/g3"),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        assert len(result.warnings) == 1
        assert "C0:FF:EE:00:00:01" in result.warnings[0].message
        assert result.warnings[0].code == "bridge_unknown_mac"
        assert "sw-test" in result.warnings[0].message
        assert "1/g3" in result.warnings[0].message

    def test_locally_administered_macs_skipped(self):
        """Locally administered MACs (bit 1 of first octet) are silently skipped."""
        site = _make_site_with_vlans()
        # 0xBA = 10111010, bit 1 (0x02) is set → locally administered
        switch = _make_switch_with_bridge(
            "sw-test", [],
            mac_table=(("BA:BE:12:34:56:78", 5, 50, "1/xg50"),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_switch_own_mac_is_known(self):
        """The switch's own management MAC should be in known_macs."""
        site = _make_site_with_vlans()
        # The switch has MAC 08:bd:43:6b:b8:d8 on its manage interface
        switch = _make_switch_with_bridge(
            "sw-test", [],
            mac_table=(("08:BD:43:6B:B8:D8", 5, 313, "CPU Interface:  0/5/1"),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_case_insensitive_mac_matching(self):
        """MAC comparison should be case-insensitive."""
        site = _make_site_with_vlans()
        desktop = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("Aa:Bb:Cc:Dd:Ee:Ff"),
                    ip_addresses=(IPv4Address("10.1.10.5"),),
                ),
            ],
        )
        switch = _make_switch_with_bridge(
            "sw-test", [],
            mac_table=(("aa:bb:cc:dd:ee:ff", 10, 3, "1/g3"),),
        )
        inventory = _make_inventory_with_switch(switch, [desktop], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid

    def test_multiple_unknown_macs(self):
        """Multiple unknown MACs should each produce a separate warning."""
        site = _make_site_with_vlans()
        # Use globally unique MACs (bit 1 of first octet NOT set)
        switch = _make_switch_with_bridge(
            "sw-test", [],
            mac_table=(
                ("C0:FF:EE:00:00:01", 5, 3, "1/g3"),
                ("C0:FF:EE:00:00:02", 10, 4, "1/g4"),
            ),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        assert len(result.warnings) == 2

    def test_hosts_without_bridge_data_skipped(self):
        """Hosts without bridge_data should not be iterated for MAC table."""
        site = _make_site_with_vlans()
        desktop = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.10.5"),),
                ),
            ],
        )
        inventory = _make_inventory_with_switch(desktop, [], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid

    def test_locally_administered_check_various_macs(self):
        """Verify _is_locally_administered logic on edge cases."""
        site = _make_site_with_vlans()
        # 0x02 → locally administered (first octet = 0x02)
        # 0x00 → NOT locally administered
        # 0xFE → 11111110, bit 1 set → locally administered
        # 0x01 → 00000001, bit 1 NOT set → globally unique
        switch = _make_switch_with_bridge(
            "sw-test", [],
            mac_table=(
                ("02:00:00:00:00:01", 5, 1, "1/g1"),  # LA
                ("00:00:00:00:00:01", 5, 2, "1/g2"),  # not LA, unknown
                ("FE:00:00:00:00:01", 5, 3, "1/g3"),  # LA
                ("01:00:00:00:00:01", 5, 4, "1/g4"),  # not LA (multicast), unknown
            ),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        # Only 00:00:00:00:00:01 and 01:00:00:00:00:01 should produce warnings
        assert len(result.warnings) == 2
        # Message format: "Unknown MAC XX:XX:XX seen on ..."
        warning_macs = {w.message.split()[2] for w in result.warnings}
        assert "00:00:00:00:00:01" in warning_macs
        assert "01:00:00:00:00:01" in warning_macs


# --- Task 7: LLDP topology validation ---


class TestValidateLldpTopology:
    def test_known_neighbor_no_violation(self):
        """LLDP neighbor whose chassis MAC matches a known host produces no warning."""
        site = _make_site_with_vlans()
        neighbor_switch = Host(
            machine_name="sw-cisco-shed",
            hostname="sw-cisco-shed",
            interfaces=[
                NetworkInterface(
                    name="manage",
                    mac=MACAddress.parse("c8:00:84:89:71:70"),
                    ip_addresses=(IPv4Address("10.1.5.35"),),
                ),
            ],
            hardware_type="netgear-switch",
        )
        # Use a non-matching sysName to prove matching is MAC-based
        switch = _make_switch_with_bridge(
            "sw-test", [],
            lldp_neighbors=((50, "different-name", "gi24", "C8:00:84:89:71:70", ""),),
        )
        inventory = _make_inventory_with_switch(switch, [neighbor_switch], site)
        result = validate_lldp_topology(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_unknown_lldp_neighbor_produces_warning(self):
        """An LLDP neighbor whose chassis MAC is not in inventory produces a warning."""
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge(
            "sw-test", [],
            lldp_neighbors=((50, "unknown-device", "eth0", "AA:BB:CC:DD:EE:FF", ""),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_lldp_topology(inventory)
        assert len(result.warnings) == 1
        assert "unknown-device" in result.warnings[0].message
        assert result.warnings[0].code == "bridge_unknown_lldp_neighbor"
        assert result.warnings[0].severity == Severity.WARNING

    def test_no_lldp_data_no_violations(self):
        """Host with bridge_data but no LLDP neighbors produces no warnings."""
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge("sw-test", [])
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_lldp_topology(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_mismatched_sysname_matched_by_mac(self):
        """Neighbor with non-matching sysName but matching chassis MAC → no warning.

        This covers the real-world scenario where the Netgear S3300 reports
        'manage-sw-netgear-s3300-1' as sysName but the inventory hostname
        is 'sw-netgear-s3300-1'. The chassis MAC matches, so no warning.
        """
        site = _make_site_with_vlans()
        neighbor = Host(
            machine_name="sw-netgear-s3300-1",
            hostname="sw-netgear-s3300-1",
            interfaces=[
                NetworkInterface(
                    name="manage",
                    mac=MACAddress.parse("aa:bb:cc:00:11:22"),
                    ip_addresses=(IPv4Address("10.1.5.50"),),
                ),
            ],
        )
        switch = _make_switch_with_bridge(
            "sw-test", [],
            lldp_neighbors=(
                (3, "manage-sw-netgear-s3300-1", "gi24", "AA:BB:CC:00:11:22", ""),
            ),
        )
        inventory = _make_inventory_with_switch(switch, [neighbor], site)
        result = validate_lldp_topology(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_empty_chassis_mac_skipped(self):
        """Neighbor with empty chassis MAC is silently skipped (no warning)."""
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge(
            "sw-test", [],
            lldp_neighbors=((50, "some-device", "eth0", "", ""),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_lldp_topology(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_hosts_without_bridge_data_skipped(self):
        """Hosts without bridge_data are skipped for LLDP checks."""
        site = _make_site_with_vlans()
        desktop = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.10.5"),),
                ),
            ],
        )
        inventory = _make_inventory_with_switch(desktop, [], site)
        result = validate_lldp_topology(inventory)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_multiple_lldp_neighbors_mixed(self):
        """Multiple LLDP neighbors: known MAC passes, unknown MACs produce warnings."""
        site = _make_site_with_vlans()
        known_host = Host(
            machine_name="sw-known",
            hostname="sw-known",
            interfaces=[
                NetworkInterface(
                    name="manage",
                    mac=MACAddress.parse("c8:00:84:89:71:70"),
                    ip_addresses=(IPv4Address("10.1.5.35"),),
                ),
            ],
        )
        switch = _make_switch_with_bridge(
            "sw-test", [],
            lldp_neighbors=(
                # Known by MAC (sysName doesn't match hostname)
                (50, "manage-sw-known", "gi24", "C8:00:84:89:71:70", ""),
                # Unknown MACs
                (51, "mystery-device", "eth1", "DD:EE:FF:00:11:22", ""),
                (52, "another-mystery", "eth2", "DD:EE:FF:00:33:44", ""),
            ),
        )
        inventory = _make_inventory_with_switch(switch, [known_host], site)
        result = validate_lldp_topology(inventory)
        assert len(result.warnings) == 2
        warning_names = {w.message for w in result.warnings}
        assert any("mystery-device" in msg for msg in warning_names)
        assert any("another-mystery" in msg for msg in warning_names)

    def test_warning_includes_switch_name_and_port_info(self):
        """Warning message should include the local switch name for context."""
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge(
            "sw-main", [],
            lldp_neighbors=((25, "stranger", "ge-0/0/1", "11:22:33:44:55:66", ""),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_lldp_topology(inventory)
        assert len(result.warnings) == 1
        assert "sw-main" in result.warnings[0].record_id
        assert "stranger" in result.warnings[0].message
