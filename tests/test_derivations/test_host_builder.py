"""Tests for the host builder derivation."""

from gdoc2netcfg.derivations.host_builder import (
    build_hosts,
    build_inventory,
    find_lost_credential_cells,
)
from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site
from gdoc2netcfg.sources.parser import DeviceRecord

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    vlans={
        10: VLAN(
            id=10, name="int", subdomain="int",
            third_octets=(8, 9, 10, 11, 12, 13, 14, 15),
        ),
    },
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int",
        90: "iot",
    },
)


def _make_record(
    machine="desktop",
    mac="aa:bb:cc:dd:ee:ff",
    ip="10.1.10.100",
    interface="",
    sheet_name="Network",
    extra=None,
    row_number=2,
    site="",
):
    return DeviceRecord(
        sheet_name=sheet_name,
        row_number=row_number,
        machine=machine,
        mac_address=mac,
        ip=ip,
        interface=interface,
        site=site,
        extra=extra or {},
    )


class TestBuildHosts:
    def test_single_record(self):
        records = [_make_record()]
        hosts = build_hosts(records, SITE)

        assert len(hosts) == 1
        h = hosts[0]
        assert h.hostname == "desktop"
        assert h.machine_name == "desktop"
        assert len(h.interfaces) == 1
        assert str(h.first_ipv4) == "10.1.10.100"

    def test_multi_interface_host(self):
        records = [
            _make_record(
                machine="desktop", mac="aa:bb:cc:dd:ee:01",
                ip="10.1.10.100", interface="eth0",
            ),
            _make_record(
                machine="desktop", mac="aa:bb:cc:dd:ee:02",
                ip="10.1.10.101", interface="eth1",
            ),
        ]
        hosts = build_hosts(records, SITE)

        assert len(hosts) == 1
        h = hosts[0]
        assert len(h.interfaces) == 2
        assert h.is_multi_interface()

    def test_iot_device_hostname_suffix(self):
        records = [_make_record(machine="thermostat", sheet_name="IoT", ip="10.1.90.10")]
        hosts = build_hosts(records, SITE)

        assert hosts[0].hostname == "thermostat.iot"
        assert hosts[0].sheet_type == "IoT"

    def test_ipv6_addresses_generated(self):
        records = [_make_record()]
        hosts = build_hosts(records, SITE)

        iface = hosts[0].interfaces[0]
        assert len(iface.ipv6_addresses) == 1
        assert str(iface.ipv6_addresses[0]) == "2404:e80:a137:110::100"

    def test_vlan_assigned(self):
        records = [_make_record()]
        hosts = build_hosts(records, SITE)

        assert hosts[0].interfaces[0].vlan_id == 10

    def test_dhcp_name_with_interface(self):
        records = [_make_record(interface="eth0")]
        hosts = build_hosts(records, SITE)

        assert hosts[0].interfaces[0].dhcp_name == "eth0-desktop"

    def test_dhcp_name_without_interface(self):
        records = [_make_record(interface="")]
        hosts = build_hosts(records, SITE)

        assert hosts[0].interfaces[0].dhcp_name == "desktop"

    def test_skips_records_missing_fields(self):
        records = [
            _make_record(machine=""),  # Missing machine
            _make_record(mac=""),       # Missing MAC
            _make_record(ip=""),        # Missing IP
            _make_record(),             # Valid
        ]
        hosts = build_hosts(records, SITE)
        assert len(hosts) == 1

    def test_first_ipv4_from_interface(self):
        """first_ipv4 returns the first interface's IPv4."""
        records = [_make_record(interface="", ip="10.1.10.50")]
        hosts = build_hosts(records, SITE)
        assert str(hosts[0].first_ipv4) == "10.1.10.50"


class TestBuildInventory:
    def test_ip_to_hostname_mapping(self):
        records = [_make_record(ip="10.1.10.100")]
        hosts = build_hosts(records, SITE)
        inv = build_inventory(hosts, SITE)

        assert "10.1.10.100" in inv.ip_to_hostname
        assert inv.ip_to_hostname["10.1.10.100"] == "desktop"

    def test_ip_to_macs_mapping(self):
        records = [_make_record(mac="aa:bb:cc:dd:ee:ff", ip="10.1.10.100")]
        hosts = build_hosts(records, SITE)
        inv = build_inventory(hosts, SITE)

        assert "10.1.10.100" in inv.ip_to_macs
        macs = inv.ip_to_macs["10.1.10.100"]
        assert len(macs) == 1
        assert str(macs[0][0]) == "aa:bb:cc:dd:ee:ff"
        assert macs[0][1] == "desktop"

    def test_multi_interface_ip_hostname(self):
        """Common suffix is used for IP→hostname when multiple interfaces."""
        records = [
            _make_record(
                machine="desktop", mac="aa:bb:cc:dd:ee:01",
                ip="10.1.10.100", interface="eth0",
            ),
            _make_record(
                machine="desktop", mac="aa:bb:cc:dd:ee:02",
                ip="10.1.10.101", interface="eth1",
            ),
        ]
        hosts = build_hosts(records, SITE)
        inv = build_inventory(hosts, SITE)

        # eth0.desktop → hostname is "desktop" for the common suffix
        assert "desktop" in inv.ip_to_hostname["10.1.10.100"]


class TestFindLostCredentialCells:
    """build_hosts() drops records without machine+mac+ip and takes
    Host.extra from the first surviving record only — a filled credential
    cell anywhere else is silently lost at fetch time unless this guard
    reports it."""

    def test_password_on_dropped_no_ip_row_is_reported(self):
        # The m4300 pattern: password lives on the inventory `base` row
        # (MAC, no IP); only the `manage` row (MAC + IP) builds the host.
        records = [
            _make_record(
                machine="sw1", mac="aa:bb:cc:dd:ee:01", ip="",
                interface="base", extra={"Password": "secret"}, row_number=10,
            ),
            _make_record(
                machine="sw1", mac="aa:bb:cc:dd:ee:02", ip="10.1.10.30",
                interface="manage", row_number=11,
            ),
        ]
        hosts = build_hosts(records, SITE)

        lost = find_lost_credential_cells(records, hosts, SITE)

        assert len(lost) == 1
        cell = lost[0]
        assert cell.sheet_name == "Network"
        assert cell.row_number == 10
        assert cell.machine == "sw1"
        assert cell.interface == "base"
        assert cell.field == "Password"

    def test_password_on_surviving_row_is_not_reported(self):
        records = [
            _make_record(
                machine="sw1", mac="aa:bb:cc:dd:ee:01", ip="10.1.10.30",
                extra={"Password": "secret"},
            ),
        ]
        hosts = build_hosts(records, SITE)
        assert find_lost_credential_cells(records, hosts, SITE) == []

    def test_password_on_non_first_surviving_row_is_reported(self):
        # Host.extra comes from group[0] only; a credential on a later
        # interface row of the same host is just as lost as a dropped row.
        records = [
            _make_record(
                machine="desktop", mac="aa:bb:cc:dd:ee:01",
                ip="10.1.10.100", interface="eth0", row_number=5,
            ),
            _make_record(
                machine="desktop", mac="aa:bb:cc:dd:ee:02",
                ip="10.1.10.101", interface="eth1",
                extra={"Password": "secret"}, row_number=6,
            ),
        ]
        hosts = build_hosts(records, SITE)

        lost = find_lost_credential_cells(records, hosts, SITE)

        assert [(c.row_number, c.field) for c in lost] == [(6, "Password")]

    def test_same_value_also_on_surviving_row_is_not_reported(self):
        # The identical password on both the dropped and the surviving row
        # reaches the store via the surviving one — nothing is lost.
        records = [
            _make_record(
                machine="sw1", mac="aa:bb:cc:dd:ee:01", ip="",
                interface="base", extra={"Password": "secret"}, row_number=10,
            ),
            _make_record(
                machine="sw1", mac="aa:bb:cc:dd:ee:02", ip="10.1.10.30",
                interface="manage", extra={"Password": "secret"}, row_number=11,
            ),
        ]
        hosts = build_hosts(records, SITE)
        assert find_lost_credential_cells(records, hosts, SITE) == []

    def test_other_site_record_is_not_reported(self):
        # A record filtered out for a different site legitimately stores
        # nothing here — not a lost cell.
        records = [
            _make_record(
                machine="sw-other", mac="aa:bb:cc:dd:ee:01", ip="10.2.10.30",
                site="monarto", extra={"Password": "secret"},
            ),
        ]
        hosts = build_hosts(records, SITE)
        assert hosts == []
        assert find_lost_credential_cells(records, hosts, SITE) == []

    def test_bmc_row_credential_is_not_reported(self):
        # BMC rows become separate hosts (bmc.machine) sharing machine_name
        # with the parent; their credential survives via the BMC host.
        records = [
            _make_record(
                machine="server1", mac="aa:bb:cc:dd:ee:01", ip="10.1.10.40",
            ),
            _make_record(
                machine="server1", mac="aa:bb:cc:dd:ee:02", ip="10.1.10.41",
                interface="bmc", extra={"Password": "admin:secret"},
            ),
        ]
        hosts = build_hosts(records, SITE)
        assert find_lost_credential_cells(records, hosts, SITE) == []
