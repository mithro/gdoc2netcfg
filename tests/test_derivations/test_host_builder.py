"""Tests for the host builder derivation."""

from gdoc2netcfg.derivations.host_builder import build_hosts, build_inventory
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
):
    return DeviceRecord(
        sheet_name=sheet_name,
        row_number=2,
        machine=machine,
        mac_address=mac,
        ip=ip,
        interface=interface,
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
        assert str(h.default_ipv4) == "10.1.10.100"
        assert h.subdomain == "int"

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

    def test_default_ip_no_name_interface(self):
        """Interface with no name should be the default IP."""
        records = [_make_record(interface="", ip="10.1.10.50")]
        hosts = build_hosts(records, SITE)
        assert str(hosts[0].default_ipv4) == "10.1.10.50"


class TestIPv6CapabilityDetection:
    def test_build_hosts_espressif_device_not_ipv6_capable(self):
        """Hosts with Espressif MAC OUIs should have ipv6_capable=False."""
        from gdoc2netcfg.derivations.ipv6_capability import detect_ipv6_capability

        records = [_make_record(
            machine="au-plug-1",
            mac="7C:2C:67:D9:BA:24",  # Espressif OUI
            ip="10.1.90.51",
            sheet_name="IoT",
        )]
        hosts = build_hosts(records, SITE)
        assert len(hosts) == 1
        host = hosts[0]

        # Before detection, defaults to True
        assert host.ipv6_capable is True

        # After detection, Espressif OUI → False
        host.ipv6_capable = detect_ipv6_capability(host)
        assert host.ipv6_capable is False

    def test_build_hosts_regular_device_ipv6_capable(self):
        """Hosts with non-Espressif MACs should remain ipv6_capable=True."""
        from gdoc2netcfg.derivations.ipv6_capability import detect_ipv6_capability

        records = [_make_record(
            machine="desktop",
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.1.10.100",
        )]
        hosts = build_hosts(records, SITE)
        host = hosts[0]
        host.ipv6_capable = detect_ipv6_capability(host)
        assert host.ipv6_capable is True


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
