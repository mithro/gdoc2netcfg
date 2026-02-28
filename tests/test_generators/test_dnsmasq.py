"""Tests for the dnsmasq internal generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.dnsmasq import generate_dnsmasq_internal
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int",
    },
)


def _make_inventory(hosts=None, ip_to_hostname=None, ip_to_macs=None):
    return NetworkInventory(
        site=SITE,
        hosts=hosts or [],
        ip_to_hostname=ip_to_hostname or {},
        ip_to_macs=ip_to_macs or {},
    )


def _host_with_iface(hostname, mac, ip, interface_name=None, dhcp_name="test"):
    ipv4 = IPv4Address(ip)
    ipv6s = []
    if ip.startswith("10."):
        parts = ip.split(".")
        aa = parts[1]
        bb = parts[2].zfill(2)
        ccc = parts[3]
        ipv6s = [IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")]

    iface = NetworkInterface(
        name=interface_name,
        mac=MACAddress.parse(mac),
        ip_addresses=(ipv4, *ipv6s),
        dhcp_name=dhcp_name,
    )
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[iface],
        default_ipv4=ipv4,
        subdomain="int" if ip.startswith("10.1.10.") else None,
    )
    # Run DNS name derivation to populate dns_names
    derive_all_dns_names(host, SITE)
    return host


def _inventory_with_host(hostname, mac, ip, interface_name=None, dhcp_name="test"):
    """Build a complete inventory with a single host and consistent indexes."""
    host = _host_with_iface(hostname, mac, ip, interface_name, dhcp_name)
    return _make_inventory(
        hosts=[host],
        ip_to_hostname={ip: hostname},
        ip_to_macs={ip: [(MACAddress.parse(mac), dhcp_name)]},
    )


class TestDnsmasqGenerator:
    def test_returns_dict(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        result = generate_dnsmasq_internal(inv)
        assert isinstance(result, dict)

    def test_returns_dict_with_hostname_keys(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        result = generate_dnsmasq_internal(inv)
        assert "desktop.conf" in result

    def test_generates_dhcp_host_section(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "dhcp-host=aa:bb:cc:dd:ee:ff,10.1.10.1," in output

    def test_dhcp_host_includes_ipv6(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "[2404:e80:a137:110::1]" in output

    def test_generates_ptr_records(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "ptr-record=/desktop.welland.mithis.com/10.1.10.1" in output

    def test_generates_ipv6_ptr_records(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "ip6.arpa" in output

    def test_generates_host_records(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        assert "host-record=desktop.welland.mithis.com,10.1.10.1," in output
        assert "host-record=desktop,10.1.10.1," in output

    def test_generates_subdomain_variant(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        assert "host-record=desktop.int.welland.mithis.com," in output

    def test_generates_ipv4_only_record(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        assert "host-record=ipv4.desktop.welland.mithis.com,10.1.10.1" in output

    def test_generates_ipv6_only_record(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        assert "host-record=ipv6.desktop.welland.mithis.com," in output

    def test_generates_caa_record(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        assert "dns-rr=desktop.welland.mithis.com,257," in output

    def test_generates_sshfp_records(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        host.sshfp_records = ["server IN SSHFP 1 2 abc123"]
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_internal(inv)
        output = result["server.conf"]

        assert "dns-rr=server.welland.mithis.com,44,1:2:abc123" in output

    def test_sshfp_skipped_when_no_records(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        lines = [
            line for line in output.split("\n")
            if line.startswith("dns-rr=") and ",44," in line
        ]
        assert len(lines) == 0

    def test_multiple_hosts_produce_separate_files(self):
        host1 = _host_with_iface("alpha", "aa:bb:cc:dd:ee:01", "10.1.10.1", dhcp_name="alpha")
        host2 = _host_with_iface("bravo", "aa:bb:cc:dd:ee:02", "10.1.10.2", dhcp_name="bravo")
        inv = _make_inventory(
            hosts=[host1, host2],
            ip_to_hostname={"10.1.10.1": "alpha", "10.1.10.2": "bravo"},
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:01"), "alpha")],
                "10.1.10.2": [(MACAddress.parse("aa:bb:cc:dd:ee:02"), "bravo")],
            },
        )
        result = generate_dnsmasq_internal(inv)
        assert "alpha.conf" in result
        assert "bravo.conf" in result
        # Each file only contains its own host's records
        assert "10.1.10.1" in result["alpha.conf"]
        assert "10.1.10.2" not in result["alpha.conf"]
        assert "10.1.10.2" in result["bravo.conf"]
        assert "10.1.10.1" not in result["bravo.conf"]

    def test_all_record_types_in_single_file(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="server")
        host.sshfp_records = ["server IN SSHFP 1 2 abc123"]
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.1": "server"},
            ip_to_macs={"10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "server")]},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["server.conf"]

        # DHCP
        assert "dhcp-host=" in output
        # PTR
        assert "ptr-record=" in output
        # host-record
        assert "host-record=" in output
        # CAA
        assert "dns-rr=server.welland.mithis.com,257," in output
        # SSHFP
        assert "dns-rr=server.welland.mithis.com,44," in output


class TestAltNames:
    def test_in_zone_alt_name_gets_host_record(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        host.alt_names = ["alias.welland.mithis.com"]
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.1": "desktop"},
            ip_to_macs={"10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")]},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "host-record=alias.welland.mithis.com," in output

    def test_out_of_zone_alt_name_excluded(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        host.alt_names = ["alias.example.com"]
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.1": "desktop"},
            ip_to_macs={"10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")]},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "alias.example.com" not in output

    def test_wildcard_alt_name_excluded_from_host_record(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        host.alt_names = ["*.welland.mithis.com"]
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.1": "desktop"},
            ip_to_macs={"10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")]},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "*.welland.mithis.com" not in output

    def test_mixed_alt_names_filters_correctly(self):
        """Only non-wildcard, in-zone alt names produce host-records."""
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        host.alt_names = [
            "alias.welland.mithis.com",   # in-zone, non-wildcard → included
            "*.welland.mithis.com",        # in-zone, wildcard → excluded
            "alias.example.com",           # out-of-zone → excluded
        ]
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.1": "desktop"},
            ip_to_macs={"10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")]},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "host-record=alias.welland.mithis.com," in output
        assert "*.welland.mithis.com" not in output
        assert "alias.example.com" not in output


class TestDhcpIpv6Capability:
    """DHCP bindings skip IPv6 for IPv6-incapable hosts."""

    def test_dhcp_excludes_ipv6_when_incapable(self):
        """IPv6-incapable hosts should have DHCP without IPv6 addresses."""
        host = _host_with_iface("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.10.51",
                                dhcp_name="au-plug-1")
        host.ipv6_capable = False
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.51": "au-plug-1"},
            ip_to_macs={"10.1.10.51": [(MACAddress.parse("7c:2c:67:d9:ba:24"), "au-plug-1")]},
        )
        result = generate_dnsmasq_internal(inv)
        conf = result["au-plug-1.conf"]
        # DHCP should NOT have [ipv6] brackets
        assert "dhcp-host=7c:2c:67:d9:ba:24,10.1.10.51,au-plug-1" in conf
        assert "[2404:" not in conf.split("host-record")[0]  # Before host-record section

    def test_dhcp_includes_ipv6_when_capable(self):
        """IPv6-capable hosts should have DHCP with IPv6 addresses as normal."""
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.100",
                                dhcp_name="desktop")
        # ipv6_capable defaults to True
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.100": "desktop"},
            ip_to_macs={"10.1.10.100": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")]},
        )
        result = generate_dnsmasq_internal(inv)
        conf = result["desktop.conf"]
        assert "[2404:e80:a137:110::100]" in conf

    def test_host_record_keeps_ipv6_when_incapable(self):
        """host-record entries must keep AAAA records even for incapable hosts.

        IPv6 clients need the AAAA record to resolve the address that
        TAYGA will intercept for NAT64 translation.
        """
        host = _host_with_iface("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.10.51",
                                dhcp_name="au-plug-1")
        host.ipv6_capable = False
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.51": "au-plug-1"},
            ip_to_macs={"10.1.10.51": [(MACAddress.parse("7c:2c:67:d9:ba:24"), "au-plug-1")]},
        )
        result = generate_dnsmasq_internal(inv)
        conf = result["au-plug-1.conf"]
        # host-record MUST still contain IPv6 (for TAYGA NAT64)
        assert "host-record=au-plug-1.welland.mithis.com,10.1.10.51,2404:e80:a137:110::51" in conf


def _shared_ip_host(hostname, ip, macs, dhcp_name="test"):
    """Create a host with multiple NICs sharing the same IP."""
    ipv4 = IPv4Address(ip)
    ipv6s = []
    if ip.startswith("10."):
        parts = ip.split(".")
        aa = parts[1]
        bb = parts[2].zfill(2)
        ccc = parts[3]
        ipv6s = [IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")]

    ifaces = [
        NetworkInterface(
            name=f"eth{i}",
            mac=MACAddress.parse(mac),
            ip_addresses=(ipv4, *ipv6s) if i == 0 else (ipv4,),
            dhcp_name=dhcp_name,
        )
        for i, mac in enumerate(macs)
    ]
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=ifaces,
        default_ipv4=ipv4,
        subdomain="int" if ip.startswith("10.1.10.") else None,
    )
    derive_all_dns_names(host, SITE)
    return host


class TestSharedIP:
    """Tests for hosts with multiple NICs sharing the same IPv4 address."""

    def test_shared_ip_produces_single_dhcp_line(self):
        host = _shared_ip_host("roku", "10.1.10.50",
                               ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
                               dhcp_name="roku")
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.50": "roku"},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["roku.conf"]
        dhcp_lines = [line for line in output.split("\n") if line.startswith("dhcp-host=")]
        assert len(dhcp_lines) == 1
        assert "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02" in dhcp_lines[0]

    def test_shared_ip_produces_single_ptr_record(self):
        host = _shared_ip_host("roku", "10.1.10.50",
                               ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.50": "roku"},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["roku.conf"]
        ipv4_ptrs = [line for line in output.split("\n")
                     if line.startswith("ptr-record=/") and "in-addr.arpa" not in line]
        assert len(ipv4_ptrs) == 1

    def test_shared_ip_sshfp_ptr_appears_once(self):
        host = _shared_ip_host("roku", "10.1.10.50",
                               ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])
        host.sshfp_records = ["roku IN SSHFP 1 2 abc123"]
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_internal(inv)
        output = result["roku.conf"]
        # Count SSHFP records for the PTR name (in-addr.arpa)
        sshfp_ptr_lines = [line for line in output.split("\n")
                           if "in-addr.arpa,44," in line]
        assert len(sshfp_ptr_lines) == 1

    def test_shared_ip_sshfp_per_interface_names_preserved(self):
        host = _shared_ip_host("roku", "10.1.10.50",
                               ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])
        host.sshfp_records = ["roku IN SSHFP 1 2 abc123"]
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_internal(inv)
        output = result["roku.conf"]
        # Both named interfaces should still get SSHFP FQDN records
        assert "eth0.roku.welland.mithis.com,44," in output
        assert "eth1.roku.welland.mithis.com,44," in output
