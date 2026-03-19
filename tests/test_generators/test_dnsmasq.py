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
        assert "ptr-record=1.10.1.10.in-addr.arpa,ipv4.desktop.int.welland.mithis.com" in output

    def test_generates_ipv6_ptr_records(self):
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "ip6.arpa,ipv6.desktop.int.welland.mithis.com" in output

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
                     if line.startswith("ptr-record=") and "in-addr.arpa" in line
                     and "ip6.arpa" not in line]
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


class TestMostSpecificFQDN:
    """Tests for most-specific FQDN selection in PTR records."""

    def test_single_iface_dual_stack_gets_ipv4_ipv6_prefixed_ptrs(self):
        """Dual-stack host: IPv4 PTR gets ipv4. prefix, IPv6 gets ipv6. prefix."""
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        assert "ptr-record=1.10.1.10.in-addr.arpa,ipv4.desktop.int.welland.mithis.com" in output
        assert "ipv6.desktop.int.welland.mithis.com" in output
        # Verify they're different names
        ipv4_ptrs = [line for line in output.split("\n")
                     if line.startswith("ptr-record=") and "in-addr.arpa" in line]
        ipv6_ptrs = [line for line in output.split("\n")
                     if line.startswith("ptr-record=") and "ip6.arpa" in line]
        assert len(ipv4_ptrs) == 1
        assert len(ipv6_ptrs) == 1
        assert "ipv4." in ipv4_ptrs[0]
        assert "ipv6." in ipv6_ptrs[0]

    def test_no_subdomain_dual_stack(self):
        """Host without VLAN subdomain still gets most-specific name."""
        # Use an IP outside the int VLAN range (no subdomain mapping)
        host = _host_with_iface("router", "aa:bb:cc:dd:ee:ff", "10.1.99.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_internal(inv)
        output = result["router.conf"]
        # No subdomain, so most specific for IPv4 is ipv4.router.welland.mithis.com
        assert "ptr-record=1.99.1.10.in-addr.arpa,ipv4.router.welland.mithis.com" in output

    def test_no_interface_name_uses_hostname(self):
        """Unnamed interface uses hostname-based names (not interface-prefixed)."""
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        # Should NOT have an interface prefix like eth0.desktop
        ipv4_ptrs = [line for line in output.split("\n")
                     if line.startswith("ptr-record=") and "in-addr.arpa" in line]
        assert len(ipv4_ptrs) == 1
        assert "ipv4.desktop.int.welland.mithis.com" in ipv4_ptrs[0]

    def test_alt_name_excluded_from_ptr(self):
        """Alt names are never used for PTR records."""
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        # Add a long alt name that would have more dots than any regular name
        host.alt_names = ["a.b.c.d.desktop.welland.mithis.com"]
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        # PTR should use the regular most-specific name, not the alt name
        assert "a.b.c.d.desktop.welland.mithis.com" not in [
            line.split(",", 1)[1] for line in output.split("\n")
            if line.startswith("ptr-record=") and "in-addr.arpa" in line
        ]
        assert "ptr-record=1.10.1.10.in-addr.arpa,ipv4.desktop.int.welland.mithis.com" in output

    def test_named_interface_gets_interface_prefixed_ptr(self):
        """Named interface produces PTR with interface name in most-specific FQDN."""
        inv = _inventory_with_host(
            "desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", interface_name="eth0",
        )
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        # With named interface + subdomain + dual-stack:
        # most-specific is ipv4.eth0.desktop.int.welland.mithis.com
        expected = "ptr-record=1.10.1.10.in-addr.arpa,"
        expected += "ipv4.eth0.desktop.int.welland.mithis.com"
        assert expected in output

    def test_ipv4_only_gets_subdomain_name_not_ipv4_prefix(self):
        """IPv4-only host gets ipv4. prefix, which becomes most-specific PTR name."""
        # Create a host without IPv6 addresses
        ipv4 = IPv4Address("10.1.10.1")
        iface = NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(ipv4,),
            dhcp_name="desktop",
        )
        host = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[iface],
        )
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(
            hosts=[host],
            ip_to_macs={"10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")]},
        )
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]
        # ipv4. prefix is now always generated; it's the most-specific name
        assert "ipv4.desktop.int.welland.mithis.com" in output
        assert "ptr-record=" in output
        # No IPv6 PTRs
        assert "ip6.arpa" not in output


class TestMultiInterfacePTR:
    """Tests for multi-interface hosts getting per-IP most-specific PTRs."""

    def test_each_interface_ip_gets_own_ptr_name(self):
        """Each interface's IP gets its own most-specific FQDN in PTR."""
        iface1 = NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
            ip_addresses=(
                IPv4Address("10.1.10.1"),
                IPv6Address("2404:e80:a137:110::1", "2404:e80:a137:"),
            ),
            dhcp_name="server",
        )
        iface2 = NetworkInterface(
            name="eth0",
            mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
            ip_addresses=(
                IPv4Address("10.1.10.2"),
                IPv6Address("2404:e80:a137:110::2", "2404:e80:a137:"),
            ),
            dhcp_name="eth0-server",
        )
        host = Host(
            machine_name="server",
            hostname="server",
            interfaces=[iface1, iface2],
        )
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(
            hosts=[host],
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:01"), "server")],
                "10.1.10.2": [(MACAddress.parse("aa:bb:cc:dd:ee:02"), "eth0-server")],
            },
        )
        result = generate_dnsmasq_internal(inv)
        output = result["server.conf"]
        # Default IP (unnamed iface) gets hostname-based name
        assert "ptr-record=1.10.1.10.in-addr.arpa,ipv4.server.int.welland.mithis.com" in output
        # Named interface IP gets interface-prefixed name
        assert "ptr-record=2.10.1.10.in-addr.arpa,ipv4.eth0.server.int.welland.mithis.com" in output

    def test_hostname_host_record_one_pair_per_line(self):
        """Multi-interface hostname host-record emits one (IPv4, IPv6) pair per line.

        dnsmasq host-record accepts at most one IPv4 and one IPv6 per line.
        For multi-interface hosts, the hostname DNS name includes all IPs,
        so we must emit multiple host-record lines.
        """
        iface1 = NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
            ip_addresses=(
                IPv4Address("10.1.10.1"),
                IPv6Address("2404:e80:a137:110::1", "2404:e80:a137:"),
            ),
            dhcp_name="server",
        )
        iface2 = NetworkInterface(
            name="eth0",
            mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
            ip_addresses=(
                IPv4Address("10.1.10.2"),
                IPv6Address("2404:e80:a137:110::2", "2404:e80:a137:"),
            ),
            dhcp_name="eth0-server",
        )
        host = Host(
            machine_name="server",
            hostname="server",
            interfaces=[iface1, iface2],
        )
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(
            hosts=[host],
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:01"), "server")],
                "10.1.10.2": [(MACAddress.parse("aa:bb:cc:dd:ee:02"), "eth0-server")],
            },
        )
        result = generate_dnsmasq_internal(inv)
        output = result["server.conf"]

        # Hostname FQDN should have two separate host-record lines
        # (one per IPv4/IPv6 pair), not one giant line with all IPs
        hostname_lines = [
            line for line in output.splitlines()
            if line.startswith("host-record=server.welland.mithis.com,")
        ]
        assert len(hostname_lines) == 2
        assert "10.1.10.1" in hostname_lines[0]
        assert "2404:e80:a137:110::1" in hostname_lines[0]
        assert "10.1.10.2" in hostname_lines[1]
        assert "2404:e80:a137:110::2" in hostname_lines[1]

        # Each line must have at most one IPv4 and one IPv6
        for line in hostname_lines:
            after_name = line.split(",", 1)[1]
            addrs = after_name.split(",")
            ipv4_count = sum(1 for a in addrs if "." in a)
            ipv6_count = sum(1 for a in addrs if ":" in a)
            assert ipv4_count <= 1, f"Multiple IPv4 on one line: {line}"
            assert ipv6_count <= 1, f"Multiple IPv6 on one line: {line}"


class TestHostRecordOrdering:
    """host-record lines must be sorted by name specificity (most dots first).

    dnsmasq auto-generates PTR records from host-record lines. The first
    host-record containing each IP determines its auto-PTR name. Sorting
    by specificity ensures the most-specific interface name wins.
    """

    def test_most_specific_name_comes_first_for_each_ip(self):
        """For each IP, the first host-record line must use the most-specific name."""
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        host_records = [
            line for line in output.splitlines()
            if line.startswith("host-record=")
        ]
        # Verify sorted by dot count (descending)
        dot_counts = [
            line.split("=", 1)[1].split(",", 1)[0].count(".")
            for line in host_records
        ]
        assert dot_counts == sorted(dot_counts, reverse=True), (
            f"host-record lines not sorted by specificity: {host_records}"
        )

    def test_ipv4_prefix_before_hostname_for_same_ip(self):
        """ipv4.desktop.int.domain (5 dots) must come before desktop.domain (3 dots)."""
        inv = _inventory_with_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        result = generate_dnsmasq_internal(inv)
        output = result["desktop.conf"]

        lines = output.splitlines()
        # Find positions of the two records containing 10.1.10.1
        ipv4_prefix_pos = None
        hostname_pos = None
        for i, line in enumerate(lines):
            if line.startswith("host-record=ipv4.desktop.int.welland.mithis.com,"):
                ipv4_prefix_pos = i
            if line.startswith("host-record=desktop.welland.mithis.com,") and "10.1.10.1" in line:
                hostname_pos = i

        assert ipv4_prefix_pos is not None, "Missing ipv4.desktop.int host-record"
        assert hostname_pos is not None, "Missing desktop hostname host-record"
        assert ipv4_prefix_pos < hostname_pos, (
            f"ipv4.desktop.int (line {ipv4_prefix_pos}) should come before "
            f"desktop (line {hostname_pos})"
        )

    def test_multi_interface_each_ip_first_record_is_most_specific(self):
        """For a multi-interface host, each IP's first host-record is the most specific."""
        iface1 = NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
            ip_addresses=(
                IPv4Address("10.1.10.1"),
                IPv6Address("2404:e80:a137:110::1", "2404:e80:a137:"),
            ),
            dhcp_name="server",
        )
        iface2 = NetworkInterface(
            name="eth0",
            mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
            ip_addresses=(
                IPv4Address("10.1.10.2"),
                IPv6Address("2404:e80:a137:110::2", "2404:e80:a137:"),
            ),
            dhcp_name="eth0-server",
        )
        host = Host(
            machine_name="server",
            hostname="server",
            interfaces=[iface1, iface2],
        )
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_internal(inv)
        output = result["server.conf"]

        # For each IP, find the FIRST host-record line containing it
        first_for_ip: dict[str, str] = {}
        for line in output.splitlines():
            if not line.startswith("host-record="):
                continue
            parts = line.split("=", 1)[1].split(",")
            name = parts[0]
            for addr in parts[1:]:
                if addr not in first_for_ip:
                    first_for_ip[addr] = name

        # IPv4 addresses should get ipv4.* prefix names first
        assert first_for_ip["10.1.10.1"].startswith("ipv4."), (
            f"First host-record for 10.1.10.1 is '{first_for_ip['10.1.10.1']}', "
            f"expected ipv4.* prefix"
        )
        assert first_for_ip["10.1.10.2"].startswith("ipv4."), (
            f"First host-record for 10.1.10.2 is '{first_for_ip['10.1.10.2']}', "
            f"expected ipv4.* prefix"
        )
        # IPv6 addresses should get ipv6.* prefix names first
        assert first_for_ip["2404:e80:a137:110::1"].startswith("ipv6."), (
            f"First host-record for ::1 is '{first_for_ip['2404:e80:a137:110::1']}', "
            f"expected ipv6.* prefix"
        )
        assert first_for_ip["2404:e80:a137:110::2"].startswith("ipv6."), (
            f"First host-record for ::2 is '{first_for_ip['2404:e80:a137:110::2']}', "
            f"expected ipv6.* prefix"
        )
