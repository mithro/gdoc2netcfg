"""Tests for the dnsmasq external (split-horizon) generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.dnsmasq_external import generate_dnsmasq_external
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
    public_ipv4="203.0.113.1",
)

SITE_NO_PUBLIC = Site(
    name="welland",
    domain="welland.mithis.com",
    ipv6_prefixes=[],
    network_subdomains={},
)


def _make_inventory(site=SITE, hosts=None, ip_to_hostname=None, ip_to_macs=None):
    return NetworkInventory(
        site=site,
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


class TestDnsmasqExternalGenerator:
    def test_returns_empty_dict_when_no_public_ipv4(self):
        inv = _make_inventory(site=SITE_NO_PUBLIC)
        result = generate_dnsmasq_external(inv)
        assert result == {}

    def test_returns_dict(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        assert isinstance(result, dict)

    def test_returns_dict_with_hostname_keys(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        assert "server.conf" in result

    def test_generates_host_records_with_public_ip(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        # Should use public IP, not the RFC 1918 internal IP
        assert "host-record=server.welland.mithis.com,203.0.113.1" in output
        # host-record lines must not contain the internal IP
        # (PTR records correctly use original IPs, so check only host-record lines)
        for line in output.split("\n"):
            if line.startswith("host-record="):
                assert "10.1.10.1" not in line, f"Internal IP leaked into host-record: {line}"

    def test_preserves_non_rfc1918_ips(self):
        host = _host_with_iface("external", "aa:bb:cc:dd:ee:ff", "198.51.100.10")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["external.conf"]

        # Non-RFC1918 IPs should be preserved as-is
        assert "host-record=external.welland.mithis.com,198.51.100.10" in output

    def test_uses_arg_public_ipv4_over_site(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv, public_ipv4="192.0.2.99")
        output = result["server.conf"]

        # Should use the argument public IP, not the site's
        assert "host-record=server.welland.mithis.com,192.0.2.99" in output
        assert "203.0.113.1" not in output

    def test_generates_sshfp_records(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        host.sshfp_records = ["server IN SSHFP 1 2 abc123"]
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        assert "dns-rr=server.welland.mithis.com,44,1:2:abc123" in output

    def test_sshfp_includes_interface_fqdns(self):
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
        host.sshfp_records = ["server IN SSHFP 1 2 abc123"]
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        # Should have SSHFP for both hostname and interface name
        assert "dns-rr=server.welland.mithis.com,44,1:2:abc123" in output
        assert "dns-rr=eth0.server.welland.mithis.com,44,1:2:abc123" in output

    def test_sshfp_ptr_uses_public_ip(self):
        """External SSHFP PTR entries should use the public IP, not internal."""
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        host.sshfp_records = ["server IN SSHFP 1 2 abc123"]
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        # PTR-based SSHFP should use the public IP (reversed)
        assert "1.113.0.203.in-addr.arpa" in output
        # SSHFP PTR entries should use public IP, not internal
        sshfp_lines = [line for line in output.split("\n") if "dns-rr=" in line and "44," in line]
        for line in sshfp_lines:
            assert "1.10.1.10.in-addr.arpa" not in line

    def test_sshfp_skipped_when_no_records(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        lines = [
            line for line in output.split("\n")
            if line.startswith("dns-rr=") and ",44," in line
        ]
        assert len(lines) == 0

    def test_multiple_hosts_produce_separate_files(self):
        host1 = _host_with_iface("alpha", "aa:bb:cc:dd:ee:01", "10.1.10.1")
        host2 = _host_with_iface("bravo", "aa:bb:cc:dd:ee:02", "10.1.10.2")
        inv = _make_inventory(hosts=[host1, host2])
        result = generate_dnsmasq_external(inv)
        assert "alpha.conf" in result
        assert "bravo.conf" in result

    def test_host_record_includes_ipv6(self):
        """External DNS should include IPv6 addresses alongside the public IPv4."""
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        # Should have public IPv4 AND the IPv6 address
        assert "host-record=server.welland.mithis.com,203.0.113.1,2404:e80:a137:110::1" in output

    def test_host_record_includes_short_name(self):
        """External DNS should include the short hostname record."""
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        assert "host-record=server,203.0.113.1,2404:e80:a137:110::1" in output

    def test_host_record_includes_subdomain_variant(self):
        """External DNS should include subdomain variants like server.int.domain."""
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        assert "host-record=server.int.welland.mithis.com," in output

    def test_host_record_includes_ipv4_prefix_variant(self):
        """External DNS should include ipv4.hostname.domain records."""
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        assert "host-record=ipv4.server.welland.mithis.com,203.0.113.1" in output

    def test_host_record_includes_ipv6_prefix_variant(self):
        """External DNS should include ipv6.hostname.domain records."""
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        assert "host-record=ipv6.server.welland.mithis.com,2404:e80:a137:110::1" in output

    def test_host_record_includes_interface_fqdn(self):
        """External DNS should include interface-specific FQDNs."""
        ipv4 = IPv4Address("10.1.10.2")
        ipv6s = [IPv6Address("2404:e80:a137:110::2", "2404:e80:a137:")]
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
            ip_addresses=(ipv4, *ipv6s),
            dhcp_name="eth0-server",
        )
        host = Host(
            machine_name="server",
            hostname="server",
            interfaces=[iface1, iface2],
        )
        derive_all_dns_names(host, SITE)
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        expected = "host-record=eth0.server.welland.mithis.com,203.0.113.1,2404:e80:a137:110::2"
        assert expected in output

    def test_multi_interface_hostname_pairs_addresses(self):
        """External hostname host-record emits paired lines, deduping public IPv4."""
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
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        # Both RFC 1918 IPs map to the same public IP, so IPv4 deduplicates
        # to a single entry, but there are two IPv6 addresses.
        hostname_lines = [
            line for line in output.splitlines()
            if line.startswith("host-record=server.welland.mithis.com,")
        ]
        # First line: public IPv4 + first IPv6. Second line: second IPv6 only.
        assert len(hostname_lines) == 2
        assert "203.0.113.1" in hostname_lines[0]
        assert "2404:e80:a137:110::1" in hostname_lines[0]
        assert "2404:e80:a137:110::2" in hostname_lines[1]
        # Second line should NOT repeat the public IPv4
        assert "203.0.113.1" not in hostname_lines[1]

    def test_generates_caa_record(self):
        """External DNS should include CAA records (for Let's Encrypt)."""
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        result = generate_dnsmasq_external(inv)
        output = result["server.conf"]

        assert "dns-rr=server.welland.mithis.com,257," in output
