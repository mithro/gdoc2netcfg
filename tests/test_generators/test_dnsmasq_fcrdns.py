"""Tests for post-generation FCrDNS validation of dnsmasq output."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.dnsmasq import generate_dnsmasq_internal
from gdoc2netcfg.generators.dnsmasq_common import validate_dnsmasq_output
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
    derive_all_dns_names(host, SITE)
    return host


class TestValidOutputPasses:
    """Generated output from the real pipeline should always pass validation."""

    def test_single_host_internal(self):
        host = _host_with_iface(
            "desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", dhcp_name="desktop",
        )
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.1": "desktop"},
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")],
            },
        )
        files = generate_dnsmasq_internal(inv)
        result = validate_dnsmasq_output(files)
        assert result.is_valid, result.report()

    def test_single_host_external(self):
        host = _host_with_iface(
            "server", "aa:bb:cc:dd:ee:ff", "10.1.10.1",
        )
        inv = _make_inventory(hosts=[host])
        files = generate_dnsmasq_external(inv)
        result = validate_dnsmasq_output(files)
        assert result.is_valid, result.report()

    def test_multi_host_all_ptrs_have_forwards(self):
        host1 = _host_with_iface(
            "alpha", "aa:bb:cc:dd:ee:01", "10.1.10.1", dhcp_name="alpha",
        )
        host2 = _host_with_iface(
            "bravo", "aa:bb:cc:dd:ee:02", "10.1.10.2", dhcp_name="bravo",
        )
        inv = _make_inventory(
            hosts=[host1, host2],
            ip_to_hostname={"10.1.10.1": "alpha", "10.1.10.2": "bravo"},
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:01"), "alpha")],
                "10.1.10.2": [(MACAddress.parse("aa:bb:cc:dd:ee:02"), "bravo")],
            },
        )
        files = generate_dnsmasq_internal(inv)
        result = validate_dnsmasq_output(files)
        assert result.is_valid, result.report()

    def test_named_interface_host(self):
        """Host with a named interface (e.g. eth0) passes validation."""
        host = _host_with_iface(
            "server", "aa:bb:cc:dd:ee:ff", "10.1.10.1",
            interface_name="eth0", dhcp_name="server",
        )
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.1": "server"},
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "server")],
            },
        )
        files = generate_dnsmasq_internal(inv)
        result = validate_dnsmasq_output(files)
        assert result.is_valid, result.report()

    def test_multi_interface_host(self):
        """Multi-interface host with per-IP PTR names passes validation."""
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
        files = generate_dnsmasq_internal(inv)
        result = validate_dnsmasq_output(files)
        assert result.is_valid, result.report()


class TestOrphanPtrDetected:
    """Manually crafted configs with orphan PTRs should fail validation."""

    def test_ipv4_ptr_without_forward(self):
        files = {
            "orphan.conf": (
                "host-record=real.welland.mithis.com,10.1.10.1\n"
                "ptr-record=1.10.1.10.in-addr.arpa,ghost.welland.mithis.com\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.has_errors
        assert len(result.errors) == 1
        assert result.errors[0].code == "ptr_without_forward"
        assert "ghost.welland.mithis.com" in result.errors[0].message

    def test_ipv6_ptr_without_forward(self):
        files = {
            "orphan6.conf": (
                "host-record=real.welland.mithis.com,2404:e80:a137:110::1\n"
                "ptr-record=1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
                ".0.0.0.0.0.1.1.0.7.3.1.a.0.8.e.4.0.4.2.ip6.arpa,"
                "ghost.welland.mithis.com\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.has_errors
        assert len(result.errors) == 1
        assert result.errors[0].code == "ptr_without_forward"
        assert "ghost.welland.mithis.com" in result.errors[0].message

    def test_multiple_orphans_all_reported(self):
        files = {
            "multi.conf": (
                "host-record=real.welland.mithis.com,10.1.10.1\n"
                "ptr-record=1.10.1.10.in-addr.arpa,ghost1.welland.mithis.com\n"
                "ptr-record=2.10.1.10.in-addr.arpa,ghost2.welland.mithis.com\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.has_errors
        assert len(result.errors) == 2
        names = {e.message for e in result.errors}
        assert any("ghost1" in m for m in names)
        assert any("ghost2" in m for m in names)

    def test_valid_ptr_not_flagged(self):
        """PTR names that DO have a matching host-record should pass."""
        files = {
            "ok.conf": (
                "host-record=server.welland.mithis.com,10.1.10.1\n"
                "ptr-record=1.10.1.10.in-addr.arpa,server.welland.mithis.com\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.is_valid

    def test_ptr_name_matched_across_files(self):
        """PTR in one file can match a host-record in a different file."""
        files = {
            "forward.conf": (
                "host-record=server.welland.mithis.com,10.1.10.1\n"
            ),
            "reverse.conf": (
                "ptr-record=1.10.1.10.in-addr.arpa,server.welland.mithis.com\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.is_valid

    def test_error_includes_filename(self):
        """Violation record_id should be the filename containing the PTR."""
        files = {
            "badhost.conf": (
                "ptr-record=1.10.1.10.in-addr.arpa,missing.welland.mithis.com\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.has_errors
        assert result.errors[0].record_id == "badhost.conf"


class TestEmptyAndEdgeCases:
    def test_empty_files_dict(self):
        result = validate_dnsmasq_output({})
        assert result.is_valid

    def test_no_ptr_records(self):
        files = {
            "forward_only.conf": (
                "host-record=server.welland.mithis.com,10.1.10.1\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.is_valid

    def test_comments_and_blank_lines_ignored(self):
        files = {
            "test.conf": (
                "# This is a comment\n"
                "\n"
                "host-record=server.welland.mithis.com,10.1.10.1\n"
                "# Another comment\n"
                "ptr-record=1.10.1.10.in-addr.arpa,server.welland.mithis.com\n"
            ),
        }
        result = validate_dnsmasq_output(files)
        assert result.is_valid
