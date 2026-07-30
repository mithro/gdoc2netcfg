"""Tests for the DNS name derivation passes.

Tests each of the five passes independently, plus the combined
derive_all_dns_names orchestrator. Pass semantics follow the
dns-redesign three-scope grammar (see test_dns_grammar.py for the
normative Appendix-A cases).
"""

from gdoc2netcfg.derivations.dns_names import (
    derive_all_dns_names,
    derive_dns_names_alt_names,
    derive_dns_names_hostname,
    derive_dns_names_interface,
    derive_dns_names_ip_prefix,
    derive_dns_names_subdomain,
)
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.models.network import IPv6Prefix, Site

DOMAIN = "welland.mithis.com"
SITE = Site(
    name="welland",
    domain=DOMAIN,
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int",
        90: "iot",
    },
)


def _make_host(
    hostname="desktop",
    ip="10.1.10.100",
    interfaces=None,
):
    """Build a Host with sensible defaults for testing."""
    ipv4 = IPv4Address(ip)
    parts = ip.split(".")
    aa = parts[1]
    bb = parts[2].zfill(2)
    ccc = parts[3]
    ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

    if interfaces is None:
        interfaces = [
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ip_addresses=(ipv4, ipv6),
                dhcp_name=hostname,
            )
        ]

    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=interfaces,
    )


def _make_multi_iface_host():
    """Build a host with two named interfaces (both on int)."""
    ipv4_eth0 = IPv4Address("10.1.10.100")
    ipv6_eth0 = IPv6Address("2404:e80:a137:110::100", "2404:e80:a137:")
    ipv4_eth1 = IPv4Address("10.1.10.101")
    ipv6_eth1 = IPv6Address("2404:e80:a137:110::101", "2404:e80:a137:")

    return Host(
        machine_name="ten64",
        hostname="ten64",
        interfaces=[
            NetworkInterface(
                name="eth0",
                mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
                ip_addresses=(ipv4_eth0, ipv6_eth0),
                dhcp_name="eth0-ten64",
            ),
            NetworkInterface(
                name="eth1",
                mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
                ip_addresses=(ipv4_eth1, ipv6_eth1),
                dhcp_name="eth1-ten64",
            ),
        ],
    )


class TestPass1Hostname:
    def test_adds_fqdn_and_short_name(self):
        host = _make_host()
        names = derive_dns_names_hostname(host, DOMAIN, SITE)

        assert len(names) == 2
        assert names[0].name == "desktop.welland.mithis.com"
        assert names[0].is_fqdn is True
        assert names[0].scope == "site"
        assert names[0].kind == "native"
        assert names[1].name == "desktop"
        assert names[1].is_fqdn is False
        assert names[1].scope == "short"

    def test_ipv4_set_on_both(self):
        host = _make_host()
        names = derive_dns_names_hostname(host, DOMAIN, SITE)

        assert str(names[0].ipv4) == "10.1.10.100"
        assert str(names[1].ipv4) == "10.1.10.100"

    def test_ipv6_set_on_both(self):
        host = _make_host()
        names = derive_dns_names_hostname(host, DOMAIN, SITE)

        assert len(names[0].ipv6_addresses) == 1
        assert str(names[0].ipv6_addresses[0]) == "2404:e80:a137:110::100"
        assert len(names[1].ipv6_addresses) == 1

    def test_no_interfaces_returns_empty(self):
        host = Host(
            machine_name="empty",
            hostname="empty",
            interfaces=[],
        )
        names = derive_dns_names_hostname(host, DOMAIN, SITE)
        assert names == []

    def test_iot_hostname(self):
        host = _make_host(hostname="thermostat.iot", ip="10.1.90.10")
        names = derive_dns_names_hostname(host, DOMAIN, SITE)

        assert names[0].name == "thermostat.iot.welland.mithis.com"
        assert names[1].name == "thermostat.iot"

    def test_all_parked_returns_empty(self):
        """A host whose only address is parked (site-octet, no network)
        gets no names at all."""
        host = _make_host(ip="10.1.253.1")
        names = derive_dns_names_hostname(host, DOMAIN, SITE)
        assert names == []


class TestPass2Interface:
    def test_no_named_interfaces_returns_empty(self):
        host = _make_host()
        names = derive_dns_names_interface(host, DOMAIN, SITE)
        assert names == []

    def test_named_interfaces_get_projection_native_and_short(self):
        host = _make_multi_iface_host()
        names = derive_dns_names_interface(host, DOMAIN, SITE)

        # 2 interfaces × (site CNAME projection + net native + short)
        assert len(names) == 6
        cnames = [n for n in names if n.kind == "cname"]
        net_natives = [n for n in names if n.kind == "native" and n.is_fqdn]
        shorts = [n for n in names if not n.is_fqdn]
        assert len(cnames) == 2
        assert len(net_natives) == 2
        assert len(shorts) == 2

    def test_interface_name_format(self):
        host = _make_multi_iface_host()
        names = derive_dns_names_interface(host, DOMAIN, SITE)

        name_strs = [n.name for n in names]
        assert "eth0.ten64.welland.mithis.com" in name_strs
        assert "eth0.ten64.int.welland.mithis.com" in name_strs
        assert "eth0.ten64" in name_strs
        assert "eth1.ten64.welland.mithis.com" in name_strs
        assert "eth1.ten64.int.welland.mithis.com" in name_strs
        assert "eth1.ten64" in name_strs

    def test_site_form_is_projection_cname(self):
        host = _make_multi_iface_host()
        names = derive_dns_names_interface(host, DOMAIN, SITE)

        eth0_site = next(n for n in names if n.name == "eth0.ten64.welland.mithis.com")
        assert eth0_site.kind == "cname"
        assert eth0_site.cname_target == "eth0.ten64.int.welland.mithis.com"

    def test_interface_ip_matches_interface(self):
        host = _make_multi_iface_host()
        names = derive_dns_names_interface(host, DOMAIN, SITE)

        eth0_native = next(
            n for n in names if n.name == "eth0.ten64.int.welland.mithis.com"
        )
        assert str(eth0_native.ipv4) == "10.1.10.100"

        eth1_native = next(
            n for n in names if n.name == "eth1.ten64.int.welland.mithis.com"
        )
        assert str(eth1_native.ipv4) == "10.1.10.101"


class TestPass3Subdomain:
    def test_adds_net_native_and_projection(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        assert len(names) == 2
        native = next(n for n in names if n.kind == "native")
        assert native.name == "desktop.int.welland.mithis.com"
        assert native.is_fqdn is True
        assert native.scope == "net"
        cname = next(n for n in names if n.kind == "cname")
        assert cname.name == "int.desktop.welland.mithis.com"
        assert cname.cname_target == "desktop.int.welland.mithis.com"

    def test_no_subdomain_for_short_names(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        # Only FQDN names come out of the per-net pass
        short_variants = [n for n in names if not n.is_fqdn]
        assert len(short_variants) == 0

    def test_multi_iface_single_net_grouped(self):
        """Two interfaces on the same net produce ONE net-scoped host name
        carrying both addresses (union within one net, design Appendix A
        rpi4-kindle case)."""
        host = _make_multi_iface_host()
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        natives = [n for n in names if n.kind == "native"]
        assert len(natives) == 1
        assert natives[0].name == "ten64.int.welland.mithis.com"
        assert {str(a) for a in natives[0].ipv4_addresses} == {
            "10.1.10.100", "10.1.10.101",
        }

    def test_no_subdomain_for_unmapped_ip(self):
        host = _make_host(ip="10.31.1.5")
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)
        assert names == []

    def test_preserves_ipv4_and_ipv6(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        native = next(n for n in names if n.kind == "native")
        assert str(native.ipv4) == "10.1.10.100"
        assert len(native.ipv6_addresses) == 1


class TestPass4IpPrefix:
    def test_adds_ipv4_and_ipv6_prefixes(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        # Only the FQDN entry has both IPv4 and IPv6
        assert len(names) == 2
        name_strs = [n.name for n in names]
        assert "ipv4.desktop.welland.mithis.com" in name_strs
        assert "ipv6.desktop.welland.mithis.com" in name_strs

    def test_ipv4_prefix_has_only_ipv4(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        ipv4_name = next(n for n in names if n.name.startswith("ipv4."))
        assert ipv4_name.ipv4 is not None
        assert ipv4_name.ipv6_addresses == ()

    def test_ipv6_prefix_has_only_ipv6(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        ipv6_name = next(n for n in names if n.name.startswith("ipv6."))
        assert ipv6_name.ipv4 is None
        assert len(ipv6_name.ipv6_addresses) == 1

    def test_ipv4_only_still_gets_ipv4_prefix(self):
        """If host has only IPv4, ipv4.{name} is still generated."""
        ipv4 = IPv4Address("192.168.1.1")
        host = Host(
            machine_name="printer",
            hostname="printer",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(ipv4,),
                    dhcp_name="printer",
                )
            ],
        )
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        names = derive_dns_names_ip_prefix(host, DOMAIN)
        assert len(names) == 1
        assert names[0].name == "ipv4.printer.welland.mithis.com"
        assert names[0].ipv4 is not None
        assert names[0].ipv6_addresses == ()

    def test_prefix_of_cname_is_cname(self):
        host = _make_multi_iface_host()
        host.dns_names = derive_dns_names_interface(host, DOMAIN, SITE)
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        c = next(
            n for n in names if n.name == "ipv4.eth0.ten64.welland.mithis.com"
        )
        assert c.kind == "cname"
        assert c.cname_target == "ipv4.eth0.ten64.int.welland.mithis.com"

    def test_scans_all_previous_fqdn_names(self):
        """Pass 4 should create prefixed variants for all FQDNs."""
        host = _make_multi_iface_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN, SITE)
        host.dns_names.extend(derive_dns_names_interface(host, DOMAIN, SITE))
        host.dns_names.extend(derive_dns_names_subdomain(host, DOMAIN, SITE))
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        # Each FQDN with IPv4 gets an ipv4. variant; each with IPv6 gets ipv6.
        # This host has both on all FQDNs, so each FQDN produces 2 names.
        fqdn_names = [n for n in host.dns_names if n.is_fqdn]
        expected = sum(
            bool(n.ipv4_addresses) + bool(n.ipv6_addresses)
            for n in fqdn_names
        )
        assert len(names) == expected


class TestDeriveAllDnsNames:
    def test_single_interface_host(self):
        host = _make_host()
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        # Pass 1: hostname
        assert "desktop.welland.mithis.com" in name_strs
        assert "desktop" in name_strs
        # Pass 3: net native + projection
        assert "desktop.int.welland.mithis.com" in name_strs
        assert "int.desktop.welland.mithis.com" in name_strs
        # Pass 4: ipv4/ipv6 prefixes
        assert "ipv4.desktop.welland.mithis.com" in name_strs
        assert "ipv6.desktop.welland.mithis.com" in name_strs

    def test_multi_interface_host(self):
        host = _make_multi_iface_host()
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        # Pass 1
        assert "ten64.welland.mithis.com" in name_strs
        # Pass 2
        assert "eth0.ten64.welland.mithis.com" in name_strs
        assert "eth0.ten64.int.welland.mithis.com" in name_strs
        assert "eth1.ten64.welland.mithis.com" in name_strs
        # Pass 3
        assert "ten64.int.welland.mithis.com" in name_strs
        assert "int.ten64.welland.mithis.com" in name_strs
        # Pass 4
        assert "ipv4.ten64.welland.mithis.com" in name_strs
        assert "ipv6.ten64.welland.mithis.com" in name_strs

    def test_all_fqdns_flagged_correctly(self):
        host = _make_host()
        derive_all_dns_names(host, SITE)

        for dns_name in host.dns_names:
            if dns_name.name.endswith(f".{DOMAIN}") or dns_name.name.startswith("ipv"):
                assert dns_name.is_fqdn, f"{dns_name.name} should be FQDN"
            else:
                assert not dns_name.is_fqdn, f"{dns_name.name} should not be FQDN"

    def test_host_with_no_subdomain(self):
        host = _make_host(ip="10.31.1.5")
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        # No subdomain variants
        assert not any(".int." in n or ".sm." in n for n in name_strs if "." in n)
        # Still has hostname and ip-prefix
        assert "desktop.welland.mithis.com" in name_strs
        assert "ipv4.desktop.welland.mithis.com" in name_strs

    def test_alt_names_included(self):
        host = _make_host()
        host.alt_names = ["alias.example.com", "other.example.com"]
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        assert "alias.example.com" in name_strs
        assert "other.example.com" in name_strs

    def test_wildcard_alt_names_included(self):
        host = _make_host()
        host.alt_names = ["*.example.com"]
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        assert "*.example.com" in name_strs


class TestPass5AltNames:
    def test_adds_alt_names_as_fqdns(self):
        host = _make_host()
        host.alt_names = ["alias.example.com"]
        names = derive_dns_names_alt_names(host)

        assert len(names) == 1
        assert names[0].name == "alias.example.com"
        assert names[0].is_fqdn is True

    def test_uses_all_interface_ips(self):
        host = _make_host()
        host.alt_names = ["alias.example.com"]
        names = derive_dns_names_alt_names(host)

        assert str(names[0].ipv4) == "10.1.10.100"
        assert len(names[0].ipv6_addresses) == 1
        assert str(names[0].ipv6_addresses[0]) == "2404:e80:a137:110::100"

    def test_multiple_alt_names(self):
        host = _make_host()
        host.alt_names = ["a.example.com", "b.example.com", "*.example.com"]
        names = derive_dns_names_alt_names(host)

        assert len(names) == 3
        name_strs = [n.name for n in names]
        assert "a.example.com" in name_strs
        assert "b.example.com" in name_strs
        assert "*.example.com" in name_strs

    def test_empty_alt_names_returns_empty(self):
        host = _make_host()
        host.alt_names = []
        names = derive_dns_names_alt_names(host)
        assert names == []

    def test_no_interfaces_returns_empty(self):
        host = Host(
            machine_name="empty",
            hostname="empty",
            interfaces=[],
            alt_names=["alias.example.com"],
        )
        names = derive_dns_names_alt_names(host)
        assert names == []
