"""Tests for the redesigned three-scope DNS name grammar (dns-redesign §3).

Every DNSName now carries scope ("site" | "net" | "short") and kind
("native" | "cname"). The normative cases mirror the design's Appendix A
worked examples:

  - site natives {P.}H.S = union of the host's addresses (aggregate),
    honoring the per-host aggregate_override interface list;
  - net natives {P.}H.N.S / {P.}I.H.N.S carry ONLY that net's addresses
    (fixing the live defect where big-storage.int.welland served all four);
  - site projections {P.}N.H.S and {P.}I.H.S are CNAMEs to the net forms
    (replacing the old site-scoped native interface records 1:1);
  - parked interfaces (site-octet address on no known network, e.g.
    ten64's 10.1.253/254 NICs) produce no records at all;
  - global-VLAN nets (sm = 10.41/16) and wg tunnels (10.98/16, 10.255/16)
    map to net labels like the site-octet nets do.
"""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.derivations.vlan import ip_to_net
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site

DOMAIN = "welland.mithis.com"
SITE = Site(
    name="welland",
    domain=DOMAIN,
    site_octet=1,
    vlans={
        7: VLAN(id=7, name="store", subdomain="store", third_octets=(7,)),
        10: VLAN(
            id=10, name="int", subdomain="int",
            third_octets=(8, 9, 10, 11, 12, 13, 14, 15, 16),
        ),
        41: VLAN(id=41, name="sm", subdomain="sm", is_global=True),
        90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90, 91)),
        121: VLAN(
            id=121, name="tfpgas", subdomain="tfpgas",
            is_transit=True, transit_match=(99, 21),
        ),
    },
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        7: "store",
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int", 16: "int",
        90: "iot", 91: "iot",
    },
)


def _iface(name, mac_suffix, v4, v6=None):
    ips = [IPv4Address(v4)]
    if v6:
        ips.append(IPv6Address(v6, "2404:e80:a137:"))
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(f"aa:bb:cc:dd:ee:{mac_suffix}"),
        ip_addresses=tuple(ips),
        dhcp_name=f"{name}-host" if name else "host",
    )


def _big_storage():
    """Design Appendix A: int 10g1/10g2 = 10.1.11.154/.155;
    store 25g1/25g2 = 10.1.7.15/.16."""
    host = Host(
        machine_name="big-storage",
        hostname="big-storage",
        interfaces=[
            _iface("10g1", "01", "10.1.11.154", "2404:e80:a137:111::154"),
            _iface("10g2", "02", "10.1.11.155", "2404:e80:a137:111::155"),
            _iface("25g1", "03", "10.1.7.15", "2404:e80:a137:107::15"),
            _iface("25g2", "04", "10.1.7.16", "2404:e80:a137:107::16"),
        ],
    )
    derive_all_dns_names(host, SITE)
    return host


def _by_name(host, name):
    matches = [n for n in host.dns_names if n.name == name]
    assert matches, f"no DNSName {name!r}; have: {sorted(n.name for n in host.dns_names)}"
    assert len(matches) == 1, f"duplicate DNSName {name!r}"
    return matches[0]


def _v4set(dns_name):
    return {str(a) for a in dns_name.ipv4_addresses}


class TestIpToNet:
    def test_site_octet_net(self):
        assert ip_to_net(IPv4Address("10.1.11.154"), SITE) == "int"

    def test_store_net(self):
        assert ip_to_net(IPv4Address("10.1.7.15"), SITE) == "store"

    def test_global_vlan(self):
        assert ip_to_net(IPv4Address("10.41.4.18"), SITE) == "sm"

    def test_transit_vlan(self):
        assert ip_to_net(IPv4Address("10.99.21.2"), SITE) == "tfpgas"

    def test_wg_tunnels(self):
        assert ip_to_net(IPv4Address("10.98.6.1"), SITE) == "wg"

    def test_wg_legacy_255(self):
        assert ip_to_net(IPv4Address("10.255.0.1"), SITE) == "wg"

    def test_parked_returns_none(self):
        assert ip_to_net(IPv4Address("10.1.254.1"), SITE) is None
        assert ip_to_net(IPv4Address("10.1.253.2"), SITE) is None

    def test_non_rfc1918_returns_none(self):
        assert ip_to_net(IPv4Address("87.121.95.37"), SITE) is None


class TestSiteAggregates:
    def test_site_native_union(self):
        host = _big_storage()
        agg = _by_name(host, "big-storage.welland.mithis.com")
        assert agg.kind == "native"
        assert agg.scope == "site"
        assert _v4set(agg) == {"10.1.11.154", "10.1.11.155", "10.1.7.15", "10.1.7.16"}
        assert len(agg.ipv6_addresses) == 4

    def test_prefix_variants_native(self):
        host = _big_storage()
        v4 = _by_name(host, "ipv4.big-storage.welland.mithis.com")
        assert v4.kind == "native"
        assert _v4set(v4) == {"10.1.11.154", "10.1.11.155", "10.1.7.15", "10.1.7.16"}
        assert v4.ipv6_addresses == ()

    def test_short_name(self):
        host = _big_storage()
        short = _by_name(host, "big-storage")
        assert short.scope == "short"
        assert short.kind == "native"

    def test_aggregate_override_limits_addresses(self):
        host = Host(
            machine_name="ten64",
            hostname="ten64",
            interfaces=[
                _iface("br-int", "01", "10.1.10.1", "2404:e80:a137:110::1"),
                _iface("br-store", "02", "10.1.7.1", "2404:e80:a137:107::1"),
            ],
            aggregate_override=["br-int"],
        )
        derive_all_dns_names(host, SITE)
        agg = _by_name(host, "ten64.welland.mithis.com")
        assert _v4set(agg) == {"10.1.10.1"}
        # the non-aggregate interface still has its net-scoped records
        assert _by_name(host, "br-store.ten64.store.welland.mithis.com").kind == "native"

    def test_parked_excluded_from_aggregate(self):
        host = Host(
            machine_name="ten64",
            hostname="ten64",
            interfaces=[
                _iface("br-int", "01", "10.1.10.1", "2404:e80:a137:110::1"),
                _iface("eth1", "02", "10.1.254.1"),  # parked: no such network
            ],
        )
        derive_all_dns_names(host, SITE)
        agg = _by_name(host, "ten64.welland.mithis.com")
        assert _v4set(agg) == {"10.1.10.1"}


class TestNetNatives:
    def test_host_net_native_is_net_only(self):
        """THE defect fix: big-storage.int.welland carries only the int
        addresses, not all four."""
        host = _big_storage()
        int_native = _by_name(host, "big-storage.int.welland.mithis.com")
        assert int_native.kind == "native"
        assert int_native.scope == "net"
        assert _v4set(int_native) == {"10.1.11.154", "10.1.11.155"}
        assert len(int_native.ipv6_addresses) == 2

    def test_store_net_native_exists(self):
        """Design: store leaf creates the previously-missing name."""
        host = _big_storage()
        store_native = _by_name(host, "big-storage.store.welland.mithis.com")
        assert _v4set(store_native) == {"10.1.7.15", "10.1.7.16"}

    def test_iface_net_native(self):
        host = _big_storage()
        n = _by_name(host, "10g1.big-storage.int.welland.mithis.com")
        assert n.kind == "native"
        assert n.scope == "net"
        assert _v4set(n) == {"10.1.11.154"}

    def test_prefix_net_natives(self):
        host = _big_storage()
        n = _by_name(host, "ipv4.big-storage.int.welland.mithis.com")
        assert n.kind == "native"
        assert n.scope == "net"
        assert _v4set(n) == {"10.1.11.154", "10.1.11.155"}
        assert n.ipv6_addresses == ()


class TestCnameProjections:
    def test_net_projection(self):
        host = _big_storage()
        c = _by_name(host, "int.big-storage.welland.mithis.com")
        assert c.kind == "cname"
        assert c.scope == "site"
        assert c.cname_target == "big-storage.int.welland.mithis.com"

    def test_iface_projection(self):
        """Replaces the old site-scoped native iface records 1:1."""
        host = _big_storage()
        c = _by_name(host, "10g1.big-storage.welland.mithis.com")
        assert c.kind == "cname"
        assert c.cname_target == "10g1.big-storage.int.welland.mithis.com"

    def test_prefix_projections(self):
        host = _big_storage()
        c4 = _by_name(host, "ipv4.int.big-storage.welland.mithis.com")
        assert c4.kind == "cname"
        assert c4.cname_target == "ipv4.big-storage.int.welland.mithis.com"
        c6 = _by_name(host, "ipv6.10g1.big-storage.welland.mithis.com")
        assert c6.kind == "cname"
        assert c6.cname_target == "ipv6.10g1.big-storage.int.welland.mithis.com"

    def test_no_native_site_iface_records(self):
        """Removed family: site-scoped *native* interface records."""
        host = _big_storage()
        for n in host.dns_names:
            if n.scope == "site" and n.kind == "native" and n.is_fqdn:
                assert n.name in (
                    "big-storage.welland.mithis.com",
                    "ipv4.big-storage.welland.mithis.com",
                    "ipv6.big-storage.welland.mithis.com",
                ), f"unexpected site native: {n.name}"


class TestParkedInterfaces:
    def test_parked_iface_has_no_records(self):
        host = Host(
            machine_name="ten64",
            hostname="ten64",
            interfaces=[
                _iface("br-int", "01", "10.1.10.1", "2404:e80:a137:110::1"),
                _iface("eth1", "02", "10.1.254.1"),
            ],
        )
        derive_all_dns_names(host, SITE)
        parked = [n for n in host.dns_names if "eth1" in n.name]
        assert parked == [], f"parked iface produced records: {parked}"


class TestOtherNetKinds:
    def test_global_vlan_host_gets_net_names(self):
        """sm hosts gain net-scoped names (new vs today's output)."""
        host = Host(
            machine_name="sm-pcie-1",
            hostname="sm-pcie-1",
            interfaces=[
                _iface("eth0", "01", "10.41.4.18", "2404:e80:a137:4104::18"),
            ],
        )
        derive_all_dns_names(host, SITE)
        n = _by_name(host, "sm-pcie-1.sm.welland.mithis.com")
        assert n.kind == "native"
        assert n.scope == "net"
        c = _by_name(host, "eth0.sm-pcie-1.welland.mithis.com")
        assert c.kind == "cname"
        assert c.cname_target == "eth0.sm-pcie-1.sm.welland.mithis.com"

    def test_wg_host_gets_net_names(self):
        host = Host(
            machine_name="ten64",
            hostname="ten64",
            interfaces=[
                _iface("wg-x1c-work", "01", "10.98.6.1", "2404:e80:a137:9806::1"),
            ],
        )
        derive_all_dns_names(host, SITE)
        n = _by_name(host, "wg-x1c-work.ten64.wg.welland.mithis.com")
        assert n.kind == "native"
        assert _v4set(n) == {"10.98.6.1"}

    def test_single_net_host_degrades_cleanly(self):
        """Design Appendix A: single-net cases (gsm7252ps-s1 shape)."""
        host = Host(
            machine_name="sw",
            hostname="sw",
            interfaces=[_iface(None, "01", "10.1.5.22")],
        )
        # net 5 needs a subdomain for this case
        site = Site(
            name="welland", domain=DOMAIN, site_octet=1,
            ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
            network_subdomains={5: "net"},
        )
        derive_all_dns_names(host, site)
        agg = _by_name(host, "sw.welland.mithis.com")
        assert agg.kind == "native"
        net_native = _by_name(host, "sw.net.welland.mithis.com")
        assert net_native.kind == "native"
        assert _v4set(net_native) == {"10.1.5.22"}
        c = _by_name(host, "net.sw.welland.mithis.com")
        assert c.kind == "cname"
        assert c.cname_target == "sw.net.welland.mithis.com"
