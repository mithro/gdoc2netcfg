"""Tests for the per-net dnsmasq leaf generator (dns-redesign §7).

Each leaf net gets its hosts' fragments under "{net}/{hostname}.conf":
dhcp-host lines for that net's interfaces, net-scoped host-records only
({P.}H.N.S, {P.}I.H.N.S), ptr-records, and advisory SSHFPs at net-scoped
native names. No site-scoped records, no cname= lines (projections live
in the central auth zone), no CAA (central-only).

Transit/wg nets get NO leaf output (their zones live in the central
auth), and delegated nets (fpgas → tweed) are excluded entirely.
"""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.dnsmasq_leaf import generate_dnsmasq_leaf
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
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
        21: VLAN(id=21, name="fpgas", subdomain="fpgas", is_global=True),
        41: VLAN(id=41, name="sm", subdomain="sm", is_global=True),
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


def _inventory(*hosts):
    for host in hosts:
        derive_all_dns_names(host, SITE)
    return NetworkInventory(site=SITE, hosts=list(hosts))


def _big_storage():
    return Host(
        machine_name="big-storage",
        hostname="big-storage",
        interfaces=[
            _iface("10g1", "01", "10.1.11.154", "2404:e80:a137:111::154"),
            _iface("10g2", "02", "10.1.11.155", "2404:e80:a137:111::155"),
            _iface("25g1", "03", "10.1.7.15", "2404:e80:a137:107::15"),
            _iface("25g2", "04", "10.1.7.16", "2404:e80:a137:107::16"),
        ],
        sshfp_records=[
            "big-storage IN SSHFP 4 2 "
            "996b3981b870b4b2473e3dbadb3c435a8f2314b6a962a429a78760426bb13ba6"
        ],
    )


class TestLeafSplit:
    def test_multi_net_host_splits_per_net(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        assert "int/big-storage.conf" in files
        assert "store/big-storage.conf" in files

    def test_int_leaf_has_only_int_content(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        conf = files["int/big-storage.conf"]
        assert "host-record=big-storage.int.welland.mithis.com,10.1.11.154" in conf
        assert "host-record=10g1.big-storage.int.welland.mithis.com,10.1.11.154" in conf
        assert "host-record=ipv4.big-storage.int.welland.mithis.com,10.1.11.154" in conf
        assert "10.1.7.15" not in conf
        assert "25g1" not in conf

    def test_store_leaf_has_previously_missing_name(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        conf = files["store/big-storage.conf"]
        assert "host-record=big-storage.store.welland.mithis.com,10.1.7.15" in conf
        assert "10.1.11.154" not in conf

    def test_dhcp_hosts_follow_their_net(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        assert "dhcp-host=aa:bb:cc:dd:ee:01,10.1.11.154" in files["int/big-storage.conf"]
        assert "dhcp-host=aa:bb:cc:dd:ee:03,10.1.7.15" in files["store/big-storage.conf"]
        assert "10.1.7.15" not in files["int/big-storage.conf"]


class TestLeafScopeDiscipline:
    def test_no_site_records_or_cnames(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        for content in files.values():
            for line in content.splitlines():
                if line.startswith("host-record="):
                    name = line.split("=", 1)[1].split(",", 1)[0]
                    assert ".int.welland" in name or ".store.welland" in name, (
                        f"site-scoped record leaked into a leaf: {line}"
                    )
                assert not line.startswith("cname="), f"cname in leaf: {line}"

    def test_no_caa_in_leaves(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        for content in files.values():
            assert ",257," not in content

    def test_ptr_targets_net_scoped_prefix_forms(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        conf = files["int/big-storage.conf"]
        assert (
            "ptr-record=154.11.1.10.in-addr.arpa,"
            "ipv4.10g1.big-storage.int.welland.mithis.com" in conf
        )

    def test_sshfp_advisory_at_net_natives(self):
        files = generate_dnsmasq_leaf(_inventory(_big_storage()))
        conf = files["int/big-storage.conf"]
        assert "dns-rr=big-storage.int.welland.mithis.com,44," in conf
        assert "dns-rr=10g1.big-storage.int.welland.mithis.com,44," in conf
        # site names never carry leaf SSHFPs
        assert "dns-rr=big-storage.welland.mithis.com,44," not in conf


class TestLeafExclusions:
    def test_wg_and_transit_get_no_leaf(self):
        host = Host(
            machine_name="ten64",
            hostname="ten64",
            interfaces=[
                _iface("wg-x1c-work", "01", "10.98.6.1"),
                _iface("br-tfpgas", "02", "10.99.21.1"),
                _iface("br-int", "03", "10.1.10.1"),
            ],
        )
        files = generate_dnsmasq_leaf(_inventory(host))
        assert not any(f.startswith("wg/") for f in files)
        assert not any(f.startswith("tfpgas/") for f in files)
        assert "int/ten64.conf" in files

    def test_delegated_fpgas_excluded(self):
        host = Host(
            machine_name="pi4",
            hostname="pi4",
            interfaces=[_iface(None, "01", "10.21.4.1")],
        )
        files = generate_dnsmasq_leaf(_inventory(host))
        assert files == {}

    def test_parked_only_host_gets_no_files(self):
        host = Host(
            machine_name="junk",
            hostname="junk",
            interfaces=[_iface("eth1", "01", "10.1.254.1")],
        )
        files = generate_dnsmasq_leaf(_inventory(host))
        assert files == {}
