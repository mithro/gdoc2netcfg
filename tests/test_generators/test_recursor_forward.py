"""Tests for the recursor forward-zones generator (dns-redesign §7).

The forward-zones file is the recursor's whole routing table: leaf net
zones and their reverse slices → that net's leaf gateway; the site zone,
transit/wg zones and their central reverses → the central auth
(127.0.0.1:5300); delegated nets (fpgas) → tweed; peer-site zones →
the configured peer targets (flipped from the wg endpoint to the peer
central anchor in Phase 6).
"""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.recursor_forward import generate_recursor_forward
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site

DOMAIN = "welland.mithis.com"
SITE = Site(
    name="welland",
    domain=DOMAIN,
    site_octet=1,
    vlans={
        10: VLAN(
            id=10, name="int", subdomain="int",
            third_octets=(8, 9, 10, 11, 12, 13, 14, 15, 16),
        ),
        21: VLAN(id=21, name="fpgas", subdomain="fpgas", is_global=True),
        41: VLAN(id=41, name="sm", subdomain="sm", is_global=True),
        90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90, 91)),
        121: VLAN(
            id=121, name="tfpgas", subdomain="tfpgas",
            is_transit=True, transit_match=(99, 21),
        ),
    },
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
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


def _ten64():
    return Host(
        machine_name="ten64",
        hostname="ten64",
        interfaces=[
            _iface("br-int", "01", "10.1.10.1", "2404:e80:a137:110::1"),
            _iface("br-iot", "02", "10.1.90.1", "2404:e80:a137:190::1"),
            _iface("br-sm", "03", "10.41.0.1", "2404:e80:a137:4100::1"),
            _iface("br-tfpgas", "04", "10.99.21.1", "2404:e80:a137:9921::1"),
            _iface("wg-x1c-work", "05", "10.98.6.1", "2404:e80:a137:9806::1"),
        ],
    )


def _generate(**kwargs):
    host = _ten64()
    derive_all_dns_names(host, SITE)
    inv = NetworkInventory(site=SITE, hosts=[host])
    return generate_recursor_forward(inv, **kwargs)


def _entries(yaml_text):
    """Parse the simple emitted YAML back into {zone: [forwarders]}."""
    entries = {}
    zone = None
    for line in yaml_text.splitlines():
        line = line.strip()
        if line.startswith("- zone:"):
            zone = line.split(":", 1)[1].strip()
            entries[zone] = []
        elif line.startswith("forwarders:"):
            vals = line.split(":", 1)[1].strip().strip("[]")
            entries[zone] = [v.strip().strip("'\"") for v in vals.split(",")]
    return entries


class TestForwardZones:
    def test_leaf_net_zones_to_gateways(self):
        e = _entries(_generate())
        assert e[f"int.{DOMAIN}"] == ["10.1.10.1", "2404:e80:a137:110::1"]
        assert e[f"iot.{DOMAIN}"] == ["10.1.90.1", "2404:e80:a137:190::1"]
        assert e[f"sm.{DOMAIN}"] == ["10.41.0.1", "2404:e80:a137:4100::1"]

    def test_site_and_central_zones_to_central(self):
        e = _entries(_generate())
        assert e[DOMAIN] == ["127.0.0.1:5300"]
        assert e[f"wg.{DOMAIN}"] == ["127.0.0.1:5300"]
        assert e[f"tfpgas.{DOMAIN}"] == ["127.0.0.1:5300"]

    def test_delegated_fpgas_to_tweed(self):
        e = _entries(_generate())
        assert e[f"fpgas.{DOMAIN}"] == ["10.21.0.1"]
        assert e["21.10.in-addr.arpa"] == ["10.21.0.1"]

    def test_leaf_v4_reverse_slices(self):
        e = _entries(_generate())
        for c in range(8, 17):
            assert e[f"{c}.1.10.in-addr.arpa"] == [
                "10.1.10.1", "2404:e80:a137:110::1",
            ], f"missing v4 slice for third octet {c}"
        assert e["90.1.10.in-addr.arpa"][0] == "10.1.90.1"
        assert e["41.10.in-addr.arpa"][0] == "10.41.0.1"

    def test_leaf_v6_reverse_slices(self):
        e = _entries(_generate())
        # int contributes nine /64 slices :108..:116 (design §4)
        assert e["8.0.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa"][0] == "10.1.10.1"
        assert e["6.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa"][0] == "10.1.10.1"
        int_slices = [
            z for z, f in e.items()
            if z.endswith("7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa") and f[0] == "10.1.10.1"
        ]
        assert len(int_slices) == 9
        # sm (global VLAN) gets a two-nibble /56-style slice
        assert e["1.4.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa"][0] == "10.41.0.1"

    def test_central_reverses(self):
        e = _entries(_generate())
        assert e["98.10.in-addr.arpa"] == ["127.0.0.1:5300"]
        assert e["255.10.in-addr.arpa"] == ["127.0.0.1:5300"]
        assert e["21.99.10.in-addr.arpa"] == ["127.0.0.1:5300"]
        # wg v6 /56-style slice + tfpgas /64 → central
        assert e["8.9.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa"] == ["127.0.0.1:5300"]
        assert e["1.2.9.9.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa"] == ["127.0.0.1:5300"]

    def test_peer_zones_knob(self):
        e = _entries(_generate(peer_zones={
            "monarto.mithis.com": ["10.98.2.2"],
            "2.10.in-addr.arpa": ["10.98.2.2"],
        }))
        assert e["monarto.mithis.com"] == ["10.98.2.2"]
        assert e["2.10.in-addr.arpa"] == ["10.98.2.2"]

    def test_no_leaf_zone_for_wg_or_transit(self):
        e = _entries(_generate())
        # wg/tfpgas must NOT point at a leaf gateway
        assert e[f"wg.{DOMAIN}"] == ["127.0.0.1:5300"]
        assert e[f"tfpgas.{DOMAIN}"] == ["127.0.0.1:5300"]


class TestRecurseFlags:
    """Zones served by dnsmasq (leaf gateways, delegated tweed, peer
    sites) are RECURSIVE forwards: dnsmasq isn't a clean auth — names
    missing from its local data are forwarded upstream and come back
    without aa/SOA, which an auth-style forward treats as lame
    (SERVFAIL). Central pdns zones stay auth-style (no recurse flag)."""

    def test_leaf_zones_recurse(self):
        yaml_text = _generate()
        blocks = yaml_text.split("- zone: ")
        int_block = next(b for b in blocks if b.startswith("int."))
        assert "recurse: true" in int_block

    def test_central_zones_do_not_recurse(self):
        yaml_text = _generate()
        blocks = yaml_text.split("- zone: ")
        site_block = next(
            b for b in blocks if b.startswith("welland.mithis.com")
        )
        assert "recurse" not in site_block

    def test_delegated_net_recurses(self):
        yaml_text = _generate()
        blocks = yaml_text.split("- zone: ")
        fpgas_block = next(b for b in blocks if b.startswith("fpgas."))
        assert "recurse: true" in fpgas_block
