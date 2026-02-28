"""Tests for the TAYGA NAT64 configuration generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.tayga import generate_tayga
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={90: "iot"},
)


def _make_host(hostname, mac, ip, ipv6_capable=True, sheet_type="IoT"):
    ipv4 = IPv4Address(ip)
    parts = ip.split(".")
    aa = parts[1]
    bb = parts[2].zfill(2)
    ccc = parts[3]
    ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

    iface = NetworkInterface(
        name=None,
        mac=MACAddress.parse(mac),
        ip_addresses=(ipv4, ipv6),
        dhcp_name=hostname,
    )
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        sheet_type=sheet_type,
        interfaces=[iface],
        default_ipv4=ipv4,
        subdomain="iot",
        ipv6_capable=ipv6_capable,
    )
    derive_all_dns_names(host, SITE)
    return host


def _make_inventory(*hosts):
    return NetworkInventory(
        site=SITE,
        hosts=list(hosts),
        ip_to_hostname={str(h.default_ipv4): h.hostname for h in hosts},
        ip_to_macs={},
    )


class TestTaygaGenerator:
    def test_returns_dict(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        assert isinstance(result, dict)

    def test_output_file_keys(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        assert "tayga.conf" in result
        assert "nat64.netdev" in result
        assert "nat64.network" in result

    def test_tayga_conf_has_map_entry(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "map 10.1.90.51\t2404:e80:a137:190::51" in conf

    def test_tayga_conf_has_header(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "tun-device nat64" in conf
        assert "ipv4-addr 100.64.1.1" in conf

    def test_tayga_conf_skips_capable_hosts(self):
        capable = _make_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.90.100",
                             ipv6_capable=True)
        incapable = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                               ipv6_capable=False)
        inv = _make_inventory(capable, incapable)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "10.1.90.51" in conf
        assert "10.1.90.100" not in conf

    def test_netdev_file(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        netdev = result["nat64.netdev"]
        assert "[NetDev]" in netdev
        assert "Name=nat64" in netdev
        assert "Kind=tun" in netdev

    def test_network_file_has_routes(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        network = result["nat64.network"]
        assert "Address=100.64.1.1/32" in network
        assert "Destination=2404:e80:a137:190::51/128" in network

    def test_empty_when_no_incapable_hosts(self):
        host = _make_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.90.100",
                          ipv6_capable=True)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "map " not in conf

    def test_multiple_incapable_hosts(self):
        hosts = [
            _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                       ipv6_capable=False),
            _make_host("au-plug-2", "7c:2c:67:d8:b9:60", "10.1.90.52",
                       ipv6_capable=False),
        ]
        inv = _make_inventory(*hosts)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "map 10.1.90.51" in conf
        assert "map 10.1.90.52" in conf
        network = result["nat64.network"]
        assert "Destination=2404:e80:a137:190::51/128" in network
        assert "Destination=2404:e80:a137:190::52/128" in network

    def test_configurable_tun_device_name(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv, tun_device="nat64-iot")
        assert "tun-device nat64-iot" in result["tayga.conf"]
        assert "Name=nat64-iot" in result["nat64-iot.netdev"]
        assert "Name=nat64-iot" in result["nat64-iot.network"]

    def test_configurable_ipv4_addr(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv, ipv4_addr="100.64.2.1")
        assert "ipv4-addr 100.64.2.1" in result["tayga.conf"]

    def test_comment_includes_hostname(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "# au-plug-1" in conf
