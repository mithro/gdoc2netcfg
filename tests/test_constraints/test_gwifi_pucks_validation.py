"""Tests for gwifi puck constraint validation against the inventory."""

from ipaddress import IPv4Address

from gdoc2netcfg.constraints.gwifi_pucks_validation import validate_gwifi_pucks
from gdoc2netcfg.models.addressing import MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.gwifi_pucks_parser import PuckRecord


def make_puck(number: int, eth0: str, eth1: str, serial: str = "") -> PuckRecord:
    return PuckRecord(
        number=number,
        name=f"puck{number:02d}",
        serial=serial or f"SER{number:08d}",
        eth0=eth0,
        eth1=eth1,
        ip=f"10.1.4.{100 + number}",
    )


def make_inventory(mac: str = "AA:BB:CC:00:00:01", ip: str = "10.1.5.50") -> NetworkInventory:
    site = Site(name="welland", domain="welland.mithis.com")
    iface = NetworkInterface(
        name=None,
        mac=MACAddress.parse(mac),
        ip_addresses=(IPv4Address(ip),),
        dhcp_name="existing-host",
    )
    host = Host(
        machine_name="existing-host",
        hostname="existing-host.welland.mithis.com",
        interfaces=[iface],
    )
    return NetworkInventory(site=site, hosts=[host])


class TestValidateGwifiPucks:
    def test_clean_pucks_pass(self):
        pucks = [
            make_puck(4, "44:07:0B:01:87:B4", "44:07:0B:01:87:B5"),
            make_puck(12, "44:07:0B:01:A2:21", "44:07:0B:01:A2:22"),
        ]
        result = validate_gwifi_pucks(pucks, make_inventory())
        assert not result.has_errors

    def test_puck_mac_collides_with_inventory(self):
        pucks = [make_puck(4, "AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02")]
        result = validate_gwifi_pucks(pucks, make_inventory())
        assert result.has_errors
        assert any(v.code == "gwifi_mac_collision" for v in result.errors)

    def test_puck_macs_collide_across_pucks(self):
        pucks = [
            make_puck(4, "44:07:0B:01:87:B4", "44:07:0B:01:87:B5"),
            make_puck(5, "44:07:0B:01:87:B4", "44:07:0B:01:87:B6"),
        ]
        result = validate_gwifi_pucks(pucks, make_inventory())
        assert result.has_errors
        assert any(v.code == "gwifi_mac_duplicate" for v in result.errors)

    def test_puck_ip_collides_with_inventory(self):
        pucks = [make_puck(4, "44:07:0B:01:87:B4", "44:07:0B:01:87:B5")]
        inv = make_inventory(ip="10.1.4.104")
        result = validate_gwifi_pucks(pucks, inv)
        assert result.has_errors
        assert any(v.code == "gwifi_ip_collision" for v in result.errors)

    def test_mac_collision_case_insensitive(self):
        pucks = [make_puck(4, "aa:bb:cc:00:00:01".upper(), "AA:BB:CC:00:00:02")]
        inv = make_inventory(mac="aa:bb:cc:00:00:01")
        result = validate_gwifi_pucks(pucks, inv)
        assert result.has_errors

    def test_empty_pucks_pass(self):
        result = validate_gwifi_pucks([], make_inventory())
        assert not result.has_errors
