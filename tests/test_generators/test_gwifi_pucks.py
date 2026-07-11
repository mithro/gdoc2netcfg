"""Tests for the gwifi pucks identity + DNS generators."""

import json

from gdoc2netcfg.generators.gwifi_pucks import (
    generate_gwifi_pucks,
    generate_gwifi_pucks_dns,
)
from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.gwifi_pucks_parser import PuckRecord


def make_inventory(pucks: list[PuckRecord]) -> NetworkInventory:
    site = Site(name="welland", domain="welland.mithis.com")
    return NetworkInventory(site=site, gwifi_pucks=pucks)


PUCKS = [
    PuckRecord(number=12, name="puck12", serial="2831HW00WGD",
               eth0="44:07:0B:01:A2:21", eth1="44:07:0B:01:A2:22",
               ip="10.1.4.112"),
    PuckRecord(number=4, name="puck04", serial="2831HW00VZA",
               eth0="44:07:0B:01:87:B4", eth1="44:07:0B:01:87:B5",
               ip="10.1.4.104"),
]


class TestGenerateGwifiPucks:
    def test_json_shape(self):
        out = generate_gwifi_pucks(make_inventory(PUCKS))
        data = json.loads(out)
        assert data["version"] == 1
        assert data["generated_by"] == "gdoc2netcfg"
        assert [p["number"] for p in data["pucks"]] == [4, 12]  # sorted
        assert data["pucks"][0] == {
            "name": "puck04",
            "number": 4,
            "serial": "2831HW00VZA",
            "eth0": "44:07:0B:01:87:B4",
            "eth1": "44:07:0B:01:87:B5",
            "ip": "10.1.4.104",
        }

    def test_deterministic_and_trailing_newline(self):
        a = generate_gwifi_pucks(make_inventory(PUCKS))
        b = generate_gwifi_pucks(make_inventory(list(reversed(PUCKS))))
        assert a == b
        assert a.endswith("\n")

    def test_empty(self):
        data = json.loads(generate_gwifi_pucks(make_inventory([])))
        assert data["pucks"] == []


class TestGenerateGwifiPucksDns:
    def test_host_records(self):
        out = generate_gwifi_pucks_dns(make_inventory(PUCKS))
        lines = [line for line in out.splitlines() if not line.startswith("#")]
        assert lines == [
            "host-record=puck04.wifi.welland.mithis.com,10.1.4.104",
            "host-record=puck12.wifi.welland.mithis.com,10.1.4.112",
        ]

    def test_header_comment_names_owner(self):
        out = generate_gwifi_pucks_dns(make_inventory(PUCKS))
        assert out.startswith("#")
        assert "wisp" in out  # points the reader at who owns DHCP

    def test_deterministic(self):
        a = generate_gwifi_pucks_dns(make_inventory(PUCKS))
        b = generate_gwifi_pucks_dns(make_inventory(list(reversed(PUCKS))))
        assert a == b
        assert a.endswith("\n")

    def test_domain_follows_site(self):
        site = Site(name="monarto", domain="monarto.mithis.com")
        inv = NetworkInventory(site=site, gwifi_pucks=PUCKS)
        out = generate_gwifi_pucks_dns(inv)
        assert "puck04.wifi.monarto.mithis.com" in out
