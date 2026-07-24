"""Tests for the gwifi pucks.json identity generator.

The output contract is byte-identical to the historical bespoke-pipeline
output (tests/fixtures/pucks.json.golden, captured from the live
wisp.welland.mithis.com deployment before the rework). These tests build
the inventory through the REAL pipeline path — parse_csv -> build_hosts ->
enrich_hosts_with_puck_data -> NetworkInventory — from a WiFi-sheet CSV
fixture mirroring every puck in the golden file, and assert the generator's
output matches the golden bytes exactly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gdoc2netcfg.derivations.host_builder import build_hosts
from gdoc2netcfg.derivations.puck_data import enrich_hosts_with_puck_data
from gdoc2netcfg.generators.gwifi_pucks import generate_gwifi_pucks
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory, PuckData
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.parser import parse_csv

FIXTURES = Path(__file__).parent.parent / "fixtures"
GOLDEN = FIXTURES / "pucks.json.golden"
WIFI_SHEET_CSV = FIXTURES / "wifi_sheet.csv"

WELLAND = Site(name="welland", domain="welland.mithis.com", site_octet=1)


def _build_puck_inventory() -> NetworkInventory:
    """Build a NetworkInventory the way the real pipeline does.

    parse_csv -> build_hosts -> enrich_hosts_with_puck_data -> inventory.
    """
    csv_text = WIFI_SHEET_CSV.read_text()
    records = parse_csv(csv_text, "wifi")
    hosts = build_hosts(records, WELLAND)
    enrich_hosts_with_puck_data(hosts)
    return NetworkInventory(site=WELLAND, hosts=hosts)


class TestGenerateGwifiPucks:
    def test_matches_golden_byte_for_byte(self):
        inventory = _build_puck_inventory()
        out = generate_gwifi_pucks(inventory)
        assert out == GOLDEN.read_text()

    def test_missing_lan_interface_raises_with_hostname(self):
        wan_only = Host(
            machine_name="puck99",
            hostname="puck99.wifi",
            sheet_type="WiFi",
            interfaces=[
                NetworkInterface(
                    name="wan",
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
                    ip_addresses=(IPv4Address("10.1.4.199"),),
                ),
            ],
            puck_data=PuckData(number=99, serial="TESTSERIAL01"),
        )

        inventory = NetworkInventory(site=WELLAND, hosts=[wan_only])
        with pytest.raises(ValueError, match="puck99.wifi"):
            generate_gwifi_pucks(inventory)

    def test_missing_wan_interface_raises_with_hostname(self):
        lan_only = Host(
            machine_name="puck98",
            hostname="puck98.wifi",
            sheet_type="WiFi",
            interfaces=[
                NetworkInterface(
                    name="lan",
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
                    ip_addresses=(IPv4Address("10.1.4.198"),),
                ),
            ],
            puck_data=PuckData(number=98, serial="TESTSERIAL02"),
        )

        inventory = NetworkInventory(site=WELLAND, hosts=[lan_only])
        with pytest.raises(ValueError, match="puck98.wifi"):
            generate_gwifi_pucks(inventory)

    def test_no_puck_hosts_raises_instead_of_emitting_empty_json(self):
        # A missing/misconfigured 'wifi' sheet source, a failed fetch, or a
        # renamed '#'/Serial column all silently leave zero hosts with
        # puck_data -- without this guard that would produce a valid-looking
        # but empty pucks.json, which would wipe wisp's fleet identity if
        # deployed.
        non_puck_host = Host(
            machine_name="openmesh-ab-30",
            hostname="openmesh-ab-30.wifi",
            sheet_type="WiFi",
            interfaces=[
                NetworkInterface(
                    name="lan",
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:03"),
                    ip_addresses=(IPv4Address("10.1.5.40"),),
                ),
            ],
        )

        inventory = NetworkInventory(site=WELLAND, hosts=[non_puck_host])
        with pytest.raises(ValueError, match="no puck hosts found"):
            generate_gwifi_pucks(inventory)

    def test_empty_inventory_raises(self):
        inventory = NetworkInventory(site=WELLAND, hosts=[])
        with pytest.raises(ValueError, match="no puck hosts found"):
            generate_gwifi_pucks(inventory)
