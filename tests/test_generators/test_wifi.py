"""Tests for the wifi generator (pucks.json identity generator).

The output contract is byte-identical to the historical bespoke-pipeline
output (tests/fixtures/pucks.json.golden, captured from the live
wisp.welland.mithis.com deployment before the rework). These tests build
the inventory through the REAL pipeline path — parse_csv -> build_hosts ->
enrich_hosts_with_wifi_data -> NetworkInventory — from a WiFi-sheet CSV
fixture mirroring every puck in the golden file, and assert the generator's
output matches the golden bytes exactly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gdoc2netcfg.derivations.host_builder import build_hosts
from gdoc2netcfg.derivations.wifi_data import enrich_hosts_with_wifi_data
from gdoc2netcfg.generators.wifi import generate_wifi
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory, WifiData
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.parser import parse_csv

FIXTURES = Path(__file__).parent.parent / "fixtures"
GOLDEN = FIXTURES / "pucks.json.golden"
WIFI_SHEET_CSV = FIXTURES / "wifi_sheet.csv"

WELLAND = Site(name="welland", domain="welland.mithis.com", site_octet=1)
MONARTO = Site(name="monarto", domain="monarto.mithis.com", site_octet=2)


def _build_puck_inventory() -> NetworkInventory:
    """Build a NetworkInventory the way the real pipeline does.

    parse_csv -> build_hosts -> enrich_hosts_with_wifi_data -> inventory.
    """
    csv_text = WIFI_SHEET_CSV.read_text()
    records = parse_csv(csv_text, "wifi")
    hosts = build_hosts(records, WELLAND)
    enrich_hosts_with_wifi_data(hosts)
    return NetworkInventory(site=WELLAND, hosts=hosts)


def _build_hosts_for_site(site: Site) -> list[Host]:
    """Same real pipeline as `_build_puck_inventory`, parameterized by site.

    Used by TestSiteFilteredWifiSheetHosts below to prove the full fixture
    (12 pucks + 6 OpenMesh machines' 42 rows + the 6 VLAN-4 infra rows)
    resolves to the right per-site host set end to end: parse_csv's
    WiFi-sheet Site carry-forward (anchor-only Site cells inherit down each
    machine block) feeding build_hosts' per-site filtering
    (derivations/ip_remap.py).
    """
    csv_text = WIFI_SHEET_CSV.read_text()
    records = parse_csv(csv_text, "wifi")
    hosts = build_hosts(records, site)
    enrich_hosts_with_wifi_data(hosts)
    return hosts


class TestGenerateWifi:
    def test_matches_golden_byte_for_byte(self):
        inventory = _build_puck_inventory()
        out = generate_wifi(inventory)
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
            wifi_data=WifiData(number=99, serial="TESTSERIAL01"),
        )

        inventory = NetworkInventory(site=WELLAND, hosts=[wan_only])
        with pytest.raises(ValueError, match="puck99.wifi"):
            generate_wifi(inventory)

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
            wifi_data=WifiData(number=98, serial="TESTSERIAL02"),
        )

        inventory = NetworkInventory(site=WELLAND, hosts=[lan_only])
        with pytest.raises(ValueError, match="puck98.wifi"):
            generate_wifi(inventory)

    def test_no_puck_hosts_raises_instead_of_emitting_empty_json(self):
        # A missing/misconfigured 'wifi' sheet source, a failed fetch, or a
        # renamed '#'/Serial column all silently leave zero hosts with
        # wifi_data -- without this guard that would produce a valid-looking
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
            generate_wifi(inventory)

    def test_empty_inventory_raises(self):
        inventory = NetworkInventory(site=WELLAND, hosts=[])
        with pytest.raises(ValueError, match="no puck hosts found"):
            generate_wifi(inventory)


class TestSiteFilteredWifiSheetHosts:
    """End-to-end site-filter integration test against the full wifi_sheet.csv
    fixture (12 pucks + 6 OpenMesh machines' 42 rows + the 6 VLAN-4 infra
    rows -- see docs/superpowers/specs/2026-07-29-wifi-sheet-tenwrt-site-merge-design.md
    section 5 for the authoritative per-site counts). Proves parse_csv's
    WiFi-sheet Site carry-forward (merged Site cells export anchor-only,
    inherited down each contiguous machine block) plus build_hosts' per-site
    filtering resolve to the right host set at both sites -- including that
    an OpenMesh AP's blank-covered rows don't leak into every site
    (the pre-existing ab-30 partial-filter bug this carry-forward fixes)."""

    def test_welland_hosts(self):
        hosts = _build_hosts_for_site(WELLAND)
        hostnames = sorted(h.hostname for h in hosts)
        expected = sorted(
            [f"puck{n:02d}.wifi" for n in range(1, 13)]
            + ["openmesh-ab-38.wifi", "openmesh-96-00.wifi"]
            + ["ten64.wifi", "wisp.wifi", "tenwrt.wifi"]
        )
        assert hostnames == expected
        assert len(hosts) == 17

    def test_monarto_hosts(self):
        hosts = _build_hosts_for_site(MONARTO)
        hostnames = sorted(h.hostname for h in hosts)
        expected = sorted(
            [
                "openmesh-ab-30.wifi",
                "openmesh-94-98.wifi",
                "openmesh-95-80.wifi",
                "openmesh-95-88.wifi",
            ]
            + ["ten64.wifi", "wisp.wifi", "tenwrt.wifi"]
        )
        assert hostnames == expected
        assert len(hosts) == 7

    def test_tenwrt_wifi_has_no_wifi_data(self):
        # No '#'/Serial on the infra rows -- enrich_hosts_with_wifi_data must
        # leave tenwrt.wifi (and ten64.wifi/wisp.wifi) out of pucks.json.
        hosts = _build_hosts_for_site(WELLAND)
        tenwrt = next(h for h in hosts if h.hostname == "tenwrt.wifi")
        assert tenwrt.wifi_data is None

    def test_golden_pucks_json_still_byte_identical(self):
        # Belt-and-braces alongside TestGenerateWifi.test_matches_golden_byte_for_byte:
        # the broadened fixture (OpenMesh + infra rows) must not perturb
        # pucks.json, which only ever sees hosts with wifi_data set.
        inventory = _build_puck_inventory()
        out = generate_wifi(inventory)
        assert out == GOLDEN.read_text()
