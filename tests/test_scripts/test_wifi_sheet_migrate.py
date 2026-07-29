"""Tests for scripts/wifi-sheet-migrate.py's pure row-building/planning logic.

No network access anywhere in this module -- every fixture is a hand-built
(or live-scan-derived, but hardcoded) values grid standing in for a Sheets
API response. The real header orders (both 'Google WiFi Pucks' and
'Welland - IP Allocation') were confirmed against the live spreadsheet
(read-only) while writing this tool, and are pinned here as golden-row
regression fixtures.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

# scripts/wifi-sheet-migrate.py is a standalone script, not an installed
# module (hyphenated filename -- can't be `import`ed normally).
_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "wifi-sheet-migrate.py"
_spec = importlib.util.spec_from_file_location("wifi_sheet_migrate", _SCRIPT)
wsm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wsm)


# ---------------------------------------------------------------------------
# Fixtures mirroring the live spreadsheet's real header layout.
# ---------------------------------------------------------------------------

FLASH_HEADER = [
    "Name", "Location", "Upstream", "Controlled By", "#", "Model", "Firmware",
    "Serial", "MLB Serial", "Region", "HWID", "MAC", "Setup Network",
    "Setup Code", "wan", "lan",
]

# A stock Google-firmware row (must produce NO rows) + puck04's real row
# (Name is deliberately blank -- a live scan found it blank for several
# current OpenWRT rows, so Machine/Name must NOT depend on it).
FLASH_VALUES = [
    FLASH_HEADER,
    ["", "Lounge", "", "", 1, "AC-1304", "Google Original", "1605HW000GM",
     "", "", "", "70:3A:CB:94:AF:E9", "setupAFF00", "ctwgkpdsg"],
    ["", "", "", "", 4, "AC-1304", "OpenWRT", "2831HW00VZA",
     "NJOKI350392FX01", "us", "GALE C2I-A2A-A3C-A4I-E87",
     "44:07:0B:01:87:B4", "setup87BB0", "ndqybqkbp",
     "44:07:0B:01:87:B4", "44:07:0B:01:87:B5"],
]

IP_ALLOC_HEADER = [
    "Site", "Machine", "Interface", "Notes", "Partner", "Location",
    "Sensors", "Controlled By", "VLAN", "MAC Address", "IPv4",
    "IPv4 Alt", "IPv6 A", "Alt Names", "Old Interface", "Serial Number",
]

# openmesh-ab-30's real 7-row block (live scan, 2026-07-24), plus one
# unrelated row before/after to prove the Machine-prefix filter works.
IP_ALLOC_VALUES = [
    IP_ALLOC_HEADER,
    ["", "node3-wifi-google", "b6-98", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:98", "10.X.20.39", "", "2404:e80:a137:X20::39"],
    ["", "openmesh-ab-30", "lan",
     "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627518",
     0, "Monarto - Power Meter Box", "", "", 5, "AC:86:74:0D:AB:30",
     "10.X.5.40", "", "2404:e80:a137:X05::40"],
    ["", "openmesh-ab-30", "poe", "", 1, "", "", "", 10,
     "AC:86:74:0D:AB:31", "10.X.10.40", "", "2404:e80:a137:X10::40"],
    ["", "openmesh-ab-30", "manage", "", 2, "", "", "", 10,
     "AC:86:74:0D:AB:32", "10.X.11.40", "", "2404:e80:a137:X11::40"],
    ["", "openmesh-ab-30", "wifi-roam", "", 3, "", "", "", 20,
     "AC:86:74:0d:AB:33", "10.X.20.40", "", "2404:e80:a137:X20::40"],
    ["", "openmesh-ab-30", "wifi-guest", "", 4, "", "", "", 99,
     "AC:86:74:0d:AB:34", "10.X.99.40", "", "2404:e80:a137:X99::40"],
    ["", "openmesh-ab-30", "wifi-iot", "", 5, "", "", "", 90,
     "AC:86:74:0D:AB:35", "10.X.90.40", "", "2404:e80:a137:X90::40"],
    ["", "openmesh-ab-30", "wifi-raw", "", 7, "", "", "", "Q",
     "AC:86:74:0D:AB:37", "10.X.12.40", "", "2404:e80:a137:X12::40"],
    ["", "tplink-powerline", "", "", "", "", "", "", 5,
     "78:20:51:6E:F8:0A", "10.X.5.90", "", "2404:e80:a137:X05::90"],
]

HARDWARE_MAP = {"openmesh-ab-30": "OM2P-LC"}

# The three ex-stock pucks' node*-wifi-google 8-row blocks (live scan,
# 2026-07-25, rows 312-335 of the real sheet) -- still in IP Allocation
# until delete-old-rows runs; used by the google-node block validators.
GOOGLE_NODE_VALUES = [
    ["", "node1-wifi-google", "af-e9", "AC-1304", "", "", "", "", 20,
     "70:3A:CB:94:AF:E9", "10.X.20.16", "192.168.86.1",
     "2404:e80:a137:X20::16", "", "AF:F0", "1605HW000GM"],
    ["", "node1-wifi-google", "af-ea", "", "", "", "", "", 20,
     "70:3A:CB:94:AF:EA", "10.X.20.17", "", "2404:e80:a137:X20::17",
     "", "wlan"],
    ["", "node1-wifi-google", "af-eb", "", "", "", "", "", 20,
     "70:3A:CB:94:AF:EB", "10.X.20.18", "", "2404:e80:a137:X20::18"],
    ["", "node1-wifi-google", "af-ec", "", "", "", "", "", 20,
     "70:3A:CB:94:AF:EC", "10.X.20.19", "", "2404:e80:a137:X20::19"],
    ["", "node1-wifi-google", "af-ed", "", "", "", "", "", 20,
     "70:3A:CB:94:AF:ED", "10.X.20.20", "", "2404:e80:a137:X20::20"],
    ["", "node1-wifi-google", "af-ee", "", "", "", "", "", 20,
     "70:3A:CB:94:AF:EE", "10.X.20.21", "", "2404:e80:a137:X20::21"],
    ["", "node1-wifi-google", "af-ef", "", "", "", "", "", 20,
     "70:3A:CB:94:AF:EF", "10.X.20.22", "", "2404:e80:a137:X20::22"],
    ["", "node1-wifi-google", "af-f0", "", "", "", "", "", 20,
     "70:3A:CB:94:AF:F0", "10.X.20.23", "", "2404:e80:a137:X20::23"],
    ["", "node2-wifi-google", "ae-b4", "AC-1304", "", "", "", "", 20,
     "70:3A:CB:99:AE:B4", "10.X.20.24", "192.168.86.35",
     "2404:e80:a137:X20::24", "", "AE:BB", "1609HW00AUJ"],
    ["", "node2-wifi-google", "ae-b5", "", "", "", "", "", 20,
     "70:3A:CB:99:AE:B5", "10.X.20.25", "", "2404:e80:a137:X20::25",
     "", "wlan"],
    ["", "node2-wifi-google", "ae-b6", "", "", "", "", "", 20,
     "70:3A:CB:99:AE:B6", "10.X.20.26", "", "2404:e80:a137:X20::26"],
    ["", "node2-wifi-google", "ae-b7", "", "", "", "", "", 20,
     "70:3A:CB:99:AE:B7", "10.X.20.27", "", "2404:e80:a137:X20::27"],
    ["", "node2-wifi-google", "ae-b8", "", "", "", "", "", 20,
     "70:3A:CB:99:AE:B8", "10.X.20.28", "", "2404:e80:a137:X20::28"],
    ["", "node2-wifi-google", "ae-b9", "", "", "", "", "", 20,
     "70:3A:CB:99:AE:B9", "10.X.20.29", "", "2404:e80:a137:X20::29"],
    ["", "node2-wifi-google", "ae-ba", "", "", "", "", "", 20,
     "70:3A:CB:99:AE:BA", "10.X.20.30", "", "2404:e80:a137:X20::30"],
    ["", "node2-wifi-google", "ae-bb", "", "", "", "", "", 20,
     "70:3A:CB:99:AE:BB", "10.X.20.31", "", "2404:e80:a137:X20::31"],
    ["", "node3-wifi-google", "b6-91", "AC-1304", "", "", "", "", 20,
     "70:3A:CB:99:B6:91", "10.X.20.32", "192.168.86.36",
     "2404:e80:a137:X20::32", "", "B6:98", "1609HW00AZM"],
    ["", "node3-wifi-google", "b6-92", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:92", "10.X.20.33", "", "2404:e80:a137:X20::33",
     "", "wlan"],
    ["", "node3-wifi-google", "b6-93", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:93", "10.X.20.34", "", "2404:e80:a137:X20::34"],
    ["", "node3-wifi-google", "b6-94", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:94", "10.X.20.35", "", "2404:e80:a137:X20::35"],
    ["", "node3-wifi-google", "b6-95", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:95", "10.X.20.36", "", "2404:e80:a137:X20::36"],
    ["", "node3-wifi-google", "b6-96", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:96", "10.X.20.37", "", "2404:e80:a137:X20::37"],
    ["", "node3-wifi-google", "b6-97", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:97", "10.X.20.38", "", "2404:e80:a137:X20::38"],
    ["", "node3-wifi-google", "b6-98", "", "", "", "", "", 20,
     "70:3A:CB:99:B6:98", "10.X.20.39", "", "2404:e80:a137:X20::39"],
]

# IP-Allocation grid with COMPLETE node blocks + one OpenMesh block + an
# unrelated row -- the minimum compute_new_tab_rows needs now that stock
# pucks are part of the populate output.
STOCK_IP_ALLOC_VALUES = (
    [IP_ALLOC_HEADER] + GOOGLE_NODE_VALUES + [row[:] for row in IP_ALLOC_VALUES[2:]]
)

# FULL_IP_ALLOC_VALUES (below) plus the node blocks in front -- for tests
# that exercise the whole populate row set against all six OpenMesh blocks.

# All 6 OpenMesh blocks, complete and in OPENMESH_MACHINES_IN_ORDER order
# (live scan, 2026-07-24, rows 337-378 of the real sheet) -- used to test
# the "clean, no drift" case of the block-shape validator. Header is at
# index 0 (local row 1); the first OpenMesh row (openmesh-ab-30 lan) is at
# index 1 (local row 2).
FULL_IP_ALLOC_VALUES = [
    IP_ALLOC_HEADER,
    ["", "openmesh-ab-30", "lan",
     "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627518",
     0, "Monarto - Power Meter Box", "", "", 5, "AC:86:74:0D:AB:30",
     "10.X.5.40", "", "2404:e80:a137:X05::40"],
    ["", "openmesh-ab-30", "poe", "", 1, "", "", "", 10,
     "AC:86:74:0D:AB:31", "10.X.10.40", "", "2404:e80:a137:X10::40"],
    ["", "openmesh-ab-30", "manage", "", 2, "", "", "", 10,
     "AC:86:74:0D:AB:32", "10.X.11.40", "", "2404:e80:a137:X11::40"],
    ["", "openmesh-ab-30", "wifi-roam", "", 3, "", "", "", 20,
     "AC:86:74:0d:AB:33", "10.X.20.40", "", "2404:e80:a137:X20::40"],
    ["", "openmesh-ab-30", "wifi-guest", "", 4, "", "", "", 99,
     "AC:86:74:0d:AB:34", "10.X.99.40", "", "2404:e80:a137:X99::40"],
    ["", "openmesh-ab-30", "wifi-iot", "", 5, "", "", "", 90,
     "AC:86:74:0D:AB:35", "10.X.90.40", "", "2404:e80:a137:X90::40"],
    ["", "openmesh-ab-30", "wifi-raw", "", 7, "", "", "", "Q",
     "AC:86:74:0D:AB:37", "10.X.12.40", "", "2404:e80:a137:X12::40"],
    ["", "openmesh-ab-38", "lan",
     "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627517",
     8, "Welland - Tim's Bedroom", "", "", 5, "AC:86:74:0D:AB:38",
     "10.X.5.41", "", "2404:e80:a137:X05::41"],
    ["", "openmesh-ab-38", "poe", "", 9, "", "", "", 10,
     "AC:86:74:0D:AB:39", "10.X.10.41", "", "2404:e80:a137:X10::41"],
    ["", "openmesh-ab-38", "manage", "", "A / 10", "", "", "", 10,
     "AC:86:74:0D:AB:3A", "10.X.11.41", "", "2404:e80:a137:X11::41"],
    ["", "openmesh-ab-38", "wifi-roam", "", "B / 11", "", "", "", 20,
     "AC:86:74:0D:AB:3B", "10.X.20.41", "", "2404:e80:a137:X20::41"],
    ["", "openmesh-ab-38", "wifi-guest", "", "C / 12", "", "", "", 99,
     "AC:86:74:0D:AB:3C", "10.X.99.41", "", "2404:e80:a137:X99::41"],
    ["", "openmesh-ab-38", "wifi-iot", "", "D / 13", "", "", "", 90,
     "AC:86:74:0D:AB:3D", "10.X.90.41", "", "2404:e80:a137:X90::41"],
    ["", "openmesh-ab-38", "wifi-raw", "", "F / 15", "", "", "", "Q",
     "AC:86:74:0D:AB:3F", "10.X.12.41", "", "2404:e80:a137:X12::41"],
    ["", "openmesh-94-98", "lan",
     "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627552",
     8, "Monarto - Purple Bedroom", "", "", "Q", "AC:86:74:07:94:98",
     "10.X.5.42", "", "2404:e80:a137:X05::42"],
    ["", "openmesh-94-98", "poe", "", 9, "", "", "", "Q",
     "AC:86:74:07:94:99", "10.X.10.42", "", "2404:e80:a137:X10::42"],
    ["", "openmesh-94-98", "manage", "", "A / 10", "", "", "", "Q",
     "AC:86:74:07:94:9A", "10.X.11.42", "", "2404:e80:a137:X11::42"],
    ["", "openmesh-94-98", "wifi-roam", "", "B / 11", "", "", "", 20,
     "AC:86:74:07:94:9B", "10.X.20.42", "", "2404:e80:a137:X20::42"],
    ["", "openmesh-94-98", "wifi-guest", "", "C / 12", "", "", "", 99,
     "AC:86:74:07:94:9C", "10.X.99.42", "", "2404:e80:a137:X99::42"],
    ["", "openmesh-94-98", "wifi-iot", "", "D / 13", "", "", "", 90,
     "AC:86:74:07:94:9D", "10.X.90.42", "", "2404:e80:a137:X90::42"],
    ["", "openmesh-94-98", "wifi-raw", "", "F / 15", "", "", "", "Q",
     "AC:86:74:07:94:9F", "10.X.12.42", "", "2404:e80:a137:X12::42"],
    ["", "openmesh-95-80", "lan",
     "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627519",
     0, "Monarto - Back Corner Room", "", "", 5, "AC:86:74:07:95:80",
     "10.X.5.43", "", "2404:e80:a137:X05::43"],
    ["", "openmesh-95-80", "poe", "", 1, "", "", "", 10,
     "AC:86:74:07:95:81", "10.X.10.43", "", "2404:e80:a137:X10::43"],
    ["", "openmesh-95-80", "manage", "", 2, "", "", "", 10,
     "AC:86:74:07:95:82", "10.X.11.43", "", "2404:e80:a137:X11::43"],
    ["", "openmesh-95-80", "wifi-roam", "", 3, "", "", "", 20,
     "AC:86:74:07:95:83", "10.X.20.43", "", "2404:e80:a137:X20::43"],
    ["", "openmesh-95-80", "wifi-guest", "", 4, "", "", "", 99,
     "AC:86:74:07:95:84", "10.X.99.43", "", "2404:e80:a137:X99::43"],
    ["", "openmesh-95-80", "wifi-iot", "", 5, "", "", "", 90,
     "AC:86:74:07:95:85", "10.X.90.43", "", "2404:e80:a137:X90::43"],
    ["", "openmesh-95-80", "wifi-raw", "", 7, "", "", "", "Q",
     "AC:86:74:07:95:87", "10.X.12.43", "", "2404:e80:a137:X12::43"],
    ["", "openmesh-95-88", "lan",
     "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627520",
     8, "Monarto - Back Door near Shed", "", "", 5, "AC:86:74:07:95:88",
     "10.X.5.44", "", "2404:e80:a137:X05::44"],
    ["", "openmesh-95-88", "poe", "", 9, "", "", "", 10,
     "AC:86:74:07:95:89", "10.X.10.44", "", "2404:e80:a137:X10::44"],
    ["", "openmesh-95-88", "manage", "", "A / 10", "", "", "", 10,
     "AC:86:74:07:95:8A", "10.X.11.44", "", "2404:e80:a137:X11::44"],
    ["", "openmesh-95-88", "wifi-roam", "", "B / 11", "", "", "", 20,
     "AC:86:74:07:95:8B", "10.X.20.44", "", "2404:e80:a137:X20::44"],
    ["", "openmesh-95-88", "wifi-guest", "", "C / 12", "", "", "", 99,
     "AC:86:74:07:95:8C", "10.X.99.44", "", "2404:e80:a137:X99::44"],
    ["", "openmesh-95-88", "wifi-iot", "", "D / 13", "", "", "", 90,
     "AC:86:74:07:95:8D", "10.X.90.44", "", "2404:e80:a137:X90::44"],
    ["", "openmesh-95-88", "wifi-raw", "", "F / 15", "", "", "", "Q",
     "AC:86:74:07:95:8F", "10.X.12.44", "", "2404:e80:a137:X12::44"],
    ["", "openmesh-96-00", "lan",
     "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627521",
     0, "Welland - Back Shed", "", "", 5, "AC:86:74:07:96:00",
     "10.X.5.45", "", "2404:e80:a137:X05::45"],
    ["", "openmesh-96-00", "poe", "", 1, "", "", "", 10,
     "AC:86:74:07:96:01", "10.X.10.45", "", "2404:e80:a137:X10::45"],
    ["", "openmesh-96-00", "manage", "", 2, "", "", "", 10,
     "AC:86:74:07:96:02", "10.X.11.45", "", "2404:e80:a137:X11::45"],
    ["", "openmesh-96-00", "wifi-roam", "", 3, "", "", "", 20,
     "AC:86:74:07:96:03", "10.X.20.45", "", "2404:e80:a137:X20::45"],
    ["", "openmesh-96-00", "wifi-guest", "", 4, "", "", "", 99,
     "AC:86:74:07:96:04", "10.X.99.45", "", "2404:e80:a137:X99::45"],
    ["", "openmesh-96-00", "wifi-iot", "", 5, "", "", "", 90,
     "AC:86:74:07:96:05", "10.X.90.45", "", "2404:e80:a137:X90::45"],
    ["", "openmesh-96-00", "wifi-raw", "", 7, "", "", "", "Q",
     "AC:86:74:07:96:07", "10.X.12.45", "", "2404:e80:a137:X12::45"],
]

# The six VLAN-4 infra source rows (site-literal MACs/IPs, live facts from
# the design doc: welland 02:00:0a:01:04:0N / 10.1.4.N, monarto
# 02:00:0a:02:04:0N / 10.2.4.N). welland/tenwrt's VLAN cell is deliberately
# the STRING "4" (not the int 4) to prove build_infra_rows' type-agnostic
# coercion; every other row uses the int, matching the live sheet's mixed
# column.
INFRA_IP_ALLOC_ROWS = [
    ["welland", "ten64", "br-wifi", "", "", "", "", "", 4,
     "02:00:0a:01:04:01", "10.1.4.1"],
    ["welland", "wisp", "", "", "", "", "", "", 4,
     "02:00:0a:01:04:02", "10.1.4.2"],
    ["welland", "tenwrt", "", "", "", "", "", "", "4",
     "02:00:0a:01:04:03", "10.1.4.3"],
    ["monarto", "ten64", "br-wifi", "", "", "", "", "", 4,
     "02:00:0a:02:04:01", "10.2.4.1"],
    ["monarto", "wisp", "", "", "", "", "", "", 4,
     "02:00:0a:02:04:02", "10.2.4.2"],
    ["monarto", "tenwrt", "", "", "", "", "", "", 4,
     "02:00:0a:02:04:03", "10.2.4.3"],
]

INFRA_IP_ALLOC_VALUES = [IP_ALLOC_HEADER] + [row[:] for row in INFRA_IP_ALLOC_ROWS]

# STOCK_IP_ALLOC_VALUES gains the infra rows too -- compute_new_tab_rows now
# always appends build_infra_rows' output, which fails loud without a
# matching source row for all six (site, machine) pairs.
STOCK_IP_ALLOC_VALUES = STOCK_IP_ALLOC_VALUES + [row[:] for row in INFRA_IP_ALLOC_ROWS]

FULL_IP_ALLOC_WITH_NODES = (
    [IP_ALLOC_HEADER]
    + GOOGLE_NODE_VALUES
    + [row[:] for row in FULL_IP_ALLOC_VALUES[1:]]
    + [row[:] for row in INFRA_IP_ALLOC_ROWS]
)


# ---------------------------------------------------------------------------
# col_letter / header_index
# ---------------------------------------------------------------------------


class TestColLetter:
    def test_first_columns(self):
        assert wsm.col_letter(0) == "A"
        assert wsm.col_letter(1) == "B"
        assert wsm.col_letter(25) == "Z"

    def test_double_letter_wrap(self):
        assert wsm.col_letter(26) == "AA"
        assert wsm.col_letter(27) == "AB"
        assert wsm.col_letter(701) == "ZZ"

    def test_negative_rejected(self):
        with pytest.raises(ValueError, match=">= 0"):
            wsm.col_letter(-1)


class TestHeaderIndex:
    def test_found(self):
        assert wsm.header_index(["Machine", "MAC"], "MAC", sheet_label="x") == 1

    def test_missing_fails_loud(self):
        with pytest.raises(ValueError, match="Flash Tab.*Firmware"):
            wsm.header_index(["Name"], "Firmware", sheet_label="Flash Tab")


# ---------------------------------------------------------------------------
# build_puck_rows -- OpenWRT filter + golden row
# ---------------------------------------------------------------------------


class TestBuildPuckRows:
    def test_google_original_row_produces_no_output(self):
        # Only the stock row (Firmware="Google Original") in isolation.
        stock_only = [FLASH_HEADER, FLASH_VALUES[1]]
        assert wsm.build_puck_rows(stock_only, start_row=2) == []

    def test_only_openwrt_rows_produce_output(self):
        rows = wsm.build_puck_rows(FLASH_VALUES, start_row=2)
        # 1 OpenWRT puck (#4) -> exactly 2 rows (wan, lan); the stock row
        # contributes nothing.
        assert len(rows) == 2

    def test_puck04_wan_row_golden(self):
        rows = wsm.build_puck_rows(FLASH_VALUES, start_row=2)
        wan_row = rows[0]
        assert wan_row == [
            "4",  # #
            '="puck"&TEXT($A2,"00")',  # Name
            '="puck"&TEXT($A2,"00")',  # Machine
            "wan",  # Interface
            "=IFERROR(INDEX('Google WiFi Pucks'!O:O,"
            "MATCH($A2,'Google WiFi Pucks'!E:E,0)),\"\")",  # MAC Address
            '="10.X.4."&(100+$A2)',  # IP
            "DHCP:wisp",  # Type
            "welland",  # Site
            "=IFERROR(INDEX('Google WiFi Pucks'!B:B,"
            "MATCH($A2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Physical Location
            "gale",  # Hardware
            "=IFERROR(INDEX('Google WiFi Pucks'!C:C,"
            "MATCH($A2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Upstream
            "=IFERROR(INDEX('Google WiFi Pucks'!D:D,"
            "MATCH($A2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Controlled By
            "=IFERROR(INDEX('Google WiFi Pucks'!H:H,"
            "MATCH($A2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Serial
            "",  # Notes / Comments
        ]

    def test_puck04_lan_row_uses_lan_column_and_next_row(self):
        rows = wsm.build_puck_rows(FLASH_VALUES, start_row=2)
        lan_row = rows[1]
        assert lan_row[3] == "lan"
        assert lan_row[4] == (
            "=IFERROR(INDEX('Google WiFi Pucks'!P:P,"
            "MATCH($A3,'Google WiFi Pucks'!E:E,0)),\"\")"
        )
        assert lan_row[5] == '="10.X.4."&(100+$A3)'
        assert lan_row[0] == "4"

    def test_start_row_offsets_all_formulas(self):
        rows = wsm.build_puck_rows(FLASH_VALUES, start_row=10)
        assert "$A10" in rows[0][4]
        assert "$A11" in rows[1][4]

    def test_missing_hash_value_fails_loud(self):
        broken = [
            FLASH_HEADER,
            ["", "", "", "", "", "AC-1304", "OpenWRT", "SERIAL1",
             "", "", "", "aa:bb:cc:dd:ee:01", "", "", "aa:bb:cc:dd:ee:01",
             "aa:bb:cc:dd:ee:02"],
        ]
        with pytest.raises(ValueError, match="missing '#' value"):
            wsm.build_puck_rows(broken, start_row=2)

    def test_missing_required_column_fails_loud(self):
        with pytest.raises(ValueError, match="Google WiFi Pucks.*Firmware"):
            wsm.build_puck_rows([["Name", "#"]], start_row=2)

    def test_empty_flash_tab_fails_loud(self):
        with pytest.raises(ValueError, match="empty"):
            wsm.build_puck_rows([], start_row=2)


# ---------------------------------------------------------------------------
# build_openmesh_rows -- golden row + hardware-map fail-loud
# ---------------------------------------------------------------------------


class TestBuildOpenmeshRows:
    def test_filters_to_openmesh_machines_only(self):
        rows = wsm.build_openmesh_rows(IP_ALLOC_VALUES, HARDWARE_MAP)
        # 7 openmesh-ab-30 rows; node3-wifi-google and tplink-powerline
        # rows excluded.
        assert len(rows) == 7
        assert all(row[2] == "openmesh-ab-30" for row in rows)

    def test_openmesh_ab_30_first_row_golden(self):
        rows = wsm.build_openmesh_rows(IP_ALLOC_VALUES, HARDWARE_MAP)
        assert rows[0] == [
            "",  # #
            "",  # Name
            "openmesh-ab-30",  # Machine
            "lan",  # Interface
            "AC:86:74:0D:AB:30",  # MAC Address
            "10.X.5.40",  # IP
            "",  # Type
            "monarto",  # Site (overlaid from OPENMESH_SITE_BY_MACHINE, not the source cell)
            "Monarto - Power Meter Box",  # Physical Location
            "OM2P-LC",  # Hardware
            "",  # Upstream
            "",  # Controlled By
            "",  # Serial
            "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627518",  # Notes
        ]

    def test_subsequent_rows_have_no_location_or_notes(self):
        rows = wsm.build_openmesh_rows(IP_ALLOC_VALUES, HARDWARE_MAP)
        poe_row = rows[1]
        assert poe_row[3] == "poe"
        assert poe_row[8] == ""  # Physical Location blank for non-first rows
        assert poe_row[13] == ""  # Notes blank too

    def test_unmapped_machine_fails_loud(self):
        with pytest.raises(ValueError, match="openmesh-ab-30.*hardware-map"):
            wsm.build_openmesh_rows(IP_ALLOC_VALUES, hardware_map={})

    def test_missing_required_column_fails_loud(self):
        with pytest.raises(ValueError, match="Welland - IP Allocation.*Machine"):
            wsm.build_openmesh_rows([["Site"]], HARDWARE_MAP)

    def test_empty_tab_fails_loud(self):
        with pytest.raises(ValueError, match="empty"):
            wsm.build_openmesh_rows([], HARDWARE_MAP)

    def test_formula_cell_fails_loud(self):
        # If ip_alloc_values were fetched with render=FORMULA instead of
        # UNFORMATTED_VALUE, a formula cell would be pasted as a live
        # formula via USER_ENTERED and silently re-evaluate in the new tab.
        # This is the backstop that catches it.
        poisoned = [
            IP_ALLOC_HEADER,
            ["", "openmesh-ab-30", "lan", "", 0,
             "='Some Other Tab'!A1",  # Location cell holding a live formula
             "", "", 5, "AC:86:74:0D:AB:30", "10.X.5.40", "",
             "2404:e80:a137:X05::40"],
        ]
        with pytest.raises(ValueError, match="live formula.*UNFORMATTED_VALUE"):
            wsm.build_openmesh_rows(poisoned, HARDWARE_MAP)


# ---------------------------------------------------------------------------
# compute_new_tab_rows -- puck rows + openmesh rows combined
# ---------------------------------------------------------------------------


class TestComputeNewTabRows:
    def test_openmesh_start_row_follows_all_puck_rows(self):
        rows, openmesh_start_row = wsm.compute_new_tab_rows(
            FLASH_VALUES, STOCK_IP_ALLOC_VALUES, HARDWARE_MAP
        )
        # 2 fleet-puck rows (rows 2-3) then openmesh starts at row 4 --
        # the node*-wifi-google blocks in the source contribute NOTHING
        # (pucks 01-03 are ordinary OpenWRT flash-tab rows since
        # 2026-07-25). 7 OpenMesh rows (openmesh-ab-30) + 6 infra rows
        # (ten64/wisp/tenwrt at both sites) follow.
        assert openmesh_start_row == 4
        assert len(rows) == 2 + 7 + 6
        assert rows[2][2] == "openmesh-ab-30"

    def test_infra_rows_appended_after_openmesh_block(self):
        rows, openmesh_start_row = wsm.compute_new_tab_rows(
            FLASH_VALUES, STOCK_IP_ALLOC_VALUES, HARDWARE_MAP
        )
        machine_col = wsm.NEW_TAB_HEADER.index("Machine")
        # 2 puck rows + 7 openmesh rows, then the 6 infra rows.
        infra_machines = [row[machine_col] for row in rows[9:15]]
        assert infra_machines == ["ten64", "wisp", "tenwrt", "ten64", "wisp", "tenwrt"]
        assert len(rows) == 15  # nothing left over


class TestOpenmeshSiteOverlay:
    """Every OpenMesh row (all 42, across all 6 blocks) carries its
    machine's site from OPENMESH_SITE_BY_MACHINE, not the (today mostly
    blank) source Site cell -- see build_openmesh_rows."""

    FULL_HARDWARE_MAP = {m: "OM2P" for m in wsm.OPENMESH_MACHINES_IN_ORDER}

    def test_openmesh_site_by_machine_contract(self):
        assert wsm.OPENMESH_SITE_BY_MACHINE == {
            "openmesh-ab-38": "welland",
            "openmesh-96-00": "welland",
            "openmesh-ab-30": "monarto",
            "openmesh-94-98": "monarto",
            "openmesh-95-80": "monarto",
            "openmesh-95-88": "monarto",
        }

    def test_every_row_of_every_block_carries_its_machines_site(self):
        rows, openmesh_start_row = wsm.compute_new_tab_rows(
            FLASH_VALUES, FULL_IP_ALLOC_WITH_NODES, self.FULL_HARDWARE_MAP
        )
        machine_col = wsm.NEW_TAB_HEADER.index("Machine")
        site_col = wsm.NEW_TAB_HEADER.index("Site")
        openmesh_rows = rows[openmesh_start_row - 2 : openmesh_start_row - 2 + 42]
        assert len(openmesh_rows) == 42
        for row in openmesh_rows:
            machine = row[machine_col]
            assert row[site_col] == wsm.OPENMESH_SITE_BY_MACHINE[machine], (
                f"{machine}: expected {wsm.OPENMESH_SITE_BY_MACHINE[machine]!r}, "
                f"got {row[site_col]!r}"
            )

    def test_unmapped_openmesh_machine_fails_loud(self):
        rows = [
            IP_ALLOC_HEADER,
            ["", "openmesh-unknown-machine", "lan", "", 0, "Somewhere", "", "", 5,
             "AC:86:74:0D:FF:FF", "10.X.5.99", "", "2404:e80:a137:X05::99"],
        ]
        with pytest.raises(ValueError, match="openmesh-unknown-machine"):
            wsm.build_openmesh_rows(rows, {"openmesh-unknown-machine": "OM2P"})


# ---------------------------------------------------------------------------
# build_infra_rows -- six-row VLAN-4 infra block (task 6b/6d)
# ---------------------------------------------------------------------------


class TestBuildInfraRows:
    def test_six_rows_site_then_machine_order(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        machine_col = wsm.NEW_TAB_HEADER.index("Machine")
        site_col = wsm.NEW_TAB_HEADER.index("Site")
        assert [(r[site_col], r[machine_col]) for r in rows] == [
            ("welland", "ten64"),
            ("welland", "wisp"),
            ("welland", "tenwrt"),
            ("monarto", "ten64"),
            ("monarto", "wisp"),
            ("monarto", "tenwrt"),
        ]

    def test_interface_only_on_ten64_rows(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        machine_col = wsm.NEW_TAB_HEADER.index("Machine")
        interface_col = wsm.NEW_TAB_HEADER.index("Interface")
        for row in rows:
            if row[machine_col] == "ten64":
                assert row[interface_col] == "br-wifi"
            else:
                assert row[interface_col] == ""

    def test_type_static_except_tenwrt_dhcp_wisp(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        machine_col = wsm.NEW_TAB_HEADER.index("Machine")
        type_col = wsm.NEW_TAB_HEADER.index("Type")
        for row in rows:
            if row[machine_col] == "tenwrt":
                assert row[type_col] == "DHCP:wisp"
            else:
                assert row[type_col] == "static"

    def test_literals_for_location_hardware_controlled_by(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        machine_col = wsm.NEW_TAB_HEADER.index("Machine")
        loc_col = wsm.NEW_TAB_HEADER.index("Physical Location")
        hw_col = wsm.NEW_TAB_HEADER.index("Hardware")
        cb_col = wsm.NEW_TAB_HEADER.index("Controlled By")
        by_machine = {row[machine_col]: row for row in rows}
        assert by_machine["ten64"][loc_col] == "ten64"
        assert by_machine["wisp"][loc_col] == "ten64 (VM)"
        assert by_machine["tenwrt"][loc_col] == "ten64 (VM)"
        assert by_machine["ten64"][hw_col] == "Ten64"
        assert by_machine["wisp"][hw_col] == "QEMU VM"
        assert by_machine["tenwrt"][hw_col] == "QEMU VM"
        assert by_machine["ten64"][cb_col] == ""
        assert by_machine["wisp"][cb_col] == "ten64 libvirt"
        assert by_machine["tenwrt"][cb_col] == "ten64 libvirt"

    def test_hash_name_serial_notes_blank(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        for col_name in ("#", "Name", "Serial", "Notes / Comments"):
            col = wsm.NEW_TAB_HEADER.index(col_name)
            for row in rows:
                assert row[col] == ""

    def test_mac_and_ip_are_formulas_with_no_fixed_row(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        mac_col = wsm.NEW_TAB_HEADER.index("MAC Address")
        ip_col = wsm.NEW_TAB_HEADER.index("IP")
        # IP_ALLOC_HEADER: Site=A, Machine=B, VLAN=I, MAC Address=J, IPv4=K.
        for row in rows:
            for formula in (row[mac_col], row[ip_col]):
                assert formula.startswith("=")
                assert "'Welland - IP Allocation'" in formula
                # Whole-column references only (letters, no digits) --
                # never a fixed row number.
                assert not re.search(
                    r"'Welland - IP Allocation'!\$?[A-Za-z]+\$?\d", formula
                )
        assert "J:J" in rows[0][mac_col]  # MAC Address column
        assert "K:K" in rows[0][ip_col]  # IPv4 column

    def test_mac_formula_matches_site_and_machine_and_vlan4(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        machine_col = wsm.NEW_TAB_HEADER.index("Machine")
        site_col = wsm.NEW_TAB_HEADER.index("Site")
        mac_col = wsm.NEW_TAB_HEADER.index("MAC Address")
        wisp_welland = next(
            r for r in rows if r[machine_col] == "wisp" and r[site_col] == "welland"
        )
        formula = wisp_welland[mac_col]
        assert 'A:A="welland"' in formula  # Site col
        assert 'B:B="wisp"' in formula  # Machine col

    def test_vlan_criterion_uses_type_agnostic_coercion(self):
        rows = wsm.build_infra_rows(INFRA_IP_ALLOC_VALUES)
        mac_col = wsm.NEW_TAB_HEADER.index("MAC Address")
        for row in rows:
            assert '&""="4"' in row[mac_col]

    def test_missing_source_row_fails_loud(self):
        # Drop the monarto/tenwrt row -- build_infra_rows must refuse to
        # emit a formula for a pair with no matching source row (it would
        # silently evaluate to #N/A).
        rows = [
            row
            for row in INFRA_IP_ALLOC_VALUES
            if not (row[0] == "monarto" and row[1] == "tenwrt")
        ]
        with pytest.raises(ValueError, match=r"monarto.*tenwrt"):
            wsm.build_infra_rows(rows)

    def test_empty_tab_fails_loud(self):
        with pytest.raises(ValueError, match="empty"):
            wsm.build_infra_rows([])


# ---------------------------------------------------------------------------
# grid_growth_requests -- populate's grid-too-small guard (task 6c)
# ---------------------------------------------------------------------------


class TestGridGrowthRequests:
    def test_no_growth_needed_returns_empty(self):
        assert wsm.grid_growth_requests(42, current_row_count=100, needed_rows=100) == []

    def test_grid_already_larger_returns_empty(self):
        assert wsm.grid_growth_requests(42, current_row_count=100, needed_rows=50) == []

    def test_growth_needed_returns_append_dimension_request(self):
        reqs = wsm.grid_growth_requests(42, current_row_count=61, needed_rows=67)
        assert reqs == [
            {"appendDimension": {"sheetId": 42, "dimension": "ROWS", "length": 6}}
        ]


# ---------------------------------------------------------------------------
# Rewrite-target + delete-range pure computations
# ---------------------------------------------------------------------------


class TestOpenmeshBlockFirstRows:
    def test_six_blocks_of_seven(self):
        assert wsm.openmesh_block_first_rows(20, 7, 6) == [20, 27, 34, 41, 48, 55]

    def test_matches_live_delete_range_first_row(self):
        # Live scan (2026-07-24): openmesh-ab-30 starts at row 337 in the
        # OLD sheet; blocks are 7 rows apart there too.
        assert wsm.openmesh_block_first_rows(337, 7, 6) == [
            337, 344, 351, 358, 365, 372
        ]


class TestOpenmeshDeleteRange:
    def test_matches_live_sheet_range(self):
        # Live-verified (2026-07-24): the 6 OpenMesh blocks in
        # 'Welland - IP Allocation' span rows 337-378 inclusive.
        assert wsm.openmesh_delete_range(337, 7, 6) == (337, 378)

    def test_single_block(self):
        assert wsm.openmesh_delete_range(10, 7, 1) == (10, 16)


class TestComputeTrailingClearRange:
    """populate's re-run idempotency: clear stale rows below a shrunk write."""

    def test_no_trailing_content_returns_none(self):
        assert wsm.compute_trailing_clear_range(existing_row_count=10, new_last_row=10) is None

    def test_existing_shorter_than_new_returns_none(self):
        # Growing (more pucks/APs than last time) -- nothing stale to clear.
        assert wsm.compute_trailing_clear_range(existing_row_count=10, new_last_row=61) is None

    def test_existing_longer_than_new_returns_trailing_range(self):
        # Shrinking (a puck/AP removed since the last populate run).
        assert wsm.compute_trailing_clear_range(existing_row_count=65, new_last_row=61) == (
            62,
            65,
        )

    def test_single_stale_row(self):
        assert wsm.compute_trailing_clear_range(existing_row_count=61, new_last_row=60) == (
            61,
            61,
        )


class TestValidateOpenmeshRange:
    """delete-old-rows' stale-snapshot-position guard."""

    def test_clean_range_has_no_violations(self):
        machine_col = IP_ALLOC_HEADER.index("Machine")
        violations = wsm.validate_openmesh_range(FULL_IP_ALLOC_VALUES, machine_col, 2, 43)
        assert violations == []

    def test_non_openmesh_row_inside_range_is_a_violation(self):
        machine_col = IP_ALLOC_HEADER.index("Machine")
        rows = [row[:] for row in FULL_IP_ALLOC_VALUES]
        rows[5] = ["", "some-other-machine", "eth0"]  # was openmesh-ab-30 row
        violations = wsm.validate_openmesh_range(rows, machine_col, 2, 43)
        assert len(violations) == 1
        assert "row 6" in violations[0]
        assert "not an OpenMesh row" in violations[0]

    def test_openmesh_row_outside_range_is_a_violation(self):
        machine_col = IP_ALLOC_HEADER.index("Machine")
        rows = [
            IP_ALLOC_HEADER,
            ["", "not-openmesh", "eth0"],  # row 2 -- outside the range below
            ["", "openmesh-in-range", "lan"],  # row 3 -- inside [3, 3]
            ["", "openmesh-leaked-out", "lan"],  # row 4 -- OUTSIDE [3, 3]
        ]
        violations = wsm.validate_openmesh_range(rows, machine_col, first_row=3, last_row=3)
        assert len(violations) == 1
        assert "row 4" in violations[0]
        assert "OUTSIDE the delete range" in violations[0]

    def test_row_shift_detected(self):
        # Simulates the exact scenario the coordinator flagged: rows shifted
        # (one row inserted before the block) so the snapshot's [first,last]
        # no longer lines up with the real OpenMesh rows.
        machine_col = IP_ALLOC_HEADER.index("Machine")
        shifted = [FULL_IP_ALLOC_VALUES[0], ["", "new-inserted-machine", ""]] + (
            FULL_IP_ALLOC_VALUES[1:]
        )
        # Snapshot still thinks OpenMesh starts at row 2 (the stale position).
        violations = wsm.validate_openmesh_range(shifted, machine_col, 2, 43)
        assert violations  # drift detected, not silently accepted


class TestValidateOpenmeshBlockShape:
    """populate/rewrite-refs' block order+contiguity+size guard."""

    def test_clean_six_blocks_has_no_violations(self):
        assert wsm.validate_openmesh_block_shape(FULL_IP_ALLOC_VALUES, first_row=2) == []

    def test_wrong_machine_at_a_slot_is_detected(self):
        rows = [row[:] for row in FULL_IP_ALLOC_VALUES]
        rows[1][1] = "openmesh-wrong-machine"  # was openmesh-ab-30's first row
        violations = wsm.validate_openmesh_block_shape(rows, first_row=2)
        assert any("row 2" in v and "openmesh-ab-30" in v for v in violations)

    def test_out_of_order_blocks_detected(self):
        # Swap the first two blocks' machine names -- contiguity/size intact,
        # but the ORDER OPENMESH_MACHINES_IN_ORDER assumes is now wrong.
        rows = [row[:] for row in FULL_IP_ALLOC_VALUES]
        for i in range(1, 8):
            rows[i][1], rows[i + 7][1] = rows[i + 7][1], rows[i][1]
        violations = wsm.validate_openmesh_block_shape(rows, first_row=2)
        assert len(violations) >= 14  # both swapped blocks' 7 rows each mismatch

    def test_short_block_detected(self):
        # Delete one row from the first block -- everything after shifts up
        # by one, breaking the assumed 7-row block size/contiguity.
        rows = [row[:] for row in FULL_IP_ALLOC_VALUES]
        del rows[2]  # remove openmesh-ab-30's 'poe' row
        violations = wsm.validate_openmesh_block_shape(rows, first_row=2)
        assert violations

    def test_extra_openmesh_row_outside_span_detected(self):
        rows = [row[:] for row in FULL_IP_ALLOC_VALUES]
        rows.append(["", "openmesh-extra-unexpected", "lan"])
        violations = wsm.validate_openmesh_block_shape(rows, first_row=2)
        assert any("openmesh-extra-unexpected" in v for v in violations)

    def test_missing_header_fails_loud(self):
        with pytest.raises(ValueError, match="Welland - IP Allocation.*Machine"):
            wsm.validate_openmesh_block_shape([["Site"]], first_row=2)

    def test_empty_tab_fails_loud(self):
        with pytest.raises(ValueError, match="empty"):
            wsm.validate_openmesh_block_shape([], first_row=2)


class TestValidateGoogleNodeBlockShape:
    """populate/delete-old-rows' guard for the node*-wifi-google blocks."""

    def test_clean_three_blocks_has_no_violations(self):
        values = [IP_ALLOC_HEADER] + GOOGLE_NODE_VALUES
        assert wsm.validate_google_node_block_shape(values, first_row=2) == []

    def test_wrong_machine_at_a_slot_is_detected(self):
        values = [IP_ALLOC_HEADER] + [row[:] for row in GOOGLE_NODE_VALUES]
        values[1][1] = "node9-wifi-google"  # was node1-wifi-google's first row
        violations = wsm.validate_google_node_block_shape(values, first_row=2)
        assert any("row 2" in v and "node1-wifi-google" in v for v in violations)

    def test_node_row_outside_span_detected(self):
        values = [IP_ALLOC_HEADER] + [row[:] for row in GOOGLE_NODE_VALUES]
        values.append(["", "node2-wifi-google", "stray"])
        violations = wsm.validate_google_node_block_shape(values, first_row=2)
        assert any("OUTSIDE the delete range" in v for v in violations)


class TestSnapshotDeleteRanges:
    SNAPSHOT = {
        "ip_alloc_openmesh_first_row": 337,
        "ip_alloc_openmesh_block_size": 7,
        "ip_alloc_openmesh_num_blocks": 6,
        "ip_alloc_google_first_row": 312,
        "ip_alloc_google_block_size": 8,
        "ip_alloc_google_num_blocks": 3,
    }

    def test_live_snapshot_yields_both_ranges(self):
        assert wsm.snapshot_delete_ranges(self.SNAPSHOT) == [
            ("OpenMesh", 337, 378),
            ("node*-wifi-google", 312, 335),
        ]

    def test_pre_stock_puck_snapshot_fails_loud(self):
        stale = {k: v for k, v in self.SNAPSHOT.items() if not k.startswith("ip_alloc_google")}
        with pytest.raises(KeyError):
            wsm.snapshot_delete_ranges(stale)

    def test_every_range_has_a_validator(self):
        labels = {label for label, _f, _l in wsm.snapshot_delete_ranges(self.SNAPSHOT)}
        assert labels == set(wsm._RANGE_VALIDATORS)


class TestRewriteRefFormulas:
    def test_maps_all_six_iot_rows(self):
        formulas = wsm.rewrite_ref_formulas(20)
        assert set(formulas) == set(wsm.IOT_REF_ROWS)

    def test_formula_targets_correct_new_tab_cell(self):
        formulas = wsm.rewrite_ref_formulas(20)
        assert formulas[24] == "='wifi.welland - WiFi Infrastructure'!I20"
        assert formulas[25] == "='wifi.welland - WiFi Infrastructure'!I27"
        assert formulas[29] == "='wifi.welland - WiFi Infrastructure'!I55"

    def test_consistent_with_compute_new_tab_rows(self):
        _, openmesh_start_row = wsm.compute_new_tab_rows(
            FLASH_VALUES, STOCK_IP_ALLOC_VALUES, HARDWARE_MAP
        )
        formulas = wsm.rewrite_ref_formulas(openmesh_start_row)
        # openmesh-ab-30 (first machine) starts at row 4 in this fixture's
        # new tab; that's exactly where rows[2] (build_openmesh_rows[0])
        # landed.
        assert formulas[24] == "='wifi.welland - WiFi Infrastructure'!I4"


class TestValidateNewTabOpenmeshPositions:
    """rewrite-refs' guard that the NEW tab actually has what it's about to
    point iot.welland's formulas at."""

    FULL_HARDWARE_MAP = {m: "OM2P" for m in wsm.OPENMESH_MACHINES_IN_ORDER}

    def _new_tab_values(self):
        rows, openmesh_start_row = wsm.compute_new_tab_rows(
            FLASH_VALUES, FULL_IP_ALLOC_WITH_NODES, self.FULL_HARDWARE_MAP
        )
        return [list(wsm.NEW_TAB_HEADER)] + rows, openmesh_start_row

    def test_clean_new_tab_has_no_violations(self):
        new_tab_values, openmesh_start_row = self._new_tab_values()
        assert (
            wsm.validate_new_tab_openmesh_positions(new_tab_values, openmesh_start_row) == []
        )

    def test_wrong_machine_at_position_detected(self):
        new_tab_values, openmesh_start_row = self._new_tab_values()
        idx = openmesh_start_row - 1  # 0-based index of the first OpenMesh row
        new_tab_values[idx] = list(new_tab_values[idx])
        new_tab_values[idx][2] = "openmesh-wrong"  # was openmesh-ab-30 (Machine col)
        violations = wsm.validate_new_tab_openmesh_positions(new_tab_values, openmesh_start_row)
        assert len(violations) == 1
        assert "openmesh-ab-30" in violations[0]
        assert "openmesh-wrong" in violations[0]

    def test_missing_rows_detected(self):
        new_tab_values, openmesh_start_row = self._new_tab_values()
        # Slice to just BEFORE the first OpenMesh row (index openmesh_start_row
        # - 1) so every expected block-first-row is now out of bounds.
        truncated = new_tab_values[: openmesh_start_row - 1]
        violations = wsm.validate_new_tab_openmesh_positions(truncated, openmesh_start_row)
        assert len(violations) == len(wsm.OPENMESH_MACHINES_IN_ORDER)

    def test_empty_new_tab_fails_loud(self):
        with pytest.raises(ValueError, match="empty"):
            wsm.validate_new_tab_openmesh_positions([], openmesh_start_row=2)


# ---------------------------------------------------------------------------
# find_row_index
# ---------------------------------------------------------------------------


class TestFindRowIndex:
    def test_finds_absolute_row_number(self):
        machine_col = IP_ALLOC_HEADER.index("Machine")
        assert wsm.find_row_index(IP_ALLOC_VALUES, machine_col, "openmesh-ab-30") == 3

    def test_not_found_fails_loud(self):
        machine_col = IP_ALLOC_HEADER.index("Machine")
        with pytest.raises(ValueError, match="not found"):
            wsm.find_row_index(IP_ALLOC_VALUES, machine_col, "openmesh-does-not-exist")


# ---------------------------------------------------------------------------
# validate_new_tab_header -- create-phase idempotency check
# ---------------------------------------------------------------------------


class TestValidateNewTabHeader:
    def test_matching_header_ok(self):
        wsm.validate_new_tab_header(list(wsm.NEW_TAB_HEADER))  # no raise

    def test_mismatched_header_fails_loud(self):
        with pytest.raises(ValueError, match="DIFFERENT header"):
            wsm.validate_new_tab_header(["Name", "Machine"])


# ---------------------------------------------------------------------------
# find_formula_refs_into_range / find_ref_errors -- verify-phase scan logic
# ---------------------------------------------------------------------------


class TestFindFormulaRefsIntoRange:
    def test_finds_ref_inside_range(self):
        tab_formulas = {
            "iot.welland - IoT Devices": [
                ["", "", "", "", "", "", "", "='Welland - IP Allocation'!F337"],
            ],
        }
        hits = wsm.find_formula_refs_into_range(
            tab_formulas, "Welland - IP Allocation", 337, 378
        )
        assert len(hits) == 1
        assert "R1C8" in hits[0]

    def test_ignores_ref_outside_range(self):
        tab_formulas = {
            "iot.welland - IoT Devices": [
                ["='Welland - IP Allocation'!B7"],
            ],
        }
        hits = wsm.find_formula_refs_into_range(
            tab_formulas, "Welland - IP Allocation", 337, 378
        )
        assert hits == []

    def test_ignores_refs_to_a_different_tab(self):
        tab_formulas = {
            "some tab": [["='Other Tab'!A337"]],
        }
        hits = wsm.find_formula_refs_into_range(
            tab_formulas, "Welland - IP Allocation", 337, 378
        )
        assert hits == []

    def test_scans_multiple_tabs(self):
        tab_formulas = {
            "tab-a": [["='Welland - IP Allocation'!A340"]],
            "tab-b": [["plain value"], ["='Welland - IP Allocation'!A400"]],
        }
        hits = wsm.find_formula_refs_into_range(
            tab_formulas, "Welland - IP Allocation", 337, 378
        )
        assert len(hits) == 1
        assert hits[0].startswith("tab-a")


class TestFindRefErrors:
    def test_finds_ref_error_cells(self):
        tab_values = {"tab-a": [["ok", "#REF!"], ["also ok"]]}
        hits = wsm.find_ref_errors(tab_values)
        assert len(hits) == 1
        assert "R1C2" in hits[0]

    def test_no_errors_returns_empty(self):
        tab_values = {"tab-a": [["ok", "fine"]]}
        assert wsm.find_ref_errors(tab_values) == []


# ---------------------------------------------------------------------------
# values_to_csv_text + parse_csv -- verify-phase parse check
# ---------------------------------------------------------------------------


class TestValuesToCsvText:
    def test_round_trips_through_parse_csv(self):
        from gdoc2netcfg.sources.parser import parse_csv

        values = [
            list(wsm.NEW_TAB_HEADER),
            ["4", "puck04", "puck04", "wan", "44:07:0B:01:87:B4", "10.1.4.104",
             "DHCP:wisp", "welland", "", "gale", "", "wisp",
             "2831HW00VZA", ""],
        ]
        csv_text = wsm.values_to_csv_text(values)
        records = parse_csv(csv_text, "wifi")
        assert len(records) == 1
        assert records[0].machine == "puck04"
