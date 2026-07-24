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
            '="puck"&TEXT($M2,"00")',  # Name
            '="puck"&TEXT($M2,"00")',  # Machine
            "wan",  # Interface
            "=IFERROR(INDEX('Google WiFi Pucks'!O:O,"
            "MATCH($M2,'Google WiFi Pucks'!E:E,0)),\"\")",  # MAC Address
            '="10.X.4."&(100+$M2)',  # IP
            "DHCP:wisp",  # Type
            "welland",  # Site
            "=IFERROR(INDEX('Google WiFi Pucks'!B:B,"
            "MATCH($M2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Physical Location
            "gale",  # Hardware
            "=IFERROR(INDEX('Google WiFi Pucks'!C:C,"
            "MATCH($M2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Upstream
            "=IFERROR(INDEX('Google WiFi Pucks'!D:D,"
            "MATCH($M2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Controlled By
            "=IFERROR(INDEX('Google WiFi Pucks'!H:H,"
            "MATCH($M2,'Google WiFi Pucks'!E:E,0)),\"\")",  # Serial
            "4",  # #
            "",  # Notes / Comments
        ]

    def test_puck04_lan_row_uses_lan_column_and_next_row(self):
        rows = wsm.build_puck_rows(FLASH_VALUES, start_row=2)
        lan_row = rows[1]
        assert lan_row[2] == "lan"
        assert lan_row[3] == (
            "=IFERROR(INDEX('Google WiFi Pucks'!P:P,"
            "MATCH($M3,'Google WiFi Pucks'!E:E,0)),\"\")"
        )
        assert lan_row[4] == '="10.X.4."&(100+$M3)'
        assert lan_row[12] == "4"

    def test_start_row_offsets_all_formulas(self):
        rows = wsm.build_puck_rows(FLASH_VALUES, start_row=10)
        assert "$M10" in rows[0][3]
        assert "$M11" in rows[1][3]

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
        assert all(row[1] == "openmesh-ab-30" for row in rows)

    def test_openmesh_ab_30_first_row_golden(self):
        rows = wsm.build_openmesh_rows(IP_ALLOC_VALUES, HARDWARE_MAP)
        assert rows[0] == [
            "",  # Name
            "openmesh-ab-30",  # Machine
            "lan",  # Interface
            "AC:86:74:0D:AB:30",  # MAC Address
            "10.X.5.40",  # IP
            "",  # Type
            "",  # Site (preserved blank)
            "Monarto - Power Meter Box",  # Physical Location
            "OM2P-LC",  # Hardware
            "",  # Upstream
            "",  # Controlled By
            "",  # Serial
            "",  # #
            "https://ct4.cloudtrax.com/monitor/nodes?network_id=530264#1627518",  # Notes
        ]

    def test_subsequent_rows_have_no_location_or_notes(self):
        rows = wsm.build_openmesh_rows(IP_ALLOC_VALUES, HARDWARE_MAP)
        poe_row = rows[1]
        assert poe_row[2] == "poe"
        assert poe_row[7] == ""  # Physical Location blank for non-first rows
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


# ---------------------------------------------------------------------------
# compute_new_tab_rows -- puck rows + openmesh rows combined
# ---------------------------------------------------------------------------


class TestComputeNewTabRows:
    def test_openmesh_start_row_follows_all_puck_rows(self):
        rows, openmesh_start_row = wsm.compute_new_tab_rows(
            FLASH_VALUES, IP_ALLOC_VALUES, HARDWARE_MAP
        )
        # 2 puck rows (rows 2-3) then openmesh starts at row 4.
        assert openmesh_start_row == 4
        assert len(rows) == 2 + 7
        assert rows[2][1] == "openmesh-ab-30"


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


class TestRewriteRefFormulas:
    def test_maps_all_six_iot_rows(self):
        formulas = wsm.rewrite_ref_formulas(20)
        assert set(formulas) == set(wsm.IOT_REF_ROWS)

    def test_formula_targets_correct_new_tab_cell(self):
        formulas = wsm.rewrite_ref_formulas(20)
        assert formulas[24] == "='wifi.welland - WiFi Infrastructure'!H20"
        assert formulas[25] == "='wifi.welland - WiFi Infrastructure'!H27"
        assert formulas[29] == "='wifi.welland - WiFi Infrastructure'!H55"

    def test_consistent_with_compute_new_tab_rows(self):
        _, openmesh_start_row = wsm.compute_new_tab_rows(
            FLASH_VALUES, IP_ALLOC_VALUES, HARDWARE_MAP
        )
        formulas = wsm.rewrite_ref_formulas(openmesh_start_row)
        # openmesh-ab-30 (first machine) starts at row 4 in this fixture's
        # new tab; that's exactly what rows[2] (build_openmesh_rows[0])
        # landed at.
        assert formulas[24] == "='wifi.welland - WiFi Infrastructure'!H4"


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
            ["puck04", "puck04", "wan", "44:07:0B:01:87:B4", "10.1.4.104",
             "DHCP:wisp", "welland", "", "gale", "", "wisp",
             "2831HW00VZA", "4", ""],
        ]
        csv_text = wsm.values_to_csv_text(values)
        records = parse_csv(csv_text, "wifi")
        assert len(records) == 1
        assert records[0].machine == "puck04"
