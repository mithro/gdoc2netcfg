#!/usr/bin/env python3
"""Migrate gwifi puck + OpenMesh AP inventory into the `wifi.welland` tab.

See ``docs/superpowers/specs/2026-07-24-wifi-sheet-hosts-and-mqtt-credentials-design.md``
(Part 1) and ``docs/superpowers/plans/2026-07-24-wifi-sheet-hosts-and-mqtt-credentials.md``
(Task 10) for the full design. Summary:

Today, gwifi pucks live only in the ``Google WiFi Pucks`` flash tab (never
read by gdoc2netcfg) and the OpenMesh APs are 7-row interface blocks buried
inside ``Welland - IP Allocation``. This tool builds a new
``wifi.welland - WiFi Infrastructure`` tab that gdoc2netcfg's standard CSV
parser can read directly: puck rows are cross-tab formulas pointing back at
the flash tab (so it stays the single source of truth), and the OpenMesh
rows are copied by value out of the old tab.

Rollout phases (each idempotent; run in this order — this is a live-sheet
migration, NOT something this task/PR performs):

  1. ``create``          — add the new tab + header row (no-op if already
                            present with an identical header).
  2. ``populate``         — write fleet-puck + OpenMesh rows below the
                            header (all pucks incl. 01-03 are OpenWRT
                            flash-tab rows since 2026-07-25), and
                            save a snapshot (``--snapshot``) of iot.welland's
                            evaluated values + the old sheet's OpenMesh row
                            positions, needed by phases 3-4. Refuses if a
                            fresh scan shows the OpenMesh block no longer
                            matches ``OPENMESH_MACHINES_IN_ORDER``'s assumed
                            order/contiguity/7-row shape (see
                            ``validate_openmesh_block_shape``). OpenMesh rows
                            are fetched with ``UNFORMATTED_VALUE`` (not
                            ``FORMULA``) and checked cell-by-cell for stray
                            ``=`` formulas before being copied by value.
                            Idempotent even across a shrinking source: if a
                            previous run left more rows than this run
                            computes, the stale trailing rows are cleared in
                            the same write (see
                            ``compute_trailing_clear_range``).
  3. ``rewrite-refs``     — repoint iot.welland's 6 formulas (rows 24-29,
                            column H) at the new tab's Physical Location
                            cells, using the snapshot from `populate`. First
                            confirms the new tab actually has
                            ``OPENMESH_MACHINES_IN_ORDER``'s machines at the
                            targeted rows (see
                            ``validate_new_tab_openmesh_positions``), then
                            re-runs the OLD-tab block-shape check against a
                            FRESH fetch (rows may have shifted since
                            `populate` ran).
  4. ``delete-old-rows``  — delete the OpenMesh AND node*-wifi-google blocks
                            from ``Welland - IP Allocation``. REFUSES to run
                            unless a fresh formula scan shows zero remaining
                            references into that range (i.e. `rewrite-refs`
                            has actually landed) AND a fresh values fetch
                            confirms the snapshot's row range still holds
                            exactly the OpenMesh rows and nothing else (see
                            ``validate_openmesh_range``) — protects against
                            rows shifting during the rollout hold between
                            `populate` and this phase.
  5. ``verify``           — full formula scan (zero #REF!, zero refs into
                            the deleted range) + confirms iot.welland's
                            evaluated values are unchanged vs the snapshot +
                            confirms the new tab parses via
                            ``gdoc2netcfg.sources.parser.parse_csv``.

Every phase prints a diff of what it intends to change before touching the
spreadsheet; pass ``--dry-run`` to print-only. Running this against the live
spreadsheet is the ROLLOUT — gated on user go-ahead per the plan's
"Rollout runbook" — not part of implementing this tool.

Usage:
    uv run scripts/wifi-sheet-migrate.py create
    uv run scripts/wifi-sheet-migrate.py populate --hardware-map hw.json --snapshot snap.json
    uv run scripts/wifi-sheet-migrate.py rewrite-refs --snapshot snap.json
    uv run scripts/wifi-sheet-migrate.py delete-old-rows --snapshot snap.json
    uv run scripts/wifi-sheet-migrate.py verify --snapshot snap.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account

from gdoc2netcfg.sources.parser import find_header_row, parse_csv

DEFAULT_SPREADSHEET_ID = "1fFm2irzmnLb7RQNmAi4DmAm2_c61wrd5A2j3ZzdqIWE"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
DEFAULT_SA_PATH = Path.home() / ".config" / "gale-fleet" / "sheets-sa.json"
REQUEST_TIMEOUT = 60  # seconds; every network call below is a single small REST request

NEW_TAB_TITLE = "wifi.welland - WiFi Infrastructure"
# Column order matches the LIVE tab: after the initial populate rollout the
# '#' column was moved to column A on the sheet (Sheets rewrote the row
# formulas' $-references to follow). The sheet's order is canonical --
# cmd_create/validate_new_tab_header fail loud on any mismatch, and every
# row builder below emits via _row_from_dict so nothing else in this script
# depends on positions.
NEW_TAB_HEADER = [
    "#",
    "Name",
    "Machine",
    "Interface",
    "MAC Address",
    "IP",
    "Type",
    "Site",
    "Physical Location",
    "Hardware",
    "Upstream",
    "Controlled By",
    "Serial",
    "Notes / Comments",
]

FLASH_TAB_TITLE = "Google WiFi Pucks"
_FLASH_REQUIRED_COLUMNS = [
    "Firmware",
    "#",
    "wan",
    "lan",
    "Location",
    "Upstream",
    "Controlled By",
    "Serial",
]

IP_ALLOC_TAB_TITLE = "Welland - IP Allocation"
_IP_ALLOC_REQUIRED_COLUMNS = [
    "Site",
    "Machine",
    "Interface",
    "MAC Address",
    "IPv4",
    "Location",
    "Controlled By",
    "Serial Number",
    "Notes",
]
OPENMESH_MACHINE_PREFIX = "openmesh-"
OPENMESH_BLOCK_SIZE = 7
# The order these machines appear in Welland - IP Allocation today (rows
# 337, 344, 351, 358, 365, 372) -- and hence the order build_openmesh_rows
# will emit them in, since it preserves source row order.
OPENMESH_MACHINES_IN_ORDER = [
    "openmesh-ab-30",
    "openmesh-ab-38",
    "openmesh-94-98",
    "openmesh-95-80",
    "openmesh-95-88",
    "openmesh-96-00",
]

# The stock Google-firmware pucks' interface blocks in Welland - IP
# Allocation (rows 312-335 today, 8 rows each, contiguous, in this order).
# Migrated to the new tab under the fleet's puckNN naming (user decision,
# 2026-07-25).
GOOGLE_NODE_BLOCK_SIZE = 8
GOOGLE_NODE_MACHINES_IN_ORDER = [
    ("node1-wifi-google", "puck01"),
    ("node2-wifi-google", "puck02"),
    ("node3-wifi-google", "puck03"),
]
GOOGLE_NODE_OLD_NAMES = [old for old, _new in GOOGLE_NODE_MACHINES_IN_ORDER]

IOT_TAB_TITLE = "iot.welland - IoT Devices"
# The 6 formula cells (found by scripts/wifi-sheet-scan.py) referencing the
# OpenMesh block being moved, one per OPENMESH_MACHINES_IN_ORDER entry.
IOT_REF_ROWS = [24, 25, 26, 27, 28, 29]

NEW_TAB_HASH_COL = None  # filled in below, after col_letter is defined
NEW_TAB_PHYSICAL_LOCATION_COL = None


# ---------------------------------------------------------------------------
# Pure helpers -- column arithmetic, row builders, rewrite/delete targets.
# No network I/O; unit-tested in tests/test_scripts/test_wifi_sheet_migrate.py.
# ---------------------------------------------------------------------------


def col_letter(index: int) -> str:
    """Convert a 0-based column index to its A1-notation letter(s)."""
    if index < 0:
        raise ValueError(f"column index must be >= 0, got {index}")
    n = index + 1
    letters = ""
    while n > 0:
        n, rem = divmod(n - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def header_index(headers: list[str], name: str, *, sheet_label: str) -> int:
    """0-based index of `name` in `headers`; fails loud if missing."""
    try:
        return headers.index(name)
    except ValueError as e:
        raise ValueError(
            f"{sheet_label}: missing required column {name!r}; header is {headers!r}"
        ) from e


def _cell(row: list, index: int) -> str:
    """Stringify a raw sheet cell (the Sheets API returns numbers as int/float,
    not str, for plain numeric cells -- e.g. the flash tab's '#' column)."""
    if index >= len(row):
        return ""
    value = row[index]
    return "" if value is None else str(value)


def _row_from_dict(cells: dict[str, str]) -> list[str]:
    """Serialize a {header-name: value} dict into NEW_TAB_HEADER column order.

    Fails loud on any key that isn't a real column -- a typo'd key would
    otherwise silently drop that cell's value.
    """
    unknown = set(cells) - set(NEW_TAB_HEADER)
    if unknown:
        raise ValueError(f"row dict has keys not in NEW_TAB_HEADER: {sorted(unknown)}")
    return [cells.get(name, "") for name in NEW_TAB_HEADER]


def _lookup_formula(value_col: str, key_col: str, row: int) -> str:
    """INDEX/MATCH formula pulling `value_col` from the flash tab by '#'."""
    return (
        f"=IFERROR(INDEX('{FLASH_TAB_TITLE}'!{value_col}:{value_col},"
        f"MATCH(${NEW_TAB_HASH_COL}{row},'{FLASH_TAB_TITLE}'!{key_col}:{key_col},0)),\"\")"
    )


def build_puck_rows(flash_tab_values: list[list[str]], start_row: int) -> list[list[str]]:
    """Build WiFi-sheet rows (2 per OpenWRT puck: wan, lan) as cross-tab formulas.

    ``flash_tab_values`` is the 'Google WiFi Pucks' tab's raw values with the
    header as row 0. Only rows with ``Firmware == "OpenWRT"`` produce
    output -- stock Google-firmware pucks get no rows; the sheet is the sole
    source of that exclusion, not this code. ``start_row`` is the 1-based
    row number in the NEW tab where the first output row lands (needed to
    build each row's self-referencing '#'/IP formulas).

    Name/Machine are computed as ``="puck"&TEXT($#,"00")`` from the row's
    own '#' value, NOT looked up from the flash tab's 'Name' column: a live
    scan (2026-07-24) found that column blank for several current OpenWRT
    rows (puck04, 05, 08, 09) -- it is a free-text nickname field, filled in
    inconsistently, not a reliable machine-name source. The number->name
    mapping is otherwise already the fleet's identity convention (see
    ``derivations/puck_data.py``'s ``f"puck{number:02d}"`` check), so
    deriving it here keeps the sheet self-consistent even when that column
    is empty.

    Fails loud (ValueError) if the flash tab is missing a required column,
    or an OpenWRT row has no '#' value.
    """
    if not flash_tab_values:
        raise ValueError(f"{FLASH_TAB_TITLE}: tab is empty (no header row)")
    headers = flash_tab_values[0]
    idx = {
        name: header_index(headers, name, sheet_label=FLASH_TAB_TITLE)
        for name in _FLASH_REQUIRED_COLUMNS
    }
    col = {name: col_letter(i) for name, i in idx.items()}
    hash_col = col["#"]

    def get(row: list, name: str) -> str:
        return _cell(row, idx[name])

    rows: list[list[str]] = []
    row_num = start_row
    for data_row in flash_tab_values[1:]:
        if get(data_row, "Firmware").strip() != "OpenWRT":
            continue
        number = get(data_row, "#").strip()
        if not number:
            raise ValueError(f"{FLASH_TAB_TITLE}: OpenWRT row missing '#' value: {data_row!r}")
        for interface in ("wan", "lan"):
            name_formula = f'="puck"&TEXT(${NEW_TAB_HASH_COL}{row_num},"00")'
            rows.append(
                _row_from_dict(
                    {
                        "#": number,
                        "Name": name_formula,
                        "Machine": name_formula,  # same source column as Name
                        "Interface": interface,
                        "MAC Address": _lookup_formula(col[interface], hash_col, row_num),
                        "IP": f'="10.X.4."&(100+${NEW_TAB_HASH_COL}{row_num})',
                        "Type": "DHCP:wisp",
                        "Site": "welland",  # pucks are welland-only
                        "Physical Location": _lookup_formula(col["Location"], hash_col, row_num),
                        "Hardware": "gale",  # all gwifi pucks are gale hardware
                        "Upstream": _lookup_formula(col["Upstream"], hash_col, row_num),
                        "Controlled By": _lookup_formula(col["Controlled By"], hash_col, row_num),
                        "Serial": _lookup_formula(col["Serial"], hash_col, row_num),
                    }
                )
            )
            row_num += 1
    return rows


def build_openmesh_rows(
    ip_alloc_values: list[list[str]], hardware_map: dict[str, str]
) -> list[list[str]]:
    """Build WiFi-sheet rows for the OpenMesh interface blocks, as VALUES (not formulas).

    ``ip_alloc_values`` is 'Welland - IP Allocation' with the header as row
    0 -- locate it first with ``gdoc2netcfg.sources.parser.find_header_row``
    (row 1 in the live sheet is a metadata row, not the header). Every row
    whose Machine starts with 'openmesh-' is copied, preserving source row
    order (block contiguity matters -- ``rewrite_ref_formulas`` assumes each
    machine's 7 rows land contiguously in ``OPENMESH_MACHINES_IN_ORDER``
    order). ``Site`` is preserved as-is (today blank == all sites).
    ``Hardware`` is looked up per-machine in ``hardware_map`` -- fails loud
    for any openmesh machine missing from the map.

    ``ip_alloc_values`` MUST be fetched with ``valueRenderOption=UNFORMATTED_VALUE``
    (not ``FORMULA``): a formula cell copied verbatim would be pasted as a
    live formula via ``USER_ENTERED`` and silently re-evaluate in the new
    tab. As a backstop, every copied cell is checked and this fails loud if
    any of them still starts with ``=``.
    """
    if not ip_alloc_values:
        raise ValueError(f"{IP_ALLOC_TAB_TITLE}: tab is empty (no header row)")
    headers = ip_alloc_values[0]
    idx = {
        name: header_index(headers, name, sheet_label=IP_ALLOC_TAB_TITLE)
        for name in _IP_ALLOC_REQUIRED_COLUMNS
    }

    def get(row: list, name: str) -> str:
        value = _cell(row, idx[name])
        if value.startswith("="):
            raise ValueError(
                f"{IP_ALLOC_TAB_TITLE}: machine {machine!r} column {name!r} is a "
                f"live formula ({value!r}) -- ip_alloc_values must be fetched "
                "with valueRenderOption=UNFORMATTED_VALUE, not FORMULA, before "
                "copying (a formula pasted via USER_ENTERED would silently "
                "re-evaluate in the new tab)"
            )
        return value

    rows: list[list[str]] = []
    for data_row in ip_alloc_values[1:]:
        machine = _cell(data_row, idx["Machine"])
        if not machine.startswith(OPENMESH_MACHINE_PREFIX):
            continue
        if machine not in hardware_map:
            raise ValueError(
                f"{IP_ALLOC_TAB_TITLE}: openmesh machine {machine!r} has no entry in "
                "--hardware-map"
            )
        rows.append(
            _row_from_dict(
                {
                    "Machine": machine,
                    "Interface": get(data_row, "Interface"),
                    "MAC Address": get(data_row, "MAC Address"),
                    "IP": get(data_row, "IPv4"),
                    "Site": get(data_row, "Site"),  # preserved as-is, even if blank
                    "Physical Location": get(data_row, "Location"),
                    "Hardware": hardware_map[machine],  # family, from --hardware-map
                    "Controlled By": get(data_row, "Controlled By"),
                    "Serial": get(data_row, "Serial Number"),
                    "Notes / Comments": get(data_row, "Notes"),
                }
            )
        )
    return rows


def compute_new_tab_rows(
    flash_tab_values: list[list[str]],
    ip_alloc_values: list[list[str]],
    hardware_map: dict[str, str],
) -> tuple[list[list[str]], int]:
    """Build the full (fleet puck + OpenMesh) block for `populate`.

    Returns ``(rows, openmesh_start_row)``: ``rows`` is written starting at
    the new tab's row 2 (row 1 is the header); ``openmesh_start_row`` is the
    absolute new-tab row number of the OpenMesh block's first row, needed by
    ``rewrite_ref_formulas``.

    The stock Google pucks (puck01-03) briefly had their own value-copied
    row builder here (2026-07-25 morning): at that point they still ran
    stock firmware and lived as node*-wifi-google roam-VLAN blocks in
    'Welland - IP Allocation'. All three were flashed to fleet firmware
    later that day, which made them ordinary ``Firmware == "OpenWRT"``
    flash-tab rows -- ``build_puck_rows`` picks them up like the rest of
    the fleet, and their roam-VLAN identity retires with the old IP
    Allocation rows (``delete-old-rows`` still removes the node blocks;
    the GOOGLE_NODE constants/validators below exist for that phase).
    """
    puck_rows = build_puck_rows(flash_tab_values, start_row=2)
    openmesh_start_row = 2 + len(puck_rows)
    openmesh_rows = build_openmesh_rows(ip_alloc_values, hardware_map)
    return puck_rows + openmesh_rows, openmesh_start_row


def openmesh_block_first_rows(start_row: int, block_size: int, num_blocks: int) -> list[int]:
    """1-based row numbers of each OpenMesh block's first (interface) row."""
    return [start_row + i * block_size for i in range(num_blocks)]


def openmesh_delete_range(first_row: int, block_size: int, num_blocks: int) -> tuple[int, int]:
    """Inclusive 1-based (first_row, last_row) spanning every OpenMesh block."""
    return (first_row, first_row + block_size * num_blocks - 1)


def compute_trailing_clear_range(
    existing_row_count: int, new_last_row: int
) -> tuple[int, int] | None:
    """Return the inclusive 1-based (first, last) row range to CLEAR so a
    re-run of `populate` is truly idempotent, or None if there's nothing to
    clear.

    ``existing_row_count`` is how many rows the new tab currently holds
    (from a plain values fetch -- the last row with ANY content);
    ``new_last_row`` is the last row this populate run is about to write
    (header + data). If a PREVIOUS populate wrote more rows than this run
    computes (e.g. a puck or OpenMesh AP was removed from the source data),
    the tail of the old write would otherwise survive as stale leftover
    rows below the new content.
    """
    if existing_row_count <= new_last_row:
        return None
    return (new_last_row + 1, existing_row_count)


def validate_openmesh_range(
    rows: list[list[str]], machine_col: int, first_row: int, last_row: int
) -> list[str]:
    """Return violation descriptions (empty == OK) for the "the delete range IS
    the OpenMesh block, and nothing else" invariant.

    ``rows`` is the FULL, freshly-fetched 'Welland - IP Allocation' values
    (element 0 == sheet row 1 -- i.e. absolute, 1-based row numbering).
    Checks, against those fresh values:

    (a) every row in ``[first_row, last_row]`` (inclusive) has a Machine
        value starting with ``OPENMESH_MACHINE_PREFIX``, and
    (b) no row OUTSIDE that range does either.

    This guards against rows shifting in the live sheet during the rollout
    hold between `populate` (which computed the range from a snapshot taken
    earlier) and `delete-old-rows` actually running -- a snapshot-derived
    range is only safe to delete if it still matches reality.
    """
    return _validate_machine_range(
        rows,
        machine_col,
        first_row,
        last_row,
        is_member=lambda m: m.startswith(OPENMESH_MACHINE_PREFIX),
        label="an OpenMesh",
    )


def _validate_machine_range(
    rows: list[list[str]],
    machine_col: int,
    first_row: int,
    last_row: int,
    *,
    is_member,
    label: str,
) -> list[str]:
    """Generic "the delete range IS this machine family, and nothing else" check.

    ``is_member`` decides whether a Machine value belongs to the family being
    deleted; ``label`` names the family in violation messages (e.g. "an
    OpenMesh"). See ``validate_openmesh_range`` for the full contract.
    """
    violations: list[str] = []
    for i, row in enumerate(rows, start=1):
        machine = _cell(row, machine_col)
        member = is_member(machine)
        in_range = first_row <= i <= last_row
        if in_range and not member:
            violations.append(
                f"row {i} is inside the delete range [{first_row}, {last_row}] "
                f"but Machine={machine!r} is not {label} row"
            )
        elif member and not in_range:
            violations.append(
                f"row {i} (Machine={machine!r}) is {label} row OUTSIDE the "
                f"delete range [{first_row}, {last_row}]"
            )
    return violations


def validate_google_node_range(
    rows: list[list[str]], machine_col: int, first_row: int, last_row: int
) -> list[str]:
    """``validate_openmesh_range``'s contract, for the node*-wifi-google blocks."""
    return _validate_machine_range(
        rows,
        machine_col,
        first_row,
        last_row,
        is_member=lambda m: m in GOOGLE_NODE_OLD_NAMES,
        label="a node*-wifi-google",
    )


def validate_openmesh_block_shape(ip_alloc_values: list[list[str]], first_row: int) -> list[str]:
    """Return violation descriptions (empty == OK) for the block-shape contract
    that `populate` and `rewrite-refs` both silently assume:
    ``OPENMESH_MACHINES_IN_ORDER`` appears as exactly-``OPENMESH_BLOCK_SIZE``-row
    contiguous, in-order blocks starting at ``first_row``.

    ``ip_alloc_values`` is the FULL, freshly-fetched 'Welland - IP Allocation'
    values (element 0 == sheet row 1, so row numbers are absolute/1-based).
    The header row is located with
    ``gdoc2netcfg.sources.parser.find_header_row`` rather than assumed at
    index 0 -- the live sheet has a metadata row (IPv6 prefix) above the
    real header. ``first_row`` is the absolute row of the first block's
    first row (e.g. the snapshot's ``ip_alloc_openmesh_first_row``).

    Checks per-slot machine identity (drift: a row holds the wrong machine,
    a block is short/long, or blocks are out of order) AND -- via
    ``validate_openmesh_range`` -- that no OpenMesh row exists outside the
    expected span.
    """
    return _validate_machine_block_shape(
        ip_alloc_values,
        first_row,
        machines_in_order=OPENMESH_MACHINES_IN_ORDER,
        block_size=OPENMESH_BLOCK_SIZE,
        range_validator=validate_openmesh_range,
    )


def _validate_machine_block_shape(
    ip_alloc_values: list[list[str]],
    first_row: int,
    *,
    machines_in_order: list[str],
    block_size: int,
    range_validator,
) -> list[str]:
    """Generic per-slot block-shape check; see ``validate_openmesh_block_shape``.

    ``range_validator`` is the matching family-range validator (e.g.
    ``validate_openmesh_range``) used for the "no family row outside the
    expected span" half of the contract.
    """
    if not ip_alloc_values:
        raise ValueError(f"{IP_ALLOC_TAB_TITLE}: tab is empty (no header row)")
    header_idx = find_header_row(ip_alloc_values)
    machine_col = header_index(
        ip_alloc_values[header_idx], "Machine", sheet_label=IP_ALLOC_TAB_TITLE
    )
    expected_first_rows = openmesh_block_first_rows(first_row, block_size, len(machines_in_order))
    last_row = expected_first_rows[-1] + block_size - 1

    violations: list[str] = []
    for machine, block_start in zip(machines_in_order, expected_first_rows):
        for offset in range(block_size):
            row_num = block_start + offset
            row = ip_alloc_values[row_num - 1] if row_num - 1 < len(ip_alloc_values) else []
            actual = _cell(row, machine_col)
            if actual != machine:
                violations.append(
                    f"row {row_num}: expected Machine={machine!r} "
                    f"(block position {offset + 1}/{block_size}), found {actual!r}"
                )
    violations.extend(range_validator(ip_alloc_values, machine_col, first_row, last_row))
    return violations


def validate_google_node_block_shape(
    ip_alloc_values: list[list[str]], first_row: int
) -> list[str]:
    """``validate_openmesh_block_shape``'s contract, for the node*-wifi-google blocks."""
    return _validate_machine_block_shape(
        ip_alloc_values,
        first_row,
        machines_in_order=GOOGLE_NODE_OLD_NAMES,
        block_size=GOOGLE_NODE_BLOCK_SIZE,
        range_validator=validate_google_node_range,
    )


def rewrite_ref_formulas(new_tab_openmesh_start_row: int) -> dict[int, str]:
    """iot.welland row -> replacement formula pointing at the new tab.

    Maps each of ``IOT_REF_ROWS`` (in ``OPENMESH_MACHINES_IN_ORDER`` order)
    to a formula referencing that machine's first row's Physical Location
    cell in the new tab.
    """
    first_rows = openmesh_block_first_rows(
        new_tab_openmesh_start_row, OPENMESH_BLOCK_SIZE, len(OPENMESH_MACHINES_IN_ORDER)
    )
    if len(IOT_REF_ROWS) != len(first_rows):
        raise ValueError("IOT_REF_ROWS and OPENMESH_MACHINES_IN_ORDER length mismatch")
    return {
        iot_row: f"='{NEW_TAB_TITLE}'!{NEW_TAB_PHYSICAL_LOCATION_COL}{new_row}"
        for iot_row, new_row in zip(IOT_REF_ROWS, first_rows)
    }


def validate_new_tab_openmesh_positions(
    new_tab_values: list[list[str]], openmesh_start_row: int
) -> list[str]:
    """Return violation descriptions (empty == OK) confirming the NEW tab's
    Machine column holds ``OPENMESH_MACHINES_IN_ORDER`` at the block
    first-rows computed from ``openmesh_start_row`` -- exactly the rows
    ``rewrite_ref_formulas`` points the rewritten iot.welland formulas at.

    ``new_tab_values`` is the FULL, freshly-fetched new tab (element 0 ==
    its row 1, the header, so row numbers are absolute/1-based). Guards
    against rewriting formulas to point at rows that don't actually hold
    what the snapshot assumed (e.g. populate wrote something unexpected, or
    the new tab was hand-edited between populate and rewrite-refs).
    """
    if not new_tab_values:
        raise ValueError(f"{NEW_TAB_TITLE}: tab is empty (no header row)")
    machine_col = header_index(new_tab_values[0], "Machine", sheet_label=NEW_TAB_TITLE)
    first_rows = openmesh_block_first_rows(
        openmesh_start_row, OPENMESH_BLOCK_SIZE, len(OPENMESH_MACHINES_IN_ORDER)
    )
    violations: list[str] = []
    for machine, row_num in zip(OPENMESH_MACHINES_IN_ORDER, first_rows):
        row = new_tab_values[row_num - 1] if row_num - 1 < len(new_tab_values) else []
        actual = _cell(row, machine_col)
        if actual != machine:
            violations.append(
                f"{NEW_TAB_TITLE} row {row_num}: expected Machine={machine!r}, "
                f"found {actual!r}"
            )
    return violations


def find_row_index(rows: list[list[str]], col: int, value: str) -> int:
    """1-based row number of the first row whose column `col` (0-based) equals `value`."""
    for i, row in enumerate(rows, start=1):
        if _cell(row, col) == value:
            return i
    raise ValueError(f"value {value!r} not found in column index {col}")


def validate_new_tab_header(existing_header: list[str]) -> None:
    """Raise if an existing new-tab header doesn't match NEW_TAB_HEADER exactly."""
    if existing_header != NEW_TAB_HEADER:
        raise ValueError(
            f"{NEW_TAB_TITLE!r} already exists with a DIFFERENT header.\n"
            f"  expected: {NEW_TAB_HEADER}\n"
            f"  found:    {existing_header}"
        )


_REF_INTO_RANGE_RE_TEMPLATE = r"'{tab}'!\$?[A-Za-z]+\$?(\d+)"


def find_formula_refs_into_range(
    tab_formulas: dict[str, list[list[str]]], target_tab: str, min_row: int, max_row: int
) -> list[str]:
    """Return 'Tab!R{row}C{col}: formula' for every formula cell across every
    scanned tab that references `target_tab` at a row within [min_row, max_row].

    Used by `delete-old-rows` (refuse unless empty) and `verify` (must be
    empty after the migration completes).
    """
    pattern = re.compile(_REF_INTO_RANGE_RE_TEMPLATE.format(tab=re.escape(target_tab)))
    hits = []
    for tab_title, values in tab_formulas.items():
        for r, row in enumerate(values, start=1):
            for c, cell in enumerate(row, start=1):
                if not (isinstance(cell, str) and cell.startswith("=")):
                    continue
                for m in pattern.finditer(cell):
                    if min_row <= int(m.group(1)) <= max_row:
                        hits.append(f"{tab_title}!R{r}C{c}: {cell}")
                        break
    return hits


def find_ref_errors(tab_values: dict[str, list[list[str]]]) -> list[str]:
    """Return 'Tab!R{row}C{col}: #REF!' for every cell evaluating to #REF! across every tab."""
    hits = []
    for tab_title, values in tab_values.items():
        for r, row in enumerate(values, start=1):
            for c, cell in enumerate(row, start=1):
                if isinstance(cell, str) and cell.strip() == "#REF!":
                    hits.append(f"{tab_title}!R{r}C{c}: #REF!")
    return hits


def values_to_csv_text(values: list[list[str]]) -> str:
    """Render a fetched values grid back to CSV text (for feeding parse_csv)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in values:
        writer.writerow(row)
    return buf.getvalue()


NEW_TAB_HASH_COL = col_letter(NEW_TAB_HEADER.index("#"))
NEW_TAB_PHYSICAL_LOCATION_COL = col_letter(NEW_TAB_HEADER.index("Physical Location"))


# ---------------------------------------------------------------------------
# Sheets API client (thin) -- network I/O lives only below this line.
# ---------------------------------------------------------------------------


class SheetsClient:
    def __init__(self, sa_path: Path, spreadsheet_id: str, *, readonly: bool):
        scope = "spreadsheets.readonly" if readonly else "spreadsheets"
        creds = service_account.Credentials.from_service_account_file(
            str(sa_path), scopes=[f"https://www.googleapis.com/auth/{scope}"]
        )
        creds.refresh(Request())
        self._headers = {"Authorization": f"Bearer {creds.token}"}
        self._base = f"{SHEETS_API}/{spreadsheet_id}"

    def list_tabs(self) -> list[dict]:
        resp = requests.get(
            self._base,
            headers=self._headers,
            params={"fields": "sheets.properties"},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return [s["properties"] for s in resp.json().get("sheets", [])]

    def get_values(self, tab_title: str, rng: str = "", render: str = "FORMULA") -> list[list[str]]:
        quoted = "'" + tab_title.replace("'", "''") + "'" + (f"!{rng}" if rng else "")
        url = f"{self._base}/values/{requests.utils.quote(quoted)}"
        resp = requests.get(
            url,
            headers=self._headers,
            params={"valueRenderOption": render},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("values", [])

    def update_values(self, tab_title: str, rng: str, values: list[list[str]]) -> None:
        quoted = "'" + tab_title.replace("'", "''") + "'!" + rng
        url = f"{self._base}/values/{requests.utils.quote(quoted)}"
        resp = requests.put(
            url,
            headers=self._headers,
            params={"valueInputOption": "USER_ENTERED"},
            json={"values": values},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()

    def clear_values(self, tab_title: str, rng: str) -> None:
        quoted = "'" + tab_title.replace("'", "''") + "'!" + rng
        url = f"{self._base}/values/{requests.utils.quote(quoted)}:clear"
        resp = requests.post(url, headers=self._headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()

    def batch_update(self, requests_body: list[dict]) -> dict:
        url = f"{self._base}:batchUpdate"
        resp = requests.post(
            url,
            headers=self._headers,
            json={"requests": requests_body},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()


def sheet_id_by_title(tabs: list[dict], title: str) -> int | None:
    for t in tabs:
        if t["title"] == title:
            return t["sheetId"]
    return None


# ---------------------------------------------------------------------------
# Phase commands
# ---------------------------------------------------------------------------


def cmd_create(client: SheetsClient, *, dry_run: bool) -> int:
    tabs = client.list_tabs()
    existing_id = sheet_id_by_title(tabs, NEW_TAB_TITLE)
    if existing_id is not None:
        last_col = col_letter(len(NEW_TAB_HEADER) - 1)
        existing_header = client.get_values(NEW_TAB_TITLE, f"A1:{last_col}1")
        existing = existing_header[0] if existing_header else []
        validate_new_tab_header(existing)  # raises if different
        print(f"{NEW_TAB_TITLE!r} already exists with the expected header; no-op.")
        return 0

    print(f"Would create tab {NEW_TAB_TITLE!r} with header:\n  {NEW_TAB_HEADER}")
    if dry_run:
        print("(dry-run: not applied)")
        return 0

    client.batch_update([{"addSheet": {"properties": {"title": NEW_TAB_TITLE}}}])
    last_col = col_letter(len(NEW_TAB_HEADER) - 1)
    client.update_values(NEW_TAB_TITLE, f"A1:{last_col}1", [NEW_TAB_HEADER])
    print(f"Created {NEW_TAB_TITLE!r}.")
    return 0


def cmd_populate(
    client: SheetsClient, *, hardware_map_path: Path, snapshot_path: Path, dry_run: bool
) -> int:
    hardware_map = json.loads(hardware_map_path.read_text())

    flash_values = client.get_values(FLASH_TAB_TITLE)
    # UNFORMATTED_VALUE, not FORMULA: OpenMesh rows are copied by VALUE into
    # the new tab. Fetching formulas here would paste them as live formulas
    # via USER_ENTERED and silently re-evaluate in the new tab (see
    # build_openmesh_rows, which also asserts no copied cell starts with "=").
    all_ip_alloc = client.get_values(IP_ALLOC_TAB_TITLE, render="UNFORMATTED_VALUE")
    header_idx = find_header_row(all_ip_alloc)
    ip_alloc_values = all_ip_alloc[header_idx:]

    machine_col = header_index(
        all_ip_alloc[header_idx], "Machine", sheet_label=IP_ALLOC_TAB_TITLE
    )
    ip_alloc_openmesh_first_row = find_row_index(
        all_ip_alloc, machine_col, OPENMESH_MACHINES_IN_ORDER[0]
    )
    shape_violations = validate_openmesh_block_shape(all_ip_alloc, ip_alloc_openmesh_first_row)
    if shape_violations:
        print(
            f"REFUSING to populate: {IP_ALLOC_TAB_TITLE!r} OpenMesh block shape has "
            "drifted from what OPENMESH_MACHINES_IN_ORDER assumes:",
            file=sys.stderr,
        )
        for v in shape_violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    ip_alloc_google_first_row = find_row_index(all_ip_alloc, machine_col, GOOGLE_NODE_OLD_NAMES[0])
    google_violations = validate_google_node_block_shape(all_ip_alloc, ip_alloc_google_first_row)
    if google_violations:
        print(
            f"REFUSING to populate: {IP_ALLOC_TAB_TITLE!r} node*-wifi-google block "
            "shape has drifted from what GOOGLE_NODE_MACHINES_IN_ORDER assumes:",
            file=sys.stderr,
        )
        for v in google_violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    rows, openmesh_start_row = compute_new_tab_rows(flash_values, ip_alloc_values, hardware_map)

    last_col = col_letter(len(NEW_TAB_HEADER) - 1)
    last_row = 1 + len(rows)
    print(f"Would write {len(rows)} rows to {NEW_TAB_TITLE!r}!A2:{last_col}{last_row}")
    n_openmesh = len(rows) - (openmesh_start_row - 2)
    print(f"  ({openmesh_start_row - 2} puck rows, {n_openmesh} OpenMesh rows)")
    print(f"  OpenMesh block starts at new-tab row {openmesh_start_row}")
    for row in rows:
        print(f"  {row}")

    # Idempotency: if a PREVIOUS populate run wrote more rows than this run
    # computes (e.g. a puck/AP was removed from the source data), clear the
    # stale trailing rows so a re-run leaves no leftovers below the new
    # content.
    tabs = client.list_tabs()
    existing_new_tab = (
        client.get_values(NEW_TAB_TITLE) if sheet_id_by_title(tabs, NEW_TAB_TITLE) else []
    )
    trailing_range = compute_trailing_clear_range(len(existing_new_tab), last_row)
    if trailing_range:
        print(
            f"Would also clear stale trailing rows {trailing_range[0]}-{trailing_range[1]} "
            f"(a previous populate run left {len(existing_new_tab)} rows; this run only needs "
            f"{last_row})"
        )

    # Snapshot: iot.welland's current evaluated values + the old sheet's
    # OpenMesh row positions -- needed by rewrite-refs/delete-old-rows/verify.
    iot_evaluated = client.get_values(IOT_TAB_TITLE, "A1:Z250", render="FORMATTED_VALUE")
    snapshot = {
        "iot_range": "A1:Z250",
        "iot_evaluated_values": iot_evaluated,
        "ip_alloc_openmesh_first_row": ip_alloc_openmesh_first_row,
        "ip_alloc_openmesh_block_size": OPENMESH_BLOCK_SIZE,
        "ip_alloc_openmesh_num_blocks": len(OPENMESH_MACHINES_IN_ORDER),
        "ip_alloc_google_first_row": ip_alloc_google_first_row,
        "ip_alloc_google_block_size": GOOGLE_NODE_BLOCK_SIZE,
        "ip_alloc_google_num_blocks": len(GOOGLE_NODE_MACHINES_IN_ORDER),
        "new_tab_openmesh_start_row": openmesh_start_row,
    }

    if dry_run:
        print("(dry-run: not applied; snapshot not written)")
        return 0

    # Unmerge before writing: values.update silently DROPS values written
    # into non-anchor cells of a merged range, so merges left by a previous
    # wifi-sheet-format.py run at now-shifted block positions would eat
    # cells (observed live 2026-07-25: Physical Location values vanished
    # when the stock pucks shifted the OpenMesh blocks down 24 rows).
    # Re-run wifi-sheet-format.py after populate to restore the styling.
    new_tab_sheet_id = sheet_id_by_title(tabs, NEW_TAB_TITLE)
    if new_tab_sheet_id is not None:
        client.batch_update([{"unmergeCells": {"range": {"sheetId": new_tab_sheet_id}}}])
        print("Unmerged all cells (stale merges would silently eat written values).")

    client.update_values(NEW_TAB_TITLE, f"A2:{last_col}{last_row}", rows)
    if trailing_range:
        client.clear_values(NEW_TAB_TITLE, f"A{trailing_range[0]}:{last_col}{trailing_range[1]}")
        print(f"Cleared stale trailing rows {trailing_range[0]}-{trailing_range[1]}.")
    snapshot_path.write_text(json.dumps(snapshot, indent=2) + "\n")
    print(f"Wrote {len(rows)} rows; snapshot saved to {snapshot_path}")
    return 0


def cmd_rewrite_refs(client: SheetsClient, *, snapshot_path: Path, dry_run: bool) -> int:
    snapshot = json.loads(snapshot_path.read_text())

    # Re-validate the block-shape contract against a FRESH fetch: the
    # snapshot's row positions were captured at `populate` time, and rows may
    # have shifted in the old sheet during the rollout hold since then.
    all_ip_alloc = client.get_values(IP_ALLOC_TAB_TITLE, render="UNFORMATTED_VALUE")
    shape_violations = validate_openmesh_block_shape(
        all_ip_alloc, snapshot["ip_alloc_openmesh_first_row"]
    )
    if shape_violations:
        print(
            f"REFUSING to rewrite-refs: {IP_ALLOC_TAB_TITLE!r} OpenMesh block shape "
            "has drifted since populate ran:",
            file=sys.stderr,
        )
        for v in shape_violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    formulas = rewrite_ref_formulas(snapshot["new_tab_openmesh_start_row"])

    # Confirm the NEW tab actually has the OpenMesh machines at the rows the
    # rewritten formulas will point at -- catches populate having written
    # something unexpected, or the new tab being hand-edited since.
    new_tab_values = client.get_values(NEW_TAB_TITLE)
    position_violations = validate_new_tab_openmesh_positions(
        new_tab_values, snapshot["new_tab_openmesh_start_row"]
    )
    if position_violations:
        print(
            f"REFUSING to rewrite-refs: {NEW_TAB_TITLE!r} doesn't have the expected "
            "OpenMesh machines at the target rows:",
            file=sys.stderr,
        )
        for v in position_violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    current = client.get_values(IOT_TAB_TITLE, "A1:Z35")
    print("Would rewrite iot.welland formulas:")
    for row in sorted(formulas):
        old = ""
        if row - 1 < len(current) and len(current[row - 1]) > 7:
            old = current[row - 1][7]
        print(f"  R{row}C8: {old!r} -> {formulas[row]!r}")

    if dry_run:
        print("(dry-run: not applied)")
        return 0

    for row, formula in formulas.items():
        client.update_values(IOT_TAB_TITLE, f"H{row}", [[formula]])
    print(f"Rewrote {len(formulas)} formula(s).")
    return 0


def snapshot_delete_ranges(snapshot: dict) -> list[tuple[str, int, int]]:
    """The (label, first_row, last_row) IP-Allocation ranges `delete-old-rows` removes.

    A pre-stock-puck snapshot (no ``ip_alloc_google_*`` keys) fails loud with
    KeyError -- re-run `populate` to refresh it.
    """
    openmesh = openmesh_delete_range(
        snapshot["ip_alloc_openmesh_first_row"],
        snapshot["ip_alloc_openmesh_block_size"],
        snapshot["ip_alloc_openmesh_num_blocks"],
    )
    google = openmesh_delete_range(
        snapshot["ip_alloc_google_first_row"],
        snapshot["ip_alloc_google_block_size"],
        snapshot["ip_alloc_google_num_blocks"],
    )
    return [
        ("OpenMesh", openmesh[0], openmesh[1]),
        ("node*-wifi-google", google[0], google[1]),
    ]


_RANGE_VALIDATORS = {
    "OpenMesh": validate_openmesh_range,
    "node*-wifi-google": validate_google_node_range,
}


def cmd_delete_old_rows(client: SheetsClient, *, snapshot_path: Path, dry_run: bool) -> int:
    snapshot = json.loads(snapshot_path.read_text())
    ranges = snapshot_delete_ranges(snapshot)

    tabs = [t["title"] for t in client.list_tabs()]
    tab_formulas = {title: client.get_values(title) for title in tabs}
    fresh_ip_alloc = tab_formulas[IP_ALLOC_TAB_TITLE]
    fresh_header_idx = find_header_row(fresh_ip_alloc)
    machine_col = header_index(
        fresh_ip_alloc[fresh_header_idx], "Machine", sheet_label=IP_ALLOC_TAB_TITLE
    )

    for label, first_row, last_row in ranges:
        # Refuse unless a fresh scan shows zero remaining references into the range.
        remaining = find_formula_refs_into_range(
            tab_formulas, IP_ALLOC_TAB_TITLE, first_row, last_row
        )
        if remaining:
            print(
                f"REFUSING to delete {IP_ALLOC_TAB_TITLE!r} rows {first_row}-{last_row} "
                f"({label}): {len(remaining)} formula(s) still reference this range "
                "(run rewrite-refs first):",
                file=sys.stderr,
            )
            for hit in remaining:
                print(f"  {hit}", file=sys.stderr)
            return 1

        # Refuse unless the range still IS exactly this machine family's block,
        # against the SAME fresh fetch above: the snapshot's positions were
        # captured at `populate` time and rows may have shifted during the
        # rollout hold.
        range_violations = _RANGE_VALIDATORS[label](
            fresh_ip_alloc, machine_col, first_row, last_row
        )
        if range_violations:
            print(
                f"REFUSING to delete {IP_ALLOC_TAB_TITLE!r} rows {first_row}-{last_row} "
                f"({label}): stale snapshot positions -- fresh scan disagrees:",
                file=sys.stderr,
            )
            for v in range_violations:
                print(f"  {v}", file=sys.stderr)
            return 1

        print(f"Would delete {IP_ALLOC_TAB_TITLE!r} rows {first_row}-{last_row} ({label}).")

    if dry_run:
        print("(dry-run: not applied)")
        return 0

    sheet_id = sheet_id_by_title(client.list_tabs(), IP_ALLOC_TAB_TITLE)
    if sheet_id is None:
        raise ValueError(f"{IP_ALLOC_TAB_TITLE!r} not found")
    # One batch, higher range first: deleting later rows never shifts earlier
    # ones, so descending order keeps every request's indices valid.
    requests_body = [
        {
            "deleteDimension": {
                "range": {
                    "sheetId": sheet_id,
                    "dimension": "ROWS",
                    "startIndex": first_row - 1,
                    "endIndex": last_row,
                }
            }
        }
        for _label, first_row, last_row in sorted(ranges, key=lambda r: -r[1])
    ]
    client.batch_update(requests_body)
    for label, first_row, last_row in ranges:
        print(f"Deleted rows {first_row}-{last_row} ({label}).")
    return 0


def cmd_verify(client: SheetsClient, *, snapshot_path: Path) -> int:
    snapshot = json.loads(snapshot_path.read_text())
    ok = True

    tabs = [t["title"] for t in client.list_tabs()]
    tab_formulas = {title: client.get_values(title) for title in tabs}
    ref_errors = find_ref_errors(
        {title: client.get_values(title, render="FORMATTED_VALUE") for title in tabs}
    )
    if ref_errors:
        ok = False
        print("FAIL: #REF! errors found:")
        for hit in ref_errors:
            print(f"  {hit}")
    else:
        print("OK: no #REF! errors anywhere.")

    for label, first_row, last_row in snapshot_delete_ranges(snapshot):
        remaining = find_formula_refs_into_range(
            tab_formulas, IP_ALLOC_TAB_TITLE, first_row, last_row
        )
        if remaining:
            ok = False
            print(
                f"FAIL: {len(remaining)} formula(s) still reference the deleted "
                f"{label} range (rows {first_row}-{last_row}):"
            )
            for hit in remaining:
                print(f"  {hit}")
        else:
            print(f"OK: no references into the deleted {label} range.")

    current_iot = client.get_values(IOT_TAB_TITLE, snapshot["iot_range"], render="FORMATTED_VALUE")
    if current_iot != snapshot["iot_evaluated_values"]:
        ok = False
        print(f"FAIL: {IOT_TAB_TITLE!r} evaluated values changed vs the snapshot.")
    else:
        print(f"OK: {IOT_TAB_TITLE!r} evaluated values unchanged.")

    new_tab_values = client.get_values(NEW_TAB_TITLE, render="FORMATTED_VALUE")
    csv_text = values_to_csv_text(new_tab_values)
    records = parse_csv(csv_text, "wifi")
    if not records:
        ok = False
        print(f"FAIL: {NEW_TAB_TITLE!r} parsed to 0 records via parse_csv.")
    else:
        print(f"OK: {NEW_TAB_TITLE!r} parsed to {len(records)} records via parse_csv.")

    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--sa-path", type=Path, default=DEFAULT_SA_PATH)
    parser.add_argument("--spreadsheet-id", default=DEFAULT_SPREADSHEET_ID)
    parser.add_argument("--dry-run", action="store_true", help="Print intended changes only")
    sub = parser.add_subparsers(dest="phase", required=True)

    sub.add_parser("create", help="Add the new tab + header row (idempotent)")

    snapshot_help = "Path to the populate snapshot JSON"

    pop = sub.add_parser(
        "populate", help="Write fleet-puck + stock-puck + OpenMesh rows; save a snapshot"
    )
    pop.add_argument("--hardware-map", type=Path, required=True, help="JSON: machine -> hardware")
    pop.add_argument("--snapshot", type=Path, required=True, help="Path to write the snapshot JSON")

    rw = sub.add_parser("rewrite-refs", help="Repoint iot.welland's 6 formulas at the new tab")
    rw.add_argument("--snapshot", type=Path, required=True, help=snapshot_help)

    dele = sub.add_parser(
        "delete-old-rows",
        help="Delete the OpenMesh + node*-wifi-google blocks from the old tab",
    )
    dele.add_argument("--snapshot", type=Path, required=True, help=snapshot_help)

    ver = sub.add_parser("verify", help="Full post-migration verification")
    ver.add_argument("--snapshot", type=Path, required=True, help=snapshot_help)

    args = parser.parse_args(argv)

    readonly = args.phase == "verify" or args.dry_run
    client = SheetsClient(args.sa_path, args.spreadsheet_id, readonly=readonly)

    if args.phase == "create":
        return cmd_create(client, dry_run=args.dry_run)
    if args.phase == "populate":
        return cmd_populate(
            client,
            hardware_map_path=args.hardware_map,
            snapshot_path=args.snapshot,
            dry_run=args.dry_run,
        )
    if args.phase == "rewrite-refs":
        return cmd_rewrite_refs(client, snapshot_path=args.snapshot, dry_run=args.dry_run)
    if args.phase == "delete-old-rows":
        return cmd_delete_old_rows(client, snapshot_path=args.snapshot, dry_run=args.dry_run)
    if args.phase == "verify":
        return cmd_verify(client, snapshot_path=args.snapshot)
    raise AssertionError(f"unhandled phase {args.phase!r}")


if __name__ == "__main__":
    sys.exit(main())
