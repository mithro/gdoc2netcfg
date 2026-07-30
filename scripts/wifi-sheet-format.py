#!/usr/bin/env python3
"""Apply the house formatting style to the `wifi.welland` tab (idempotent).

`wifi-sheet-migrate.py populate` writes VALUES only; this tool owns the
tab's look, matching the conventions of the sibling `iot.welland` /
`Welland - IP Allocation` tabs:

  - frozen, bold header row on the site-green background
  - alternating row banding (white / light green) over the data rows
  - monospace (Consolas) for the technical columns (#, MAC Address, IP,
    Serial), middle vertical alignment everywhere
  - per-machine blocks: Site, Physical Location, Hardware, Controlled By,
    Serial, and Notes / Comments cells merged vertically (blocks of 2+
    rows) and a solid top/bottom border around each block
  - grid trimmed to exactly the used range, columns auto-resized

Because populate can shift every block (e.g. inserting the stock pucks
moved the OpenMesh blocks down by 24 rows), this tool always starts from a
clean slate: it unmerges everything, clears all borders on the full grid,
deletes existing banding, then re-derives blocks from the CURRENT Machine
column. Clearing borders prevents stale block borders surviving at their
old row positions after a shift (the border-clear must precede the new
per-block borders, and comes right after unmergeCells since a merged
cell's borders belong to its anchor). Safe to re-run any time.

Usage:
    uv run scripts/wifi-sheet-format.py [--dry-run]
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import requests

# Reuse the migrate tool's SheetsClient + tab constants (hyphenated filename
# -- can't be `import`ed normally; same loading idiom as its tests).
_MIGRATE = Path(__file__).resolve().parent / "wifi-sheet-migrate.py"
_spec = importlib.util.spec_from_file_location("wifi_sheet_migrate", _MIGRATE)
wsm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wsm)

HEADER_BG = {"red": 0.388, "green": 0.824, "blue": 0.592}
BAND_FIRST = {"red": 1.0, "green": 1.0, "blue": 1.0}
BAND_SECOND = {"red": 0.906, "green": 0.976, "blue": 0.937}
MONO_FONT = "Consolas"
MONO_COLUMNS = ["#", "MAC Address", "IP", "Serial"]
BORDER = {"style": "SOLID", "color": {"red": 0.2, "green": 0.2, "blue": 0.2}}
NO_BORDER = {"style": "NONE"}
MERGE_COLUMNS_PER_BLOCK = [
    "Site",
    "Physical Location",
    "Hardware",
    "Controlled By",
    "Serial",
    "Notes / Comments",
]


def compute_machine_blocks(values: list[list[str]], machine_col: int) -> list[tuple[int, int, str]]:
    """Contiguous same-Machine runs as (first_row, last_row, machine), 1-based.

    ``values`` element 0 is the header (sheet row 1); rows with an empty
    Machine cell terminate any run and belong to no block.
    """
    blocks: list[tuple[int, int, str]] = []
    current: str | None = None
    start = 0
    for row_num, row in enumerate(values[1:], start=2):
        machine = wsm._cell(row, machine_col)
        if machine != current:
            if current:
                blocks.append((start, row_num - 1, current))
            current = machine or None
            start = row_num
    if current:
        blocks.append((start, len(values), current))
    return blocks


def build_requests(
    sheet_id: int,
    values: list[list[str]],
    grid_rows: int,
    grid_cols: int,
    existing_banded_range_ids: list[int],
) -> list[dict]:
    """The full batchUpdate request list for one formatting pass."""
    header = values[0]
    n_rows = len(values)
    n_cols = len(header)
    machine_col = wsm.header_index(header, "Machine", sheet_label=wsm.NEW_TAB_TITLE)
    merge_cols = [
        wsm.header_index(header, name, sheet_label=wsm.NEW_TAB_TITLE)
        for name in MERGE_COLUMNS_PER_BLOCK
    ]
    blocks = compute_machine_blocks(values, machine_col)
    if not blocks:
        raise ValueError(f"{wsm.NEW_TAB_TITLE}: no machine blocks found -- nothing to format")

    # Data-collapse guard (before emitting any merge request): a merge
    # keeps only the anchor row's value, so if a MERGE column holds two
    # DIFFERING non-empty values within one block, merging would silently
    # relabel/discard one of them -- e.g. a future machine-grouped infra
    # ordering putting a welland row and a monarto row in the same 2-row
    # block would have the merge silently relabel the second row's Site.
    # An anchor-non-blank + covered-blank (or vice versa) pair is fine --
    # that's the normal single-value-written-once-per-block shape.
    for first_row, last_row, block_machine in blocks:
        if last_row == first_row:
            continue
        for col_name, col in zip(MERGE_COLUMNS_PER_BLOCK, merge_cols):
            distinct_values = {
                wsm._cell(values[r - 1], col) for r in range(first_row, last_row + 1)
            } - {""}
            if len(distinct_values) > 1:
                raise ValueError(
                    f"{wsm.NEW_TAB_TITLE}: machine {block_machine!r} column {col_name!r} "
                    f"has differing non-empty values within its block (rows {first_row}-"
                    f"{last_row}): {sorted(distinct_values)} -- merging would silently "
                    "collapse one of them"
                )

    def grid_range(start_row: int, end_row: int, start_col: int = 0, end_col: int = n_cols):
        # start_* inclusive 1-based row / 0-based col; end_row inclusive.
        return {
            "sheetId": sheet_id,
            "startRowIndex": start_row - 1,
            "endRowIndex": end_row,
            "startColumnIndex": start_col,
            "endColumnIndex": end_col,
        }

    requests_body: list[dict] = []

    # Clean slate: unmerge everything, clear all borders (stale block
    # borders otherwise survive at their pre-shift row positions -- must
    # come right after unmergeCells, before any other formatting request),
    # then drop existing banding.
    requests_body.append({"unmergeCells": {"range": {"sheetId": sheet_id}}})
    requests_body.append(
        {
            "updateBorders": {
                "range": grid_range(1, grid_rows, 0, grid_cols),
                "top": NO_BORDER,
                "bottom": NO_BORDER,
                "left": NO_BORDER,
                "right": NO_BORDER,
                "innerHorizontal": NO_BORDER,
                "innerVertical": NO_BORDER,
            }
        }
    )
    for banded_range_id in existing_banded_range_ids:
        requests_body.append({"deleteBanding": {"bandedRangeId": banded_range_id}})

    # Trim the grid to the used range (rows first; deleting is only valid
    # when the grid is larger than the target).
    if grid_rows > n_rows:
        requests_body.append(
            {
                "deleteDimension": {
                    "range": {
                        "sheetId": sheet_id,
                        "dimension": "ROWS",
                        "startIndex": n_rows,
                        "endIndex": grid_rows,
                    }
                }
            }
        )
    if grid_cols > n_cols:
        requests_body.append(
            {
                "deleteDimension": {
                    "range": {
                        "sheetId": sheet_id,
                        "dimension": "COLUMNS",
                        "startIndex": n_cols,
                        "endIndex": grid_cols,
                    }
                }
            }
        )

    # Frozen + bold header on the site green.
    requests_body.append(
        {
            "updateSheetProperties": {
                "properties": {
                    "sheetId": sheet_id,
                    "gridProperties": {"frozenRowCount": 1},
                },
                "fields": "gridProperties.frozenRowCount",
            }
        }
    )
    requests_body.append(
        {
            "repeatCell": {
                "range": grid_range(1, 1),
                "cell": {
                    "userEnteredFormat": {
                        "backgroundColor": HEADER_BG,
                        "textFormat": {"bold": True},
                        "verticalAlignment": "MIDDLE",
                    }
                },
                "fields": (
                    "userEnteredFormat(backgroundColor,textFormat.bold,verticalAlignment)"
                ),
            }
        }
    )

    # Middle-align all data rows, then banding over them.
    requests_body.append(
        {
            "repeatCell": {
                "range": grid_range(2, n_rows),
                "cell": {"userEnteredFormat": {"verticalAlignment": "MIDDLE"}},
                "fields": "userEnteredFormat.verticalAlignment",
            }
        }
    )
    requests_body.append(
        {
            "addBanding": {
                "bandedRange": {
                    "range": grid_range(2, n_rows),
                    "rowProperties": {
                        "firstBandColor": BAND_FIRST,
                        "secondBandColor": BAND_SECOND,
                    },
                }
            }
        }
    )

    # Monospace technical columns (data rows only).
    for name in MONO_COLUMNS:
        col = wsm.header_index(header, name, sheet_label=wsm.NEW_TAB_TITLE)
        requests_body.append(
            {
                "repeatCell": {
                    "range": grid_range(2, n_rows, col, col + 1),
                    "cell": {
                        "userEnteredFormat": {"textFormat": {"fontFamily": MONO_FONT}}
                    },
                    "fields": "userEnteredFormat.textFormat.fontFamily",
                }
            }
        )

    # Per-block: merge each of MERGE_COLUMNS_PER_BLOCK vertically (2+ row
    # blocks) and a solid top/bottom border spanning the full row width.
    for first_row, last_row, _machine in blocks:
        if last_row > first_row:
            for col in merge_cols:
                requests_body.append(
                    {
                        "mergeCells": {
                            "range": grid_range(first_row, last_row, col, col + 1),
                            "mergeType": "MERGE_COLUMNS",
                        }
                    }
                )
        requests_body.append(
            {
                "updateBorders": {
                    "range": grid_range(first_row, last_row),
                    "top": BORDER,
                    "bottom": BORDER,
                }
            }
        )

    # Fit column widths to content.
    requests_body.append(
        {
            "autoResizeDimensions": {
                "dimensions": {
                    "sheetId": sheet_id,
                    "dimension": "COLUMNS",
                    "startIndex": 0,
                    "endIndex": n_cols,
                }
            }
        }
    )
    return requests_body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--sa-path", type=Path, default=wsm.DEFAULT_SA_PATH)
    parser.add_argument("--spreadsheet-id", default=wsm.DEFAULT_SPREADSHEET_ID)
    parser.add_argument("--dry-run", action="store_true", help="Print intended requests only")
    args = parser.parse_args(argv)

    client = wsm.SheetsClient(args.sa_path, args.spreadsheet_id, readonly=args.dry_run)

    # Tab metadata: sheetId, grid size, and any existing banded ranges.
    resp = requests.get(
        client._base,
        headers=client._headers,
        params={"fields": "sheets(properties,bandedRanges)"},
        timeout=wsm.REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    sheet = next(
        (
            s
            for s in resp.json().get("sheets", [])
            if s["properties"]["title"] == wsm.NEW_TAB_TITLE
        ),
        None,
    )
    if sheet is None:
        raise ValueError(f"{wsm.NEW_TAB_TITLE!r} not found")
    props = sheet["properties"]
    banded_ids = [b["bandedRangeId"] for b in sheet.get("bandedRanges", [])]

    values = client.get_values(wsm.NEW_TAB_TITLE, render="FORMATTED_VALUE")
    if not values:
        raise ValueError(f"{wsm.NEW_TAB_TITLE}: tab is empty")
    wsm.validate_new_tab_header(values[0])

    requests_body = build_requests(
        props["sheetId"],
        values,
        props["gridProperties"]["rowCount"],
        props["gridProperties"]["columnCount"],
        banded_ids,
    )
    blocks = compute_machine_blocks(
        values, wsm.header_index(values[0], "Machine", sheet_label=wsm.NEW_TAB_TITLE)
    )
    print(
        f"{len(values)} used rows, {len(blocks)} machine blocks, "
        f"{len(requests_body)} formatting requests"
    )
    if args.dry_run:
        for req in requests_body:
            print(f"  {next(iter(req))}: {req}")
        print("(dry-run: not applied)")
        return 0

    client.batch_update(requests_body)
    print("Applied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
