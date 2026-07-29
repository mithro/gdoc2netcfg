"""Tests for scripts/wifi-sheet-format.py's pure request-building logic."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "wifi-sheet-format.py"
_spec = importlib.util.spec_from_file_location("wifi_sheet_format", _SCRIPT)
wsf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wsf)

HEADER = list(wsf.wsm.NEW_TAB_HEADER)
MACHINE = HEADER.index("Machine")


def _row(machine: str) -> list[str]:
    row = [""] * len(HEADER)
    row[MACHINE] = machine
    return row


VALUES = [
    HEADER,
    _row("puck04"),  # rows 2-3
    _row("puck04"),
    _row("puck01"),  # rows 4-5
    _row("puck01"),
    _row("openmesh-ab-30"),  # row 6 (single-row block)
]


class TestComputeMachineBlocks:
    def test_contiguous_runs(self):
        assert wsf.compute_machine_blocks(VALUES, MACHINE) == [
            (2, 3, "puck04"),
            (4, 5, "puck01"),
            (6, 6, "openmesh-ab-30"),
        ]

    def test_empty_machine_cell_breaks_runs(self):
        values = [HEADER, _row("a"), _row(""), _row("a")]
        assert wsf.compute_machine_blocks(values, MACHINE) == [(2, 2, "a"), (4, 4, "a")]

    def test_no_data_rows(self):
        assert wsf.compute_machine_blocks([HEADER], MACHINE) == []


class TestBuildRequests:
    def _requests(self, **kwargs):
        defaults = dict(
            sheet_id=42,
            values=VALUES,
            grid_rows=len(VALUES),
            grid_cols=len(HEADER),
            existing_banded_range_ids=[],
        )
        defaults.update(kwargs)
        return wsf.build_requests(**defaults)

    def test_merges_only_multi_row_blocks(self):
        merges = [r["mergeCells"] for r in self._requests() if "mergeCells" in r]
        # puck04 (rows 2-3) and puck01 (rows 4-5) merge, one per column in
        # MERGE_COLUMNS_PER_BLOCK; the single-row openmesh block does not.
        assert len(merges) == 2 * len(wsf.MERGE_COLUMNS_PER_BLOCK)
        merged_rows = {(m["range"]["startRowIndex"], m["range"]["endRowIndex"]) for m in merges}
        assert merged_rows == {(1, 3), (3, 5)}

    def test_merges_cover_all_six_columns_per_block(self):
        merges = [r["mergeCells"] for r in self._requests() if "mergeCells" in r]
        puck04_cols = sorted(
            m["range"]["startColumnIndex"]
            for m in merges
            if (m["range"]["startRowIndex"], m["range"]["endRowIndex"]) == (1, 3)
        )
        expected_cols = sorted(
            wsf.wsm.header_index(HEADER, name, sheet_label=wsf.wsm.NEW_TAB_TITLE)
            for name in wsf.MERGE_COLUMNS_PER_BLOCK
        )
        assert puck04_cols == expected_cols
        for m in merges:
            assert m["mergeType"] == "MERGE_COLUMNS"
            assert m["range"]["endColumnIndex"] == m["range"]["startColumnIndex"] + 1

    def test_single_row_block_gets_no_merges(self):
        merges = [r["mergeCells"] for r in self._requests() if "mergeCells" in r]
        merged_rows = {(m["range"]["startRowIndex"], m["range"]["endRowIndex"]) for m in merges}
        # openmesh-ab-30 is row 6 (0-based startRowIndex 5, endRowIndex 6).
        assert (5, 6) not in merged_rows

    def test_borders_wrap_every_block(self):
        borders = [r for r in self._requests() if "updateBorders" in r]
        # 1 clear-all-borders request + 1 per block (3 blocks).
        assert len(borders) == 1 + 3

    def test_clear_borders_is_second_request_after_unmerge(self):
        reqs = self._requests()
        assert next(iter(reqs[0])) == "unmergeCells"
        assert next(iter(reqs[1])) == "updateBorders"
        clear = reqs[1]["updateBorders"]
        # Full grid: no row/col bounds narrower than the sheet's own size.
        assert clear["range"] == {
            "sheetId": 42,
            "startRowIndex": 0,
            "endRowIndex": len(VALUES),
            "startColumnIndex": 0,
            "endColumnIndex": len(HEADER),
        }
        none_style = {"style": "NONE"}
        for position in ("top", "bottom", "left", "right", "innerHorizontal", "innerVertical"):
            assert clear[position] == none_style

    def test_clear_borders_spans_full_grid_even_when_larger_than_used_range(self):
        reqs = self._requests(grid_rows=1000, grid_cols=26)
        clear = reqs[1]["updateBorders"]
        assert clear["range"] == {
            "sheetId": 42,
            "startRowIndex": 0,
            "endRowIndex": 1000,
            "startColumnIndex": 0,
            "endColumnIndex": 26,
        }

    def test_trims_oversized_grid(self):
        reqs = self._requests(grid_rows=1000, grid_cols=26)
        deletes = [r["deleteDimension"]["range"] for r in reqs if "deleteDimension" in r]
        assert {(d["dimension"], d["startIndex"], d["endIndex"]) for d in deletes} == {
            ("ROWS", len(VALUES), 1000),
            ("COLUMNS", len(HEADER), 26),
        }

    def test_exact_grid_needs_no_trim(self):
        assert not [r for r in self._requests() if "deleteDimension" in r]

    def test_existing_banding_deleted_before_readd(self):
        reqs = self._requests(existing_banded_range_ids=[7, 9])
        kinds = [next(iter(r)) for r in reqs]
        assert kinds.count("deleteBanding") == 2
        assert kinds.index("deleteBanding") < kinds.index("addBanding")

    def test_mono_columns_get_font_requests(self):
        reqs = self._requests()
        fonts = [
            r
            for r in reqs
            if "repeatCell" in r
            and r["repeatCell"]["fields"] == "userEnteredFormat.textFormat.fontFamily"
        ]
        assert len(fonts) == len(wsf.MONO_COLUMNS)

    def test_no_blocks_fails_loud(self):
        with pytest.raises(ValueError, match="no machine blocks"):
            self._requests(values=[HEADER])
