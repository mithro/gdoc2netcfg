#!/usr/bin/env python3
"""Scan the gwifi fleet spreadsheet for cross-tab formula references and #REF! errors.

Read-only tool (uses the ``spreadsheets.readonly`` OAuth scope) — safe to
run at any time; it never modifies the spreadsheet. It exists so anyone
editing the sheet (moving rows, renaming tabs, deleting a range) can check
what would break *before* they do it, and confirm nothing broke *after*.

It underlies the ``verify`` phase of ``wifi-sheet-migrate.py``, which uses
the same detection logic to refuse `delete-old-rows` while formulas still
reference the OpenMesh block, and to confirm zero ``#REF!`` cells remain
after the migration completes.

Promoted from the ad-hoc seed script written during the 2026-07-24
WiFi-sheet migration investigation
(``/home/tim/local/gwifi/tmp/scan_formulas.py`` — see
``docs/superpowers/specs/2026-07-24-wifi-sheet-hosts-and-mqtt-credentials-design.md``,
Part 1). That seed run found exactly 6 formulas referencing the OpenMesh
block being moved: ``iot.welland - IoT Devices`` rows 24-29, column H.

Usage:
    uv run scripts/wifi-sheet-scan.py                    # scan every tab
    uv run scripts/wifi-sheet-scan.py --tab 'iot.welland - IoT Devices'
    uv run scripts/wifi-sheet-scan.py --watch-tab 'Welland - IP Allocation' \\
        --watch-min-row 337 --watch-max-row 378           # flag refs into a range
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account

DEFAULT_SPREADSHEET_ID = "1fFm2irzmnLb7RQNmAi4DmAm2_c61wrd5A2j3ZzdqIWE"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
DEFAULT_SA_PATH = Path.home() / ".config" / "gale-fleet" / "sheets-sa.json"
REQUEST_TIMEOUT = 60  # seconds; every network call below is a single small REST request

# A formula references another tab if it contains a quoted-or-bare sheet
# name immediately followed by '!' (e.g. "'IoT'!F1" or "Sheet1!A1").
_CROSS_TAB_RE = re.compile(r"('[^']+'!|\b[A-Za-z][\w. ]*!)")


def get_token(sa_path: Path, *, readonly: bool = True) -> str:
    """Refresh a service-account token scoped to the Sheets API."""
    scope = "spreadsheets.readonly" if readonly else "spreadsheets"
    creds = service_account.Credentials.from_service_account_file(
        str(sa_path), scopes=[f"https://www.googleapis.com/auth/{scope}"]
    )
    creds.refresh(Request())
    return creds.token


def list_tabs(token: str, spreadsheet_id: str) -> list[dict]:
    """Return [{'title', 'sheetId', ...}] for every tab in the spreadsheet."""
    resp = requests.get(
        f"{SHEETS_API}/{spreadsheet_id}",
        headers={"Authorization": f"Bearer {token}"},
        params={"fields": "sheets.properties"},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return [s["properties"] for s in resp.json().get("sheets", [])]


def fetch_values(
    token: str, spreadsheet_id: str, tab_title: str, render: str = "FORMULA"
) -> list[list[str]]:
    """Fetch a tab's values. ``render`` is a Sheets API valueRenderOption."""
    quoted = "'" + tab_title.replace("'", "''") + "'"
    url = f"{SHEETS_API}/{spreadsheet_id}/values/{requests.utils.quote(quoted)}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params={"valueRenderOption": render},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json().get("values", [])


def find_cross_tab_formula_cells(values: list[list[str]]) -> list[tuple[int, int, str]]:
    """Return (row, col, formula) — both 1-based — for every cross-tab formula cell."""
    hits = []
    for r, row in enumerate(values, start=1):
        for c, cell in enumerate(row, start=1):
            if isinstance(cell, str) and cell.startswith("=") and _CROSS_TAB_RE.search(cell):
                hits.append((r, c, cell))
    return hits


def find_ref_errors(values: list[list[str]]) -> list[tuple[int, int, str]]:
    """Return (row, col, value) — both 1-based — for every cell evaluating to #REF!."""
    hits = []
    for r, row in enumerate(values, start=1):
        for c, cell in enumerate(row, start=1):
            if isinstance(cell, str) and cell.strip() == "#REF!":
                hits.append((r, c, cell))
    return hits


def refs_into_watch_range(
    cells: list[tuple[int, int, str]], watch_tab: str, min_row: int, max_row: int
) -> list[tuple[int, int, str]]:
    """Filter cross-tab formula cells to those referencing watch_tab rows in [min_row, max_row]."""
    pattern = re.compile(re.escape(f"'{watch_tab}'!") + r"\$?[A-Za-z]+\$?(\d+)")
    out = []
    for r, c, formula in cells:
        for m in pattern.finditer(formula):
            if min_row <= int(m.group(1)) <= max_row:
                out.append((r, c, formula))
                break
    return out


def scan_spreadsheet(
    token: str,
    spreadsheet_id: str,
    *,
    tab_filter: str | None = None,
    watch_tab: str | None = None,
    watch_min_row: int | None = None,
    watch_max_row: int | None = None,
) -> dict:
    """Scan every (or one) tab; return a report dict for printing/asserting on.

    Report shape: {"tabs": [title,...], "cross_tab_cells": {title: [...]}, ,
    "ref_errors": {title: [...]}, "watch_hits": {title: [...]}}
    """
    tabs = [t["title"] for t in list_tabs(token, spreadsheet_id)]
    if tab_filter is not None:
        tabs = [t for t in tabs if t == tab_filter]

    report: dict = {"tabs": tabs, "cross_tab_cells": {}, "ref_errors": {}, "watch_hits": {}}
    for title in tabs:
        formula_values = fetch_values(token, spreadsheet_id, title, render="FORMULA")
        cross_tab = find_cross_tab_formula_cells(formula_values)
        if cross_tab:
            report["cross_tab_cells"][title] = cross_tab
        if watch_tab is not None and watch_min_row is not None and watch_max_row is not None:
            hits = refs_into_watch_range(cross_tab, watch_tab, watch_min_row, watch_max_row)
            if hits:
                report["watch_hits"][title] = hits

        rendered_values = fetch_values(token, spreadsheet_id, title, render="FORMATTED_VALUE")
        ref_errors = find_ref_errors(rendered_values)
        if ref_errors:
            report["ref_errors"][title] = ref_errors
    return report


def print_report(report: dict) -> None:
    print(f"tabs scanned: {report['tabs']}")
    for title, cells in report["cross_tab_cells"].items():
        print(f"\n{title}: {len(cells)} cross-tab formula cell(s)")
        for r, c, formula in cells:
            print(f"  R{r}C{c}: {formula[:160]}")
    if report["watch_hits"]:
        print("\n=== References into the watched range (would break if deleted) ===")
        for title, hits in report["watch_hits"].items():
            for r, c, formula in hits:
                print(f"  {title}!R{r}C{c}: {formula}")
    if report["ref_errors"]:
        print("\n=== #REF! errors ===")
        for title, hits in report["ref_errors"].items():
            for r, c, value in hits:
                print(f"  {title}!R{r}C{c}: {value}")
    if not report["watch_hits"] and not report["ref_errors"]:
        print("\nNo #REF! errors and no references into the watched range.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sa-path", type=Path, default=DEFAULT_SA_PATH)
    parser.add_argument("--spreadsheet-id", default=DEFAULT_SPREADSHEET_ID)
    parser.add_argument("--tab", default=None, help="Scan only this tab (default: all tabs)")
    parser.add_argument(
        "--watch-tab", default=None, help="Tab whose rows are about to move/be deleted"
    )
    parser.add_argument("--watch-min-row", type=int, default=None)
    parser.add_argument("--watch-max-row", type=int, default=None)
    args = parser.parse_args(argv)

    token = get_token(args.sa_path)
    report = scan_spreadsheet(
        token,
        args.spreadsheet_id,
        tab_filter=args.tab,
        watch_tab=args.watch_tab,
        watch_min_row=args.watch_min_row,
        watch_max_row=args.watch_max_row,
    )
    print_report(report)
    return 1 if (report["watch_hits"] or report["ref_errors"]) else 0


if __name__ == "__main__":
    sys.exit(main())
