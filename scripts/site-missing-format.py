"""Install a conditional-format rule that flags a missing Site on the live sheet.

On the Network and IoT tabs, paint a device row's Site cell RED when the row
has a Machine (hostname) but a blank Site. This is the on-sheet, human-facing
counterpart to the Phase-2 `site_missing` validator (constraints/validators.py):
the validator fails `generate`/`fetch`; this makes the gap obvious while editing.

Scope — Network + IoT only, deliberately NOT WiFi: the WiFi tab's Site column is
vertically merged per host block (wifi-sheet-format.py), so every covered row is
blank by design and the parser's carry-forward fills it in-pipeline. A
machine-populated/Site-blank rule there would paint a false error on every
legitimate covered row.

Idempotent: a re-run deletes the rule(s) this script previously added (matched by
their formula shape) before adding the fresh one, so it never stacks duplicates.

Reads the Site/Machine columns and the header row from the live sheet itself
(no CSV dependency). Writes with the per-site service account, so run as root on
prod, from /opt (like `fetch`/`password`). Dry-run by default; --apply to write.
"""
from __future__ import annotations

import re

# Device tabs to format. gids match scripts/site_populate.py (cross-checked
# against the published-CSV gids). WiFi is intentionally excluded (see module
# docstring).
_TABS = {"Network": 1476589425, "IoT": 1695016218}

# Strong red background + white text: an unmissable error colour, readable.
_RED_FORMAT = {
    "backgroundColor": {"red": 0.918, "green": 0.263, "blue": 0.208},
    "textFormat": {"foregroundColor": {"red": 1.0, "green": 1.0, "blue": 1.0}},
}

# A rule this script owns: =AND($<machine><row><>"",$<site><row>="").
_OUR_RULE_RE = re.compile(r'^=AND\(\$[A-Z]+\d+<>"",\$[A-Z]+\d+=""\)$')


def _col_letter(idx0: int) -> str:
    """0-based column index -> A1 column letters (0->A, 25->Z, 26->AA)."""
    if idx0 < 0:
        raise ValueError(f"negative column index: {idx0}")
    letters = ""
    n = idx0 + 1
    while n:
        n, rem = divmod(n - 1, 26)
        letters = chr(ord("A") + rem) + letters
    return letters


def _header_info(rows: list[list[str]]) -> tuple[int, int, int]:
    """(header_row_0based, site_col_0based, machine_col_0based) from sheet rows.

    The header is the first row containing a 'site' cell; Site/Machine columns
    are matched case-insensitively within it. Raises if either is missing — a
    silent skip would leave the tab unguarded (fail loud).
    """
    for i, row in enumerate(rows):
        lower = [c.strip().lower() for c in row]
        if "site" not in lower:
            continue
        site = lower.index("site")
        machine = next((lower.index(n) for n in ("machine", "machine name",
                                                 "name") if n in lower), None)
        if machine is None:
            raise ValueError(f"header row {i} has 'site' but no machine column")
        return i, site, machine
    raise ValueError("no header row with a 'site' cell found")


def _rule_formula(machine_col0: int, site_col0: int, first_data_row1: int) -> str:
    """CUSTOM_FORMULA for the rule, anchored at the range's first data row.

    Absolute column, relative row (``$B3``) so Sheets evaluates it per row:
    flag when the machine cell is non-empty and the site cell is empty.
    """
    m = f"${_col_letter(machine_col0)}{first_data_row1}"
    s = f"${_col_letter(site_col0)}{first_data_row1}"
    return f'=AND({m}<>"",{s}="")'


def _our_rule_indices(conditional_formats: list[dict]) -> list[int]:
    """Indices (descending) of existing rules this script owns, for deletion.

    Descending so each delete doesn't shift the indices still to be removed.
    """
    hits = []
    for idx, cf in enumerate(conditional_formats or []):
        values = (cf.get("booleanRule", {}).get("condition", {}).get("values")
                  or [])
        formula = values[0].get("userEnteredValue", "") if values else ""
        if _OUR_RULE_RE.match(formula.replace(" ", "")):
            hits.append(idx)
    return sorted(hits, reverse=True)


def _requests_for_tab(gid: int, header_rows: list[list[str]],
                      existing_cf: list[dict]) -> list[dict]:
    """Build the delete-then-add batchUpdate requests for one tab."""
    hdr_i, site_c, machine_c = _header_info(header_rows)
    first_data_row0 = hdr_i + 1          # 0-based: row after the header
    formula = _rule_formula(machine_c, site_c, first_data_row0 + 1)
    reqs: list[dict] = []
    for idx in _our_rule_indices(existing_cf):
        reqs.append({"deleteConditionalFormatRule": {"sheetId": gid,
                                                      "index": idx}})
    reqs.append({"addConditionalFormatRule": {"index": 0, "rule": {
        "ranges": [{
            "sheetId": gid,
            "startRowIndex": first_data_row0,
            "startColumnIndex": site_c,
            "endColumnIndex": site_c + 1,
        }],
        "booleanRule": {
            "condition": {"type": "CUSTOM_FORMULA",
                          "values": [{"userEnteredValue": formula}]},
            "format": _RED_FORMAT,
        },
    }}})
    return reqs


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true",
                    help="write the rule(s) to the live sheet (prod, root)")
    args = ap.parse_args(argv)

    from gdoc2netcfg.config import load_config
    from gdoc2netcfg.utils.gsheets import get_gspread_client

    config = load_config()
    if not config.spreadsheet_url:
        raise SystemExit("spreadsheet_url not configured in [sheets]")
    client = get_gspread_client(config.sheets_config)
    sh = client.open_by_url(config.spreadsheet_url)
    meta = sh.fetch_sheet_metadata(params={
        "fields": "sheets(properties(sheetId,title),conditionalFormats)"})
    cf_by_gid = {s["properties"]["sheetId"]: s.get("conditionalFormats", [])
                 for s in meta.get("sheets", [])}

    requests: list[dict] = []
    for title, gid in _TABS.items():
        if gid not in cf_by_gid:
            raise SystemExit(f"tab {title!r} (gid {gid}) not found in sheet")
        ws = sh.get_worksheet_by_id(gid)
        head = ws.get("A1:BZ5")
        hdr_i, site_c, machine_c = _header_info(head)
        formula = _rule_formula(machine_c, site_c, hdr_i + 2)
        existing = len(_our_rule_indices(cf_by_gid[gid]))
        print(f"{title}: Site={_col_letter(site_c)} Machine="
              f"{_col_letter(machine_c)} data from row {hdr_i + 2}; "
              f"rule {formula} (replacing {existing} existing)")
        requests.extend(_requests_for_tab(gid, head, cf_by_gid[gid]))

    if not args.apply:
        print(f"\n--dry-run: {len(requests)} batchUpdate requests "
              f"(pass --apply to write).")
        return 0
    print(f"\napplying {len(requests)} requests...")
    sh.batch_update({"requests": requests})
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
