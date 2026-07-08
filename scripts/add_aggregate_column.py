"""One-off (2026-07-09, dns-redesign Task 1.2): add the 'Aggregate' column.

Adds the 'Aggregate' header to the Welland IP Allocation tab and sets
'br-int' on the ten64 rows for both sites — the interfaces whose
addresses form ten64's site-level aggregate DNS records (design §3
override column; excludes the parked 10.X.253/254 NICs and the WAN).

Formatting-safe: values-only batch_update with RAW input (per
reference-gsheets-api-write). Idempotent: skips writes whose cell
already holds the target value.

Run with: /opt/gdoc2netcfg/.venv/bin/python scripts/add_aggregate_column.py
"""

import google.auth.transport.requests
import google.oauth2.credentials
import gspread

SPREADSHEET_ID = "1fFm2irzmnLb7RQNmAi4DmAm2_c61wrd5A2j3ZzdqIWE"
WELLAND_GID = 1476589425
HEADER_ROW = 2  # 1-based; row 1 holds the IPv6 prefix metadata

AGGREGATE_VALUES = {
    # (site, machine, interface, ipv4) -> value; ipv4 disambiguates the
    # duplicate-named br-int rows (10.1.16.255 stays without an override).
    ("welland", "ten64", "br-int", "10.1.10.1"): "br-int",
    ("monarto", "ten64", "br-int", "10.2.10.1"): "br-int",
}


def main() -> None:
    creds = google.oauth2.credentials.Credentials.from_authorized_user_file(
        "/home/tim/local/tweed/sheets_token.json"
    )
    creds.refresh(google.auth.transport.requests.Request())
    gc = gspread.authorize(creds)
    ws = gc.open_by_key(SPREADSHEET_ID).get_worksheet_by_id(WELLAND_GID)

    rows = ws.get_all_values()
    header = rows[HEADER_ROW - 1]

    if "Aggregate" in header:
        agg_col = header.index("Aggregate") + 1  # 1-based
        print(f"'Aggregate' header already present (col {agg_col})")
    else:
        agg_col = len(header) + 1
        if ws.col_count < agg_col:
            ws.add_cols(agg_col - ws.col_count)
            print(f"grew grid to {agg_col} columns")
        ws.update_cell(HEADER_ROW, agg_col, "Aggregate")
        print(f"added 'Aggregate' header at col {agg_col}")

    site_i = header.index("Site")
    machine_i = header.index("Machine")
    iface_i = header.index("Interface")
    ipv4_i = header.index("IPv4")

    updates = []
    for row_num, row in enumerate(rows[HEADER_ROW:], start=HEADER_ROW + 1):
        key = (
            row[site_i].strip().lower(),
            row[machine_i].strip().lower(),
            row[iface_i].strip(),
            row[ipv4_i].strip(),
        )
        value = AGGREGATE_VALUES.get(key)
        if value is None:
            continue
        current = row[agg_col - 1] if len(row) >= agg_col else ""
        if current == value:
            print(f"row {row_num}: already '{value}', skipping")
            continue
        cell = gspread.utils.rowcol_to_a1(row_num, agg_col)
        updates.append({"range": cell, "values": [[value]]})
        print(f"row {row_num}: {key} -> {cell} = '{value}'")

    if updates:
        ws.batch_update(updates, value_input_option="RAW")
        print(f"wrote {len(updates)} cell(s)")
    else:
        print("nothing to write")


if __name__ == "__main__":
    main()
