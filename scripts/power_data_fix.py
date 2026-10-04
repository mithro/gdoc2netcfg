"""One-off: clean the sheet so the power-tree Controls/Location contract passes
AND canonicalise the Site/Location taxonomy (operator-confirmed 2026-10-04).

Modes:
  (default)        read cached CSVs, print a change-count summary (no creds).
  --apply-to-csv D edit iot/network/wifi .csv in copy dir D (for the verify harness).
  --diff           connect to the LIVE sheet, print every cell change (A1, old->new),
                   write NOTHING. Needs [sheets] spreadsheet_url + service account; root.
  --apply          same as --diff, then WRITE the changes. Needs creds; run as root.

Decisions encoded (see the per-table constants). Throwaway: remove after the sheet
is clean and the power-tree branch has landed.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from gdoc2netcfg.config import load_config

# au-plug-9 (multi-value; resolves once 'starlink' exists) and au-plug-17
# (already 'nbn-router') are intentionally absent.
IOT_CONTROLS = {
    "au-plug-3": "appliance: bar heater",
    "au-plug-6": "left.nvmeof, right.nvmeof",
    "au-plug-10": "rpi4-asus-aspeed2050-dev",
    "au-plug-11": "esp32cam-elec-welland",
    "au-plug-12": "appliance: speakers.rpiz-dash-2",
    "au-plug-20": "appliance: monitors.desktop",
    "au-plug-29": "appliance: aux.gvc",
    "au-plug-35": "appliance: heater tv room",
    "au-plug-47": "ups-apc-srv3k",
    "us-plug-1": "appliance: ac",
}

LOCATION_MAP: dict[str, tuple[str, str | None]] = {
    "Back Shed - Xmas Tree Rack": ("Back Shed - Xmas Tree Rack", None),
    "Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack", None),
    "Xmas Tree Rack": ("Back Shed - Xmas Tree Rack", None),
    "Bottom of Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack - Bottom", None),
    "Middle of Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack - Middle", None),
    "Top of Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack - Top", None),
    "On top of Xmas Tree Rack in backshed": ("Back Shed - Xmas Tree Rack - Top", None),
    "Back Shed - Soundproof Rack": ("Back Shed - Soundproof Rack", None),
    "Soundproof Rack in Back Shed": ("Back Shed - Soundproof Rack", None),
    "Sound Proof Rack": ("Back Shed - Soundproof Rack", None),
    "Back Shed - Ontop of Soundproof rack": ("Back Shed - Soundproof Rack - Top", None),
    "Right RPi Zero on top of the soundproof rack connected to a monitor":
        ("Back Shed - Soundproof Rack - Top", "Right RPi Zero connected to a monitor"),
    "Left RPi Zero on top of the soundproof rack connected to a monitor":
        ("Back Shed - Soundproof Rack - Top", "Left RPi Zero connected to a monitor"),
    "Mains -> UPS\nBack Shed - Soundproof Rack":
        ("Back Shed - Soundproof Rack", "Mains -> UPS feed"),
    "Back Shed - SuperMicro Rack": ("Back Shed - SuperMicro Rack", None),
    "Back Shed Bench": ("Back Shed - Bench", None),
    "Back Shed on Bench": ("Back Shed - Bench", None),
    "Back Shed": ("Back Shed", None),
    "Welland - Back Shed": ("Back Shed", None),
    "433 MHz test bench (with rpi5-433mhz)": ("433 MHz Test Bench", "with rpi5-433mhz"),
    "ESP dev station (on rpi4-esp)": ("ESP Dev Station", "on rpi4-esp"),
    "fpgas.online rack (on pi-sw2-p30)": ("fpgas.online Rack", "on pi-sw2-p30"),
    "fpgas.online rack (on pi-sw2-p30) — deployment TBD":
        ("fpgas.online Rack", "on pi-sw2-p30; deployment TBD"),
    "Tim's Bedroom": ("Tim's Bedroom", None),
    "Welland - Tim's Bedroom": ("Tim's Bedroom", None),
    "Living Room": ("Living Room", None),
    "Living Room under ten64": ("Living Room", "under ten64"),
    "Living Room - TV (16x-s2 port 1/0/9)": ("Living Room", "TV; 16x-s2 port 1/0/9"),
    "Lounge": ("Living Room", None),
    "Lounge Room": ("Living Room", None),
    "TV Room": ("TV Room", None),
    "Front Door": ("Front Door", None),
    "Driveway": ("Driveway", None),
    "Carport": ("Carport", None),
    "Welland - Meter Box": ("Meter Box", None),
    "Parent's Bedroom": ("Parent's Bedroom", None),
    "With Tish": ("With Tish", None),
    "Monarto - Power Meter Box": ("Meter Box", None),
    "Monarto - Meter Box": ("Meter Box", None),
    "Monarto - Purple Bedroom": ("Purple Bedroom", None),
    "Monarto - Back Corner Room": ("Back Corner Room", None),
    "Monarto - Back Door near Shed": ("Back Door near Shed", None),
    "Monarto cabinet in dinning room": ("Dining Room", "in cabinet"),
    "????": ("", None),  # no site hint -> blank, Site left as-is
}

OFFLINE_SWITCHES = {
    "sw-netgear-m7300", "sw-netgear-xs748t", "sw-edgecore-7512",
    "sw-edgecore-switch", "sw-cisco-shed",
}
SITE_CASE = {"Welland": "welland", "Monarto": "monarto", "Special": "special"}
# A bare site name (or a site-hint placeholder) in the Location field belongs
# in the Site column: set Site and clear Location (fixes blank-Site rows like
# light7/light8 / rpi-sdr-rtlsdr-v4 that recorded the site in Location).
SITE_AS_LOCATION = {"Monarto": "monarto", "Welland": "welland",
                    "???? - Monarto?": "monarto"}
# A 'Site - sublocation' prefix names the site; set Site (only when blank, so a
# real Site value is never clobbered) — the LOCATION_MAP strips the prefix.
SITE_PREFIXES = {"Welland": "welland", "Monarto": "monarto"}

IOT_NEW_ROWS = [{
    "Machine": "ups-apc-srv3k", "Site": "welland",
    "Physical Location": "Back Shed - Soundproof Rack",
    "Human Name": "APC/Voltronic SRV 3kVA (nutdrv_qx) - monitored by rpi4-ups",
    "Controls": "au-plug-48",
}]
NETWORK_NEW_ROWS = [
    {"Site": "welland", "Machine": "nbn-router", "MAC Address": "C8:52:61:02:EA:95",
     "Notes": "nbn HFC NTD, Arris CM8200B (nbn-managed); mgmt 192.168.100.1 only in the "
              "1-2 min window after a hard reset (see nbnsucks/hfcmon); powered by au-plug-17"},
    {"Site": "monarto", "Machine": "starlink", "MAC Address": "26:12:ac:1a:80:01",
     "IPv4": "192.168.100.1",
     "Notes": "Starlink dish management (dishy); off-VLAN; powered by au-plug-9"},
]

# Per-table column names: (location col, notes col, controls col or None, is_network).
TABLES = {
    "iot": ("Physical Location", "Notes / Comments", "Controls", False),
    "network": ("Location", "Notes", None, True),
    "wifi": ("Physical Location", "Notes / Comments", None, False),
}


def _pad(row: list[str], idx: int) -> None:
    while len(row) <= idx:
        row.append("")


def _edit_row(row: list[str], cols: dict[str, int], loc_col: str, notes_col: str,
              ctrl_col: str | None, is_network: bool) -> bool:
    """Apply all edits to one row in place. Returns True if anything changed."""
    mi, si, li, ni = cols["Machine"], cols["Site"], cols[loc_col], cols[notes_col]
    _pad(row, max(mi, si, li, ni))
    if not row[mi]:
        return False
    before = list(row)
    machine = row[mi]
    if row[si] in SITE_CASE:
        row[si] = SITE_CASE[row[si]]
    if is_network and machine in OFFLINE_SWITCHES:
        row[si], row[li] = "special", ""
        return row != before
    if row[li] in SITE_AS_LOCATION:  # bare site name in Location -> Site column
        row[si], row[li] = SITE_AS_LOCATION[row[li]], ""
    elif not row[si]:  # 'Site - sublocation' prefix names the site (Site blank)
        for pfx, s in SITE_PREFIXES.items():
            if row[li].startswith(pfx + " - "):
                row[si] = s
                break
    if ctrl_col and machine in IOT_CONTROLS:
        ci = cols[ctrl_col]
        _pad(row, ci)
        row[ci] = IOT_CONTROLS[machine]
    cur = row[li]
    if cur in LOCATION_MAP:
        canon, note = LOCATION_MAP[cur]
        if canon != cur:
            row[li] = canon
        if note and note not in row[ni]:
            row[ni] = f"{row[ni].strip()}; {note}" if row[ni].strip() else note
    return row != before


def _cols(hdr: list[str]) -> dict[str, int]:
    return {name: i for i, name in enumerate(hdr)}


def _header_idx(rows: list[list[str]]) -> int:
    for i, r in enumerate(rows):
        if "Machine" in r:
            return i
    raise SystemExit("no header row with 'Machine'")


# ---------------- CSV modes ------------------------------------------------

def _read(cache_dir: Path, name: str):
    with open(cache_dir / f"{name}.csv", newline="") as f:
        rows = list(csv.reader(f))
    return rows, _header_idx(rows)


def _run_csv(cache_dir: Path, write_dir: Path | None) -> None:
    for name, (loc, notes, ctrl, isnet) in TABLES.items():
        rows, h = _read(cache_dir, name)
        cols = _cols(rows[h])
        changed = sum(_edit_row(r, cols, loc, notes, ctrl, isnet) for r in rows[h + 1:])
        new_rows = {"iot": IOT_NEW_ROWS, "network": NETWORK_NEW_ROWS}.get(name, [])
        if write_dir is not None:
            for spec in new_rows:
                rows.append([spec.get(c, "") for c in rows[h]])
            with open(write_dir / f"{name}.csv", "w", newline="") as f:
                csv.writer(f).writerows(rows)
        print(f"{name}: {changed} rows changed (+{len(new_rows)} new)")


# ---------------- live gspread modes --------------------------------------

def _classify(hdr: list[str]) -> str | None:
    if "Controls" in hdr and "Device ID" in hdr:
        return "iot"
    if "Upstream" in hdr and "Controlled By" in hdr:
        return "wifi"
    if "Controlled By" in hdr and "IPv4" in hdr:
        return "network"
    return None


def _gspread(config, write: bool) -> int:
    import gspread

    from gdoc2netcfg.utils.gsheets import get_gspread_client

    if not config.spreadsheet_url:
        raise SystemExit("spreadsheet_url not set in [sheets] of the toml")
    sh = get_gspread_client(config.sheets_config).open_by_url(config.spreadsheet_url)

    found: dict[str, tuple] = {}
    for ws in sh.worksheets():
        vals = ws.get_all_values()
        hidx = next((i for i, r in enumerate(vals[:6]) if "Machine" in r), None)
        if hidx is None:
            continue
        kind = _classify(vals[hidx])
        if kind and kind not in found:
            found[kind] = (ws, vals, hidx)

    total = 0
    for name, (loc, notes, ctrl, isnet) in TABLES.items():
        if name not in found:
            print(f"WARN: {name} tab not found — skipped", file=sys.stderr)
            continue
        ws, vals, h = found[name]
        cols = _cols(vals[h])
        updates = []
        for r_i in range(h + 1, len(vals)):
            old = list(vals[r_i])
            new = list(old)
            if not _edit_row(new, cols, loc, notes, ctrl, isnet):
                continue
            for c_i, (o, n) in enumerate(zip(old + [""] * (len(new) - len(old)), new)):
                if o != n:
                    a1 = gspread.utils.rowcol_to_a1(r_i + 1, c_i + 1)
                    print(f"  {ws.title}!{a1}  {vals[h][c_i]}: {o!r} -> {n!r}")
                    updates.append({"range": a1, "values": [[n]]})
        if write and updates:
            ws.batch_update(updates, value_input_option="RAW")
        total += len(updates)
        for spec in {"iot": IOT_NEW_ROWS, "network": NETWORK_NEW_ROWS}.get(name, []):
            vals_row = [spec.get(c, "") for c in vals[h]]
            print(f"  {ws.title}: APPEND {spec.get('Machine')}  {vals_row}")
            total += 1
            if write:
                ws.append_row(vals_row, value_input_option="RAW")
    print(f"\n{total} change(s) {'WRITTEN' if write else 'to write (dry — pass --apply)'}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-c", "--config", default="gdoc2netcfg.toml")
    ap.add_argument("--apply-to-csv", metavar="DIR", help="edit CSVs in a throwaway copy dir")
    ap.add_argument("--diff", action="store_true", help="connect to the live sheet, print every change, write nothing")
    ap.add_argument("--apply", action="store_true", help="connect, print, and WRITE (needs creds; run as root)")
    args = ap.parse_args()

    if args.apply_to_csv:
        _run_csv(Path(args.apply_to_csv), Path(args.apply_to_csv))
        return 0
    config = load_config(args.config)
    if args.diff or args.apply:
        return _gspread(config, write=args.apply)
    _run_csv(config.cache.directory, None)  # count summary, no creds
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
