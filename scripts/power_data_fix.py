"""One-off: clean the sheet so the power-tree Controls/Location contract passes
AND canonicalise the Site/Location taxonomy (operator-confirmed 2026-10-04).

Dry-run by default (reads cached CSVs, no credentials): prints the plan. With
--apply-to-csv DIR it edits iot.csv/network.csv in a throwaway cache copy (for
the validate+generate verification). With --apply it would write the live sheet
via gspread (needs prod creds; run as root) — not yet wired.

Decisions encoded:
  - Controls: typo fixes + 'appliance:' prefixes + UPS wiring (au-plug-9/au-plug-17
    intentionally untouched — see IOT_CONTROLS note).
  - Location canonicalised (no site prefix — Site column scopes it; rack position
    kept as a sub-level; Living Room = Lounge = Lounge Room, TV Room separate);
    device/port annotations moved to the Notes column; '????'/bare 'Monarto'
    blanked (-> [unknown location]).
  - Offline switches -> Site 'special', Location cleared (keeps history, drops
    them from the active per-site power tree).
  - Site case normalised to the Sites-sheet shortnames: welland / monarto / special.
  - New rows: ups-apc-srv3k (IoT infra), nbn-router (Arris CM8200B, DNS-only MAC),
    starlink (dish mgmt).
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from gdoc2netcfg.config import load_config

# --- IoT Controls (match by Machine). au-plug-9 is multi-value and resolves
#     once 'starlink' exists; au-plug-17 is already 'nbn-router' — both untouched.
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

# raw Location cell -> (canonical location, note-to-append-to-Notes or None).
# "" canonical clears the cell (-> [unknown location]). Applies to both sheets.
LOCATION_MAP: dict[str, tuple[str, str | None]] = {
    # Back Shed - Xmas Tree Rack
    "Back Shed - Xmas Tree Rack": ("Back Shed - Xmas Tree Rack", None),
    "Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack", None),
    "Xmas Tree Rack": ("Back Shed - Xmas Tree Rack", None),
    "Bottom of Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack - Bottom", None),
    "Middle of Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack - Middle", None),
    "Top of Xmas Tree Rack in Back Shed": ("Back Shed - Xmas Tree Rack - Top", None),
    "On top of Xmas Tree Rack in backshed": ("Back Shed - Xmas Tree Rack - Top", None),
    # Back Shed - Soundproof Rack
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
    # Back Shed - other
    "Back Shed - SuperMicro Rack": ("Back Shed - SuperMicro Rack", None),
    "Back Shed Bench": ("Back Shed - Bench", None),
    "Back Shed on Bench": ("Back Shed - Bench", None),
    "Back Shed": ("Back Shed", None),
    "Welland - Back Shed": ("Back Shed", None),
    # benches / racks with device annotations -> Notes (location NOT assumed Back Shed)
    "433 MHz test bench (with rpi5-433mhz)": ("433 MHz Test Bench", "with rpi5-433mhz"),
    "ESP dev station (on rpi4-esp)": ("ESP Dev Station", "on rpi4-esp"),
    "fpgas.online rack (on pi-sw2-p30)": ("fpgas.online Rack", "on pi-sw2-p30"),
    "fpgas.online rack (on pi-sw2-p30) — deployment TBD":
        ("fpgas.online Rack", "on pi-sw2-p30; deployment TBD"),
    # Welland house
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
    # Monarto
    "Monarto": ("", None),
    "Monarto - Power Meter Box": ("Meter Box", None),
    "Monarto - Meter Box": ("Meter Box", None),
    "Monarto - Purple Bedroom": ("Purple Bedroom", None),
    "Monarto - Back Corner Room": ("Back Corner Room", None),
    "Monarto - Back Door near Shed": ("Back Door near Shed", None),
    "Monarto cabinet in dinning room": ("Dining Room", "in cabinet"),
    # blanked (unknown) per operator
    "???? - Monarto?": ("", None),
    "????": ("", None),
}

# Network switches that are decommissioned/offline -> Site 'special', clear Location.
OFFLINE_SWITCHES = {
    "sw-netgear-m7300", "sw-netgear-xs748t", "sw-edgecore-7512",
    "sw-edgecore-switch", "sw-cisco-shed",
}

# Site value case -> Sites-sheet shortname (lowercase canonical).
SITE_CASE = {"Welland": "welland", "Monarto": "monarto", "Special": "special"}

IOT_NEW_ROWS = [
    {
        "Machine": "ups-apc-srv3k", "Site": "welland",
        "Physical Location": "Back Shed - Soundproof Rack",
        "Human Name": "APC/Voltronic SRV 3kVA (nutdrv_qx) - monitored by rpi4-ups",
        "Controls": "au-plug-48",
    },
]
NETWORK_NEW_ROWS = [
    {
        "Site": "welland", "Machine": "nbn-router", "MAC Address": "C8:52:61:02:EA:95",
        "Notes": "nbn HFC NTD, Arris CM8200B (nbn-managed); mgmt 192.168.100.1 only in "
                 "the 1-2 min window after a hard reset (see nbnsucks/hfcmon); "
                 "powered by au-plug-17",
    },
    {
        "Site": "monarto", "Machine": "starlink", "MAC Address": "26:12:ac:1a:80:01",
        "IPv4": "192.168.100.1",
        "Notes": "Starlink dish management (dishy); off-VLAN; powered by au-plug-9",
    },
]


def _read(cache_dir: Path, name: str):
    with open(cache_dir / f"{name}.csv", newline="") as f:
        rows = list(csv.reader(f))
    for i, r in enumerate(rows):
        if "Machine" in r:
            return r, rows, i
    raise SystemExit(f"{name}.csv: no header row with 'Machine'")


def _append_note(row: list[str], notes_idx: int, note: str) -> None:
    while len(row) <= notes_idx:
        row.append("")
    cur = row[notes_idx].strip()
    if note and note not in cur:
        row[notes_idx] = f"{cur}; {note}" if cur else note


def _edit_sheet(cache_dir: Path, name: str, loc_col: str, notes_col: str,
                controls_col: str | None, offline: bool) -> dict:
    hdr, rows, h = _read(cache_dir, name)
    li, ni, mi, si = hdr.index(loc_col), hdr.index(notes_col), hdr.index("Machine"), hdr.index("Site")
    ci = hdr.index(controls_col) if controls_col else None
    counts = {"site_case": 0, "controls": 0, "location": 0, "notes": 0, "offline": 0}
    for r in rows[h + 1:]:
        if len(r) <= mi or not r[mi]:
            continue
        machine = r[mi]
        # 1. Site case normalisation
        if len(r) > si and r[si] in SITE_CASE:
            r[si] = SITE_CASE[r[si]]
            counts["site_case"] += 1
        # 2. Offline switches (network): Site special + clear location
        if offline and machine in OFFLINE_SWITCHES:
            while len(r) <= max(si, li):
                r.append("")
            r[si], r[li] = "special", ""
            counts["offline"] += 1
            continue
        # 3. Controls (iot)
        if ci is not None and machine in IOT_CONTROLS:
            while len(r) <= ci:
                r.append("")
            r[ci] = IOT_CONTROLS[machine]
            counts["controls"] += 1
        # 4. Location canonicalisation + Notes migration
        cur_loc = r[li] if len(r) > li else ""
        if cur_loc in LOCATION_MAP:
            canon, note = LOCATION_MAP[cur_loc]
            if canon != cur_loc:
                while len(r) <= li:
                    r.append("")
                r[li] = canon
                counts["location"] += 1
            if note:
                _append_note(r, ni, note)
                counts["notes"] += 1
    return {"hdr": hdr, "rows": rows, "counts": counts}


def _dry_run(cache_dir: Path) -> None:
    for name, loc, notes, ctrl, off in (
        ("iot", "Physical Location", "Notes / Comments", "Controls", False),
        ("network", "Location", "Notes", None, True),
        ("wifi", "Physical Location", "Notes / Comments", None, False),
    ):
        hdr, rows, h = _read(cache_dir, name)
        # report without mutating the originals: operate on a deep copy
        import copy
        res = _edit_sheet_on(copy.deepcopy(rows), hdr, h, loc, notes, ctrl, off)
        print(f"== {name}: {res} ==")
    print("New IoT rows:", [r["Machine"] for r in IOT_NEW_ROWS])
    print("New Network rows:", [r["Machine"] for r in NETWORK_NEW_ROWS])
    print("\n(dry run — counts only; use --apply-to-csv DIR to edit a cache copy)")


def _edit_sheet_on(rows, hdr, h, loc_col, notes_col, controls_col, offline) -> dict:
    li, ni, mi, si = hdr.index(loc_col), hdr.index(notes_col), hdr.index("Machine"), hdr.index("Site")
    ci = hdr.index(controls_col) if controls_col else None
    c = {"site_case": 0, "controls": 0, "location": 0, "notes": 0, "offline": 0}
    for r in rows[h + 1:]:
        if len(r) <= mi or not r[mi]:
            continue
        m = r[mi]
        if len(r) > si and r[si] in SITE_CASE:
            r[si] = SITE_CASE[r[si]]; c["site_case"] += 1
        if offline and m in OFFLINE_SWITCHES:
            while len(r) <= max(si, li):
                r.append("")
            r[si], r[li] = "special", ""; c["offline"] += 1; continue
        if ci is not None and m in IOT_CONTROLS:
            while len(r) <= ci:
                r.append("")
            r[ci] = IOT_CONTROLS[m]; c["controls"] += 1
        cur = r[li] if len(r) > li else ""
        if cur in LOCATION_MAP:
            canon, note = LOCATION_MAP[cur]
            if canon != cur:
                while len(r) <= li:
                    r.append("")
                r[li] = canon; c["location"] += 1
            if note:
                _append_note(r, ni, note); c["notes"] += 1
    return c


def _apply_to_csv(csv_dir: Path) -> None:
    for name, loc, notes, ctrl, off in (
        ("iot", "Physical Location", "Notes / Comments", "Controls", False),
        ("network", "Location", "Notes", None, True),
        ("wifi", "Physical Location", "Notes / Comments", None, False),
    ):
        res = _edit_sheet(csv_dir, name, loc, notes, ctrl, off)
        new_rows = {"iot": IOT_NEW_ROWS, "network": NETWORK_NEW_ROWS}.get(name, [])
        for spec in new_rows:
            res["rows"].append([spec.get(col, "") for col in res["hdr"]])
        with open(csv_dir / f"{name}.csv", "w", newline="") as f:
            csv.writer(f).writerows(res["rows"])
        print(f"{name}: {res['counts']} (+{len(new_rows)} new rows)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-c", "--config", default="gdoc2netcfg.toml")
    ap.add_argument("--apply", action="store_true", help="write the live sheet (needs creds; run as root)")
    ap.add_argument("--apply-to-csv", metavar="DIR", help="edit iot/network.csv in DIR (throwaway copy, for testing)")
    args = ap.parse_args()
    if args.apply_to_csv:
        _apply_to_csv(Path(args.apply_to_csv))
        return 0
    config = load_config(args.config)
    if not args.apply:
        _dry_run(config.cache.directory)
        return 0
    print("--apply (gspread) not yet wired; confirm the verified plan first.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
