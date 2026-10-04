"""One-off: clean the sheet so the power-tree Controls/Location contract passes.

Dry-run by default (reads the cached CSVs, needs no credentials): prints every
planned cell edit, new row, and deletion. With --apply it performs the edits via
gspread (needs [sheets] spreadsheet_url + service_account in the prod toml; run
as root on prod). Committed as evidence; remove after the sheet is clean.

Scope (confirmed with the operator 2026-10-04):
  - IoT Controls: typo fixes + 'appliance:' prefixes + UPS/host wiring
  - IoT Physical Location consistency (Soundproof Rack)
  - New IoT infra row: ups-apc-srv3k (Controls -> au-plug-48)
  - New Network rows: nbn-router (Arris CM8200B, DNS-only MAC), starlink (dish mgmt)
  - Network Location fix ('???? - Monarto?' -> 'Monarto')
  - Delete the decommissioned sw-cisco-shed Network row
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from gdoc2netcfg.config import load_config

# --- IoT tab edits (match by Machine) ------------------------------------
# NOTE: au-plug-9 and au-plug-17 are intentionally absent.
#  - au-plug-9 controls 3 targets (ten64.monarto / starlink.monarto / gs728tpp);
#    adding the 'starlink' host makes all three resolve, so its cell is untouched.
#  - au-plug-17's cell is already 'nbn-router'; adding that host resolves it.
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
IOT_LOCATION = {
    "rpi4-ups": "Back Shed - Soundproof Rack",
    "au-plug-47": "Back Shed - Soundproof Rack",
}
# New IoT infra row (column header -> value); blank columns omitted.
IOT_NEW_ROWS = [
    {
        "Machine": "ups-apc-srv3k",
        "Site": "Welland",
        "Physical Location": "Back Shed - Soundproof Rack",
        "Human Name": "APC/Voltronic SRV 3kVA (nutdrv_qx) - monitored by rpi4-ups",
        "Controls": "au-plug-48",
    },
]

# --- Network tab edits ---------------------------------------------------
# Location fix matched by current value (we don't hardcode a row number).
NETWORK_LOCATION_FIX = {"???? - Monarto?": "Monarto"}
NETWORK_NEW_ROWS = [
    {
        "Site": "Welland",
        "Machine": "nbn-router",
        "MAC Address": "C8:52:61:02:EA:95",
        "Notes": "nbn HFC NTD, Arris CM8200B (nbn-managed, no local mgmt IP); "
                 "powered by au-plug-17",
    },
    {
        "Site": "Monarto",
        "Machine": "starlink",
        "MAC Address": "26:12:ac:1a:80:01",
        "IPv4": "192.168.100.1",
        "Notes": "Starlink dish management (dishy); off-VLAN; powered by au-plug-9",
    },
]
NETWORK_DELETE_MACHINE = "sw-cisco-shed"


def _read_cached(cache_dir: Path, name: str) -> tuple[list[str], list[list[str]], int]:
    """Return (header, rows, header_row_index) from a cached CSV.

    The header is the first row containing 'Machine'; rows precede/follow it as-is.
    """
    with open(cache_dir / f"{name}.csv", newline="") as f:
        rows = list(csv.reader(f))
    for i, r in enumerate(rows):
        if "Machine" in r:
            return r, rows, i
    raise SystemExit(f"{name}.csv: no header row with 'Machine'")


def _dry_run(cache_dir: Path) -> None:
    ihdr, irows, ih = _read_cached(cache_dir, "iot")
    ictrl, iloc, imach = ihdr.index("Controls"), ihdr.index("Physical Location"), ihdr.index("Machine")
    irows_data = [r for r in irows[ih + 1:] if len(r) > imach and r[imach]]
    iot_by_machine: dict[str, list[list[str]]] = {}
    for r in irows_data:
        iot_by_machine.setdefault(r[imach], []).append(r)

    print("== IoT Controls edits ==")
    for m, new in IOT_CONTROLS.items():
        rows = iot_by_machine.get(m, [])
        old = rows[0][ictrl] if rows and len(rows[0]) > ictrl else ""
        mark = f"  [!! {len(rows)} rows]" if len(rows) != 1 else ""
        print(f"  {m:12} Controls: {old!r:30} -> {new!r}{mark}")

    print("== IoT Physical Location edits (shows every interface row) ==")
    for m, new in IOT_LOCATION.items():
        rows = iot_by_machine.get(m, [])
        if not rows:
            print(f"  {m:12} [!! machine not found]")
        for r in rows:
            old = r[iloc] if len(r) > iloc else ""
            print(f"  {m:12} Location: {old!r:42} -> {new!r}")

    print("== New IoT rows ==")
    for row in IOT_NEW_ROWS:
        exists = row["Machine"] in iot_by_machine
        print(f"  + {row}" + ("  [!! already exists]" if exists else ""))

    nhdr, nrows, nh = _read_cached(cache_dir, "network")
    nloc, nmach = nhdr.index("Location"), nhdr.index("Machine")
    print("== Network Location fixes ==")
    for old, new in NETWORK_LOCATION_FIX.items():
        hits = [r for r in nrows[nh + 1:] if len(r) > nloc and r[nloc] == old]
        print(f"  {old!r} -> {new!r}  ({len(hits)} matching row(s))")

    print("== New Network rows ==")
    net_machines = {r[nmach] for r in nrows[nh + 1:] if len(r) > nmach}
    for row in NETWORK_NEW_ROWS:
        exists = row["Machine"] in net_machines
        print(f"  + {row}" + ("  [!! already exists]" if exists else ""))

    print("== Delete Network row ==")
    hits = [r for r in nrows[nh + 1:] if len(r) > nmach and r[nmach] == NETWORK_DELETE_MACHINE]
    print(f"  - machine {NETWORK_DELETE_MACHINE!r}  ({len(hits)} matching row(s))")
    print("\n(dry run — no changes made; re-run with --apply as root to write)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-c", "--config", default="gdoc2netcfg.toml")
    ap.add_argument("--apply", action="store_true", help="actually write (needs creds; run as root)")
    args = ap.parse_args()

    config = load_config(args.config)
    if not args.apply:
        _dry_run(config.cache.directory)
        return 0

    print("--apply path not yet exercised; aborting before any write.", file=sys.stderr)
    print("Review the dry run, then I wire the gspread writes once you confirm it.",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
