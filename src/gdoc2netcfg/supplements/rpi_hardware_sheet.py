"""Google Sheets updater for the Raspberry Pi hardware-identity inventory.

Upserts rows in the "RPi Hardware" tab of the configured spreadsheet from
the ``rpi_hardware`` scan, matched by (Site, Pi Serial) — the Pi's own
serial, which survives re-imaging and re-naming, is the key; the machine
name is data. Each site manages only its own rows. New Pis are appended;
rows already showing the current values are left alone.

Column layout (created on an empty tab; on a populated tab the header
must match exactly, or nothing is written):

  A: Site
  B: Machine          (sheet machine name at the time of the scan)
  C: Pi Serial        <- key together with Site
  D: Model            (from /proc/device-tree/model)
  E: Rev Code         (/proc/cpuinfo Revision)
  F: Header           (boards that identified themselves; "" when bare)
  G: Power            (gpio-poe-hat | bonnet-poe | usbc-supply |
                       usbc-pd-supply | ambiguous | undetermined)
  H: FPGA             (kind per board: netv2, arty, acorn, jtag)
  I: FPGA Identity    (Device DNA or Digilent serial per board)
  J: RTC Battery      (Pi 5: yes/no; else "")
  K: Fan              (Pi 5: yes/no; else "")
  L: USB-C Limit mA   (Pi 5 firmware max_current; else "")
  M: Probe User
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from gdoc2netcfg.utils.gsheets import get_gspread_client

if TYPE_CHECKING:
    from gdoc2netcfg.config import PipelineConfig

_EXPECTED_HEADER = [
    "Site", "Machine", "Pi Serial", "Model", "Rev Code", "Header", "Power",
    "FPGA", "FPGA Identity", "RTC Battery", "Fan", "USB-C Limit mA",
    "Probe User",
]
_SITE_COL = "Site"
_SERIAL_COL = "Pi Serial"


def _yes_no(value: bool | None) -> str:
    if value is None:
        return ""
    return "yes" if value else "no"


def record_to_row(site: str, machine: str, doc: dict) -> list[str]:
    """A sheet row from a stored rpi_hardware document."""
    boards = doc["fpga"]
    return [
        site,
        machine,
        doc["serial"],
        doc["model"],
        doc["revision"],
        "; ".join(doc["header"]),
        doc["power_class"],
        "; ".join(b["kind"] for b in boards),
        "; ".join(b.get("dna") or b.get("serial") or "" for b in boards),
        _yes_no(doc["rtc_battery"]),
        _yes_no(doc["fan"]),
        "" if doc["max_current_ma"] is None else str(doc["max_current_ma"]),
        doc["probe_user"],
    ]


def update_rpi_hardware_sheet(
    config: PipelineConfig,
    records: dict[str, dict],
    dry_run: bool = False,
    verbose: bool = False,
) -> int:
    """Upsert *records* (hostname -> stored doc) into the RPi Hardware tab.

    Returns the number of rows written (or that would be, in dry-run).
    """
    if not config.rpi_hardware.enabled:
        raise RuntimeError("No [rpi_hardware] section configured in gdoc2netcfg.toml")
    if not config.spreadsheet_url:
        raise RuntimeError(
            "spreadsheet_url not configured. Add it to the [sheets] section of "
            "gdoc2netcfg.toml:\n"
            "  spreadsheet_url = \"https://docs.google.com/spreadsheets/d/{ID}/edit\""
        )
    site = config.site.name.strip()
    sheet_name = config.rpi_hardware.sheet_name

    client = get_gspread_client(config.sheets_config)
    sh = client.open_by_url(config.spreadsheet_url)
    try:
        ws = sh.worksheet(sheet_name)
    except Exception as exc:  # gspread.WorksheetNotFound
        raise RuntimeError(
            f"Sheet '{sheet_name}' does not exist in the spreadsheet; create "
            "an empty tab with that name and re-run (the header is written "
            "on first use)."
        ) from exc

    all_values = ws.get_all_values()
    header_writes: list[dict] = []
    if not all_values or not any(cell.strip() for cell in all_values[0]):
        # empty tab: the header is ours to write
        header_writes.append({"range": "A1:M1", "values": [_EXPECTED_HEADER]})
        data_rows: list[list[str]] = []
        if verbose:
            print(f"  HEADER: writing the column layout to '{sheet_name}'", file=sys.stderr)
    else:
        header = all_values[0]
        if header[: len(_EXPECTED_HEADER)] != _EXPECTED_HEADER:
            raise RuntimeError(
                "Sheet header does not match the expected layout — refusing "
                f"to write.\n  expected: {_EXPECTED_HEADER}\n  found:    "
                f"{header[: len(_EXPECTED_HEADER)]}"
            )
        data_rows = all_values[1:]

    site_idx = _EXPECTED_HEADER.index(_SITE_COL)
    serial_idx = _EXPECTED_HEADER.index(_SERIAL_COL)

    def _cell(row: list[str], idx: int) -> str:
        return row[idx].strip() if idx < len(row) else ""

    key_to_row_idx: dict[str, int] = {}
    for i, row in enumerate(data_rows):
        if _cell(row, site_idx).lower() != site.lower():
            continue                      # another site's row: not ours
        serial = _cell(row, serial_idx)
        if not serial:
            continue
        if serial in key_to_row_idx:
            raise RuntimeError(
                f"duplicate rows for site={site} serial={serial} "
                f"(sheet rows {key_to_row_idx[serial] + 2} and {i + 2}); fix the sheet"
            )
        key_to_row_idx[serial] = i

    updates: list[dict] = []
    appends: list[list[str]] = []
    for hostname, doc in sorted(records.items()):
        if not doc["serial"]:
            raise RuntimeError(f"{hostname}: probe returned no Pi serial; cannot key the row")
        new_row = record_to_row(site, hostname, doc)
        row_idx = key_to_row_idx.get(doc["serial"])
        if row_idx is not None:
            existing = data_rows[row_idx]
            padded = [existing[i] if i < len(existing) else "" for i in range(len(new_row))]
            if padded == new_row:
                continue
            sheet_row = row_idx + 2
            updates.append({"range": f"A{sheet_row}:M{sheet_row}", "values": [new_row]})
            if verbose:
                print(f"  UPDATE row {sheet_row}: {hostname} ({doc['serial']})", file=sys.stderr)
        else:
            appends.append(new_row)
            if verbose:
                print(f"  APPEND: {hostname} ({doc['serial']})", file=sys.stderr)

    if not dry_run:
        if header_writes:
            ws.batch_update(header_writes)
        if updates:
            ws.batch_update(updates)
        if appends:
            ws.append_rows(appends)
    return len(updates) + len(appends)
