"""Google Sheets updater for Zigbee2MQTT device inventory.

Reads the 'Zigbee Info' tab of the configured spreadsheet and upserts
rows with fresh data from the Zigbee2MQTT scan cache.  Matches existing
rows by (Site, IEEE address) — each site manages only its own rows.
New devices are appended.

Column layout (from live sheet, gid=283200403):
  A: Site
  B: Type
  C: Entity Name     (object_id)
  D: Description
  E: Friendly Name
  F: State           (Online/Offline)
  G: (unnamed)       source unknown; existing values are preserved
  H: Model           (device-reported model_id string)
  I: IEEE Address    <- key together with Site (column A)
  J: Power Source
  K: Connected Via
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from gdoc2netcfg.utils.gsheets import get_gspread_client

if TYPE_CHECKING:
    from gdoc2netcfg.config import PipelineConfig
    from gdoc2netcfg.supplements.zigbee import ZigbeeDevice

# Expected column header for the primary key.  Must exist in the sheet.
_IEEE_COL = "IEEE Address"

# Expected column header for the row-owning site.  Must exist in the sheet.
_SITE_COL = "Site"

# Index of the unnamed column G (0-based).  Value source is unknown;
# preserved from the sheet on updates, left blank for new rows.
_UNNAMED_COL_IDX = 6

# The full header layout that _device_to_row produces and updates
# overwrite (A..K).  Writes refuse to run against anything else —
# a reordered or renamed sheet would otherwise be silently corrupted.
_EXPECTED_HEADER = [
    "Site", "Type", "Entity Name", "Description", "Friendly Name",
    "State", "", "Model", "IEEE Address", "Power Source", "Connected Via",
]

# Index of the Connected Via column K (0-based).  Populated from the Z2M
# networkmap; preserved when the current scan didn't capture a parent.
_CONNECTED_VIA_COL_IDX = 10


def _device_type_label(device: ZigbeeDevice) -> str:
    """Derive a human-readable device type from Z2M model/description information.

    Uses definition.description as the primary signal (more reliable than model
    string matching); falls back to model/model_id string matching.
    Returns an empty string when unrecognised so existing sheet values are
    preserved (see update logic below).
    """
    # Use Z2M's model description (definition.description) as primary signal
    desc = device.definition_description.lower()
    if "soil" in desc or "moisture" in desc:
        return "Soil Sensor"
    if "temperature" in desc or "humidity" in desc:
        return "Temp Sensor"
    if "motion" in desc or "occupancy" in desc or "presence" in desc:
        return "Motion Sensor"
    if "contact" in desc or "door" in desc or "window" in desc:
        return "Door Sensor"
    if "plug" in desc or "socket" in desc or "outlet" in desc:
        return "Smart Plug"
    if "relay" in desc or "switch" in desc:
        return "Smart Switch"

    # Fall back to model string matching
    text = (device.model or device.model_id or "").lower()
    if "soil" in text or "moisture" in text:
        return "Soil Sensor"
    if any(t in text for t in ("snzb-02", "thmd", "temperature", "humidity")):
        return "Temp Sensor"
    if any(t in text for t in ("snzb-03", "motion", "pir", "occupancy")):
        return "Motion Sensor"
    if any(t in text for t in ("snzb-04", "contact", "door", "window")):
        return "Door Sensor"
    if any(t in text for t in ("plug", "relay", "switch", "socket")):
        return "Smart Plug"
    return ""


def _device_to_row(
    device: ZigbeeDevice,
    col_g_value: str,
    existing_type: str,
    existing_connected_via: str,
) -> list[str]:
    """Build a sheet row from a ZigbeeDevice.

    col_g_value: preserved from the existing row (or "" for new rows).
    existing_type: existing Type cell value; used when we can't determine
                   the type ourselves.
    existing_connected_via: existing Connected Via cell value; preserved when
                            the networkmap didn't capture this device's parent.
    """
    derived_type = _device_type_label(device)
    row_type = derived_type or existing_type  # prefer derived; fall back to sheet value
    connected_via = device.connected_via or existing_connected_via

    avail = device.availability.capitalize() if device.availability else ""

    return [
        device.site,                             # A: Site
        row_type,                                # B: Type
        device.object_id or device.friendly_name,  # C: Entity Name (fallback to friendly_name)
        device.description,                      # D: Description
        device.friendly_name,                    # E: Friendly Name
        avail,                                   # F: State
        col_g_value,                             # G: unnamed — preserved or blank
        device.model_id or device.model,         # H: Model
        device.ieee_address,                     # I: IEEE Address
        device.power_source,                     # J: Power Source
        connected_via,                           # K: Connected Via (from networkmap)
    ]


def update_zigbee_sheet(
    config: PipelineConfig,
    devices: list[ZigbeeDevice],
    dry_run: bool = False,
    verbose: bool = False,
) -> int:
    """Update the Zigbee Info sheet with fresh device data.

    Upserts rows matched by (Site, IEEE address) — each site manages
    only its own rows.  Rows whose Site cell is outside this run's
    configured sites are never read or written, so a device present at
    two sites keeps one row per site.  New devices are appended;
    rows already showing the current values are left alone.
    Returns the number of rows written (or that would be in dry-run).
    """
    if not config.zigbee.enabled:
        raise RuntimeError("No [zigbee] section configured in gdoc2netcfg.toml")
    site_scope = {config.site.name.strip().lower()}

    if not config.spreadsheet_url:
        raise RuntimeError(
            "spreadsheet_url not configured. Add it to the [sheets] section of "
            "gdoc2netcfg.toml:\n"
            "  spreadsheet_url = \"https://docs.google.com/spreadsheets/d/{ID}/edit\""
        )
    client = get_gspread_client(config.sheets_config)
    sh = client.open_by_url(config.spreadsheet_url)
    ws = sh.worksheet(config.zigbee.sheet_name)

    all_values = ws.get_all_values()
    if not all_values:
        raise RuntimeError(f"Sheet '{config.zigbee.sheet_name}' is empty")

    header = all_values[0]
    data_rows = all_values[1:]

    if header[: len(_EXPECTED_HEADER)] != _EXPECTED_HEADER:
        raise RuntimeError(
            "Sheet header does not match the expected layout — refusing "
            f"to write.\n  expected: {_EXPECTED_HEADER}\n  found:    "
            f"{header[: len(_EXPECTED_HEADER)]}"
        )
    site_col_idx = header.index(_SITE_COL)
    type_col_idx = header.index("Type")
    ieee_col_idx = header.index(_IEEE_COL)

    def _cell(row: list[str], idx: int) -> str:
        return row[idx].strip() if idx < len(row) else ""

    # (site, ieee) -> row index (0-based in data_rows), for rows owned
    # by this run's sites.  Blank-Site rows are collected separately so
    # an IEEE collision with them can be flagged for manual fixing.
    key_to_row_idx: dict[tuple[str, str], int] = {}
    blank_site_ieees: set[str] = set()
    for i, row in enumerate(data_rows):
        ieee = _cell(row, ieee_col_idx)
        if not ieee:
            continue
        row_site = _cell(row, site_col_idx).lower()
        if not row_site:
            blank_site_ieees.add(ieee)
            continue
        if row_site not in site_scope:
            continue  # another site's row — not ours to touch
        key = (row_site, ieee)
        if key in key_to_row_idx:
            print(
                f"Warning: duplicate rows for site={row_site} ieee={ieee} "
                f"(sheet rows {key_to_row_idx[key] + 2} and {i + 2}); "
                "using the first",
                file=sys.stderr,
            )
            continue
        key_to_row_idx[key] = i

    updates: list[dict] = []
    appends: list[list[str]] = []

    for device in sorted(devices, key=lambda d: (d.site, d.object_id)):
        device_site = device.site.strip().lower()
        if device_site not in site_scope:
            raise RuntimeError(
                f"Device {device.ieee_address} belongs to site "
                f"'{device.site}', not in this run's configured sites "
                f"{sorted(site_scope)}"
            )
        ieee = device.ieee_address

        if ieee in blank_site_ieees:
            print(
                f"Warning: IEEE {ieee} also appears in a row with a blank "
                "Site cell — that row was left untouched; fill in its Site "
                "column manually",
                file=sys.stderr,
            )

        key = (device_site, ieee)
        if key in key_to_row_idx:
            row_idx = key_to_row_idx[key]
            existing_row = data_rows[row_idx]
            col_g_val = (
                existing_row[_UNNAMED_COL_IDX]
                if _UNNAMED_COL_IDX < len(existing_row)
                else ""
            )
            existing_type = (
                existing_row[type_col_idx]
                if type_col_idx < len(existing_row)
                else ""
            )
            existing_connected_via = (
                existing_row[_CONNECTED_VIA_COL_IDX]
                if _CONNECTED_VIA_COL_IDX < len(existing_row)
                else ""
            )
            new_row = _device_to_row(
                device, col_g_val, existing_type, existing_connected_via,
            )

            padded_existing = [
                existing_row[i] if i < len(existing_row) else ""
                for i in range(len(new_row))
            ]
            if padded_existing == new_row:
                continue  # row already current — idempotent re-run

            # Sheet rows are 1-indexed; +1 for header row, +1 for 1-indexing
            sheet_row = row_idx + 2
            end_col = chr(ord("A") + len(new_row) - 1)
            updates.append({
                "range": f"A{sheet_row}:{end_col}{sheet_row}",
                "values": [new_row],
            })
            if verbose:
                print(
                    f"  UPDATE row {sheet_row}: "
                    f"{device.site}/{device.object_id} ({ieee})",
                    file=sys.stderr,
                )
        else:
            new_row = _device_to_row(device, "", "", "")
            appends.append(new_row)
            if verbose:
                print(
                    f"  APPEND: {device.site}/{device.object_id} ({ieee})",
                    file=sys.stderr,
                )

    if not dry_run:
        if updates:
            ws.batch_update(updates)
        if appends:
            ws.append_rows(appends)

    written = len(updates) + len(appends)
    return written
