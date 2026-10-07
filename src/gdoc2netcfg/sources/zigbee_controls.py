"""Parse the 'Zigbee Info' sheet's Controls column into power-graph records.

The Zigbee Info tab is fetched and cached like any other `[sheets]` source
(as `.cache/zigbee.csv`), but it is a non-device sheet (no Machine/MAC
columns — it uses Entity Name + IEEE Address), so it gets this dedicated
parser rather than the generic device `parse_csv`, mirroring how `sites`
and `vlan_allocations` are handled.

Each Zigbee plug that lists downstream devices in a `Controls` column
becomes a controller `DeviceRecord` (``machine`` = the Entity Name, e.g.
``Z5``; ``sheet_name`` = ``"zigbee"``) that the power-topology engine
consumes exactly like an IoT plug row. An absent `Controls` column
contributes nothing, silently.
"""

from __future__ import annotations

import csv

from gdoc2netcfg.sources.parser import DeviceRecord

_NAME_COL = "Entity Name"
_SITE_COL = "Site"
_CONTROLS_COL = "Controls"


def parse_zigbee_controls(csv_text: str) -> list[DeviceRecord]:
    """Return a controller DeviceRecord per Zigbee plug with a Controls value.

    Finds the header row by the presence of an ``Entity Name`` column
    (tolerating a stray banner row above it). If there is no ``Controls``
    column, returns an empty list (the column is optional).
    """
    rows = list(csv.reader(csv_text.splitlines()))
    header_idx = next(
        (i for i, r in enumerate(rows)
         if any(c.strip() == _NAME_COL for c in r)),
        None,
    )
    if header_idx is None:
        return []
    header = [c.strip() for c in rows[header_idx]]
    if _CONTROLS_COL not in header:
        return []

    name_idx = header.index(_NAME_COL)
    controls_idx = header.index(_CONTROLS_COL)
    site_idx = header.index(_SITE_COL) if _SITE_COL in header else None

    records: list[DeviceRecord] = []
    for offset, row in enumerate(rows[header_idx + 1:], start=header_idx + 2):
        if len(row) <= max(name_idx, controls_idx):
            continue
        entity = row[name_idx].strip()
        controls = row[controls_idx].strip()
        if not entity or not controls:
            continue
        site = ""
        if site_idx is not None and site_idx < len(row):
            site = row[site_idx].strip()
        records.append(
            DeviceRecord(
                sheet_name="zigbee",
                row_number=offset,
                machine=entity,
                site=site,
                extra={_CONTROLS_COL: controls},
            )
        )
    return records
