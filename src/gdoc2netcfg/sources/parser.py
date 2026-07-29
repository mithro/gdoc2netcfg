"""CSV parser: convert raw CSV text into typed device records.

Handles header row detection, field name normalization, and basic
field extraction. No validation or derivation — those are separate
pipeline stages.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field


@dataclass
class DeviceRecord:
    """A raw device record from a spreadsheet sheet.

    Contains the normalized field values extracted from CSV, plus metadata
    about where the record came from. No derivations applied yet.
    """

    sheet_name: str
    row_number: int
    machine: str = ""
    mac_address: str = ""
    ip: str = ""
    interface: str = ""
    site: str = ""
    extra: dict[str, str] = field(default_factory=dict)


def find_header_row(rows: list[list[str]], max_rows: int = 5) -> int:
    """Find the header row index by looking for 'Machine' and 'MAC' columns.

    Some sheets have metadata in row 1 (e.g. IPv6 prefixes) with headers
    on row 2. This scans the first few rows to find the actual header.

    Args:
        rows: All CSV rows.
        max_rows: Maximum number of rows to check.

    Returns:
        Index of the header row (0-based).
    """
    for i, row in enumerate(rows[:max_rows]):
        row_str = ",".join(row).lower()
        if "machine" in row_str and "mac" in row_str:
            return i
    return 0


def _normalize_header(header: str) -> str:
    """Normalize a CSV header string.

    Strips whitespace. Does not change case — field matching is
    case-insensitive in the extraction logic.
    """
    return header.strip()


# Known column names for key fields (case-insensitive matching)
_MACHINE_COLUMNS = {"machine"}
_MAC_COLUMNS = {"mac address", "mac"}
_IP_COLUMNS = {"ip", "ipv4"}
_INTERFACE_COLUMNS = {"interface"}
_SITE_COLUMNS = {"site"}


def parse_csv(csv_text: str, sheet_name: str) -> list[DeviceRecord]:
    """Parse CSV text into DeviceRecord objects.

    Handles:
    - Header row detection (scans first 5 rows for 'Machine' + 'MAC')
    - Field name normalization (stripped whitespace)
    - Key field extraction (machine, mac, ip, interface)
    - Row length validation (skips rows not matching header count)
    - Empty row filtering
    - WiFi-sheet-only Site carry-forward within a contiguous machine block
      (see the inline comment above the row loop for the rationale)

    Args:
        csv_text: Raw CSV text content.
        sheet_name: Name of the sheet (e.g. 'Network', 'IoT'). Also drives
            behaviour, not just metadata: Site carry-forward is enabled
            only when this is 'wifi' (case-insensitive).

    Returns:
        List of DeviceRecord objects, one per valid row.
    """
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)

    if not rows:
        return []

    header_idx = find_header_row(rows)
    raw_headers = rows[header_idx]
    headers = [_normalize_header(h) for h in raw_headers]

    # Build case-insensitive column index for key fields
    header_lower = [h.lower() for h in headers]

    def _find_col(candidates: set[str]) -> int | None:
        for i, h in enumerate(header_lower):
            if h in candidates:
                return i
        return None

    machine_col = _find_col(_MACHINE_COLUMNS)
    mac_col = _find_col(_MAC_COLUMNS)
    ip_col = _find_col(_IP_COLUMNS)
    interface_col = _find_col(_INTERFACE_COLUMNS)
    site_col = _find_col(_SITE_COLUMNS)

    records: list[DeviceRecord] = []

    # WiFi-sheet-only Site carry-forward: the formatter merges the Site
    # cell per host block, and a merged cell exports its value only on
    # the anchor (first) row of the published CSV -- covered rows read
    # blank. Site filtering treats blank as "all sites"
    # (derivations/ip_remap.py::is_record_for_site), so without inheriting
    # the anchor's value, covered rows would become phantom partial hosts
    # at every other site. This rule is scoped to the wifi sheet only:
    # other sheets legitimately mix a non-blank anchor Site with blank
    # all-sites continuation rows for the SAME machine (e.g. rpiz-usbdev
    # in 'Welland - IP Allocation', where the blanks really do mean "all
    # sites", not "same site as above") -- global inheritance would
    # silently drop those records from the other sites' inventories.
    is_wifi_sheet = sheet_name.lower() == "wifi"
    prev_machine: str | None = None
    prev_site = ""

    for row_idx, row in enumerate(rows[header_idx + 1 :], start=header_idx + 1):
        # Skip rows that don't match header column count
        if len(row) != len(headers):
            continue

        # Build key→value dict for non-empty fields
        values: dict[str, str] = {}
        for col_idx, (header, value) in enumerate(zip(headers, row)):
            if header and value and value.strip():
                values[header] = value.strip()

        # Skip empty rows
        if not values:
            continue

        # Remove entries with empty string key (from unnamed columns)
        values.pop("", None)

        # Extract key fields
        machine = ""
        if machine_col is not None and machine_col < len(row):
            machine = row[machine_col].strip()

        mac = ""
        if mac_col is not None and mac_col < len(row):
            mac = row[mac_col].strip()

        ip_addr = ""
        if ip_col is not None and ip_col < len(row):
            ip_addr = row[ip_col].strip()

        interface = ""
        if interface_col is not None and interface_col < len(row):
            interface = row[interface_col].strip()

        site_value = ""
        if site_col is not None and site_col < len(row):
            site_value = row[site_col].strip()

        if is_wifi_sheet and not site_value and machine and machine == prev_machine:
            site_value = prev_site

        # Update carry-forward trackers on every data row (including rows
        # whose Site was just inherited, so an inherited value keeps
        # propagating through the rest of the block).
        prev_machine = machine
        prev_site = site_value

        # Collect extra columns (everything except the key fields)
        key_cols = {machine_col, mac_col, ip_col, interface_col, site_col} - {None}
        extra: dict[str, str] = {}
        for col_idx, (header, value) in enumerate(zip(headers, row)):
            if col_idx not in key_cols and header and value and value.strip():
                extra[header] = value.strip()

        records.append(
            DeviceRecord(
                sheet_name=sheet_name,
                row_number=row_idx + 1,  # 1-based for user display
                machine=machine,
                mac_address=mac,
                ip=ip_addr,
                interface=interface,
                site=site_value,
                extra=extra,
            )
        )

    return records
