"""IPv4 site remapping: resolve site-templated addresses and filter by site.

Spreadsheets shared across sites use 'X' as a placeholder in the second
octet of IPv4 addresses (e.g. 10.X.10.100) for devices that exist at
every site.  This module resolves those placeholders to the current site's
octet (e.g. 10.2.10.100 for monarto where site_octet=2).

Records may also carry a 'site' column.  When non-empty it must match
the current site name; records for other sites are filtered out.
"""

from __future__ import annotations

import dataclasses

from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.parser import DeviceRecord


def resolve_site_ip(ip: str, site_octet: int) -> str:
    """Replace a literal 'X' in the second octet with the site's octet.

    If the IP doesn't contain 'X' in the second octet position, it is
    returned unchanged.

    >>> resolve_site_ip('10.X.10.100', 2)
    '10.2.10.100'
    >>> resolve_site_ip('10.1.10.100', 2)
    '10.1.10.100'
    """
    parts = ip.split(".")
    if len(parts) == 4 and parts[1].upper() == "X":
        parts[1] = str(site_octet)
        return ".".join(parts)
    return ip


def is_record_for_site(record: DeviceRecord, site: Site) -> bool:
    """Check whether a record should be included for the given site.

    Rules:
    - If the record's site field is empty, it applies to all sites.
    - If the record's site field matches the site name (case-insensitive),
      it applies.
    - Otherwise, the record belongs to a different site and is skipped.
    """
    if not record.site:
        return True
    return record.site.lower() == site.name.lower()


def _validate_site_values(
    records: list[DeviceRecord], site: Site,
) -> None:
    """Validate that all non-empty site column values are known site names.

    Raises ValueError if any record has an unrecognized site value.
    This catches spreadsheet columns (like "Location") being accidentally
    mapped to the site field with values like "Back Shed" that would
    silently drop records during site filtering.

    Records without a machine name (section headers, empty rows) are
    skipped — they won't become hosts and often carry section labels
    like "Build Farm" in the Site column.
    """
    if not site.all_sites:
        return
    for record in records:
        if not record.site or not record.machine:
            continue
        if record.site.lower() not in site.all_sites:
            raise ValueError(
                f"{record.sheet_name} row {record.row_number}: "
                f"invalid site value {record.site!r} "
                f"(machine={record.machine!r}). "
                f"Valid sites: {', '.join(site.all_sites)}. "
                f"If a CSV column is being misidentified as the Site column, "
                f"rename it so it doesn't match 'Site'."
            )


def filter_and_resolve_records(
    records: list[DeviceRecord], site: Site,
) -> list[DeviceRecord]:
    """Filter records for the current site and resolve 'X' in IPs.

    Three-step process:
    1. Validate that all site column values are recognized site names.
    2. Drop records whose site column doesn't match (when non-empty).
    3. Replace 'X' in second octet with site_octet for multi-site records.

    Returns a new list of DeviceRecord objects with resolved IPs.
    Raises ValueError if any record has an unrecognized site value.
    """
    _validate_site_values(records, site)
    result: list[DeviceRecord] = []
    for record in records:
        if not is_record_for_site(record, site):
            continue
        resolved_ip = resolve_site_ip(record.ip, site.site_octet)
        if resolved_ip != record.ip:
            # dataclasses.replace() propagates every field (including ones
            # added after this call site was written, e.g. dns_only) —
            # listing fields by hand here previously dropped dns_only.
            record = dataclasses.replace(record, ip=resolved_ip)
        result.append(record)
    return result
