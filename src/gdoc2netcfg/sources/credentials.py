"""Separate credential columns out of fetched CSV data.

The spreadsheet's credential columns (the flattened CREDENTIAL_TYPES
names) are stripped from the world-readable cache and stored in the
root-only credentials.db.  These helpers do the column-level work.
"""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

from gdoc2netcfg.sources.parser import find_header_row
from gdoc2netcfg.utils.lookup import CREDENTIAL_TYPES

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host


def credential_field_names() -> list[str]:
    """The credential column names — flattened CREDENTIAL_TYPES values, deduped."""
    names: list[str] = []
    for columns in CREDENTIAL_TYPES.values():
        for column in columns:
            if column not in names:
                names.append(column)
    return names


def strip_credential_columns(csv_text: str) -> tuple[str, list[str]]:
    """Remove credential columns from CSV text.

    Returns (stripped_csv_text, present_field_names).  Columns are
    identified by header name in the detected header row and removed by
    index from every row (banner rows included).  When no credential
    columns are present, returns the input unchanged with an empty list.
    """
    rows = list(csv.reader(io.StringIO(csv_text)))
    if not rows:
        return csv_text, []

    header_idx = find_header_row(rows)
    header = rows[header_idx]
    credential_names = set(credential_field_names())
    drop = [i for i, h in enumerate(header) if h.strip() in credential_names]
    if not drop:
        return csv_text, []

    present = [header[i].strip() for i in drop]
    for row in rows:
        for i in sorted(drop, reverse=True):
            if i < len(row):
                del row[i]

    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(rows)
    return out.getvalue(), present


def extract_credentials(hosts: list[Host]) -> dict[str, dict[str, str]]:
    """Map hostname -> {credential field: value} for hosts that have any.

    Reads credential fields from ``host.extra`` (populated from the raw,
    un-stripped CSV).  Hosts with no credential fields are omitted.
    """
    names = credential_field_names()
    result: dict[str, dict[str, str]] = {}
    for host in hosts:
        fields = {n: host.extra[n] for n in names if host.extra.get(n)}
        if fields:
            result[host.hostname] = fields
    return result
