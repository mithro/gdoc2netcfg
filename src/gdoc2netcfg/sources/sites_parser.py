"""Sites sheet parser.

Parses the "Sites" tab into SiteInfo records: one per top-level site.

The sheet mixes three kinds of rows in its Shortname column:
  - site rows         : a bare label, e.g. 'welland', 'monarto', 'special'
  - per-host IPv6 /56 : 'host.site', e.g. 'ten64.welland' (a dot is present)
  - section markers   : '---', or an empty Shortname ('Decommisioned' row)

Only the site rows are returned; the others are skipped.  No derivation is
done here — SiteInfo carries the raw columns, and callers turn them into
Site.all_sites (sources/... -> cli/main.py) or cross-check them against the
per-site TOML.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass

# A site Shortname is a single lowercase identifier: it starts with an
# alphanumeric, then allows alphanumerics/dashes, and — crucially — contains
# no '.'.  A dot marks a per-host allocation ('ten64.welland'), not a site;
# a leading '-' marks the '---' separator.  fullmatch anchors both ends.
_SITE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*")


@dataclass
class SiteInfo:
    """One site row from the Sites sheet, with all columns preserved."""

    shortname: str
    domain: str = ""
    public_ipv4: str = ""
    private_ipv4: str = ""
    ipv6: str = ""
    provider: str = ""
    city: str = ""
    country: str = ""
    address: str = ""
    gps: str = ""


def _is_site_shortname(shortname: str) -> bool:
    """True if a Shortname denotes a top-level site (not a host or marker)."""
    return bool(_SITE_NAME_RE.fullmatch(shortname))


def parse_sites(csv_text: str) -> list[SiteInfo]:
    """Parse Sites CSV text into SiteInfo records (site rows only).

    Expected columns: Domain, Shortname, Public IPv4, Private IPv4, IPv6,
    Provider, City, Country, Address, GPS.  Rows whose Shortname is not a
    bare site identifier are skipped (host allocations, '---', empty).
    """
    rows = list(csv.reader(csv_text.splitlines()))
    if not rows:
        return []

    # Find the header row by looking for 'domain' and 'shortname'.
    header_idx = 0
    for i, row in enumerate(rows[:5]):
        lower = [c.strip().lower() for c in row]
        if "domain" in lower and "shortname" in lower:
            header_idx = i
            break

    headers = [h.strip().lower() for h in rows[header_idx]]

    def col(name: str) -> int | None:
        return headers.index(name) if name in headers else None

    c_short = col("shortname")
    if c_short is None:
        return []

    cols = {
        "domain": col("domain"),
        "public_ipv4": col("public ipv4"),
        "private_ipv4": col("private ipv4"),
        "ipv6": col("ipv6"),
        "provider": col("provider"),
        "city": col("city"),
        "country": col("country"),
        "address": col("address"),
        "gps": col("gps"),
    }

    def get(row: list[str], idx: int | None) -> str:
        return row[idx].strip() if idx is not None and idx < len(row) else ""

    sites: list[SiteInfo] = []
    for row in rows[header_idx + 1:]:
        shortname = get(row, c_short).lower()
        if not _is_site_shortname(shortname):
            continue
        sites.append(SiteInfo(
            shortname=shortname,
            **{field: get(row, idx) for field, idx in cols.items()},
        ))
    return sites


def site_names(sites: list[SiteInfo]) -> tuple[str, ...]:
    """Return the tuple of site shortnames (for Site.all_sites)."""
    return tuple(s.shortname for s in sites)
