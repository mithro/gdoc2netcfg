"""Sites sheet parser.

Parses the "Sites" tab into SiteInfo records: one per top-level site.

The sheet mixes three kinds of rows in its Shortname column:
  - site rows         : a bare label, e.g. 'welland', 'monarto', 'special'
  - per-host IPv6 /56 : 'host.site', e.g. 'ten64.welland' (a dot is present)
  - section markers   : '---', or an empty Shortname ('Decommisioned' row)

Only the site rows are returned; the others are skipped.  No derivation is
done here — SiteInfo carries the raw columns, and callers turn them into
Site.all_sites (cli/main.py) or cross-check them against the per-site TOML
(site_config_drift).
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.network import Site

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


def octet_from_private_ipv4(private_ipv4: str) -> int | None:
    """Extract the site octet from a Private IPv4 like '10.1.X.X' -> 1.

    Returns None if the value isn't a '10.N.*' address (N numeric).
    """
    parts = private_ipv4.split(".")
    if len(parts) >= 2 and parts[0] == "10" and parts[1].isdigit():
        return int(parts[1])
    return None


def prefix_from_sheet_ipv6(ipv6: str) -> str:
    """Normalise a sheet IPv6 CIDR to the TOML prefix form.

    '2404:e80:a137::/48' -> '2404:e80:a137:' (the TOML stores prefixes as a
    string ending in ':').  Returns '' for a blank cell.
    """
    if not ipv6:
        return ""
    base = ipv6.split("/")[0].rstrip(":")
    return base + ":" if base else ""


def site_config_drift(site: Site, info: SiteInfo) -> list[str]:
    """Describe where the per-site TOML config disagrees with the sheet row.

    Compares domain, public_ipv4, site_octet (from Private IPv4 '10.N.X.X')
    and the IPv6 /48 prefix.  Empty sheet cells mean 'no opinion' and are
    skipped (the sheet is sparse).  Returns an empty list when consistent.
    Shadow check only — the sheet is not yet authoritative for these fields.
    """
    drift: list[str] = []
    if info.domain and info.domain != site.domain:
        drift.append(f"domain: toml={site.domain!r} sheet={info.domain!r}")
    if info.public_ipv4 and info.public_ipv4 != (site.public_ipv4 or ""):
        drift.append(
            f"public_ipv4: toml={site.public_ipv4!r} sheet={info.public_ipv4!r}"
        )
    octet = octet_from_private_ipv4(info.private_ipv4)
    if octet is not None and octet != site.site_octet:
        drift.append(f"site_octet: toml={site.site_octet} sheet={octet}")
    prefix = prefix_from_sheet_ipv6(info.ipv6)
    if prefix:
        toml_prefixes = [p.prefix for p in site.ipv6_prefixes]
        if prefix not in toml_prefixes:
            drift.append(f"ipv6_prefix: toml={toml_prefixes} sheet={prefix!r}")
    return drift
