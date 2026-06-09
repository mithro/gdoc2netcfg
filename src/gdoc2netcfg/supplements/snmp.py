"""Supplement: SNMP data collection.

Scans hosts for SNMP availability and retrieves system information,
interface tables, and IP address tables. Results are cached in
snmp.json to avoid re-scanning on every pipeline run.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (SNMP agents).

pysnmp v7 is async-only. Individual SNMP operations use async/await,
wrapped in asyncio.run() from the synchronous scan_snmp().

Low-level SNMP operations (system GET, bulk walk, credential cascade,
JSON cache I/O) live in snmp_common.py and are shared with bridge.py.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import SNMPData
from gdoc2netcfg.supplements.snmp_common import (
    load_json_cache,
    save_json_cache,
    snmp_bulk_walk,
    snmp_get_system,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability

# Re-export cache functions for backward compatibility.
# Existing code imports load_snmp_cache / save_snmp_cache from this module.
load_snmp_cache = load_json_cache
save_snmp_cache = save_json_cache

# Host-level table OIDs for bulk walk
_IF_TABLE_OID = "1.3.6.1.2.1.2.2"       # ifTable
_IP_ADDR_TABLE_OID = "1.3.6.1.2.1.4.20"  # ipAddrTable


def _rows_from_walk(walk_results: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Group walk results into per-index rows.

    SNMP tables encode the row index as the last OID component(s).
    Groups results by index suffix into dicts of column->value.
    """
    if not walk_results:
        return []

    # Find the common prefix length by looking at first result
    # and finding where the table column OID ends
    rows: dict[str, dict[str, str]] = {}
    for oid, value in walk_results:
        # Split OID into parts
        parts = oid.split(".")
        # For standard tables, the index is the last component(s)
        # We use the full OID minus the last component as the column identifier
        # and the last component as the row index
        # This is a simplification that works for most standard tables
        if len(parts) > 1:
            row_index = parts[-1]
            column_oid = ".".join(parts[:-1])
            if row_index not in rows:
                rows[row_index] = {}
            rows[row_index][column_oid] = value

    return list(rows.values())


async def _collect_snmp_data(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
) -> dict | None:
    """Collect all SNMP data from a single host.

    Attempts system group GET, then bulk walks interface and IP tables.
    Returns a dict suitable for JSON serialisation, or None on failure.

    Uses shared infrastructure from snmp_common for the low-level
    SNMP GET and bulk walk operations.
    """
    from gdoc2netcfg.supplements.snmp_common import SYSTEM_OIDS

    system_info = await snmp_get_system(ip, community, timeout)
    if system_info is None:
        return None

    # System group succeeded -- collect tables
    if_walk = await snmp_bulk_walk(ip, _IF_TABLE_OID, community, timeout)
    ip_walk = await snmp_bulk_walk(ip, _IP_ADDR_TABLE_OID, community, timeout)

    if_rows = _rows_from_walk(if_walk)
    ip_rows = _rows_from_walk(ip_walk)

    # Build raw OID map from all collected data
    raw = dict(
        [(oid, val) for oid, val in
         [(k, v) for k, v in zip(SYSTEM_OIDS.values(), system_info.values())]
         + if_walk + ip_walk]
    )

    return {
        "snmp_version": "v2c",
        "system_info": system_info,
        "interfaces": if_rows,
        "ip_addresses": ip_rows,
        "raw": raw,
    }


def _try_snmp_credentials(
    ip: str,
    host: Host,
) -> dict | None:
    """Try SNMP credential cascade for a host.

    Credential order:
    1. SNMPv2c with community "public"
    2. SNMPv2c with host.extra["SNMP Community"] if present

    SNMPv3 support is deferred -- requires additional pysnmp UsmUserData
    configuration that depends on auth/priv protocol selection.

    Returns collected SNMP data dict, or None if all attempts fail.
    """
    # Try 1: SNMPv2c with "public"
    result = asyncio.run(_collect_snmp_data(ip, community="public"))
    if result is not None:
        return result

    # Try 2: SNMPv2c with custom community from spreadsheet
    custom_community = host.extra.get("SNMP Community", "").strip()
    if custom_community and custom_community != "public":
        result = asyncio.run(_collect_snmp_data(ip, community=custom_community))
        if result is not None:
            return result

    return None


def scan_snmp(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
) -> dict[str, dict]:
    """Scan reachable hosts for SNMP data.

    Args:
        hosts: Host objects with IPs to scan.
        cache_path: Path to snmp.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data from the
            reachability pass. Only reachable hosts are scanned.

    Returns:
        Mapping of hostname to SNMP data dict.
    """
    import sys

    snmp_data = load_snmp_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(f"snmp.json last updated {age:.0f}s ago, using cache.", file=sys.stderr)
            return snmp_data

    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    for host in sorted_hosts:
        # Skip hosts not in reachability data or not reachable
        host_reach = reachability.get(host.hostname) if reachability else None
        if host_reach is None or not host_reach.is_up:
            continue
        active_ips = list(host_reach.active_ips)

        if verbose:
            print(
                f"  {host.hostname:>{name_width}s} snmp({','.join(active_ips)}) ",
                end="", flush=True, file=sys.stderr,
            )

        # Try SNMP on each reachable IP until one succeeds
        for ip in active_ips:
            data = _try_snmp_credentials(ip, host)
            if data is not None:
                snmp_data[host.hostname] = data
                sys_name = data.get("system_info", {}).get("sysName", "?")
                if verbose:
                    print(f"ok (sysName={sys_name})", file=sys.stderr)
                break
        else:
            if verbose:
                print("no-snmp", file=sys.stderr)

    save_snmp_cache(cache_path, snmp_data)
    return snmp_data


def _dict_to_tuples(d: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Convert a flat dict to a tuple of key-value pairs."""
    return tuple((k, v) for k, v in d.items())


def _row_list_to_tuples(
    rows: list[dict[str, str]],
) -> tuple[tuple[tuple[str, str], ...], ...]:
    """Convert a list of dicts to nested tuples for SNMPData."""
    return tuple(_dict_to_tuples(row) for row in rows)


def enrich_hosts_with_snmp(
    hosts: list[Host],
    snmp_cache: dict[str, dict] | None,
) -> None:
    """Attach cached SNMP data to Host objects.

    Modifies hosts in-place by setting host.snmp_data.
    """
    snmp_cache = snmp_cache or {}
    for host in hosts:
        info = snmp_cache.get(host.hostname)
        if info is not None:
            host.snmp_data = SNMPData(
                snmp_version=info.get("snmp_version", "v2c"),
                system_info=_dict_to_tuples(info.get("system_info", {})),
                interfaces=_row_list_to_tuples(info.get("interfaces", [])),
                ip_addresses=_row_list_to_tuples(info.get("ip_addresses", [])),
                raw=_dict_to_tuples(info.get("raw", {})),
            )
