"""Shared SNMP infrastructure for supplements.

Provides pysnmp v7 connection handling, credential cascade, bulk walk,
and JSON cache I/O. Used by both snmp.py (host-level data) and
bridge.py (switch-level topology).

pysnmp v7 is async-only. Individual SNMP operations use async/await,
wrapped in asyncio.run() from synchronous callers.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

# System group OIDs (SNMPv2-MIB)
SYSTEM_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}


async def snmp_get_system(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
    retries: int = 1,
) -> dict[str, str] | None:
    """Query SNMP system group OIDs via SNMPv2c GET.

    Returns dict of name->value for system group, or None on failure.
    """
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (ip, 161), timeout=timeout, retries=retries
        )
        var_binds = [
            ObjectType(ObjectIdentity(oid)) for oid in SYSTEM_OIDS.values()
        ]

        error_indication, error_status, _error_index, result_binds = await get_cmd(
            engine,
            CommunityData(community),
            target,
            ContextData(),
            *var_binds,
        )

        if error_indication or error_status:
            return None

        oid_to_name = {v: k for k, v in SYSTEM_OIDS.items()}
        system_info = {}
        for var_bind in result_binds:
            oid_str = str(var_bind[0])
            value_str = str(var_bind[1])
            name = oid_to_name.get(oid_str, oid_str)
            system_info[name] = value_str

        return system_info
    except Exception:
        return None
    finally:
        engine.close_dispatcher()


async def snmp_bulk_walk(
    ip: str,
    base_oid: str,
    community: str = "public",
    timeout: float = 2.0,
    retries: int = 1,
) -> list[tuple[str, str]]:
    """Bulk walk an SNMP table and return OID->value pairs.

    Returns list of (oid_string, value_string) tuples, or empty list on failure.
    """
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        bulk_walk_cmd,
    )

    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (ip, 161), timeout=timeout, retries=retries
        )

        results = []
        async for error_indication, error_status, _error_index, var_binds in bulk_walk_cmd(
            engine,
            CommunityData(community),
            target,
            ContextData(),
            0, 25,  # nonRepeaters=0, maxRepetitions=25
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                results.append((str(var_bind[0]), str(var_bind[1])))

        return results
    except Exception:
        return []
    finally:
        engine.close_dispatcher()


async def collect_snmp_tables(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
    table_oids: dict[str, str] | None = None,
) -> dict | None:
    """Collect SNMP system info and walk specified tables.

    First queries system group. If that fails, returns None (no SNMP).
    Then bulk-walks each table OID.

    Args:
        ip: Host IP address.
        community: SNMP community string.
        timeout: Per-request timeout in seconds.
        table_oids: Mapping of table_name -> base_oid to walk.
            If None, no tables are walked.

    Returns:
        Dict with 'snmp_version', 'system_info', and one key per
        table_oid name containing the walk results. None on failure.
    """
    system_info = await snmp_get_system(ip, community, timeout)
    if system_info is None:
        return None

    result = {
        "snmp_version": "v2c",
        "system_info": system_info,
    }

    for name, oid in (table_oids or {}).items():
        result[name] = await snmp_bulk_walk(ip, oid, community, timeout)

    return result


def try_snmp_credentials(
    ip: str,
    host: Host,
    table_oids: dict[str, str] | None = None,
) -> dict | None:
    """Try SNMP credential cascade for a host.

    Credential order:
    1. SNMPv2c with community "public"
    2. SNMPv2c with host.extra["SNMP Community"] if present and different

    Returns collected SNMP data dict, or None if all attempts fail.
    """
    result = asyncio.run(collect_snmp_tables(ip, community="public", table_oids=table_oids))
    if result is not None:
        return result

    custom_community = host.extra.get("SNMP Community", "").strip()
    if custom_community and custom_community != "public":
        result = asyncio.run(
            collect_snmp_tables(ip, community=custom_community, table_oids=table_oids)
        )
        if result is not None:
            return result

    return None
