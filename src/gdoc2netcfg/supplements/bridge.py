"""Supplement: bridge/topology data collection from managed switches.

Scans managed switches for MAC address tables (Q-BRIDGE-MIB),
VLAN configuration, LLDP neighbor data, port status, and PoE status.
Results are cached in bridge.json to avoid re-scanning on every
pipeline run.

This is a Supplement, not a Source -- it enriches existing Host records
with bridge-level topology data from switch SNMP agents.

Low-level SNMP operations (system GET, bulk walk, credential cascade,
JSON cache I/O) live in snmp_common.py and are shared with snmp.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.hardware import HARDWARE_CISCO_SWITCH, HARDWARE_NETGEAR_SWITCH
from gdoc2netcfg.models.host import BridgeData
from gdoc2netcfg.models.switch_data import (
    PortLinkStatus,
    PortTrafficStats,
    SwitchData,
    SwitchDataSource,
    VLANInfo,
)
from gdoc2netcfg.supplements.snmp_common import (
    try_snmp_credentials,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability

# Hardware types that support bridge SNMP queries.
# Excludes netgear-switch-plus (unmanaged, no SNMP).
BRIDGE_CAPABLE_HARDWARE: frozenset[str] = frozenset({
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_CISCO_SWITCH,
})

# ---------------------------------------------------------------------------
# Bridge-specific OID constants
# ---------------------------------------------------------------------------

# Q-BRIDGE-MIB: dot1qTpFdbTable -- MAC address table
_DOT1Q_TP_FDB_TABLE = "1.3.6.1.2.1.17.7.1.2.2"

# BRIDGE-MIB: dot1dBasePortIfIndex -- bridge port -> ifIndex mapping
_DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"

# Q-BRIDGE-MIB: dot1qVlanStaticName -- VLAN names
_DOT1Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"

# Q-BRIDGE-MIB: dot1qPvid -- port native VLAN
_DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"

# Q-BRIDGE-MIB: dot1qVlanStaticEgressPorts -- egress ports bitmap
_DOT1Q_VLAN_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"

# Q-BRIDGE-MIB: dot1qVlanStaticUntaggedPorts -- untagged ports bitmap
_DOT1Q_VLAN_STATIC_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"

# IF-MIB: ifName -- interface names
_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

# IF-MIB: ifAlias -- operator-set port descriptions
_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# IF-MIB: ifOperStatus -- up/down status
_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

# IF-MIB: ifHighSpeed -- speed in Mbps
_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"

# LLDP-MIB: lldpRemTable -- LLDP remote neighbor table
_LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1"

# POWER-ETHERNET-MIB: pethPsePortTable -- PoE status
_PETH_PSE_PORT_TABLE = "1.3.6.1.2.1.105.1.1"

# IF-MIB: interface statistics (64-bit counters)
_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"

# All bridge table OIDs for bulk walk
_BRIDGE_TABLE_OIDS: dict[str, str] = {
    "dot1q_tp_fdb": _DOT1Q_TP_FDB_TABLE,
    "dot1d_base_port": _DOT1D_BASE_PORT_IF_INDEX,
    "vlan_names": _DOT1Q_VLAN_STATIC_NAME,
    "pvid": _DOT1Q_PVID,
    "vlan_egress": _DOT1Q_VLAN_STATIC_EGRESS,
    "vlan_untagged": _DOT1Q_VLAN_STATIC_UNTAGGED,
    "if_name": _IF_NAME,
    "if_alias": _IF_ALIAS,
    "if_oper_status": _IF_OPER_STATUS,
    "if_high_speed": _IF_HIGH_SPEED,
    "lldp_rem": _LLDP_REM_TABLE,
    "poe": _PETH_PSE_PORT_TABLE,
    "ifHCInOctets": _IF_HC_IN_OCTETS,
    "ifHCOutOctets": _IF_HC_OUT_OCTETS,
    "ifInErrors": _IF_IN_ERRORS,
}

# The base OID prefix for dot1qTpFdbPort entries:
# 1.3.6.1.2.1.17.7.1.2.2.1.2.<VLAN>.<M1>.<M2>.<M3>.<M4>.<M5>.<M6>
_DOT1Q_TP_FDB_PORT_PREFIX = "1.3.6.1.2.1.17.7.1.2.2.1.2"
_DOT1Q_TP_FDB_PORT_PREFIX_LEN = len(_DOT1Q_TP_FDB_PORT_PREFIX.split("."))


# ---------------------------------------------------------------------------
# Parsing functions for raw SNMP walk results
# ---------------------------------------------------------------------------


def _format_mac_bytes(mac_bytes: list[int]) -> str:
    """Format 6 integer MAC bytes as XX:XX:XX:XX:XX:XX uppercase."""
    return ":".join(f"{b:02X}" for b in mac_bytes)


def _is_printable_ascii(s: str) -> bool:
    """Check if a string contains only printable ASCII characters."""
    return all(32 <= ord(c) < 127 for c in s)


def _format_hex_mac(hex_str: str) -> str:
    """Format a hex MAC string (like '0xc80084897170') as XX:XX:XX:XX:XX:XX.

    Also handles raw 6-byte binary strings produced by pysnmp's str() on
    OCTET STRING values, where each character's ord() is the byte value.

    If the string is not a valid MAC in any recognised format, returns it as-is.
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    # 12 hex digits (e.g. from "0xc80084897170" after stripping prefix)
    if len(hex_str) == 12:
        try:
            int(hex_str, 16)  # Validate it's hex
            return ":".join(
                hex_str[i : i + 2].upper() for i in range(0, 12, 2)
            )
        except ValueError:
            pass
    # Raw 6-byte binary (pysnmp OCTET STRING via str())
    if len(hex_str) == 6:
        return ":".join(f"{ord(c):02X}" for c in hex_str)
    return hex_str


def _format_octet_string(s: str) -> str:
    """Format a pysnmp OCTET STRING for display.

    If the string is printable ASCII (like 'gi24' or '1/xg50'), return as-is.
    Otherwise, format as colon-separated hex bytes (like 'C4:7A:3B:4A').
    """
    if not s:
        return s
    if _is_printable_ascii(s):
        return s
    return ":".join(f"{ord(c):02X}" for c in s)


def parse_mac_table(
    walk: list[tuple[str, str]],
    bridge_to_if: dict[int, int],
    if_names: dict[int, str],
) -> list[tuple[str, int, int, str]]:
    """Parse dot1qTpFdbTable walk results into (mac, vlan, port, name) tuples.

    OID format:
        1.3.6.1.2.1.17.7.1.2.2.1.2.<VLAN>.<M1>.<M2>.<M3>.<M4>.<M5>.<M6> = INTEGER: <bridge_port>

    The suffix after the base prefix encodes the VLAN ID followed by
    the 6 MAC address bytes as decimal integers.

    Args:
        walk: Raw (oid_string, value_string) pairs from bulk walk.
        bridge_to_if: Bridge port number -> ifIndex mapping.
        if_names: ifIndex -> interface name mapping.

    Returns:
        List of (mac_str, vlan_id, bridge_port, port_name) tuples.
    """
    results = []
    for oid, value in walk:
        parts = oid.split(".")

        # After the base prefix, we expect: <VLAN>.<M1>.<M2>.<M3>.<M4>.<M5>.<M6>
        # That's 7 additional components
        suffix_parts = parts[_DOT1Q_TP_FDB_PORT_PREFIX_LEN:]
        if len(suffix_parts) != 7:
            continue

        try:
            vlan_id = int(suffix_parts[0])
            mac_bytes = [int(b) for b in suffix_parts[1:7]]
            bridge_port = int(value)
        except (ValueError, IndexError):
            continue

        mac_str = _format_mac_bytes(mac_bytes)

        # Resolve bridge port -> ifIndex -> name
        if_index = bridge_to_if.get(bridge_port, bridge_port)
        port_name = if_names.get(if_index, f"port{bridge_port}")

        results.append((mac_str, vlan_id, bridge_port, port_name))

    return results


def _parse_ifindex_strings(
    walk: list[tuple[str, str]], table_oid: str,
) -> dict[int, str]:
    """Parse an ifIndex-keyed string column walk into ifIndex -> value."""
    result = {}
    prefix = table_oid + "."
    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        try:
            if_index = int(suffix)
        except ValueError:
            continue
        result[if_index] = value
    return result


def parse_if_names(walk: list[tuple[str, str]]) -> dict[int, str]:
    """Parse ifName walk results into ifIndex -> name mapping.

    OID format: 1.3.6.1.2.1.31.1.1.1.1.<ifIndex> = STRING: <name>
    """
    return _parse_ifindex_strings(walk, _IF_NAME)


def parse_if_aliases(walk: list[tuple[str, str]]) -> dict[int, str]:
    """Parse ifAlias walk results into ifIndex -> alias mapping.

    OID format: 1.3.6.1.2.1.31.1.1.1.18.<ifIndex> = STRING: <alias>

    Aliases are the operator-set port descriptions (e.g.
    "eth0.rpi5-pmod" naming the attached host).  Unset aliases are
    empty strings and are kept, so every interface the switch reports
    has an entry.
    """
    return _parse_ifindex_strings(walk, _IF_ALIAS)


def parse_bridge_port_map(walk: list[tuple[str, str]]) -> dict[int, int]:
    """Parse dot1dBasePortIfIndex walk into bridge port -> ifIndex mapping.

    OID format: 1.3.6.1.2.1.17.1.4.1.2.<bridge_port> = INTEGER: <ifIndex>
    """
    result = {}
    prefix = _DOT1D_BASE_PORT_IF_INDEX + "."
    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        try:
            bridge_port = int(suffix)
            if_index = int(value)
        except ValueError:
            continue
        result[bridge_port] = if_index
    return result


def parse_vlan_names(walk: list[tuple[str, str]]) -> list[tuple[int, str]]:
    """Parse dot1qVlanStaticName walk into (vlan_id, name) pairs.

    OID format: 1.3.6.1.2.1.17.7.1.4.3.1.1.<vlan_id> = STRING: <name>
    """
    result = []
    prefix = _DOT1Q_VLAN_STATIC_NAME + "."
    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        try:
            vlan_id = int(suffix)
        except ValueError:
            continue
        result.append((vlan_id, value))
    return result


def parse_port_pvids(walk: list[tuple[str, str]]) -> list[tuple[int, int]]:
    """Parse dot1qPvid walk into (ifIndex, pvid) pairs.

    OID format: 1.3.6.1.2.1.17.7.1.4.5.1.1.<port> = INTEGER: <pvid>
    """
    result = []
    prefix = _DOT1Q_PVID + "."
    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        try:
            port = int(suffix)
            pvid = int(value)
        except ValueError:
            continue
        result.append((port, pvid))
    return result


def parse_port_status(
    oper_walk: list[tuple[str, str]],
    speed_walk: list[tuple[str, str]],
) -> list[tuple[int, int, int]]:
    """Parse ifOperStatus and ifHighSpeed into (ifIndex, status, speed) tuples.

    OID formats:
        1.3.6.1.2.1.2.2.1.8.<ifIndex> = INTEGER: <oper_status>
        1.3.6.1.2.1.31.1.1.1.15.<ifIndex> = Gauge32: <speed_mbps>
    """
    oper_prefix = _IF_OPER_STATUS + "."
    speed_prefix = _IF_HIGH_SPEED + "."

    # Build speed lookup
    speed_map: dict[int, int] = {}
    for oid, value in speed_walk:
        if not oid.startswith(speed_prefix):
            continue
        suffix = oid[len(speed_prefix) :]
        try:
            if_index = int(suffix)
            speed = int(value)
        except ValueError:
            continue
        speed_map[if_index] = speed

    # Build result from oper status, joining with speed
    result = []
    for oid, value in oper_walk:
        if not oid.startswith(oper_prefix):
            continue
        suffix = oid[len(oper_prefix) :]
        try:
            if_index = int(suffix)
            oper_status = int(value)
        except ValueError:
            continue
        speed = speed_map.get(if_index, 0)
        result.append((if_index, oper_status, speed))

    return result


def parse_lldp_neighbors(
    walk: list[tuple[str, str]],
) -> list[tuple[int, str, str, str]]:
    """Parse lldpRemTable walk into (localPort, sysName, portId, chassisId) tuples.

    The LLDP remote table OID structure is:
        1.0.8802.1.1.2.1.4.1.1.<column>.<timeMark>.<localPortNum>.<remIndex>

    Columns of interest:
        5 = lldpRemChassisId
        7 = lldpRemPortId
        9 = lldpRemSysName

    Entries are grouped by (timeMark, localPortNum, remIndex) to build
    per-neighbor records.
    """
    prefix = _LLDP_REM_TABLE + ".1."

    # Group entries by (timeMark, localPortNum, remIndex)
    # Key: (timeMark, localPortNum, remIndex)
    # Value: dict of column -> value
    neighbors: dict[tuple[str, str, str], dict[int, str]] = {}

    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        parts = suffix.split(".")
        if len(parts) < 4:
            continue

        try:
            column = int(parts[0])
        except ValueError:
            continue

        # key = (timeMark, localPortNum, remIndex)
        time_mark = parts[1]
        local_port = parts[2]
        rem_index = parts[3]
        key = (time_mark, local_port, rem_index)

        if key not in neighbors:
            neighbors[key] = {}
        neighbors[key][column] = value

    result = []
    for (_, local_port, _), columns in neighbors.items():
        chassis_id = columns.get(5, "")
        port_id = columns.get(7, "")
        sys_name = columns.get(9, "")

        if not sys_name and not port_id:
            continue

        # Format IDs (handles raw binary from pysnmp)
        chassis_id = _format_hex_mac(chassis_id)
        port_id = _format_octet_string(port_id)

        try:
            local_port_int = int(local_port)
        except ValueError:
            continue

        result.append((local_port_int, sys_name, port_id, chassis_id))

    return result


def parse_vlan_egress_ports(
    walk: list[tuple[str, str]],
) -> list[tuple[int, str]]:
    """Parse dot1qVlanStaticEgressPorts walk into (vlan_id, bitmap_hex) pairs.

    OID format: 1.3.6.1.2.1.17.7.1.4.3.1.2.<vlan_id> = OCTET STRING: <hex>
    """
    result = []
    prefix = _DOT1Q_VLAN_STATIC_EGRESS + "."
    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        try:
            vlan_id = int(suffix)
        except ValueError:
            continue
        result.append((vlan_id, value))
    return result


def parse_vlan_untagged_ports(
    walk: list[tuple[str, str]],
) -> list[tuple[int, str]]:
    """Parse dot1qVlanStaticUntaggedPorts walk into (vlan_id, bitmap_hex) pairs.

    OID format: 1.3.6.1.2.1.17.7.1.4.3.1.4.<vlan_id> = OCTET STRING: <hex>
    """
    result = []
    prefix = _DOT1Q_VLAN_STATIC_UNTAGGED + "."
    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        suffix = oid[len(prefix) :]
        try:
            vlan_id = int(suffix)
        except ValueError:
            continue
        result.append((vlan_id, value))
    return result


def parse_poe_status(
    walk: list[tuple[str, str]],
) -> list[tuple[int, int, int]]:
    """Parse pethPsePortTable walk into (port, admin_status, detection_status) tuples.

    OID format (RFC 3621 pethPsePortEntry, 1.3.6.1.2.1.105.1.1.1):
        1.3.6.1.2.1.105.1.1.1.<column>.<groupIndex>.<portIndex> = INTEGER

    Column 3 = pethPsePortAdminEnable (1=enabled, 2=disabled)
    Column 6 = pethPsePortDetectionStatus (1=disabled, 2=searching,
               3=deliveringPower, 4=fault, 5=test, 6=otherFault)

    Columns 1-2 are the not-accessible row indices and never appear in
    walks; the remaining columns (4-14) are ignored.

    Raises ValueError when a port is missing either column or carries a
    non-integer value: partial rows mean the table layout has drifted
    from what we expect, and silently dropping them is how this parser
    previously returned no PoE data at all.
    """
    prefix = _PETH_PSE_PORT_TABLE + ".1."

    # Group by (groupIndex, portIndex)
    ports: dict[tuple[str, str], dict[int, int]] = {}

    for oid, value in walk:
        if not oid.startswith(prefix):
            continue
        parts = oid[len(prefix) :].split(".")
        if len(parts) != 3:
            continue

        column = int(parts[0])
        if column not in (3, 6):
            continue
        group_index, port_index = parts[1], parts[2]

        try:
            ports.setdefault((group_index, port_index), {})[column] = int(value)
        except ValueError as exc:
            raise ValueError(
                f"non-integer value {value!r} for pethPsePortEntry column "
                f"{column}, port {group_index}.{port_index}"
            ) from exc

    result = []
    for (group_index, port_index), columns in sorted(
        ports.items(), key=lambda item: (int(item[0][0]), int(item[0][1]))
    ):
        admin_status = columns.get(3)
        detection_status = columns.get(6)
        if admin_status is None:
            raise ValueError(
                f"pethPsePortEntry port {group_index}.{port_index} is "
                f"missing admin status (column 3)"
            )
        if detection_status is None:
            raise ValueError(
                f"pethPsePortEntry port {group_index}.{port_index} is "
                f"missing detection status (column 6)"
            )
        result.append((int(port_index), admin_status, detection_status))

    return result


def _parse_port_statistics(
    raw: dict[str, list[tuple[str, str]]],
) -> tuple[tuple[int, int, int, int], ...]:
    """Parse interface statistics from SNMP walk results.

    Extracts ifHCInOctets (bytes received), ifHCOutOctets (bytes transmitted),
    and ifInErrors from the raw SNMP data.

    Args:
        raw: Dictionary from try_snmp_credentials with walk results.
            Keys are "ifHCInOctets", "ifHCOutOctets", "ifInErrors".
            Values are lists of (oid, value) tuples from SNMP walk.

    Returns:
        Tuple of (ifIndex, bytes_rx, bytes_tx, errors) tuples, sorted by ifIndex.
    """
    in_octets: dict[int, int] = {}
    out_octets: dict[int, int] = {}
    in_errors: dict[int, int] = {}

    # Parse ifHCInOctets
    for oid, value in raw.get("ifHCInOctets", []):
        prefix = _IF_HC_IN_OCTETS + "."
        if oid.startswith(prefix):
            suffix = oid[len(prefix):]
            try:
                ifidx = int(suffix)
                in_octets[ifidx] = int(value)
            except ValueError:
                continue

    # Parse ifHCOutOctets
    for oid, value in raw.get("ifHCOutOctets", []):
        prefix = _IF_HC_OUT_OCTETS + "."
        if oid.startswith(prefix):
            suffix = oid[len(prefix):]
            try:
                ifidx = int(suffix)
                out_octets[ifidx] = int(value)
            except ValueError:
                continue

    # Parse ifInErrors
    for oid, value in raw.get("ifInErrors", []):
        prefix = _IF_IN_ERRORS + "."
        if oid.startswith(prefix):
            suffix = oid[len(prefix):]
            try:
                ifidx = int(suffix)
                in_errors[ifidx] = int(value)
            except ValueError:
                continue

    # Combine into tuples for all interfaces that have data
    all_ifidx = set(in_octets.keys()) | set(out_octets.keys())
    result = []
    for ifidx in sorted(all_ifidx):
        result.append((
            ifidx,
            in_octets.get(ifidx, 0),
            out_octets.get(ifidx, 0),
            in_errors.get(ifidx, 0),
        ))
    return tuple(result)


# ---------------------------------------------------------------------------
# BridgeData to SwitchData conversion
# ---------------------------------------------------------------------------


def _bitmap_to_ports(bitmap: str) -> frozenset[int]:
    """Convert SNMP VLAN port bitmap to set of port numbers.

    SNMP OctetString bitmaps are stored in JSON as raw character strings
    where each character's codepoint represents a byte value (0-255).
    Bit 7 of byte 0 = port 1, bit 6 = port 2, etc.

    Args:
        bitmap: Raw byte string from SNMP OctetString via JSON.

    Returns:
        Set of 1-based port numbers that are set in the bitmap.
    """
    if not bitmap:
        return frozenset()
    try:
        bitmap_bytes = bitmap.encode("latin-1")
    except UnicodeEncodeError:
        return frozenset()
    ports = set()
    for byte_idx, byte_val in enumerate(bitmap_bytes):
        for bit in range(8):
            if byte_val & (0x80 >> bit):
                ports.add(byte_idx * 8 + bit + 1)
    return frozenset(ports)


def bridge_to_switch_data(bridge: BridgeData, model: str | None = None) -> SwitchData:
    """Convert BridgeData to unified SwitchData format.

    Transforms SNMP-collected bridge data into the unified SwitchData
    structure that can be consumed by generators without knowledge of
    the underlying data source.

    Args:
        bridge: BridgeData from SNMP bridge supplement.
        model: Optional switch model string.

    Returns:
        SwitchData with source=SwitchDataSource.SNMP.
    """
    # Build port_id to port_name mapping
    port_names = {ifidx: name for ifidx, name in bridge.port_names}

    # Convert port status (ifIndex, oper_status, speed_mbps) -> PortLinkStatus
    # oper_status: 1 = up, 2 = down (RFC 2863)
    port_status = tuple(
        PortLinkStatus(
            port_id=ifidx,
            is_up=(oper == 1),
            speed_mbps=speed,
            port_name=port_names.get(ifidx),
        )
        for ifidx, oper, speed in bridge.port_status
    )

    # Convert VLANs from bitmap format
    # Need vlan_names + vlan_egress_ports + vlan_untagged_ports
    egress_map = {vid: bitmap for vid, bitmap in bridge.vlan_egress_ports}
    untagged_map = {vid: bitmap for vid, bitmap in bridge.vlan_untagged_ports}

    vlans = []
    for vid, name in bridge.vlan_names:
        member_ports = _bitmap_to_ports(egress_map.get(vid, ""))
        untagged = _bitmap_to_ports(untagged_map.get(vid, ""))
        tagged = member_ports - untagged
        vlans.append(VLANInfo(
            vlan_id=vid,
            name=name,
            member_ports=member_ports,
            tagged_ports=tagged,
        ))

    # Convert port statistics (ifIndex, bytes_rx, bytes_tx, errors) -> PortTrafficStats
    port_stats = tuple(
        PortTrafficStats(
            port_id=ifidx,
            bytes_rx=rx,
            bytes_tx=tx,
            errors=err,
        )
        for ifidx, rx, tx, err in bridge.port_statistics
    )

    return SwitchData(
        source=SwitchDataSource.SNMP,
        model=model,
        port_status=port_status,
        port_pvids=bridge.port_pvids,
        port_stats=port_stats,
        vlans=tuple(vlans),
        # SNMP-only fields: keep as tuple (empty means "no data collected",
        # vs None which means "source doesn't support this field")
        mac_table=bridge.mac_table,
        lldp_neighbors=bridge.lldp_neighbors,
        poe_status=bridge.poe_status,
    )


# ---------------------------------------------------------------------------
# Data collection and scanning
# ---------------------------------------------------------------------------


def _collect_bridge_data(ip: str, host: Host) -> dict | None:
    """Collect bridge data from a single switch via SNMP.

    Calls try_snmp_credentials with all bridge table OIDs, then
    parses each returned table.

    Returns a JSON-serialisable dict or None on failure.
    """
    raw = try_snmp_credentials(ip, host, table_oids=_BRIDGE_TABLE_OIDS)
    if raw is None:
        return None

    # Parse supporting tables first (needed by mac_table parser)
    bridge_port_walk = raw.get("dot1d_base_port", [])
    if_name_walk = raw.get("if_name", [])

    bridge_to_if = parse_bridge_port_map(bridge_port_walk)
    if_names = parse_if_names(if_name_walk)
    if_aliases = parse_if_aliases(raw.get("if_alias", []))

    # Parse all tables
    mac_table = parse_mac_table(raw.get("dot1q_tp_fdb", []), bridge_to_if, if_names)
    vlan_names = parse_vlan_names(raw.get("vlan_names", []))
    port_pvids = parse_port_pvids(raw.get("pvid", []))
    port_status = parse_port_status(
        raw.get("if_oper_status", []),
        raw.get("if_high_speed", []),
    )
    lldp_neighbors = parse_lldp_neighbors(raw.get("lldp_rem", []))
    vlan_egress = parse_vlan_egress_ports(raw.get("vlan_egress", []))
    vlan_untagged = parse_vlan_untagged_ports(raw.get("vlan_untagged", []))
    poe = parse_poe_status(raw.get("poe", []))
    port_statistics = _parse_port_statistics(raw)

    # Port names/aliases as lists of (ifIndex, value) tuples
    port_names = [(k, v) for k, v in sorted(if_names.items())]
    port_aliases = [(k, v) for k, v in sorted(if_aliases.items())]

    return {
        "mac_table": mac_table,
        "vlan_names": vlan_names,
        "port_pvids": port_pvids,
        "port_names": port_names,
        "port_aliases": port_aliases,
        "port_status": port_status,
        "lldp_neighbors": lldp_neighbors,
        "vlan_egress_ports": vlan_egress,
        "vlan_untagged_ports": vlan_untagged,
        "poe_status": poe,
        "port_statistics": port_statistics,
    }


def _is_bridge_candidate(host: Host) -> bool:
    """Check if a host should be scanned for bridge data.

    A host is a bridge candidate if:
    - Its hardware_type is in BRIDGE_CAPABLE_HARDWARE, OR
    - It has existing snmp_data (proven SNMP reachable)
    """
    if host.hardware_type in BRIDGE_CAPABLE_HARDWARE:
        return True
    if host.snmp_data is not None:
        return True
    return False


def scan_bridge(
    hosts: list[Host],
    baseline: dict[str, dict] | None,
    *,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
) -> dict[str, dict]:
    """Scan reachable managed switches for bridge/topology data.

    Args:
        hosts: Host objects with IPs to scan.
        baseline: Last-known bridge data (from the DiscoveryDB).  Fresh
            results are merged over it; the caller persists the result.
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data from the
            reachability pass. Only reachable hosts are scanned.

    Returns:
        Mapping of hostname to bridge data dict.
    """
    import sys

    bridge_data = dict(baseline or {})

    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    for host in sorted_hosts:
        # Only scan bridge-capable hosts
        if not _is_bridge_candidate(host):
            continue

        # Skip hosts not in reachability data or not reachable
        host_reach = reachability.get(host.hostname) if reachability else None
        if host_reach is None or not host_reach.is_up:
            continue
        active_ips = list(host_reach.active_ips)

        if verbose:
            print(
                f"  {host.hostname:>{name_width}s} bridge({','.join(active_ips)}) ",
                end="", flush=True, file=sys.stderr,
            )

        # Try SNMP bridge data on each reachable IP until one succeeds
        for ip in active_ips:
            data = _collect_bridge_data(ip, host)
            if data is not None:
                bridge_data[host.hostname] = data
                mac_count = len(data.get("mac_table", []))
                vlan_count = len(data.get("vlan_names", []))
                if verbose:
                    print(
                        f"ok ({mac_count} MACs, {vlan_count} VLANs)",
                        file=sys.stderr,
                    )
                break
        else:
            if verbose:
                print("no-snmp", file=sys.stderr)

    return bridge_data


def enrich_hosts_with_bridge_data(
    hosts: list[Host],
    bridge_cache: dict[str, dict] | None,
) -> None:
    """Attach cached bridge data to Host objects.

    Modifies hosts in-place by setting host.bridge_data and host.switch_data.
    """
    bridge_cache = bridge_cache or {}
    for host in hosts:
        info = bridge_cache.get(host.hostname)
        if info is None:
            continue

        host.bridge_data = BridgeData(
            mac_table=tuple(
                tuple(entry) for entry in info.get("mac_table", [])
            ),
            vlan_names=tuple(
                tuple(entry) for entry in info.get("vlan_names", [])
            ),
            port_pvids=tuple(
                tuple(entry) for entry in info.get("port_pvids", [])
            ),
            port_names=tuple(
                tuple(entry) for entry in info.get("port_names", [])
            ),
            port_aliases=tuple(
                tuple(entry) for entry in info.get("port_aliases", [])
            ),
            port_status=tuple(
                tuple(entry) for entry in info.get("port_status", [])
            ),
            lldp_neighbors=tuple(
                tuple(entry) for entry in info.get("lldp_neighbors", [])
            ),
            vlan_egress_ports=tuple(
                tuple(entry) for entry in info.get("vlan_egress_ports", [])
            ),
            vlan_untagged_ports=tuple(
                tuple(entry) for entry in info.get("vlan_untagged_ports", [])
            ),
            poe_status=tuple(
                tuple(entry) for entry in info.get("poe_status", [])
            ),
            port_statistics=tuple(
                tuple(entry) for entry in info.get("port_statistics", [])
            ),
        )

        # Also set the unified switch_data
        host.switch_data = bridge_to_switch_data(host.bridge_data)
