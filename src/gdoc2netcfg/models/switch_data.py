"""Unified switch data model for SNMP and NSDP sources.

This module provides a common representation of switch data that can be
populated from either SNMP (managed switches) or NSDP (Netgear Plus switches).
Consumers should use these types rather than the source-specific BridgeData
or NSDPData classes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SwitchDataSource(Enum):
    """Source of switch data."""

    SNMP = "snmp"
    NSDP = "nsdp"


@dataclass(frozen=True)
class PortLinkStatus:
    """Link status for a single switch port.

    Attributes:
        port_id: 1-based port number.
        is_up: Whether the port has link.
        speed_mbps: Link speed in Mbps (0 if down).
        port_name: Human-readable port name (SNMP only, None for NSDP).
    """

    port_id: int
    is_up: bool
    speed_mbps: int
    port_name: str | None = None


@dataclass(frozen=True)
class PortTrafficStats:
    """Traffic statistics for a single port.

    Attributes:
        port_id: 1-based port number.
        bytes_rx: Total bytes received (None when the source doesn't
            expose the counter for this interface).
        bytes_tx: Total bytes transmitted (None when not exposed).
        errors: Error count (CRC errors for NSDP, ifInErrors for SNMP;
            None when not exposed).
    """

    port_id: int
    bytes_rx: int | None
    bytes_tx: int | None
    errors: int | None


@dataclass(frozen=True)
class VLANInfo:
    """VLAN configuration.

    Attributes:
        vlan_id: 802.1Q VLAN ID.
        name: VLAN name (SNMP only, None for NSDP).
        member_ports: Set of port IDs that are members.
        tagged_ports: Subset of member_ports that are tagged (trunk).
    """

    vlan_id: int
    name: str | None
    member_ports: frozenset[int]
    tagged_ports: frozenset[int] = field(default_factory=frozenset)

    @property
    def untagged_ports(self) -> frozenset[int]:
        """Ports that are untagged members (access ports)."""
        return self.member_ports - self.tagged_ports


@dataclass(frozen=True)
class SwitchData:
    """Unified switch data from SNMP or NSDP.

    This is the primary interface for consuming switch data. It provides
    a consistent view regardless of whether data came from SNMP or NSDP.

    Attributes:
        source: Where this data came from (SNMP or NSDP).
        model: Switch model string.
        firmware_version: Firmware version string.
        port_count: Total number of ports.
        port_status: Per-port link status.
        port_pvids: Per-port native VLAN as (port_id, vlan_id) tuples.
        port_stats: Per-port traffic statistics (if available).
        vlans: VLAN configuration (if available).

        # SNMP-only fields (None for NSDP, empty tuple for SNMP with no data)
        mac_table: MAC forwarding table entries.
        lldp_neighbors: LLDP neighbor information.
        poe_status: PoE port status.

        # NSDP-only fields (None for SNMP)
        serial_number: Device serial number.
        vlan_engine: VLAN mode (0=disabled, 4=advanced 802.1Q).
        qos_engine: QoS mode (0=disabled, 1=port-based, 2=802.1p).
        port_mirroring_dest: Destination port for mirroring (0=disabled).
        igmp_snooping_enabled: Whether IGMP snooping is on.
        broadcast_filtering: Whether broadcast storm control is enabled.
        loop_detection: Whether loop detection is enabled.
    """

    source: SwitchDataSource
    model: str | None = None
    firmware_version: str | None = None
    port_count: int | None = None

    # Common fields
    port_status: tuple[PortLinkStatus, ...] = ()
    port_pvids: tuple[tuple[int, int], ...] = ()  # (port_id, vlan_id)
    port_stats: tuple[PortTrafficStats, ...] = ()
    vlans: tuple[VLANInfo, ...] = ()

    # SNMP-only (None for NSDP)
    mac_table: tuple[tuple[str, int, int, str], ...] | None = None
    # (mac, vlan_id, port_id, port_name)
    lldp_neighbors: tuple[tuple[int, str, str, str], ...] | None = None
    # (port_id, remote_name, remote_port, remote_mac)
    poe_status: tuple[tuple[int, int, int], ...] | None = None
    # (port_id, admin_status, detection_status)

    # NSDP-only (None for SNMP)
    serial_number: str | None = None
    vlan_engine: int | None = None  # 0=disabled, 4=advanced 802.1Q
    qos_engine: int | None = None  # 0=disabled, 1=port-based, 2=802.1p
    port_mirroring_dest: int | None = None
    igmp_snooping_enabled: bool | None = None
    broadcast_filtering: bool | None = None
    loop_detection: bool | None = None
