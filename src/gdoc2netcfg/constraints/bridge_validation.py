"""Bridge/topology validation constraints.

Validates switch bridge data (MAC tables, VLAN config, LLDP neighbors)
against the spreadsheet inventory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host, NetworkInventory
    from gdoc2netcfg.models.network import Site


def validate_vlan_names(
    hosts: list[Host],
    site: Site,
) -> ValidationResult:
    """Validate VLAN names on switches match the VLAN Allocations spreadsheet.

    For each switch with bridge_data, compares dot1qVlanStaticName entries
    against site.vlans. Reports:
    - Name mismatches (switch says "foo", spreadsheet says "bar")
    - Unknown VLANs on switch (not in spreadsheet)

    VLAN 1 named "Default" is always accepted (standard switch default).
    """
    result = ValidationResult()

    for host in hosts:
        if host.bridge_data is None:
            continue

        for vlan_id, switch_name in host.bridge_data.vlan_names:
            # VLAN 1 "Default" is standard and always acceptable
            if vlan_id == 1 and switch_name == "Default":
                continue

            spreadsheet_vlan = site.vlans.get(vlan_id)
            if spreadsheet_vlan is None:
                result.add(ConstraintViolation(
                    severity=Severity.WARNING,
                    code="bridge_unknown_vlan",
                    message=(
                        f"VLAN {vlan_id} ({switch_name!r}) exists on switch "
                        f"but is not in VLAN Allocations spreadsheet"
                    ),
                    record_id=host.hostname,
                    field="bridge_data.vlan_names",
                ))
            elif spreadsheet_vlan.name != switch_name:
                result.add(ConstraintViolation(
                    severity=Severity.WARNING,
                    code="bridge_vlan_name_mismatch",
                    message=(
                        f"VLAN {vlan_id} named {switch_name!r} on switch "
                        f"but {spreadsheet_vlan.name!r} in spreadsheet"
                    ),
                    record_id=host.hostname,
                    field="bridge_data.vlan_names",
                ))

    return result


def _is_locally_administered(mac: str) -> bool:
    """Check if a MAC address is locally administered (LAA).

    Locally administered MACs have bit 1 of the first octet set.
    These are used by containers, VMs, and virtual interfaces.
    """
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0x02)


def validate_mac_connectivity(
    inventory: NetworkInventory,
) -> ValidationResult:
    """Cross-reference switch MAC tables with known spreadsheet MACs.

    Reports unknown MACs seen on switches (not matching any host in
    the inventory). Skips locally-administered MACs (containers/VMs).
    """
    result = ValidationResult()

    # Build set of all known MACs from inventory (upper-cased for comparison)
    known_macs: set[str] = set()
    for host in inventory.hosts:
        for mac in host.all_macs:
            known_macs.add(str(mac).upper())

    for host in inventory.hosts:
        if host.bridge_data is None:
            continue

        for mac_str, vlan_id, bridge_port, port_name in host.bridge_data.mac_table:
            mac_upper = mac_str.upper()
            # Unresolvable port names (LAG/CPU bridge ports) are empty;
            # fall back to the raw bridge port number for the message.
            port_label = port_name or f"bridge-port {bridge_port}"

            # Skip locally administered MACs (containers, VMs)
            if _is_locally_administered(mac_upper):
                continue

            # Skip known MACs
            if mac_upper in known_macs:
                continue

            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="bridge_unknown_mac",
                message=(
                    f"Unknown MAC {mac_upper} seen on {host.hostname} "
                    f"port {port_label} VLAN {vlan_id}"
                ),
                record_id=host.hostname,
                field="bridge_data.mac_table",
            ))

    return result


def validate_lldp_topology(
    inventory: NetworkInventory,
) -> ValidationResult:
    """Validate LLDP neighbor data against known inventory MACs.

    For each LLDP neighbor, checks if the chassis MAC matches any known
    MAC in the inventory. Matching on chassis MAC is more reliable than
    sysName because devices may report different naming conventions
    (e.g. Netgear S3300 reports 'manage-sw-netgear-s3300-1' but the
    inventory hostname is 'sw-netgear-s3300-1').

    Reports unknown neighbors as informational warnings for topology
    discovery purposes.
    """
    result = ValidationResult()

    # Build set of all known MACs from inventory (upper-cased for comparison)
    known_macs: set[str] = set()
    for host in inventory.hosts:
        for mac in host.all_macs:
            known_macs.add(str(mac).upper())

    for host in inventory.hosts:
        if host.bridge_data is None:
            continue

        for _local_ifindex, remote_sysname, remote_port_id, remote_chassis_mac in (
            host.bridge_data.lldp_neighbors
        ):
            if not remote_chassis_mac:
                continue

            if remote_chassis_mac.upper() in known_macs:
                continue

            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="bridge_unknown_lldp_neighbor",
                message=(
                    f"LLDP neighbor {remote_sysname!r} on port {remote_port_id} "
                    f"(chassis {remote_chassis_mac}) not found in inventory"
                ),
                record_id=host.hostname,
                field="bridge_data.lldp_neighbors",
            ))

    return result
