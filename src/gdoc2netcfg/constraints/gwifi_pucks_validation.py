"""Constraints for gwifi puck records against the network inventory.

The pucks live on the wifi VLAN (10.1.4.0/24) served by wisp, but their
MACs and fixed IPs must not collide with anything gdoc2netcfg already
manages — a collision means either a stale sheet row or a puck MAC that
was recorded for another device.

See gwifi-openwrt docs/wisp-netboot-install-design.md (section 5.3).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import NetworkInventory
    from gdoc2netcfg.sources.gwifi_pucks_parser import PuckRecord


def validate_gwifi_pucks(
    pucks: list["PuckRecord"], inventory: "NetworkInventory"
) -> ValidationResult:
    """Validate puck records against each other and the inventory.

    Checks:
    - puck MACs (eth0/eth1) unique across all pucks
    - puck MACs absent from the inventory's host interfaces
    - puck fixed IPs absent from the inventory's host interfaces
    """
    result = ValidationResult()

    inv_macs: dict[str, str] = {}
    inv_ips: dict[str, str] = {}
    for host in inventory.hosts:
        for iface in host.interfaces:
            inv_macs[str(iface.mac).lower()] = host.hostname
            for ip in iface.ip_addresses:
                inv_ips[str(ip)] = host.hostname

    seen: dict[str, str] = {}
    for puck in pucks:
        for mac in (puck.eth0, puck.eth1):
            key = mac.lower()
            if key in seen and seen[key] != puck.name:
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="gwifi_mac_duplicate",
                    message=(
                        f"puck MAC {mac} used by both {seen[key]} "
                        f"and {puck.name}"),
                    record_id=puck.name,
                    field="mac",
                ))
            seen[key] = puck.name

            if key in inv_macs:
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="gwifi_mac_collision",
                    message=(
                        f"puck {puck.name} MAC {mac} already belongs to "
                        f"inventory host {inv_macs[key]}"),
                    record_id=puck.name,
                    field="mac",
                ))

        if puck.ip in inv_ips:
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="gwifi_ip_collision",
                message=(
                    f"puck {puck.name} fixed IP {puck.ip} already belongs "
                    f"to inventory host {inv_ips[puck.ip]}"),
                record_id=puck.name,
                field="ip",
            ))

    return result
