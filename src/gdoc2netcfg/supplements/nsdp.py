"""Supplement: NSDP discovery data collection.

Scans Netgear switches via the NSDP broadcast protocol to retrieve
device identity, firmware version, port status, and VLAN configuration.
Results are cached in nsdp.json.

This is primarily useful for unmanaged switches (hardware_type =
"netgear-switch-plus") that lack SNMP support. NSDP provides the only
programmatic way to query these devices.

The NSDP protocol client lives in the standalone `nsdp` package.
This module is the bridge between that package and gdoc2netcfg's
supplement pipeline.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.hardware import HARDWARE_NETGEAR_SWITCH_PLUS
from gdoc2netcfg.models.host import NSDPData
from gdoc2netcfg.models.switch_data import (
    PortLinkStatus,
    PortTrafficStats,
    SwitchData,
    SwitchDataSource,
    VLANInfo,
)
from nsdp.types import LinkSpeed

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

NSDP_HARDWARE_TYPES = frozenset({HARDWARE_NETGEAR_SWITCH_PLUS})


def nsdp_to_switch_data(nsdp: NSDPData) -> SwitchData:
    """Convert NSDPData to unified SwitchData format.

    Args:
        nsdp: The NSDPData instance to convert.

    Returns:
        A SwitchData instance with the converted data.
    """
    # Convert port status tuples to PortLinkStatus objects
    port_status = tuple(
        PortLinkStatus(
            port_id=ps[0],
            is_up=ps[1] != LinkSpeed.DOWN.value,
            speed_mbps=LinkSpeed.from_byte(ps[1]).speed_mbps,
        )
        for ps in nsdp.port_status
    )

    # Convert port statistics tuples to PortTrafficStats objects
    port_stats = tuple(
        PortTrafficStats(
            port_id=ps[0],
            bytes_rx=ps[1],
            bytes_tx=ps[2],
            errors=ps[3],
        )
        for ps in nsdp.port_statistics
    )

    # Convert VLAN membership tuples to VLANInfo objects
    vlans = tuple(
        VLANInfo(
            vlan_id=vm[0],
            name=None,  # NSDP doesn't have VLAN names
            member_ports=vm[1],
            tagged_ports=vm[2],
        )
        for vm in nsdp.vlan_members
    )

    return SwitchData(
        source=SwitchDataSource.NSDP,
        model=nsdp.model,
        firmware_version=nsdp.firmware_version,
        port_count=nsdp.port_count,
        port_status=port_status,
        port_pvids=nsdp.port_pvids,
        port_stats=port_stats,
        vlans=vlans,
        serial_number=nsdp.serial_number,
        vlan_engine=nsdp.vlan_engine,
        qos_engine=nsdp.qos_engine,
        port_mirroring_dest=nsdp.port_mirroring_dest,
        igmp_snooping_enabled=nsdp.igmp_snooping_enabled,
        broadcast_filtering=nsdp.broadcast_filtering,
        loop_detection=nsdp.loop_detection,
    )


def load_nsdp_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached NSDP data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_nsdp_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save NSDP data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_nsdp(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
) -> dict[str, dict]:
    """Scan Netgear switches via NSDP unicast queries.

    Queries each known Netgear switch by IP address using the NSDP
    protocol to retrieve device info, port status, and VLAN config.

    Args:
        hosts: Host objects — only those with hardware_type in
            NSDP_HARDWARE_TYPES will be queried.
        cache_path: Path to nsdp.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stderr.

    Returns:
        Mapping of hostname to NSDP data dict.
    """
    nsdp_data = load_nsdp_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(f"nsdp.json last updated {age:.0f}s ago, using cache.", file=sys.stderr)
            return nsdp_data

    # Build list of (hostname, ip) pairs for switches to query
    switches_to_query: list[tuple[str, str]] = []
    for host in hosts:
        if host.hardware_type not in NSDP_HARDWARE_TYPES:
            continue
        if host.first_ipv4 is None:
            continue
        switches_to_query.append((host.hostname, str(host.first_ipv4)))

    if not switches_to_query:
        if verbose:
            print("No Netgear switches to scan.", file=sys.stderr)
        return nsdp_data

    if verbose:
        print(f"Scanning {len(switches_to_query)} Netgear switch(es) via NSDP...", file=sys.stderr)

    try:
        from nsdp import NSDPClient

        with NSDPClient() as client:
            # Query each switch by IP (unicast) - more reliable than broadcast
            for hostname, ip in switches_to_query:
                if verbose:
                    print(f"  {hostname} ({ip})... ", end="", flush=True, file=sys.stderr)

                device = client.query_ip(ip, timeout=2.0)
                if device is None:
                    if verbose:
                        print("no response", file=sys.stderr)
                    continue

                entry: dict = {
                    "model": device.model,
                    "mac": device.mac,
                }
                if device.hostname is not None:
                    entry["hostname"] = device.hostname
                if device.ip is not None:
                    entry["ip"] = device.ip
                if device.netmask is not None:
                    entry["netmask"] = device.netmask
                if device.gateway is not None:
                    entry["gateway"] = device.gateway
                if device.firmware_version is not None:
                    entry["firmware_version"] = device.firmware_version
                if device.dhcp_enabled is not None:
                    entry["dhcp_enabled"] = device.dhcp_enabled
                if device.port_count is not None:
                    entry["port_count"] = device.port_count
                if device.serial_number is not None:
                    entry["serial_number"] = device.serial_number
                if device.port_status:
                    entry["port_status"] = [
                        (ps.port_id, ps.speed.value) for ps in device.port_status
                    ]
                if device.port_pvids:
                    entry["port_pvids"] = [
                        (pp.port_id, pp.vlan_id) for pp in device.port_pvids
                    ]
                if device.vlan_engine is not None:
                    entry["vlan_engine"] = device.vlan_engine.value
                if device.vlan_members:
                    entry["vlan_members"] = [
                        (vm.vlan_id, sorted(vm.member_ports), sorted(vm.tagged_ports))
                        for vm in device.vlan_members
                    ]
                if device.port_statistics:
                    entry["port_statistics"] = [
                        (ps.port_id, ps.bytes_received, ps.bytes_sent, ps.crc_errors)
                        for ps in device.port_statistics
                    ]
                if device.qos_engine is not None:
                    entry["qos_engine"] = device.qos_engine
                if device.port_mirroring is not None:
                    entry["port_mirroring_dest"] = device.port_mirroring.destination_port
                if device.igmp_snooping is not None:
                    entry["igmp_snooping_enabled"] = device.igmp_snooping.enabled
                if device.broadcast_filtering is not None:
                    entry["broadcast_filtering"] = device.broadcast_filtering
                if device.loop_detection is not None:
                    entry["loop_detection"] = device.loop_detection

                nsdp_data[hostname] = entry
                if verbose:
                    fw = device.firmware_version or "?"
                    print(f"{device.model} fw={fw}", file=sys.stderr)

    except PermissionError:
        print(
            "Error: NSDP scan requires elevated privileges.\n"
            "  Run with: sudo uv run gdoc2netcfg nsdp\n"
            "  Or grant capability: sudo setcap cap_net_raw+ep $(which python3)",
            file=sys.stderr,
        )
    except OSError as e:
        print(f"Error during NSDP scan: {e}", file=sys.stderr)

    save_nsdp_cache(cache_path, nsdp_data)
    return nsdp_data


def enrich_hosts_with_nsdp(
    hosts: list[Host],
    nsdp_cache: dict[str, dict] | None,
) -> None:
    """Attach cached NSDP data to Host objects.

    Modifies hosts in-place by setting host.nsdp_data and host.switch_data.

    Note: For Netgear switches, NSDP data takes priority over SNMP data for
    switch_data because NSDP is the native protocol and provides more complete
    information (serial number, QoS, mirroring, etc.). This enrichment runs
    after bridge enrichment, so switch_data from SNMP will be overwritten.
    """
    nsdp_cache = nsdp_cache or {}
    for host in hosts:
        info = nsdp_cache.get(host.hostname)
        if info is not None:
            host.nsdp_data = NSDPData(
                model=info["model"],
                mac=info["mac"],
                hostname=info.get("hostname"),
                ip=info.get("ip"),
                netmask=info.get("netmask"),
                gateway=info.get("gateway"),
                firmware_version=info.get("firmware_version"),
                dhcp_enabled=info.get("dhcp_enabled"),
                port_count=info.get("port_count"),
                serial_number=info.get("serial_number"),
                port_status=tuple(
                    (ps[0], ps[1]) for ps in info.get("port_status", [])
                ),
                port_pvids=tuple(
                    (pp[0], pp[1]) for pp in info.get("port_pvids", [])
                ),
                vlan_engine=info.get("vlan_engine"),
                vlan_members=tuple(
                    (vm[0], frozenset(vm[1]), frozenset(vm[2]))
                    for vm in info.get("vlan_members", [])
                ),
                port_statistics=tuple(
                    (ps[0], ps[1], ps[2], ps[3])
                    for ps in info.get("port_statistics", [])
                ),
                qos_engine=info.get("qos_engine"),
                port_mirroring_dest=info.get("port_mirroring_dest"),
                igmp_snooping_enabled=info.get("igmp_snooping_enabled"),
                broadcast_filtering=info.get("broadcast_filtering"),
                loop_detection=info.get("loop_detection"),
            )
            # Set unified switch_data from NSDP data (overwrites any SNMP data)
            host.switch_data = nsdp_to_switch_data(host.nsdp_data)
