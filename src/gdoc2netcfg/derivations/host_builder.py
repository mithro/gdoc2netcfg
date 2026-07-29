"""Host builder: transform raw DeviceRecords into Host objects.

This is the central derivation that orchestrates all field derivations
to build the enriched Host model from raw spreadsheet records.
"""

from __future__ import annotations

from dataclasses import dataclass

from gdoc2netcfg.derivations.dns_names import (
    common_suffix,
    compute_dhcp_name,
    compute_hostname,
    derive_all_dns_names,
)
from gdoc2netcfg.derivations.hardware import detect_hardware_type
from gdoc2netcfg.derivations.ip_remap import filter_and_resolve_records
from gdoc2netcfg.derivations.ipv6 import ipv4_to_ipv6_list
from gdoc2netcfg.derivations.vlan import ip_to_vlan_id
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.credentials import credential_field_names
from gdoc2netcfg.sources.parser import DeviceRecord


def _build_interface(record: DeviceRecord, site: Site) -> NetworkInterface:
    """Build a NetworkInterface from a single DeviceRecord."""
    mac = MACAddress.parse(record.mac_address)
    ipv4 = IPv4Address(record.ip)
    ipv6_addrs = ipv4_to_ipv6_list(ipv4, site.active_ipv6_prefixes)
    vlan_id = ip_to_vlan_id(ipv4, site)
    interface_name = record.interface if record.interface else None

    # Determine sheet type from sheet_name
    sheet_type = record.sheet_name
    if sheet_type.lower() == "network":
        sheet_type = "Network"
    elif sheet_type.lower() == "iot":
        sheet_type = "IoT"

    dhcp_name = compute_dhcp_name(record.machine, record.interface, sheet_type)

    ip_addresses: list[IPv4Address | IPv6Address] = [ipv4]
    ip_addresses.extend(ipv6_addrs)
    return NetworkInterface(
        name=interface_name,
        mac=mac,
        ip_addresses=tuple(ip_addresses),
        vlan_id=vlan_id,
        dhcp_name=dhcp_name,
    )


def _is_bmc_interface(interface_name: str | None) -> bool:
    """Check if an interface name indicates a BMC (Baseboard Management Controller).

    BMC interfaces are split into separate hosts in the pipeline, matching
    the production behavior where 'bmc.machine_name' becomes its own host.
    """
    return bool(interface_name and "bmc" in interface_name.lower())


def build_hosts(records: list[DeviceRecord], site: Site) -> list[Host]:
    """Build Host objects from raw DeviceRecords.

    Groups records by machine name into Host objects, computing all
    derived fields (hostname, DHCP name, IPv6, VLAN, DNS names).

    BMC interfaces are split into separate hosts: a record with interface
    'bmc' on machine 'big-storage' creates a host 'bmc.big-storage' with
    a bare (None) interface, separate from the parent 'big-storage' host.
    This matches the production behavior where BMCs are treated as
    independent network entities.

    Records missing required fields (machine, mac, ip) are skipped
    with a warning.  Records whose site column doesn't match are
    filtered out, and 'X' placeholders in IPs are resolved to the
    site's octet.
    """
    # Filter for this site and resolve 'X' placeholders in IPs
    records = filter_and_resolve_records(records, site)

    # Group records by hostname to build hosts.
    # BMC interfaces get their own hostname: {interface}.{machine_hostname}
    host_groups: dict[str, list[DeviceRecord]] = {}
    host_sheet_type: dict[str, str] = {}
    # Track BMC records that need interface→None transformation
    bmc_hostnames: set[str] = set()

    for record in records:
        if not record.machine or not record.mac_address or not record.ip:
            continue

        # Determine sheet type
        sheet_type = record.sheet_name
        if sheet_type.lower() == "network":
            sheet_type = "Network"
        elif sheet_type.lower() == "iot":
            sheet_type = "IoT"

        base_hostname = compute_hostname(record.machine, sheet_type)

        # BMC interfaces become separate hosts
        if _is_bmc_interface(record.interface):
            hostname = f"{record.interface.lower()}.{base_hostname}"
            bmc_hostnames.add(hostname)
        else:
            hostname = base_hostname

        if hostname not in host_groups:
            host_groups[hostname] = []
            host_sheet_type[hostname] = sheet_type
        host_groups[hostname].append(record)

    hosts: list[Host] = []

    for hostname, group in host_groups.items():
        sheet_type = host_sheet_type[hostname]
        is_bmc_host = hostname in bmc_hostnames
        interfaces = []
        for r in group:
            iface = _build_interface(r, site)
            if is_bmc_host:
                # BMC host: strip the interface name so it becomes
                # the bare/default interface (None)
                iface = NetworkInterface(
                    name=None,
                    mac=iface.mac,
                    ip_addresses=iface.ip_addresses,
                    vlan_id=iface.vlan_id,
                    dhcp_name=iface.dhcp_name,
                )
            interfaces.append(iface)

        # Collect extra fields from first record (they should be the same)
        extra = group[0].extra.copy()

        # Parse alt names from "Alt Names" column (newline or comma separated).
        # Collect from all records in the group since alt names may appear on
        # any interface row (e.g. only on eth-uplink, not the first record).
        alt_names: list[str] = []
        for r in group:
            raw_alt = r.extra.get("Alt Names", "")
            if raw_alt:
                for part in raw_alt.replace("\n", ",").split(","):
                    name = part.strip()
                    if name and name not in alt_names:
                        alt_names.append(name)

        host = Host(
            machine_name=group[0].machine.lower(),
            hostname=hostname,
            sheet_type=sheet_type,
            interfaces=interfaces,
            extra=extra,
            alt_names=alt_names,
        )

        # Derive DNS names (all four passes)
        derive_all_dns_names(host, site)

        # Detect hardware type from MAC OUI
        host.hardware_type = detect_hardware_type(host)

        hosts.append(host)

    return hosts


@dataclass(frozen=True)
class LostCredentialCell:
    """A filled credential cell that ``extract_credentials()`` cannot see.

    Identifies the cell by sheet position and field name only — never the
    credential value itself.
    """

    sheet_name: str
    row_number: int
    machine: str
    interface: str
    field: str


def find_lost_credential_cells(
    records: list[DeviceRecord], hosts: list[Host], site: Site,
) -> list[LostCredentialCell]:
    """Report credential cells in raw records that no built host carries.

    ``build_hosts()`` drops records missing machine/mac/ip, and each host's
    ``extra`` comes from its first surviving record only — so a filled
    credential cell on any other row would be silently discarded at fetch
    time, never reaching credentials.db.  ``cmd_fetch`` fails loudly when
    this returns anything.

    A cell survives when some host sharing the record's machine name has
    the same field/value in its ``extra`` (BMC rows become separate hosts
    but keep the parent's machine name).  Records filtered out for another
    site are exempt — this site's store legitimately omits them.
    """
    names = credential_field_names()
    survived: dict[str, set[tuple[str, str]]] = {}
    for host in hosts:
        pairs = {(n, host.extra[n]) for n in names if host.extra.get(n)}
        survived.setdefault(host.machine_name, set()).update(pairs)

    lost: list[LostCredentialCell] = []
    for record in filter_and_resolve_records(records, site):
        if not record.machine:
            continue
        machine_pairs = survived.get(record.machine.lower(), set())
        for field in names:
            value = record.extra.get(field)
            if value and (field, value) not in machine_pairs:
                lost.append(LostCredentialCell(
                    sheet_name=record.sheet_name,
                    row_number=record.row_number,
                    machine=record.machine,
                    interface=record.interface,
                    field=field,
                ))
    return lost


def build_inventory(hosts: list[Host], site: Site) -> NetworkInventory:
    """Build a NetworkInventory with precomputed indexes.

    Computes:
    - ip_to_hostname: IP → canonical hostname (using common_suffix for
      multi-name IPs)
    - ip_to_macs: IP → [(MACAddress, dhcp_name)] for DHCP config
    """
    ip_to_hostname: dict[str, str] = {}
    ip_to_macs: dict[str, list[tuple[MACAddress, str]]] = {}

    # First pass: build ip→hostname mapping
    ip_names: dict[str, list[str]] = {}
    for host in hosts:
        for iface in host.interfaces:
            ip_str = str(iface.ipv4)

            # Build name for this interface
            if iface.name:
                name = f"{iface.name}.{host.hostname}"
            else:
                name = host.hostname

            if ip_str not in ip_names:
                ip_names[ip_str] = []
            ip_names[ip_str].append(name)

    for ip_str, names in ip_names.items():
        suffix = common_suffix(*names).strip(".")
        ip_to_hostname[ip_str] = suffix

    # Second pass: build ip→macs mapping
    for host in hosts:
        for iface in host.interfaces:
            ip_str = str(iface.ipv4)
            if ip_str not in ip_to_macs:
                ip_to_macs[ip_str] = []
            ip_to_macs[ip_str].append((iface.mac, iface.dhcp_name))

    return NetworkInventory(
        site=site,
        hosts=hosts,
        ip_to_hostname=ip_to_hostname,
        ip_to_macs=ip_to_macs,
    )
