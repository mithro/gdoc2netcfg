"""Constraint predicates organized by scope.

Field Constraints — run on raw DeviceRecords after Source.
Record Constraints — run on Hosts after Field Derivations.
Cross-Record Constraints — run on NetworkInventory after Aggregate Derivations.
"""

from __future__ import annotations

import re

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)
from gdoc2netcfg.derivations.ipv6 import ipv4_to_ipv6_list
from gdoc2netcfg.derivations.vlan import ip_to_vlan_id
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.parser import DeviceRecord

_DHCP_NAME_RE = re.compile(r'^[a-z0-9.\-_]+$')


# ---------------------------------------------------------------------------
# Field Constraints (on raw DeviceRecords)
# ---------------------------------------------------------------------------

def validate_field_constraints(records: list[DeviceRecord]) -> ValidationResult:
    """Validate field-level constraints on raw device records.

    Checks:
    - MAC address must be present
    - Machine name must be present
    - IP address must be present
    """
    result = ValidationResult()

    for record in records:
        record_id = f"{record.sheet_name}:{record.row_number}"

        if not record.mac_address:
            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="missing_mac",
                message=f"No MAC address (machine={record.machine!r})",
                record_id=record_id,
                field="mac_address",
            ))

        if not record.machine:
            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="missing_machine",
                message=f"No machine name (ip={record.ip!r})",
                record_id=record_id,
                field="machine",
            ))

        if not record.ip:
            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="missing_ip",
                message=f"No IP address (machine={record.machine!r})",
                record_id=record_id,
                field="ip",
            ))

    return result


# ---------------------------------------------------------------------------
# IPv6 Consistency Constraints (spreadsheet vs algorithmic derivation)
# ---------------------------------------------------------------------------

def validate_ipv6_consistency(
    records: list[DeviceRecord], site: Site
) -> ValidationResult:
    """Validate that explicit IPv6 addresses in the spreadsheet match
    the algorithmic derivation from IPv4.

    For each record with 'IPv6 A', 'IPv6 B', etc. columns, computes the
    expected IPv6 from the IPv4 address and checks for mismatches.
    """
    result = ValidationResult()

    for record in records:
        if not record.ip:
            continue

        record_id = f"{record.sheet_name}:{record.row_number}"

        try:
            ipv4 = IPv4Address(record.ip)
        except ValueError:
            continue

        # Compute expected IPv6 addresses from algorithm
        expected = ipv4_to_ipv6_list(ipv4, site.active_ipv6_prefixes)
        expected_by_prefix = {addr.prefix: addr.address for addr in expected}

        for key, value in record.extra.items():
            if not key.startswith("IPv6 "):
                continue
            value = value.strip()
            if not value:
                continue

            # Find which prefix this address belongs to
            matched_prefix = None
            for prefix in site.ipv6_prefixes:
                if value.startswith(prefix.prefix):
                    matched_prefix = prefix
                    break

            if matched_prefix is None:
                result.add(ConstraintViolation(
                    severity=Severity.WARNING,
                    code="ipv6_unknown_prefix",
                    message=(
                        f"IPv6 address {value} ({key}) does not match any "
                        f"known prefix (machine={record.machine!r}, "
                        f"iface={record.interface!r})"
                    ),
                    record_id=record_id,
                    field=key,
                ))
                continue

            if not matched_prefix.enabled:
                # Disabled prefix — skip validation but don't warn
                continue

            algo_addr = expected_by_prefix.get(matched_prefix.prefix)
            if algo_addr is None:
                # Algorithm couldn't derive an address (non-10.x IP)
                # but spreadsheet has one — that's notable
                result.add(ConstraintViolation(
                    severity=Severity.WARNING,
                    code="ipv6_no_algorithmic",
                    message=(
                        f"Spreadsheet has {key}={value} but IPv4 {record.ip} "
                        f"has no algorithmic IPv6 mapping "
                        f"(machine={record.machine!r}, "
                        f"iface={record.interface!r})"
                    ),
                    record_id=record_id,
                    field=key,
                ))
            elif algo_addr != value:
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="ipv6_mismatch",
                    message=(
                        f"IPv6 mismatch for {key}: spreadsheet has {value}, "
                        f"algorithm expects {algo_addr} "
                        f"(machine={record.machine!r}, "
                        f"iface={record.interface!r})"
                    ),
                    record_id=record_id,
                    field=key,
                ))

    return result


# ---------------------------------------------------------------------------
# Record Constraints (on Hosts after derivations)
# ---------------------------------------------------------------------------

def validate_record_constraints(hosts: list[Host], site: Site) -> ValidationResult:
    """Validate record-level constraints on derived Host objects.

    Checks:
    - DHCP names must match [a-z0-9.\\-_]+ pattern
    - BMC hosts must be on Network Management network (e.g. 10.1.5.X)
      unless they are on a global VLAN (e.g. 10.41.X.X)
    - Global-VLAN BMCs must be on the 10.X.1.X subnet
    """
    result = ValidationResult()

    # Derive the management network prefix from the site config
    net_prefix = site.ip_prefix_for_vlan("net")

    for host in hosts:
        for iface in host.interfaces:
            # DHCP name validation
            if iface.dhcp_name and not _DHCP_NAME_RE.match(iface.dhcp_name):
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="invalid_dhcp_name",
                    message=(
                        f"Invalid characters in DHCP name: {iface.dhcp_name!r} "
                        f"(host={host.hostname})"
                    ),
                    record_id=host.hostname,
                    field="dhcp_name",
                ))

            # BMC placement validation
            if iface.name and "bmc" in iface.name.lower():
                ip_str = str(iface.ipv4)
                a, b, c, d = iface.ipv4.octets

                # Check if BMC is on a global VLAN (second octet != site_octet)
                is_on_global_vlan = a == 10 and any(
                    v.is_global and b == v.id
                    for v in site.vlans.values()
                )

                if is_on_global_vlan:
                    # Global-VLAN BMC: must be on 10.X.1.X subnet
                    if c != 1:
                        result.add(ConstraintViolation(
                            severity=Severity.ERROR,
                            code="bmc_wrong_subnet",
                            message=(
                                f"Test-hardware BMC must be on 10.X.1.X subnet! "
                                f"{iface.dhcp_name} has IP {ip_str}, expected 10.{b}.1.X"
                            ),
                            record_id=host.hostname,
                            field="ip",
                        ))
                elif net_prefix and not ip_str.startswith(net_prefix):
                    # Regular BMC: must be on Network Management
                    result.add(ConstraintViolation(
                        severity=Severity.ERROR,
                        code="bmc_not_management",
                        message=(
                            f"BMC not on Network Management network! "
                            f"{iface.dhcp_name} has IP {ip_str}, expected {net_prefix}X"
                        ),
                        record_id=host.hostname,
                        field="ip",
                    ))

    return result


# ---------------------------------------------------------------------------
# Cross-Record Constraints (on NetworkInventory)
# ---------------------------------------------------------------------------

def _is_cross_sheet_mirror(
    macs: list[tuple[MACAddress, str]],
    ip_str: str,
    mac_to_hosts: dict[str, list[Host]],
) -> bool:
    """Is this IP's MAC collision a deliberate cross-sheet mirror?

    A mirror is an IP Allocation row and a wifi-tab formula row recording
    the SAME device twice under two hostnames (e.g. "wisp" from the
    Network sheet, "wisp.wifi" from the WiFi sheet) — permanent by design,
    not a data-entry error. It holds when every colliding record for this
    IP pairs the identical MAC, and the owning hosts — restricted to hosts
    that actually own an interface with that MAC on THIS ip_str, not
    merely hosts that share the MAC via some other IP — share one
    machine_name with exactly one owner per sheet_type (equivalently: as
    many distinct hostnames as distinct sheet_types).

    The per-sheet_type-one-owner requirement is what makes this
    "cross-sheet" and excludes a same-sheet machine_name split, e.g. a BMC
    row sharing machine_name with its parent (both sheet_type "Network",
    see CLAUDE.md 'BMC Handling') — a copy-paste error giving a BMC its
    parent's exact MAC+IP must still error, even when an unrelated
    genuine mirror also happens to exist for the same machine_name+IP.

    The per-IP restriction (rather than a MAC-global owner lookup) avoids
    two failure modes: a genuine same-IP duplicate getting masked by an
    unrelated host that merely reuses the MAC elsewhere, and a genuine
    same-IP mirror getting wrongly rejected by such an unrelated host.
    """
    unique_macs = {str(mac) for mac, _ in macs}
    if len(unique_macs) != 1:
        return False

    # Host isn't hashable (mutable dataclass with list fields), so dedupe
    # by identity rather than using a set[Host].
    owning_hosts: dict[int, Host] = {}
    for mac_str in unique_macs:
        for host in mac_to_hosts.get(mac_str, []):
            if any(
                str(iface.mac) == mac_str and str(iface.ipv4) == ip_str
                for iface in host.interfaces
            ):
                owning_hosts[id(host)] = host

    hostnames = {h.hostname for h in owning_hosts.values()}
    machine_names = {h.machine_name for h in owning_hosts.values()}
    sheet_types = {h.sheet_type for h in owning_hosts.values()}
    return (
        len(machine_names) == 1
        and len(sheet_types) > 1
        and len(hostnames) == len(sheet_types)
    )


def validate_cross_record_constraints(inventory: NetworkInventory) -> ValidationResult:
    """Validate cross-record constraints on the full inventory.

    Checks:
    - MAC address must not be assigned to multiple different IPs
    - IP address uniqueness: multiple MACs on the same non-roaming IP are
      allowed only when (a) all MACs belong to one host (e.g. a puck's
      wan+lan interfaces sharing one fixed IP), or (b) the collision is a
      deliberate cross-sheet mirror — see _is_cross_sheet_mirror() for the
      exact predicate. Multiple MACs are always allowed in the roaming
      range.
    """
    result = ValidationResult()

    # Derive roaming prefix from site config
    roam_prefix = inventory.site.ip_prefix_for_vlan("roam")

    # MAC → IP uniqueness (DNS-only interfaces have no MAC to collide)
    mac_to_ips: dict[str, list[tuple[str, str]]] = {}  # mac → [(ip, dhcp_name)]
    for host in inventory.hosts:
        for iface in host.interfaces:
            if iface.mac is None:
                continue
            mac_str = str(iface.mac)
            ip_str = str(iface.ipv4)
            if mac_str not in mac_to_ips:
                mac_to_ips[mac_str] = []
            mac_to_ips[mac_str].append((ip_str, iface.dhcp_name))

    for mac, entries in mac_to_ips.items():
        unique_ips = set(ip for ip, _ in entries)
        if len(unique_ips) > 1:
            ip_list = ", ".join(f"{ip} ({name})" for ip, name in entries)
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="mac_duplicate_ip",
                message=f"MAC {mac} assigned to multiple IPs: {ip_list}",
                record_id=mac,
                field="mac_address",
            ))

    # mac → hosts that own an interface with this MAC (normally exactly
    # one, but a sheet copy-paste error can list the same MAC on two
    # different hosts — track the full list, not last-writer-wins, so the
    # collision is visible to the checks below).
    mac_to_hosts: dict[str, list[Host]] = {}
    for host in inventory.hosts:
        for iface in host.interfaces:
            mac_to_hosts.setdefault(str(iface.mac), []).append(host)

    # Multiple MACs per IP: allowed in the roaming range, or when all MACs
    # belong to one host (e.g. a multi-port endpoint like a puck's wan+lan
    # interfaces sharing one fixed IP — this owner check stays MAC-global,
    # matching a host across all its interfaces regardless of IP), or when
    # the collision is a deliberate cross-sheet mirror (per-IP owners only
    # — see _is_cross_sheet_mirror()).
    for ip_str, macs in inventory.ip_to_macs.items():
        is_roaming = roam_prefix and ip_str.startswith(roam_prefix)
        if len(macs) <= 1 or is_roaming:
            continue
        owning_hostnames: set[str] = set()
        has_unowned_mac = False
        for mac, _ in macs:
            hosts = mac_to_hosts.get(str(mac))
            if not hosts:
                has_unowned_mac = True
            else:
                owning_hostnames.update(h.hostname for h in hosts)
        if not has_unowned_mac and len(owning_hostnames) == 1:
            continue
        if _is_cross_sheet_mirror(macs, ip_str, mac_to_hosts):
            continue
        mac_list = ", ".join(f"{mac} ({name})" for mac, name in macs)
        result.add(ConstraintViolation(
            severity=Severity.ERROR,
            code="ip_multiple_macs",
            message=(
                f"Multiple MACs for non-roaming IP {ip_str}: {mac_list}"
            ),
            record_id=ip_str,
            field="ip",
        ))

    # Cross-host IP sharing (DNS-level, MAC-independent): the same IPv4 on
    # two different hosts is always a data error — this catches stale rows
    # (e.g. a replaced switch's old row keeping the new switch's address)
    # even when one side has no MAC and so dodges the DHCP-keyed checks.
    ip_to_hosts: dict[str, set[str]] = {}
    for host in inventory.hosts:
        for iface in host.interfaces:
            ip_to_hosts.setdefault(str(iface.ipv4), set()).add(host.hostname)
    for ip_str, hostnames in sorted(ip_to_hosts.items()):
        # Same roaming-range exemption as ip_multiple_macs above: pool
        # addresses legitimately move between devices.
        if roam_prefix and ip_str.startswith(roam_prefix):
            continue
        # Same cross-sheet-mirror carve-out as ip_multiple_macs: an IP
        # Allocation row and its wifi-tab formula row share one MAC+IP by
        # design. A MAC-less duplicate never qualifies (the predicate
        # requires the identical MAC on every colliding record), so the
        # stale-row cases this check exists for still error.
        if _is_cross_sheet_mirror(
            inventory.ip_to_macs.get(ip_str, []), ip_str, mac_to_hosts
        ):
            continue
        if len(hostnames) > 1:
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="ip_multiple_hosts",
                message=(
                    f"IP {ip_str} assigned to multiple hosts: "
                    f"{', '.join(sorted(hostnames))}"
                ),
                record_id=ip_str,
                field="ip",
            ))

    return result


def validate_vlan_consistency(
    records: list[DeviceRecord], site: Site
) -> ValidationResult:
    """Validate that the spreadsheet VLAN column matches the IP-derived VLAN.

    For each record with a 'VLAN' extra column, derives the expected VLAN
    from the IP address and checks for mismatches. Skips non-numeric VLAN
    values (e.g. 'N/A', 'Q', empty).
    """
    result = ValidationResult()

    for record in records:
        if not record.ip:
            continue

        vlan_str = record.extra.get("VLAN", "").strip()
        if not vlan_str:
            continue

        # Skip non-numeric VLAN values
        try:
            sheet_vlan = int(vlan_str)
        except ValueError:
            continue

        record_id = f"{record.sheet_name}:{record.row_number}"

        try:
            ipv4 = IPv4Address(record.ip)
        except ValueError:
            continue

        derived_vlan = ip_to_vlan_id(ipv4, site)
        if derived_vlan is not None and derived_vlan != sheet_vlan:
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="vlan_mismatch",
                message=(
                    f"VLAN mismatch: spreadsheet says VLAN {sheet_vlan}, "
                    f"IP {record.ip} maps to VLAN {derived_vlan} "
                    f"(machine={record.machine!r}, iface={record.interface!r})"
                ),
                record_id=record_id,
                field="VLAN",
            ))

    return result


def validate_all(
    records: list[DeviceRecord],
    hosts: list[Host],
    inventory: NetworkInventory,
) -> ValidationResult:
    """Run all constraints at the appropriate scope.

    Returns a combined ValidationResult with all violations.
    """
    combined = ValidationResult()

    for result in [
        validate_field_constraints(records),
        validate_ipv6_consistency(records, inventory.site),
        validate_vlan_consistency(records, inventory.site),
        validate_record_constraints(hosts, inventory.site),
        validate_cross_record_constraints(inventory),
    ]:
        for violation in result.violations:
            combined.add(violation)

    return combined
