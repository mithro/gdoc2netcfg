"""PowerDNS internal-auth zone file generator (dns-redesign §7).

Emits bind-format zone files for the central internal auth instance
(pdns@internal, bind backend):

- {domain}.zone            — the internal site zone: SOA/NS, insecure NS
                             delegations + glue for every child net zone
                             (load-bearing: without them the projection
                             CNAMEs answer NXDOMAIN and, once signed,
                             validating resolvers reject the leaves —
                             verified in the V1/V2 prototypes), site-native
                             aggregates, CNAME projections, SSHFP/CAA at
                             site natives, optional $INCLUDE for extras.
- wg.{domain}.zone         — the wg transit zone (all tunnels).
- {transit}.{domain}.zone  — per transit VLAN (tfpgas).
- reverse zones            — v4 (/16 for wg, /24 per transit) + v6 /64
                             slices for the central-served nets.
- bind-internal.conf       — zone{} statements for all of the above.

Zone files use absolute owner names and epoch serials (SOA serial-0 ≠
file mtime on pdns 5.1 — verification V5/G4); the deploy step is
checksum-gated so serials only take effect when content changes.
"""

from __future__ import annotations

import ipaddress
import time

from gdoc2netcfg.derivations.vlan import (
    DELEGATED_NETS,
    PARKED_THIRD_OCTETS,
    ip_to_net,
)
from gdoc2netcfg.generators.dnsmasq_common import (
    _ipv4_to_ptr,
    _ipv6_to_ptr,
    _most_specific_fqdn,
)
from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.models.network import Site

# DNS servers for nets whose zones are delegated elsewhere (design §4:
# fpgas → tweed's dnsmasq at eth-local).
# TODO(sheet): drive from a VLAN-Allocations column if one appears.
DELEGATED_NET_SERVERS = {"fpgas": "10.21.0.1"}

# The site router whose per-net interfaces provide delegation glue.
ROUTER_HOSTNAME = "ten64"

RECORD_TTL = 300
ZONE_TTL = 3600


def _central_nets(site: Site) -> frozenset[str]:
    """Nets served by the central auth itself: wg + transit VLANs."""
    central = {"wg"}
    for vlan in site.vlans.values():
        if vlan.is_transit:
            central.add(vlan.subdomain)
    return frozenset(central)


def _soa_and_ns(zone: str, domain: str, serial: int) -> list[str]:
    primary = f"{ROUTER_HOSTNAME}.{domain}."
    return [
        f"{zone}. {ZONE_TTL} IN SOA {primary} hostmaster.mithis.com. "
        f"{serial} 10800 3600 604800 300",
        f"{zone}. {ZONE_TTL} IN NS {primary}",
    ]


def _address_lines(name: str, dns_name) -> list[str]:
    """A/AAAA lines for a native DNSName, addresses deduplicated in order."""
    lines: list[str] = []
    seen: set[str] = set()
    for addr in dns_name.ipv4_addresses:
        s = str(addr)
        if s not in seen:
            seen.add(s)
            lines.append(f"{name}. {RECORD_TTL} IN A {s}")
    for addr in dns_name.ipv6_addresses:
        s = str(addr)
        if s not in seen:
            seen.add(s)
            lines.append(f"{name}. {RECORD_TTL} IN AAAA {s}")
    return lines


def _sshfp_lines(name: str, host: Host) -> list[str]:
    lines: list[str] = []
    for line in host.sshfp_records:
        if line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 6:
            _, _, _, alg, fptype, fp = parts[:6]
            lines.append(f"{name}. {RECORD_TTL} IN SSHFP {alg} {fptype} {fp}")
    return lines


def generate_pdns_internal(
    inventory: NetworkInventory,
    serial: int | None = None,
    zones_dir: str = "/etc/powerdns/zones-internal",
    site_extra_include: str | None = None,
) -> dict[str, str]:
    """Generate the internal pdns auth zone files + bind config.

    Returns a dict mapping "{zonename}.zone" (and "bind-internal.conf")
    to file content.
    """
    if serial is None:
        serial = int(time.time())

    site = inventory.site
    domain = site.domain
    central = _central_nets(site)

    files: dict[str, str] = {}
    files[f"{domain}.zone"] = _site_zone(
        inventory, serial, central, site_extra_include
    )

    for net in sorted(central):
        content = _central_net_zone(inventory, net, serial)
        if content is not None:
            files[f"{net}.{domain}.zone"] = content

    files.update(_central_reverse_zones(inventory, central, serial))
    files.update(_catchall_reverse_zones(inventory, serial))

    zone_names = sorted(f[: -len(".zone")] for f in files)
    files["bind-internal.conf"] = "".join(
        f'zone "{z}" {{ type primary; file "{zones_dir}/{z}.zone"; }};\n'
        for z in zone_names
    )
    return files


def _data_nets(inventory: NetworkInventory) -> list[str]:
    """All nets present in the inventory, sorted."""
    nets: set[str] = set()
    for host in inventory.hosts:
        for iface in host.interfaces:
            net = ip_to_net(iface.ipv4, inventory.site)
            if net is not None:
                nets.add(net)
    return sorted(nets)


def _router_net_addresses(
    inventory: NetworkInventory,
) -> dict[str, tuple[list[str], list[str]]]:
    """The router's per-net gateway addresses: net → ([v4...], [v6...])."""
    router = inventory.host_by_hostname(ROUTER_HOSTNAME)
    gateways: dict[str, tuple[list[str], list[str]]] = {}
    if router is None:
        return gateways
    for iface in router.interfaces:
        net = ip_to_net(iface.ipv4, inventory.site)
        if net is None:
            continue
        v4s, v6s = gateways.setdefault(net, ([], []))
        v4s.append(str(iface.ipv4))
        v6s.extend(str(a) for a in iface.ipv6_addresses)
    return gateways


def _site_zone(
    inventory: NetworkInventory,
    serial: int,
    central: frozenset[str],
    site_extra_include: str | None,
) -> str:
    site = inventory.site
    domain = site.domain
    primary = f"{ROUTER_HOSTNAME}.{domain}."

    lines = _soa_and_ns(domain, domain, serial)

    # --- Insecure delegations (NS + glue, deliberately NO DS) -------------
    lines.append("")
    lines.append("; child zone delegations — insecure (NS, no DS) by design:")
    lines.append("; leaves are dnsmasq (cannot sign); missing delegations make")
    lines.append("; projections NXDOMAIN and leaf answers bogus under validation")
    gateways = _router_net_addresses(inventory)
    missing_gateways: list[str] = []
    for net in _data_nets(inventory):
        if net in central:
            # served by this same auth instance — delegate to the site NS
            lines.append(f"{net}.{domain}. {RECORD_TTL} IN NS {primary}")
            continue
        if net in DELEGATED_NETS:
            server = DELEGATED_NET_SERVERS[net]
            lines.append(f"{net}.{domain}. {RECORD_TTL} IN NS gw.{net}.{domain}.")
            lines.append(f"gw.{net}.{domain}. {RECORD_TTL} IN A {server}")
            continue
        if net not in gateways:
            missing_gateways.append(net)
            continue
        v4s, v6s = gateways[net]
        lines.append(f"{net}.{domain}. {RECORD_TTL} IN NS gw.{net}.{domain}.")
        for v4 in v4s:
            lines.append(f"gw.{net}.{domain}. {RECORD_TTL} IN A {v4}")
        for v6 in v6s:
            lines.append(f"gw.{net}.{domain}. {RECORD_TTL} IN AAAA {v6}")

    if missing_gateways:
        raise ValueError(
            f"nets with hosts but no {ROUTER_HOSTNAME} gateway interface "
            f"(cannot emit delegation): {missing_gateways}"
        )

    # --- Site-scoped records ----------------------------------------------
    for host in inventory.hosts_sorted():
        host_lines: list[str] = []
        has_site_native = False
        for dns_name in host.dns_names:
            if not dns_name.is_fqdn or dns_name.scope != "site":
                continue
            if not dns_name.name.endswith(f".{domain}"):
                continue  # alt names outside the zone live elsewhere
            if dns_name.kind == "cname":
                host_lines.append(
                    f"{dns_name.name}. {RECORD_TTL} IN CNAME {dns_name.cname_target}."
                )
            else:
                host_lines.extend(_address_lines(dns_name.name, dns_name))
                has_site_native = True

        if has_site_native:
            site_name = f"{host.hostname}.{domain}"
            host_lines.append(
                f'{site_name}. {RECORD_TTL} IN CAA 0 issue "letsencrypt.org"'
            )
            host_lines.extend(_sshfp_lines(site_name, host))

        if host_lines:
            lines.append("")
            lines.append(f"; {host.hostname}")
            lines.extend(host_lines)

    if site_extra_include:
        lines.append("")
        lines.append("; hand-maintained site records (apt-proxy, smtp, ...)")
        lines.append(f"$INCLUDE {site_extra_include}")

    return "\n".join(lines) + "\n"


def _central_net_zone(
    inventory: NetworkInventory, net: str, serial: int,
) -> str | None:
    """Zone file for a central-served net (wg, tfpgas); None if empty."""
    domain = inventory.site.domain
    zone = f"{net}.{domain}"

    record_lines: list[str] = []
    for host in inventory.hosts_sorted():
        for dns_name in host.dns_names:
            if dns_name.scope != "net" or dns_name.net != net:
                continue
            record_lines.extend(_address_lines(dns_name.name, dns_name))

    if not record_lines:
        return None

    lines = _soa_and_ns(zone, domain, serial)
    lines.append("")
    lines.extend(record_lines)
    return "\n".join(lines) + "\n"


def _catchall_reverse_zones(
    inventory: NetworkInventory, serial: int,
) -> dict[str, str]:
    """Catch-all reverse zones for site-octet addresses on NO known net
    (100G backbone 10.1.16.x, 10.1.21, 10.1.110 gadgets, …): a v4
    {site_octet}.10.in-addr.arpa zone and a v6 /48 zone at the central
    auth. Leaf slices are more specific and win in the recursor's
    forward-zones routing, so these only answer for the leftovers.
    """
    site = inventory.site
    domain = site.domain

    v4_zone = f"{site.site_octet}.10.in-addr.arpa"
    prefix = site.active_ipv6_prefixes[0].prefix if site.active_ipv6_prefixes else None
    v6_zone = None
    if prefix:
        prefix_nibbles = "".join(
            part.zfill(4) for part in prefix.rstrip(":").split(":")
        )
        v6_zone = ".".join(reversed(prefix_nibbles)) + ".ip6.arpa"

    zones: dict[str, list[str]] = {}
    for host in inventory.hosts_sorted():
        for iface in host.interfaces:
            a, b, c, d = iface.ipv4.octets
            if a != 10:
                continue
            net = ip_to_net(iface.ipv4, site)

            site_octet_no_net = (
                b == site.site_octet
                and c not in PARKED_THIRD_OCTETS
                and net is None
            )
            # Delegated-net addresses (10.21.x fpgas): tweed owns the v4
            # reverse (21.10.in-addr.arpa) but not the vanity-mapped v6
            # slices — their v6 PTRs stay central.
            delegated = net in DELEGATED_NETS
            if not (site_octet_no_net or delegated):
                continue

            ip = str(iface.ipv4)
            if site_octet_no_net:
                fqdn = _most_specific_fqdn(host, ip, domain, is_ipv6=False)
                if fqdn:
                    zones.setdefault(v4_zone, []).append(
                        f"{_ipv4_to_ptr(ip)}. {RECORD_TTL} IN PTR {fqdn}."
                    )
            if v6_zone is None:
                continue
            for ipv6_addr in iface.ipv6_addresses:
                ipv6_str = str(ipv6_addr)
                ipv6_fqdn = _most_specific_fqdn(host, ipv6_str, domain, is_ipv6=True)
                if ipv6_fqdn:
                    zones.setdefault(v6_zone, []).append(
                        f"{_ipv6_to_ptr(ipv6_str)}. {RECORD_TTL} IN PTR {ipv6_fqdn}."
                    )

    files: dict[str, str] = {}
    for zone, ptr_lines in sorted(zones.items()):
        lines = _soa_and_ns(zone, domain, serial)
        lines.append("")
        lines.extend(ptr_lines)
        files[f"{zone}.zone"] = "\n".join(lines) + "\n"
    return files


def _v4_reverse_zone_name(ip: str, site: Site) -> str | None:
    """The central reverse zone owning an IPv4 address: /16 for wg
    (98.10.in-addr.arpa, 255.10.in-addr.arpa), /24 per transit VLAN
    (21.99.10.in-addr.arpa)."""
    ipv4 = ipaddress.IPv4Address(ip)
    a, b, c, d = str(ipv4).split(".")
    net = ip_to_net_from_str(ip, site)
    if net == "wg":
        return f"{b}.{a}.in-addr.arpa"
    for vlan in site.vlans.values():
        if vlan.is_transit and vlan.subdomain == net:
            return f"{c}.{b}.{a}.in-addr.arpa"
    return None


def ip_to_net_from_str(ip: str, site: Site):
    from gdoc2netcfg.models.addressing import IPv4Address

    return ip_to_net(IPv4Address(ip), site)


def _v6_reverse_zone_name(ipv6_str: str) -> str:
    """The /64 reverse zone for an IPv6 address."""
    addr = ipaddress.IPv6Address(ipv6_str)
    prefix_nibbles = addr.exploded.replace(":", "")[:16]
    return ".".join(reversed(prefix_nibbles)) + ".ip6.arpa"


def _central_reverse_zones(
    inventory: NetworkInventory, central: frozenset[str], serial: int,
) -> dict[str, str]:
    """Reverse zone files for the central-served nets' addresses."""
    site = inventory.site
    domain = site.domain

    # zone name → list of PTR lines
    zones: dict[str, list[str]] = {}

    for host in inventory.hosts_sorted():
        for iface in host.interfaces:
            net = ip_to_net(iface.ipv4, site)
            if net not in central:
                continue

            ip = str(iface.ipv4)
            fqdn = _most_specific_fqdn(host, ip, domain, is_ipv6=False)
            zone = _v4_reverse_zone_name(ip, site)
            if fqdn and zone:
                zones.setdefault(zone, []).append(
                    f"{_ipv4_to_ptr(ip)}. {RECORD_TTL} IN PTR {fqdn}."
                )

            for ipv6_addr in iface.ipv6_addresses:
                ipv6_str = str(ipv6_addr)
                ipv6_fqdn = _most_specific_fqdn(
                    host, ipv6_str, domain, is_ipv6=True
                )
                if ipv6_fqdn:
                    zone6 = _v6_reverse_zone_name(ipv6_str)
                    zones.setdefault(zone6, []).append(
                        f"{_ipv6_to_ptr(ipv6_str)}. {RECORD_TTL} IN PTR {ipv6_fqdn}."
                    )

    files: dict[str, str] = {}
    for zone, ptr_lines in sorted(zones.items()):
        lines = _soa_and_ns(zone, domain, serial)
        lines.append("")
        lines.extend(ptr_lines)
        files[f"{zone}.zone"] = "\n".join(lines) + "\n"
    return files
