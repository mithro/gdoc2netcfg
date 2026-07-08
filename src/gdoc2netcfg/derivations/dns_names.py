"""DNS name derivations: hostname, DHCP name, common suffix, name grammar.

Implements the three-scope name grammar (dns-redesign design §3) as five
composable passes:

  Pass 1 — Site aggregate: {hostname}.{domain} (union of the host's
           addresses, honoring aggregate_override) + short {hostname}
  Pass 2 — Interfaces: net natives {iface}.{hostname}.{net}.{domain} +
           site CNAME projections {iface}.{hostname}.{domain} → net form
           + short {iface}.{hostname}
  Pass 3 — Per-net host names: net natives {hostname}.{net}.{domain}
           carrying ONLY that net's addresses + site CNAME projections
           {net}.{hostname}.{domain} → net form
  Pass 4 — IPv4/IPv6 prefix: ipv4./ipv6. variants of every FQDN —
           family-filtered natives for natives, prefix CNAMEs for CNAMEs
  Pass 5 — Alt names: site natives from the spreadsheet's Alt Names column

Parked interfaces (a site-octet address on no known network, e.g. ten64's
10.1.253/254 NICs) produce no records at all and are excluded from
aggregates. Interfaces with no net home that are NOT parked (public WAN,
tailscale CGNAT) keep a site-scoped native interface record — they have
no net zone to be projected into.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import DNSName

if TYPE_CHECKING:
    from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address
    from gdoc2netcfg.models.host import Host, NetworkInterface
    from gdoc2netcfg.models.network import Site


def compute_hostname(machine_name: str, sheet_type: str) -> str:
    """Compute the hostname from a machine name and sheet type.

    IoT devices get a '.iot' suffix appended. Network devices use the
    machine name directly (lowercased).

    >>> compute_hostname('thermostat', 'IoT')
    'thermostat.iot'
    >>> compute_hostname('Desktop', 'Network')
    'desktop'
    """
    hostname = machine_name.lower().strip()
    if sheet_type == "IoT":
        hostname += ".iot"
    elif sheet_type == "Test":
        hostname += ".test"
    return hostname


def compute_dhcp_name(machine_name: str, interface: str, sheet_type: str) -> str:
    """Compute the DHCP name from a machine name and interface.

    If an interface is specified, it's prepended with a dash separator.
    IoT devices get a '.iot' suffix.

    >>> compute_dhcp_name('desktop', 'eth0', 'Network')
    'eth0-desktop'
    >>> compute_dhcp_name('desktop', '', 'Network')
    'desktop'
    >>> compute_dhcp_name('thermostat', '', 'IoT')
    'thermostat.iot'
    >>> compute_dhcp_name('camera', 'eth0', 'IoT')
    'eth0-camera.iot'
    """
    dhcp_name = machine_name.lower().strip()
    if interface and interface.strip():
        dhcp_name = interface.lower().strip() + "-" + dhcp_name
    if sheet_type == "IoT":
        dhcp_name += ".iot"
    return dhcp_name


def common_suffix(a: str, *others: str) -> str:
    """Find the longest common suffix of two or more strings.

    Used to determine the canonical hostname when multiple interfaces
    share a machine. For example, eth1.ten64 and eth2.ten64 → ten64.

    >>> common_suffix('a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'b')
    ''
    >>> common_suffix('aa', 'a')
    'a'
    >>> common_suffix('ab', 'a')
    ''
    >>> common_suffix('aba', 'aa')
    'a'
    >>> common_suffix('abca', 'aca')
    'ca'
    >>> common_suffix('abca')
    'abca'
    """
    if not others:
        return a

    lengths = [len(b) for b in others]
    lengths.append(len(a))
    min_len = min(lengths)

    i = 1
    while i < (min_len + 1):
        if not all(a[-i:] == b[-i:] for b in others):
            break
        i += 1
    i -= 1

    if i == 0:
        return ""
    return a[-i:]


# ---------------------------------------------------------------------------
# DNS name derivation passes
# ---------------------------------------------------------------------------

def _make_dns_name(
    name: str,
    ipv4: "IPv4Address | None",
    ipv6_addresses: "tuple[IPv6Address, ...] | list[IPv6Address]",
    is_fqdn: bool,
    *,
    ipv4_addresses: "tuple[IPv4Address, ...] | None" = None,
    scope: str = "site",
    kind: str = "native",
    cname_target: str | None = None,
    net: str | None = None,
) -> DNSName:
    """Create a DNSName with unified ip_addresses tuple.

    When ipv4_addresses is provided, it takes precedence over the
    single ipv4 parameter — used for multi-homed hosts where bare
    hostnames resolve to ALL interface IPs.
    """
    ips: list["IPv4Address | IPv6Address"] = []
    if ipv4_addresses is not None:
        ips.extend(ipv4_addresses)
    elif ipv4 is not None:
        ips.append(ipv4)
    ips.extend(ipv6_addresses)
    return DNSName(
        name=name,
        ip_addresses=tuple(ips),
        is_fqdn=is_fqdn,
        scope=scope,
        kind=kind,
        cname_target=cname_target,
        net=net,
    )


def _is_parked(iface: "NetworkInterface", site: "Site") -> bool:
    """A parked interface holds a site-octet address on no known network
    (e.g. ten64's 10.1.253/254 NICs). Parked interfaces produce no DNS
    records at all (design §3 'removed families')."""
    a, b, c, d = iface.ipv4.octets
    return a == 10 and b == site.site_octet and site.network_subdomains.get(c) is None


def _aggregate_interfaces(host: "Host", site: "Site") -> "list[NetworkInterface]":
    """Interfaces whose addresses form the host's site-level aggregate.

    aggregate_override (the 'Aggregate' sheet column) selects interfaces
    by name when present; otherwise: every interface except parked ones.
    An override matching no interfaces falls back to the default rule
    (closest behavior to 'no override'; the diff harness surfaces typos).
    """
    if host.aggregate_override:
        wanted = set(host.aggregate_override)
        selected = [i for i in host.interfaces if i.name in wanted]
        if selected:
            return selected
    return [i for i in host.interfaces if not _is_parked(i, site)]


def _union_addresses(
    interfaces: "list[NetworkInterface]",
) -> "tuple[tuple[IPv4Address, ...], tuple[IPv6Address, ...]]":
    all_ipv4 = tuple(iface.ipv4 for iface in interfaces)
    all_ipv6: list["IPv6Address"] = []
    for iface in interfaces:
        all_ipv6.extend(iface.ipv6_addresses)
    return all_ipv4, tuple(all_ipv6)


def derive_dns_names_hostname(
    host: "Host", domain: str, site: "Site",
) -> list[DNSName]:
    """Pass 1 — Site aggregate: base hostname DNS names.

    Adds:
      - {hostname}.{domain}  (FQDN, scope=site) — union of the host's
        aggregate addresses (aggregate_override or all-non-parked)
      - {hostname}           (short name, scope=short)
    """
    if not host.interfaces:
        return []

    agg_ifaces = _aggregate_interfaces(host, site)
    if not agg_ifaces:
        return []
    all_ipv4, all_ipv6 = _union_addresses(agg_ifaces)

    return [
        _make_dns_name(
            f"{host.hostname}.{domain}",
            None,
            all_ipv6,
            is_fqdn=True,
            ipv4_addresses=all_ipv4,
            scope="site",
        ),
        _make_dns_name(
            host.hostname,
            None,
            all_ipv6,
            is_fqdn=False,
            ipv4_addresses=all_ipv4,
            scope="short",
        ),
    ]


def derive_dns_names_interface(
    host: "Host", domain: str, site: "Site",
) -> list[DNSName]:
    """Pass 2 — Interfaces: net natives + site CNAME projections.

    For each named, non-parked interface on a known net N:
      - {iface}.{hostname}.{N}.{domain}  (native, scope=net)
      - {iface}.{hostname}.{domain}      (CNAME → net form, scope=site)
      - {iface}.{hostname}               (short name)

    Named interfaces with no net home that are NOT parked (public WAN,
    tailscale) keep a site-scoped native record — there is no net zone
    to project them into.
    """
    from gdoc2netcfg.derivations.vlan import ip_to_net

    names: list[DNSName] = []
    for iface in host.interfaces:
        if not iface.name:
            continue
        if _is_parked(iface, site):
            continue

        net = ip_to_net(iface.ipv4, site)
        if net is None:
            # No net home (WAN, tailscale): site-scoped native fallback.
            names.append(
                _make_dns_name(
                    f"{iface.name}.{host.hostname}.{domain}",
                    iface.ipv4,
                    iface.ipv6_addresses,
                    is_fqdn=True,
                    scope="site",
                )
            )
        else:
            # Site projection emitted BEFORE the net native: consumers that
            # label things after the first matching interface FQDN (nginx
            # upstreams) keep today's site-form labels.
            net_name = f"{iface.name}.{host.hostname}.{net}.{domain}"
            names.append(
                _make_dns_name(
                    f"{iface.name}.{host.hostname}.{domain}",
                    iface.ipv4,
                    iface.ipv6_addresses,
                    is_fqdn=True,
                    scope="site",
                    kind="cname",
                    cname_target=net_name,
                )
            )
            names.append(
                _make_dns_name(
                    net_name,
                    iface.ipv4,
                    iface.ipv6_addresses,
                    is_fqdn=True,
                    scope="net",
                    net=net,
                )
            )
        names.append(
            _make_dns_name(
                f"{iface.name}.{host.hostname}",
                iface.ipv4,
                iface.ipv6_addresses,
                is_fqdn=False,
                scope="short",
            )
        )
    return names


def derive_dns_names_subdomain(
    host: "Host", domain: str, site: "Site",
) -> list[DNSName]:
    """Pass 3 — Per-net host names: net natives + site CNAME projections.

    Groups the host's non-parked interfaces by net N and, per net, adds:
      - {hostname}.{N}.{domain}  (native, scope=net) with ONLY that net's
        addresses — this fixes the live defect where multi-net hosts'
        net-scoped names served ALL their addresses
      - {N}.{hostname}.{domain}  (CNAME → net form, scope=site)
    """
    from gdoc2netcfg.derivations.vlan import ip_to_net

    by_net: dict[str, list["NetworkInterface"]] = {}
    for iface in host.interfaces:
        if _is_parked(iface, site):
            continue
        net = ip_to_net(iface.ipv4, site)
        if net is None:
            continue
        by_net.setdefault(net, []).append(iface)

    names: list[DNSName] = []
    for net, ifaces in by_net.items():
        net_ipv4, net_ipv6 = _union_addresses(ifaces)
        net_name = f"{host.hostname}.{net}.{domain}"
        names.append(
            _make_dns_name(
                net_name,
                None,
                net_ipv6,
                is_fqdn=True,
                ipv4_addresses=net_ipv4,
                scope="net",
                net=net,
            )
        )
        names.append(
            _make_dns_name(
                f"{net}.{host.hostname}.{domain}",
                None,
                net_ipv6,
                is_fqdn=True,
                ipv4_addresses=net_ipv4,
                scope="site",
                kind="cname",
                cname_target=net_name,
            )
        )
    return names


def derive_dns_names_ip_prefix(host: "Host", domain: str) -> list[DNSName]:
    """Pass 4 — IPv4/IPv6 prefix: add ipv4.{name} and ipv6.{name} variants.

    Scans ALL existing FQDN names. For natives, independently generates
    family-filtered native variants (single-stack hosts still get their
    prefix name). For CNAMEs, generates prefix CNAMEs to the target's
    prefix form ({P.}alias → {P.}target), only for address families the
    underlying interface actually has.
    """
    names: list[DNSName] = []
    for dns_name in list(host.dns_names):
        if not dns_name.is_fqdn:
            continue

        if dns_name.kind == "cname":
            assert dns_name.cname_target is not None
            if dns_name.ipv4_addresses:
                names.append(
                    _make_dns_name(
                        f"ipv4.{dns_name.name}",
                        None,
                        (),
                        is_fqdn=True,
                        ipv4_addresses=dns_name.ipv4_addresses,
                        scope=dns_name.scope,
                        kind="cname",
                        cname_target=f"ipv4.{dns_name.cname_target}",
                    )
                )
            if dns_name.ipv6_addresses:
                names.append(
                    _make_dns_name(
                        f"ipv6.{dns_name.name}",
                        None,
                        dns_name.ipv6_addresses,
                        is_fqdn=True,
                        scope=dns_name.scope,
                        kind="cname",
                        cname_target=f"ipv6.{dns_name.cname_target}",
                    )
                )
            continue

        if dns_name.ipv4_addresses:
            names.append(
                _make_dns_name(
                    f"ipv4.{dns_name.name}",
                    None,
                    (),
                    is_fqdn=True,
                    ipv4_addresses=dns_name.ipv4_addresses,
                    scope=dns_name.scope,
                    net=dns_name.net,
                )
            )
        if dns_name.ipv6_addresses:
            names.append(
                _make_dns_name(
                    f"ipv6.{dns_name.name}",
                    None,
                    dns_name.ipv6_addresses,
                    is_fqdn=True,
                    scope=dns_name.scope,
                    net=dns_name.net,
                )
            )
    return names


def derive_dns_names_alt_names(host: "Host") -> list[DNSName]:
    """Pass 5 — Alt names: add DNS names from the spreadsheet's Alt Names column.

    Each alt name is treated as a FQDN pointing to ALL interface IPs,
    matching the same treatment as Pass 1 (bare hostname).
    """
    if not host.alt_names or not host.interfaces:
        return []

    all_ipv4, all_ipv6 = _union_addresses(host.interfaces)

    names: list[DNSName] = []
    for alt_name in host.alt_names:
        names.append(
            _make_dns_name(
                alt_name,
                None,
                all_ipv6,
                is_fqdn=True,
                ipv4_addresses=all_ipv4,
                scope="site",
            )
        )
    return names


def derive_all_dns_names(host: "Host", site: "Site") -> None:
    """Run all five DNS name derivation passes on a host (in-place).

    Order matters: Pass 4 must run after Passes 1-3 since it scans
    all names from previous passes. Pass 5 runs independently.
    """
    domain = site.domain

    # Pass 1 — Site aggregate + short name
    host.dns_names = derive_dns_names_hostname(host, domain, site)

    # Pass 2 — Interface net natives + projections
    host.dns_names.extend(derive_dns_names_interface(host, domain, site))

    # Pass 3 — Per-net host natives + projections
    host.dns_names.extend(derive_dns_names_subdomain(host, domain, site))

    # Pass 4 — IPv4/IPv6 prefixes
    host.dns_names.extend(derive_dns_names_ip_prefix(host, domain))

    # Pass 5 — Alt names
    host.dns_names.extend(derive_dns_names_alt_names(host))
