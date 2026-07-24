"""DNS name derivations: hostname, DHCP name, common suffix, subdomain variants.

Includes five composable DNS name derivation passes:
  Pass 1 — Hostname: base hostname names ({hostname}.{domain}, {hostname})
  Pass 2 — Interface: per-interface names ({iface}.{hostname}.{domain}, ...)
  Pass 3 — Subdomain: subdomain variants ({hostname}.{subdomain}.{domain}, ...)
  Pass 4 — IPv4/IPv6 prefix: ipv4.{name}, ipv6.{name} for dual-stack names
  Pass 5 — Alt names: alternative FQDNs from the spreadsheet's Alt Names column
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import DNSName

if TYPE_CHECKING:
    from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.models.network import Site


# Sheet types whose hostnames get a subdomain suffix. compute_dhcp_name has
# a narrower map: Test-sheet hosts historically get NO dhcp suffix.
_HOSTNAME_SUFFIXES = {"IoT": ".iot", "Test": ".test", "WiFi": ".wifi"}
_DHCP_NAME_SUFFIXES = {"IoT": ".iot", "WiFi": ".wifi"}


def compute_hostname(machine_name: str, sheet_type: str) -> str:
    """Compute the hostname from a machine name and sheet type.

    IoT and WiFi devices get a '.iot'/'.wifi' suffix appended, and Test
    devices get '.test'. Network devices use the machine name directly
    (lowercased).

    >>> compute_hostname('thermostat', 'IoT')
    'thermostat.iot'
    >>> compute_hostname('puck04', 'WiFi')
    'puck04.wifi'
    >>> compute_hostname('Desktop', 'Network')
    'desktop'
    """
    hostname = machine_name.lower().strip()
    hostname += _HOSTNAME_SUFFIXES.get(sheet_type, "")
    return hostname


def compute_dhcp_name(machine_name: str, interface: str, sheet_type: str) -> str:
    """Compute the DHCP name from a machine name and interface.

    If an interface is specified, it's prepended with a dash separator.
    IoT and WiFi devices get a '.iot'/'.wifi' suffix. Unlike
    compute_hostname, Test-sheet hosts get NO dhcp suffix — this
    asymmetry is deliberate and preserved from the original behaviour.

    >>> compute_dhcp_name('desktop', 'eth0', 'Network')
    'eth0-desktop'
    >>> compute_dhcp_name('desktop', '', 'Network')
    'desktop'
    >>> compute_dhcp_name('thermostat', '', 'IoT')
    'thermostat.iot'
    >>> compute_dhcp_name('camera', 'eth0', 'IoT')
    'eth0-camera.iot'
    >>> compute_dhcp_name('puck04', 'wan', 'WiFi')
    'wan-puck04.wifi'
    >>> compute_dhcp_name('box', '', 'Test')
    'box'
    """
    dhcp_name = machine_name.lower().strip()
    if interface and interface.strip():
        dhcp_name = interface.lower().strip() + "-" + dhcp_name
    dhcp_name += _DHCP_NAME_SUFFIXES.get(sheet_type, "")
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
    )


def derive_dns_names_hostname(host: "Host", domain: str) -> list[DNSName]:
    """Pass 1 — Hostname: add base hostname DNS names.

    Adds:
      - {hostname}.{domain}  (FQDN)
      - {hostname}           (short name)

    Uses ALL interface IPv4 and IPv6 addresses so bare hostnames
    resolve to every IP (round-robin DNS for multi-homed hosts).
    """
    if not host.interfaces:
        return []

    # Collect all IPv4s and all IPv6s across every interface
    all_ipv4 = tuple(iface.ipv4 for iface in host.interfaces)
    all_ipv6: list["IPv6Address"] = []
    for iface in host.interfaces:
        all_ipv6.extend(iface.ipv6_addresses)

    return [
        _make_dns_name(
            f"{host.hostname}.{domain}",
            None,
            tuple(all_ipv6),
            is_fqdn=True,
            ipv4_addresses=all_ipv4,
        ),
        _make_dns_name(
            host.hostname,
            None,
            tuple(all_ipv6),
            is_fqdn=False,
            ipv4_addresses=all_ipv4,
        ),
    ]


def derive_dns_names_interface(host: "Host", domain: str) -> list[DNSName]:
    """Pass 2 — Interface: add per-interface DNS names.

    For each named interface, adds:
      - {iface}.{hostname}.{domain}  (FQDN)
      - {iface}.{hostname}           (short name)
    """
    names: list[DNSName] = []
    for iface in host.interfaces:
        if not iface.name:
            continue
        names.append(
            _make_dns_name(
                f"{iface.name}.{host.hostname}.{domain}",
                iface.ipv4,
                iface.ipv6_addresses,
                is_fqdn=True,
            )
        )
        names.append(
            _make_dns_name(
                f"{iface.name}.{host.hostname}",
                iface.ipv4,
                iface.ipv6_addresses,
                is_fqdn=False,
            )
        )
    return names


def derive_dns_names_subdomain(
    host: "Host", domain: str, site: "Site",
) -> list[DNSName]:
    """Pass 3 — Subdomain: add subdomain variants for existing FQDN names.

    For each existing FQDN name {x}.{domain}, adds:
      - {x}.{subdomain}.{domain}

    Uses ip_to_subdomain from vlan.py for subdomain lookup.
    Subdomain label is derived from the first IPv4; all IPs are propagated.
    """
    from gdoc2netcfg.derivations.vlan import ip_to_subdomain

    names: list[DNSName] = []
    for dns_name in list(host.dns_names):
        if not dns_name.is_fqdn:
            continue
        if dns_name.ipv4 is None:
            continue
        subdomain = ip_to_subdomain(dns_name.ipv4, site)
        if not subdomain:
            continue
        # Replace .{domain} with .{subdomain}.{domain}
        base = dns_name.name
        if base.endswith(f".{domain}"):
            prefix = base[: -len(f".{domain}")]
            new_name = f"{prefix}.{subdomain}.{domain}"
            names.append(
                _make_dns_name(
                    new_name,
                    dns_name.ipv4,
                    dns_name.ipv6_addresses,
                    is_fqdn=True,
                    ipv4_addresses=dns_name.ipv4_addresses or None,
                )
            )
    return names


def derive_dns_names_ip_prefix(host: "Host", domain: str) -> list[DNSName]:
    """Pass 4 — IPv4/IPv6 prefix: add ipv4.{name} and ipv6.{name} variants.

    Scans ALL existing FQDN names. Independently generates:
      - ipv4.{name}  whenever the name has any IPv4 addresses
      - ipv6.{name}  whenever the name has any IPv6 addresses

    This means single-stack hosts still get their prefix name, so
    tooling can consistently use ipv4.{host} or ipv6.{host} without
    needing to know the host's address families.
    """
    names: list[DNSName] = []
    for dns_name in list(host.dns_names):
        if not dns_name.is_fqdn:
            continue
        if dns_name.ipv4_addresses:
            names.append(
                _make_dns_name(
                    f"ipv4.{dns_name.name}",
                    None,
                    (),
                    is_fqdn=True,
                    ipv4_addresses=dns_name.ipv4_addresses,
                )
            )
        if dns_name.ipv6_addresses:
            names.append(
                _make_dns_name(
                    f"ipv6.{dns_name.name}",
                    None,
                    dns_name.ipv6_addresses,
                    is_fqdn=True,
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

    # Collect all IPv4s and all IPv6s across every interface
    all_ipv4 = tuple(iface.ipv4 for iface in host.interfaces)
    all_ipv6: list["IPv6Address"] = []
    for iface in host.interfaces:
        all_ipv6.extend(iface.ipv6_addresses)

    names: list[DNSName] = []
    for alt_name in host.alt_names:
        names.append(
            _make_dns_name(
                alt_name,
                None,
                tuple(all_ipv6),
                is_fqdn=True,
                ipv4_addresses=all_ipv4,
            )
        )
    return names


def derive_all_dns_names(host: "Host", site: "Site") -> None:
    """Run all five DNS name derivation passes on a host (in-place).

    Order matters: Pass 4 must run after Passes 1-3 since it scans
    all names from previous passes. Pass 5 runs independently.
    """
    domain = site.domain

    # Pass 1 — Hostname
    host.dns_names = derive_dns_names_hostname(host, domain)

    # Pass 2 — Interface
    host.dns_names.extend(derive_dns_names_interface(host, domain))

    # Pass 3 — Subdomain
    host.dns_names.extend(derive_dns_names_subdomain(host, domain, site))

    # Pass 4 — IPv4/IPv6 prefix
    host.dns_names.extend(derive_dns_names_ip_prefix(host, domain))

    # Pass 5 — Alt names
    host.dns_names.extend(derive_dns_names_alt_names(host))
