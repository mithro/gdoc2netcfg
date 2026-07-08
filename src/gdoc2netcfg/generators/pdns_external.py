"""PowerDNS external-auth zone file generator (dns-redesign §7).

Emits the PUBLIC view of the site zone for the pdns@external instance
(bind backend): one flat zone containing every in-domain name (site and
net scoped alike) as native records, with RFC 1918 IPv4 addresses
replaced by the site's public address and global IPv6 published as-is.

No CNAME projections and no child-zone delegations — the leaves aren't
publicly reachable, so the public view stays flat exactly like today's
dnsmasq external instance. NS records name the Rollernet secondaries
(verification V4: they are the public face of welland.mithis.com;
ten64's external auth is a hidden primary they AXFR from).

Deliberately NOT carried over from the dnsmasq external config (flagged
for the diff review): internal 10.x reverse zones served publicly, and
SSHFP copies at interface/PTR names (the enforceable SSHFP lives at the
signed site native).
"""

from __future__ import annotations

import time

from gdoc2netcfg.generators.pdns_zones import (
    RECORD_TTL,
    ZONE_TTL,
    _sshfp_lines,
)
from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.utils.ip import is_rfc1918

PUBLIC_NS = ("ns1.rollernet.us.", "ns2.rollernet.us.")


def generate_pdns_external(
    inventory: NetworkInventory,
    serial: int | None = None,
    zones_dir: str = "/etc/powerdns/zones-external",
    site_extra_include: str | None = None,
    public_ipv4: str | None = None,
) -> dict[str, str]:
    """Generate the external pdns auth zone file + bind config.

    Returns a dict with "{domain}.zone" and "bind-external.conf", or an
    empty dict when the site has no public IPv4 configured.
    """
    public_ip = public_ipv4 or inventory.site.public_ipv4
    if not public_ip:
        return {}

    if serial is None:
        serial = int(time.time())

    domain = inventory.site.domain

    lines = [
        f"{domain}. {ZONE_TTL} IN SOA {domain}. hostmaster.mithis.com. "
        f"{serial} 10800 3600 604800 300",
    ]
    for ns in PUBLIC_NS:
        lines.append(f"{domain}. {ZONE_TTL} IN NS {ns}")

    for host in inventory.hosts_sorted():
        host_lines = _host_public_lines(host, domain, public_ip)
        if host_lines:
            lines.append("")
            lines.append(f"; {host.hostname}")
            lines.extend(host_lines)

    if site_extra_include:
        lines.append("")
        lines.append("; hand-maintained public records (ACME, apt-proxy, ...)")
        lines.append(f"$INCLUDE {site_extra_include}")

    files = {f"{domain}.zone": "\n".join(lines) + "\n"}
    files["bind-external.conf"] = (
        f'zone "{domain}" {{ type primary; '
        f'file "{zones_dir}/{domain}.zone"; }};\n'
    )
    return files


def _host_public_lines(host: Host, domain: str, public_ip: str) -> list[str]:
    lines: list[str] = []
    has_site_native = False

    for dns_name in host.dns_names:
        if not dns_name.is_fqdn:
            continue
        if not (dns_name.name == domain or dns_name.name.endswith(f".{domain}")):
            continue

        # Flat public view: every name (native or projection) becomes a
        # native record set with the public transform applied.
        addr_lines: list[str] = []
        seen: set[str] = set()
        for addr in dns_name.ipv4_addresses:
            public = public_ip if is_rfc1918(str(addr)) else str(addr)
            if public not in seen:
                seen.add(public)
                addr_lines.append(f"{dns_name.name}. {RECORD_TTL} IN A {public}")
        for addr in dns_name.ipv6_addresses:
            s = str(addr)
            if s not in seen:
                seen.add(s)
                addr_lines.append(f"{dns_name.name}. {RECORD_TTL} IN AAAA {s}")

        if addr_lines:
            lines.extend(addr_lines)
            if dns_name.scope == "site" and dns_name.kind == "native":
                has_site_native = True

    if has_site_native:
        site_name = f"{host.hostname}.{domain}"
        lines.append(
            f'{site_name}. {RECORD_TTL} IN CAA 0 issue "letsencrypt.org"'
        )
        lines.extend(_sshfp_lines(site_name, host))

    return lines
