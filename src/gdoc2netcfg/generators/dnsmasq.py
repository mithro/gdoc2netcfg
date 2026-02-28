"""Dnsmasq internal configuration generator.

Produces per-host dnsmasq config files, each containing:
- DHCP host bindings (dhcp-host)
- Reverse DNS PTR records (ptr-record) for IPv4 and IPv6
- Forward DNS records (host-record) with dual-stack IPv6
- SSHFP records (dns-rr type 44)
- CAA records (dns-rr type 257)

The DNS record sections (PTR, host-record, CAA, SSHFP) use the shared
code path in dnsmasq_common with an identity IPv4 transform. DHCP
bindings are the only internal-only section.
"""

from __future__ import annotations

from gdoc2netcfg.derivations.dns_names import common_suffix
from gdoc2netcfg.generators.dnsmasq_common import (
    _ipv6_for_ip,
    identity_ipv4,
    sections_to_text,
    shared_dns_sections,
)
from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.utils.ip import ip_sort_key


def generate_dnsmasq_internal(inventory: NetworkInventory) -> dict[str, str]:
    """Generate internal dnsmasq configuration as per-host files.

    Returns a dict mapping "{hostname}.conf" to config content.
    """
    files: dict[str, str] = {}
    for host in inventory.hosts_sorted():
        content = _generate_host_internal(host, inventory)
        if content:
            files[f"{host.hostname}.conf"] = content
    return files


def _generate_host_internal(host: Host, inventory: NetworkInventory) -> str:
    """Generate all dnsmasq config sections for a single host."""
    sections = [
        _host_dhcp_config(host, inventory),
    ] + shared_dns_sections(host, inventory, identity_ipv4)
    return sections_to_text(sections)


def _host_dhcp_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate dhcp-host entries for a single host."""
    if not host.interfaces:
        return []

    output: list[str] = []
    output.append(f"# {host.hostname} — DHCP")
    for vi in sorted(host.virtual_interfaces, key=lambda v: ip_sort_key(str(v.ipv4))):
        ip = str(vi.ipv4)
        dhcp_name = common_suffix(*set(vi.dhcp_names)).strip("-")

        # Skip IPv6 in DHCP for hosts that don't support it —
        # their IPv6 addresses are handled by TAYGA NAT64 on the gateway
        ipv6_strs = _ipv6_for_ip(ip, inventory) if host.ipv6_capable else []
        mac_str = ",".join(str(mac) for mac in vi.macs)

        if ipv6_strs:
            ipv6_brackets = ",".join(f"[{addr}]" for addr in ipv6_strs)
            output.append(f"dhcp-host={mac_str},{ip},{ipv6_brackets},{dhcp_name}")
        else:
            output.append(f"dhcp-host={mac_str},{ip},{dhcp_name}")

    return output
