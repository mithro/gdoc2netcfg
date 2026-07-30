"""Per-net dnsmasq leaf configuration generator (dns-redesign §7).

Produces per-host fragments for each LEAF net, keyed
"{net}/generated/{hostname}.conf" — with output_dir = etc/dnsmasq.d the
output tree mirrors the deployed /etc/dnsmasq.d/{net}/generated/ layout. Each fragment
contains only that net's view of the host:

- dhcp-host bindings for the host's interfaces on that net
- net-scoped host-records ({P.}H.N.S, {P.}I.H.N.S) — natives only
- ptr-records (targets: the net-scoped ipv4./ipv6. prefix forms)
- advisory SSHFP dns-rr's at the net-scoped native names + PTR names

Site-scoped records, CNAME projections and CAA live in the central pdns
auth zone, never in leaves. Transit nets and wg tunnels have no leaf
process (their zones are central), and nets delegated to another server
(fpgas → tweed) are excluded entirely.
"""

from __future__ import annotations

from gdoc2netcfg.derivations.dns_names import _anchored_net, common_suffix
from gdoc2netcfg.derivations.vlan import DELEGATED_NETS, ip_to_net
from gdoc2netcfg.generators.dnsmasq_common import (
    _ipv4_to_ptr,
    _ipv6_to_ptr,
    _ipv6_for_ip,
    _most_specific_fqdn,
    host_record_config,
    identity_ipv4,
    sections_to_text,
)
from gdoc2netcfg.models.host import Host, NetworkInventory, VirtualInterface
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.utils.ip import ip_sort_key

def _non_leaf_nets(site: Site) -> frozenset[str]:
    """Nets that get no dnsmasq leaf: transit zones + wg (central-authored)
    and delegated nets."""
    non_leaf = {"wg"} | set(DELEGATED_NETS)
    for vlan in site.vlans.values():
        if vlan.is_transit:
            non_leaf.add(vlan.subdomain)
    return frozenset(non_leaf)


def generate_dnsmasq_leaf(inventory: NetworkInventory) -> dict[str, str]:
    """Generate per-net leaf dnsmasq fragments.

    Returns a dict mapping "{net}/generated/{hostname}.conf" to config
    content (deploy-relative under /etc/dnsmasq.d).
    """
    non_leaf = _non_leaf_nets(inventory.site)
    files: dict[str, str] = {}
    for host in inventory.hosts_sorted():
        for net in _host_nets(host, inventory.site):
            if net in non_leaf:
                continue
            content = _host_leaf_fragment(host, net, inventory)
            if content:
                files[f"{net}/generated/{host.hostname}.conf"] = content
    return files


def _host_nets(host: Host, site: Site) -> list[str]:
    """The nets this host has interfaces on (order of first appearance)."""
    nets: list[str] = []
    for iface in host.interfaces:
        net = ip_to_net(iface.ipv4, site)
        if net is not None and net not in nets:
            nets.append(net)
    return nets


def _net_virtual_interfaces(
    host: Host, net: str, site: Site,
) -> list[VirtualInterface]:
    return [
        vi
        for vi in host.virtual_interfaces
        if ip_to_net(vi.ipv4, site) == net
    ]


def _host_leaf_fragment(host: Host, net: str, inventory: NetworkInventory) -> str:
    sections = [
        _net_dhcp_config(host, net, inventory),
        _net_host_records(host, net, inventory),
        _short_name_records(host, net, inventory),
        _net_ptr_config(host, net, inventory),
        _anchored_caa(host, net, inventory),
        _net_sshfp_records(host, net, inventory),
    ]
    return sections_to_text(sections)


def _short_name_records(host: Host, net: str, inventory: NetworkInventory) -> list[str]:
    """Unqualified convenience names, served by the leaf when this net is
    the host's ONLY net (unambiguous home). dnsmasq can serve unqualified
    names; zone files cannot, so multi-net hosts' shorts don't survive
    the redesign (clients use search domains instead)."""
    if _host_nets(host, inventory.site) != [net]:
        return []
    shorts = [n for n in host.dns_names if not n.is_fqdn]
    return host_record_config(host, inventory, identity_ipv4, dns_names=shorts)


def _anchored_caa(host: Host, net: str, inventory: NetworkInventory) -> list[str]:
    """CAA for net-anchored hostnames (ha.iot, …): their canonical name
    lives in this leaf's zone, so the CAA parity record does too. (The
    CA-visible copy is in the public external zone.)"""
    if _anchored_net(host, inventory.site) != net:
        return []
    domain = inventory.site.domain
    return [
        f"dns-rr={host.hostname}.{domain},"
        f"257,000569737375656C657473656E63727970742E6F7267"
    ]


def _net_dhcp_config(host: Host, net: str, inventory: NetworkInventory) -> list[str]:
    """dhcp-host entries for the host's interfaces on this net."""
    vis = _net_virtual_interfaces(host, net, inventory.site)
    if not vis:
        return []

    entries: list[str] = []
    for vi in sorted(vis, key=lambda v: ip_sort_key(str(v.ipv4))):
        if not vi.macs:
            continue  # DNS-only endpoint (wg, tailscale): no DHCP binding
        ip = str(vi.ipv4)
        dhcp_name = common_suffix(*set(vi.dhcp_names)).strip("-")

        ipv6_strs = _ipv6_for_ip(ip, inventory)
        mac_str = ",".join(str(mac) for mac in vi.macs)

        if ipv6_strs:
            ipv6_brackets = ",".join(f"[{addr}]" for addr in ipv6_strs)
            entries.append(f"dhcp-host={mac_str},{ip},{ipv6_brackets},{dhcp_name}")
        else:
            entries.append(f"dhcp-host={mac_str},{ip},{dhcp_name}")

    if not entries:
        return []
    return [f"# {host.hostname} — DHCP"] + entries


def _net_host_records(host: Host, net: str, inventory: NetworkInventory) -> list[str]:
    """host-record lines for this net's native names only."""
    net_names = [
        n
        for n in host.dns_names
        if n.scope == "net" and n.net == net and n.kind == "native"
    ]
    return host_record_config(host, inventory, identity_ipv4, dns_names=net_names)


def _net_ptr_config(host: Host, net: str, inventory: NetworkInventory) -> list[str]:
    """ptr-record entries for the host's addresses on this net.

    Targets are the most-specific FQDNs, which under the three-scope
    grammar are the net-scoped ipv4./ipv6. interface prefix forms —
    today's target shape, unchanged (design §3).
    """
    domain = inventory.site.domain
    output: list[str] = []

    vis = _net_virtual_interfaces(host, net, inventory.site)
    for vi in sorted(vis, key=lambda v: ip_sort_key(str(v.ipv4))):
        ip = str(vi.ipv4)

        fqdn = _most_specific_fqdn(host, ip, domain, is_ipv6=False)
        if fqdn:
            output.append(f"ptr-record={_ipv4_to_ptr(ip)},{fqdn}")

        for ipv6_addr in vi.ipv6_addresses:
            ipv6_str = str(ipv6_addr)
            ipv6_fqdn = _most_specific_fqdn(host, ipv6_str, domain, is_ipv6=True)
            if ipv6_fqdn:
                output.append(f"ptr-record={_ipv6_to_ptr(ipv6_str)},{ipv6_fqdn}")

    return output


def _net_sshfp_records(host: Host, net: str, inventory: NetworkInventory) -> list[str]:
    """Advisory SSHFP dns-rr's at this net's native names + PTR names.

    Leaves are provably insecure (dnsmasq cannot sign), so these are
    advisory-only; the enforceable copies live at the signed site names
    in the central auth (design §3/§5).
    """
    if not host.sshfp_records:
        return []

    output: list[str] = []

    def _records(dnsname: str) -> None:
        output.append(f"# sshfp for {dnsname}")
        for line in host.sshfp_records:
            if line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                _, a, b, c, d, e = parts[:6]
                output.append(f"dns-rr={dnsname},44,{c}:{d}:{e}")

    domain = inventory.site.domain
    _records(f"{host.hostname}.{net}.{domain}")

    for iface in host.interfaces:
        if iface.name and ip_to_net(iface.ipv4, inventory.site) == net:
            _records(f"{iface.name}.{host.hostname}.{net}.{domain}")

    for vi in _net_virtual_interfaces(host, net, inventory.site):
        ptr = _ipv4_to_ptr(str(vi.ipv4))
        _records(ptr)

    return output
