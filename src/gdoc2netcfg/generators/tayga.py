"""TAYGA NAT64 configuration generator.

Produces TAYGA config and systemd-networkd files for IPv6-to-IPv4
translation of IPv6-incapable devices. The gateway (ten64) runs TAYGA
as a userspace NAT64 daemon, translating IPv6 traffic to IPv4 so that
IPv6 clients can reach IPv4-only IoT devices.

Output files:
- tayga.conf: TAYGA daemon configuration with per-host map entries
- {tun}.netdev: systemd-networkd TUN device definition
- {tun}.network: systemd-networkd network config with per-host IPv6 routes
"""

from __future__ import annotations

from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.utils.ip import ip_sort_key


def generate_tayga(
    inventory: NetworkInventory,
    *,
    tun_device: str = "nat64",
    ipv4_addr: str = "100.64.1.1",
) -> dict[str, str]:
    """Generate TAYGA NAT64 configuration files.

    Produces map entries only for hosts with ipv6_capable=False that
    have both IPv4 and IPv6 addresses.

    Args:
        inventory: The fully enriched network inventory.
        tun_device: Name of the TUN device for TAYGA (default: "nat64").
        ipv4_addr: IPv4 address for TAYGA's TUN endpoint, used as the
            source address for translated packets. Should be in the
            RFC 6598 (100.64.0.0/10) range so devices can distinguish
            NAT64-proxied connections.

    Returns:
        Dict mapping filename to file content:
        - "tayga.conf": TAYGA daemon configuration
        - "{tun_device}.netdev": systemd-networkd TUN device
        - "{tun_device}.network": systemd-networkd network config
    """
    # Collect NAT64 mappings for incapable hosts
    mappings: list[tuple[str, str, str]] = []  # (hostname, ipv4, ipv6)
    for host in inventory.hosts_sorted():
        if host.ipv6_capable:
            continue
        if host.default_ipv4 is None:
            continue
        # Find the IPv6 address on the interface matching the default IPv4
        for iface in host.interfaces:
            if iface.ipv4 == host.default_ipv4 and iface.ipv6_addresses:
                ipv4_str = str(iface.ipv4)
                ipv6_str = str(iface.ipv6_addresses[0])
                mappings.append((host.hostname, ipv4_str, ipv6_str))
                break

    # Sort by IPv4 address
    mappings.sort(key=lambda m: ip_sort_key(m[1]))

    # Generate tayga.conf
    tayga_lines = [
        f"tun-device {tun_device}",
        f"ipv4-addr {ipv4_addr}",
        "data-dir /var/lib/tayga",
        "",
    ]
    for hostname, ipv4, ipv6 in mappings:
        tayga_lines.append(f"# {hostname}")
        tayga_lines.append(f"map {ipv4}\t{ipv6}")
    tayga_conf = "\n".join(tayga_lines) + "\n"

    # Generate systemd-networkd .netdev
    netdev = (
        f"[NetDev]\n"
        f"Name={tun_device}\n"
        f"Kind=tun\n"
    )

    # Generate systemd-networkd .network with per-host IPv6 routes
    network_lines = [
        "[Match]",
        f"Name={tun_device}",
        "",
        "[Network]",
        f"Address={ipv4_addr}/32",
    ]
    for _, _, ipv6 in mappings:
        network_lines.append("")
        network_lines.append("[Route]")
        network_lines.append(f"Destination={ipv6}/128")
    network = "\n".join(network_lines) + "\n"

    return {
        "tayga.conf": tayga_conf,
        f"{tun_device}.netdev": netdev,
        f"{tun_device}.network": network,
    }
