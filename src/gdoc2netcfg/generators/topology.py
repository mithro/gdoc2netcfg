"""Generator: Graphviz DOT network topology from bridge supplement data.

Produces a DOT-format string showing the physical network topology
derived from LLDP neighbors and MAC address tables collected by
the bridge supplement.

Switch nodes (hosts with bridge_data) are shown as boxes.
Host nodes (known hosts whose MACs appear in switch MAC tables) are ellipses.
LLDP edges are bold and bidirectional.
MAC-learned edges are dashed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host, NetworkInventory


def _is_locally_administered(mac: str) -> bool:
    """Check if a MAC address is locally administered (LAA).

    Bit 1 of the first octet indicates locally administered.
    E.g. BA:BE:xx has first octet 0xBA = 0b10111010, bit 1 is set.
    """
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0x02)


def _resolve_lldp_host(
    sysname: str,
    hostname_to_host: dict[str, Host],
    domain: str,
) -> Host | None:
    """Resolve an LLDP remote_sysname to a Host.

    Tries exact match first, then strips the domain suffix.
    """
    if sysname in hostname_to_host:
        return hostname_to_host[sysname]
    # Try stripping domain
    if domain and sysname.endswith("." + domain):
        short = sysname[: -(len(domain) + 1)]
        if short in hostname_to_host:
            return hostname_to_host[short]
    return None


def generate_topology(
    inventory: NetworkInventory,
    *,
    show_unknown_macs: bool = False,
) -> str:
    """Generate a Graphviz DOT file showing physical network topology.

    Args:
        inventory: The fully enriched network inventory.
        show_unknown_macs: If True, include unknown MACs as point nodes.

    Returns:
        DOT-format string.
    """
    # Build indexes
    mac_to_host: dict[str, Host] = {}
    for host in inventory.hosts:
        for iface in host.interfaces:
            mac_to_host[str(iface.mac).upper()] = host

    hostname_to_host: dict[str, Host] = {
        h.hostname: h for h in inventory.hosts
    }

    domain = inventory.site.domain

    # Identify switches (hosts with bridge_data)
    switches = [h for h in inventory.hosts if h.bridge_data is not None]

    # Collect all nodes and edges
    switch_names: set[str] = set()
    host_names: set[str] = set()
    unknown_mac_nodes: set[str] = set()

    # LLDP edges: {canonical_pair: (src, dst, src_port, dst_port)}
    lldp_edges: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    # Pairs covered by LLDP (both directions)
    lldp_pairs: set[tuple[str, str]] = set()

    # MAC edges: list of (switch_name, target_name, port_label, vlan_id)
    mac_edges: list[tuple[str, str, str, int]] = []

    for switch in switches:
        switch_names.add(switch.hostname)
        bd = switch.bridge_data
        assert bd is not None  # for type checker

        # Build port name index: ifIndex -> name
        if_names: dict[int, str] = dict(bd.port_names)

        # Collect all MACs belonging to this switch (to skip self-references)
        switch_macs = {str(m).upper() for m in switch.all_macs}

        # --- LLDP edges ---
        for local_if, remote_sysname, remote_port_id, _chassis_mac, _port_desc in (
            bd.lldp_neighbors
        ):
            remote_host = _resolve_lldp_host(
                remote_sysname, hostname_to_host, domain,
            )
            if remote_host is None:
                continue

            local_port = if_names.get(local_if, f"if{local_if}")
            src = switch.hostname
            dst = remote_host.hostname

            # Canonical pair for deduplication
            canonical = (min(src, dst), max(src, dst))
            if canonical not in lldp_edges:
                lldp_edges[canonical] = (src, dst, local_port, remote_port_id)
                lldp_pairs.add((src, dst))
                lldp_pairs.add((dst, src))

            # Record remote as switch or host node
            if remote_host.bridge_data is not None:
                switch_names.add(remote_host.hostname)
            else:
                host_names.add(remote_host.hostname)

        # --- MAC-learned edges ---
        # Group by (switch, port, target) to avoid duplicate edges
        seen_mac_edges: set[tuple[str, int, str]] = set()

        for mac_str, vlan_id, _bridge_port, port_name in bd.mac_table:
            mac_upper = mac_str.upper()

            # Skip LAA MACs
            if _is_locally_administered(mac_upper):
                continue

            # Skip switch self-MACs
            if mac_upper in switch_macs:
                continue

            # Resolve MAC to host
            target_host = mac_to_host.get(mac_upper)

            if target_host is None:
                # Unknown MAC
                if show_unknown_macs:
                    unknown_mac_nodes.add(mac_upper)
                    edge_key = (switch.hostname, 0, mac_upper)
                    if edge_key not in seen_mac_edges:
                        seen_mac_edges.add(edge_key)
                        mac_edges.append(
                            (switch.hostname, mac_upper, port_name, vlan_id)
                        )
                continue

            target_name = target_host.hostname

            # Skip if LLDP already covers this link
            if (switch.hostname, target_name) in lldp_pairs:
                continue

            edge_key = (switch.hostname, 0, target_name)
            if edge_key not in seen_mac_edges:
                seen_mac_edges.add(edge_key)
                host_names.add(target_name)
                mac_edges.append(
                    (switch.hostname, target_name, port_name, vlan_id)
                )

    # --- Build DOT output ---
    lines: list[str] = []
    lines.append("digraph network_topology {")
    lines.append("    rankdir=LR;")
    lines.append("")

    # Switch subgraph
    if switch_names:
        lines.append("    subgraph cluster_switches {")
        lines.append('        label="Switches";')
        lines.append("        style=dashed;")
        lines.append("        color=gray;")
        for name in sorted(switch_names):
            lines.append(
                f'        "{name}" [shape=box, style=filled, fillcolor="#e0e0e0"];'
            )
        lines.append("    }")
        lines.append("")

    # Host subgraph
    if host_names:
        lines.append("    subgraph cluster_hosts {")
        lines.append('        label="Hosts";')
        lines.append("        style=dashed;")
        lines.append("        color=gray;")
        for name in sorted(host_names):
            lines.append(f'        "{name}" [shape=ellipse];')
        lines.append("    }")
        lines.append("")

    # Unknown MAC nodes
    if unknown_mac_nodes:
        for mac in sorted(unknown_mac_nodes):
            lines.append(f'    "{mac}" [shape=point, label=""];')
        lines.append("")

    # LLDP edges
    for canonical in sorted(lldp_edges.keys()):
        src, dst, src_port, dst_port = lldp_edges[canonical]
        label = f"{src_port} ↔ {dst_port}"
        lines.append(
            f'    "{canonical[0]}" -> "{canonical[1]}" '
            f'[style=bold, penwidth=2, dir=both, label="{label}"];'
        )

    # MAC edges
    for sw_name, target, port_name, vlan_id in mac_edges:
        label = f"{port_name} (VLAN {vlan_id})"
        lines.append(
            f'    "{sw_name}" -> "{target}" '
            f'[style=dashed, color="#666666", label="{label}"];'
        )

    lines.append("}")
    return "\n".join(lines)
