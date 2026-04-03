"""Generator: Graphviz DOT Zigbee mesh topology from cached scan data.

Produces a DOT-format string per site showing the Zigbee mesh network
topology derived from the Z2M networkmap parent relationships stored
in ZigbeeDevice.connected_via.

Coordinator is the root node (double-circle).
Router nodes are boxes.
EndDevice nodes are ellipses.
Edges point from child to parent (the direction of connected_via).
Devices without known parents are shown in a separate "unconnected" cluster.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.supplements.zigbee import ZigbeeBridgeInfo, ZigbeeDevice


def render_dot(dot_source: str, output_path: Path, fmt: str = "svg") -> None:
    """Render a DOT string to an image file using graphviz.

    Args:
        dot_source: The DOT-format graph string.
        output_path: Destination file path (e.g. /tmp/zigbee_welland.svg).
        fmt: Output format — "svg" or "png".

    Raises:
        RuntimeError: If graphviz ``dot`` is not installed or rendering fails.
    """
    dot_bin = shutil.which("dot")
    if dot_bin is None:
        raise RuntimeError(
            "Graphviz 'dot' command not found. "
            "Install it with: sudo apt install graphviz"
        )
    result = subprocess.run(
        [dot_bin, f"-T{fmt}", "-o", str(output_path)],
        input=dot_source,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"dot rendering failed (exit {result.returncode}):\n{result.stderr}"
        )


def generate_zigbee_topology(
    devices: list[ZigbeeDevice],
    bridge: ZigbeeBridgeInfo | None,
    site_name: str,
) -> str:
    """Generate a Graphviz DOT diagram for a single site's Zigbee mesh.

    Args:
        devices: All ZigbeeDevice records for this site.
        bridge: Bridge/coordinator info (for labelling the Coordinator node).
        site_name: Site name (used in the graph title).

    Returns:
        DOT-format string.
    """
    # Build lookup: friendly_name -> device
    name_to_device: dict[str, ZigbeeDevice] = {
        d.friendly_name: d for d in devices
    }

    # Coordinator label
    if bridge:
        coord_label = (
            f"Coordinator\\n{bridge.coordinator_type}\\n"
            f"Ch {bridge.channel}  PAN {bridge.pan_id}"
        )
    else:
        coord_label = "Coordinator"

    # Partition devices by role
    routers: list[ZigbeeDevice] = []
    end_devices: list[ZigbeeDevice] = []
    for d in devices:
        if d.device_type == "Router":
            routers.append(d)
        else:
            end_devices.append(d)

    # Partition by connectivity
    connected: list[ZigbeeDevice] = []
    unconnected: list[ZigbeeDevice] = []
    for d in devices:
        if d.connected_via:
            connected.append(d)
        else:
            unconnected.append(d)

    lines: list[str] = []
    lines.append(f'digraph zigbee_{site_name} {{')
    lines.append(f'    label="Zigbee Mesh — {site_name}";')
    lines.append("    labelloc=t;")
    lines.append("    rankdir=TB;")
    lines.append("    nodesep=0.4;")
    lines.append("    ranksep=0.6;")
    lines.append("")

    # Coordinator node
    lines.append(
        f'    "Coordinator" '
        f'[shape=doublecircle, style=filled, fillcolor="#4a90d9", '
        f'fontcolor=white, label="{coord_label}"];'
    )
    lines.append("")

    # Router nodes
    if routers:
        lines.append("    // Routers")
        for d in sorted(routers, key=lambda x: x.friendly_name):
            label = _node_label(d)
            avail_color = _avail_fill(d)
            lines.append(
                f'    "{d.friendly_name}" '
                f'[shape=box, style=filled, fillcolor="{avail_color}", '
                f'label="{label}"];'
            )
        lines.append("")

    # EndDevice nodes
    if end_devices:
        lines.append("    // End Devices")
        for d in sorted(end_devices, key=lambda x: x.friendly_name):
            label = _node_label(d)
            avail_color = _avail_fill(d)
            lines.append(
                f'    "{d.friendly_name}" '
                f'[shape=ellipse, style=filled, fillcolor="{avail_color}", '
                f'label="{label}"];'
            )
        lines.append("")

    # Edges: child -> parent (connected_via)
    if connected:
        lines.append("    // Parent links (from networkmap)")
        for d in sorted(connected, key=lambda x: x.friendly_name):
            parent = d.connected_via
            # connected_via is a friendly_name; it could be "Coordinator"
            # or another device's friendly_name
            lines.append(f'    "{d.friendly_name}" -> "{parent}";')
        lines.append("")

    # Unconnected devices cluster
    if unconnected:
        lines.append("    // Devices without known parent")
        lines.append("    subgraph cluster_unconnected {")
        lines.append('        label="Parent unknown";')
        lines.append("        style=dashed;")
        lines.append('        color="#999999";')
        lines.append('        fontcolor="#999999";')
        for d in sorted(unconnected, key=lambda x: x.friendly_name):
            lines.append(f'        "{d.friendly_name}";')
        lines.append("    }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines)


def _node_label(device: ZigbeeDevice) -> str:
    """Build a multi-line DOT node label for a device."""
    parts = [device.friendly_name]
    if device.description:
        parts.append(device.description)
    model = device.model or device.model_id
    if model:
        parts.append(model)
    return "\\n".join(parts)


def _avail_fill(device: ZigbeeDevice) -> str:
    """Return a fill colour based on device availability."""
    if device.availability == "online":
        return "#c8e6c9"  # light green
    elif device.availability == "offline":
        return "#ffcdd2"  # light red
    return "#e0e0e0"      # grey for unknown
