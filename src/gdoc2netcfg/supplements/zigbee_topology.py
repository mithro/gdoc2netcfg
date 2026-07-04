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
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.utils.sort import natural_sort_key
from gdoc2netcfg.utils.terminal import colorize

if TYPE_CHECKING:
    from gdoc2netcfg.supplements.zigbee import ZigbeeBridgeInfo, ZigbeeDevice


_ANSI_ONLINE = "32"   # green
_ANSI_OFFLINE = "31"  # red
_ANSI_UNKNOWN = "90"  # bright black / grey
_ANSI_HEADER = "1"    # bold

# Zigbee LQI is 0-255; Z2M itself calls <30 "poor" and >100 "good".
_LQI_GOOD = 100
_LQI_POOR = 30
_LQI_STRONG = 180

# Signal-strength bar: one ascending segment per quality level.
_LQI_BARS = "▂▄▆█"


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
    # Exclude devices that are both offline and have no known parent —
    # they add noise without topology information.  Offline devices WITH
    # a known parent are kept (they show the mesh structure).  Online
    # devices without a known parent are kept (they're active).
    devices = [
        d for d in devices
        if d.connected_via or d.availability != "offline"
    ]

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


def generate_zigbee_text_tree(
    devices: list[ZigbeeDevice],
    bridge: ZigbeeBridgeInfo | None,
    site_name: str,
    *,
    use_color: bool = False,
    note: str = "",
) -> str:
    """Generate a console-friendly text tree of the Zigbee mesh for a site.

    Applies the same filter as ``generate_zigbee_topology``: drops devices
    that are both offline AND have no known parent.

    Renders four sections:
      1. The Coordinator-rooted sub-tree (devices reachable from
         ``"Coordinator"`` via parent chains).
      2. Orphan sub-trees — routers with no known uplink but with their
         own children.  This is a real-world networkmap quirk where
         child→router routes are published but the router's own uplink
         is missed.
      3. Sub-trees whose root's parent is not shown — the parent was
         filtered out (offline with no known uplink) or isn't in the
         device list at all (renamed/removed device, raw IEEE address).
      4. True orphans — devices with no parent and no children.

    Every kept device is rendered exactly once; if corrupt parent data
    (e.g. a routing loop) leaves any device unreachable, this raises
    rather than silently omitting it.

    Args:
        devices: All ``ZigbeeDevice`` records for the site.
        bridge: Coordinator/bridge info (used for the header).
        site_name: Site name for the header.
        use_color: Wrap status markers in ANSI escapes when True.
        note: Optional warning line shown under the header (e.g. a
            staleness marker when rendering baseline data).

    Returns:
        Multi-line string (no trailing newline) ready to print.

    Raises:
        RuntimeError: If any kept device could not be rendered (corrupt
            parent data such as a routing loop).
    """
    total = len(devices)
    excluded = sum(
        1 for d in devices
        if not d.connected_via and d.availability == "offline"
    )
    kept = [
        d for d in devices
        if d.connected_via or d.availability != "offline"
    ]

    lookup = {d.friendly_name: d for d in kept}
    children: dict[str, list[str]] = defaultdict(list)
    for d in kept:
        if d.connected_via:
            children[d.connected_via].append(d.friendly_name)
    for kids in children.values():
        kids.sort(key=natural_sort_key)

    online = sum(1 for d in devices if d.availability == "online")
    offline = sum(1 for d in devices if d.availability == "offline")
    with_parent = sum(1 for d in devices if d.connected_via)

    sep = "=" * 60
    lines: list[str] = [
        sep,
        colorize(f"Zigbee Mesh - {site_name}", _ANSI_HEADER, use_color),
        sep,
    ]
    if note:
        lines.append(colorize(note, _ANSI_OFFLINE, use_color))
    if bridge:
        lines.append(
            f"Z2M {bridge.z2m_version}  |  "
            f"{bridge.coordinator_type} {bridge.coordinator_ieee}  |  "
            f"Ch {bridge.channel}  PAN {bridge.pan_id}"
        )
    lines.append(
        f"Devices: {total}  (online {online}, offline {offline})  "
        f"with parent info: {with_parent}/{total}"
    )
    lines.append("")

    rendered: set[str] = set()

    coord_children = children.get("Coordinator", [])
    if coord_children:
        lines.append("Coordinator")
        _walk(
            "Coordinator", children, lookup, "", lines, rendered,
            use_color=use_color,
        )
    else:
        lines.append("Coordinator  (no children in networkmap)")

    # Orphan sub-trees: kept devices with no parent that *do* have children.
    orphan_roots = sorted(
        (
            d.friendly_name for d in kept
            if not d.connected_via and children.get(d.friendly_name)
        ),
        key=natural_sort_key,
    )
    if orphan_roots:
        lines.append("")
        lines.append("Orphan sub-trees (router with no known uplink):")
        for root in orphan_roots:
            lines.append("  " + _format_node(lookup[root], use_color))
            rendered.add(root)
            _walk(
                root, children, lookup, "  ", lines, rendered,
                use_color=use_color,
            )

    # Sub-trees whose root's claimed parent is not a rendered device:
    # the parent was dropped by the offline+orphan filter, or isn't in
    # the device list at all (renamed/removed, or a raw IEEE address
    # from a networkmap node the registry doesn't know).  These MUST
    # still be rendered — silently omitting them would hide devices.
    detached_roots = sorted(
        (
            d.friendly_name for d in kept
            if d.connected_via
            and d.connected_via != "Coordinator"
            and d.connected_via not in lookup
        ),
        key=natural_sort_key,
    )
    if detached_roots:
        lines.append("")
        lines.append("Sub-trees under a parent that is not shown:")
        for root in detached_roots:
            device = lookup[root]
            lines.append(
                f"  {_format_node(device, use_color)}"
                f"  [parent: {device.connected_via}]"
            )
            rendered.add(root)
            _walk(
                root, children, lookup, "  ", lines, rendered,
                use_color=use_color,
            )

    # True orphans: no parent, no children.
    true_orphans = sorted(
        (
            d.friendly_name for d in kept
            if not d.connected_via and not children.get(d.friendly_name)
        ),
        key=natural_sort_key,
    )
    if true_orphans:
        lines.append("")
        lines.append(
            "Devices with no known parent (likely sleepy end-devices):"
        )
        for name in true_orphans:
            lines.append("  " + _format_node(lookup[name], use_color))
            rendered.add(name)

    # Completeness check: every kept device must have been rendered.
    # Anything left over means corrupt parent data (e.g. a routing
    # loop) — fail loud rather than silently omit devices.
    unrendered = sorted(set(lookup) - rendered, key=natural_sort_key)
    if unrendered:
        raise RuntimeError(
            f"[{site_name}] {len(unrendered)} device(s) unreachable from "
            "any rendered root — corrupt parent data (routing loop?): "
            + ", ".join(
                f"{name} (parent: {lookup[name].connected_via})"
                for name in unrendered
            )
        )

    if excluded:
        lines.append("")
        lines.append(f"({excluded} offline+orphan device(s) hidden)")

    return "\n".join(lines)


def _walk(
    parent: str,
    children: dict[str, list[str]],
    lookup: dict[str, ZigbeeDevice],
    prefix: str,
    lines: list[str],
    rendered: set[str],
    *,
    use_color: bool,
) -> None:
    """Recursively append rendered child rows under ``parent``.

    Every walked name is a kept device: ``children`` values are built
    exclusively from kept devices' friendly names, so ``lookup[name]``
    cannot fail.
    """
    kids = children.get(parent, [])
    for i, name in enumerate(kids):
        last = i == len(kids) - 1
        branch = "└─ " if last else "├─ "
        cont = "   " if last else "│  "
        lines.append(prefix + branch + _format_node(lookup[name], use_color))
        rendered.add(name)
        _walk(
            name, children, lookup, prefix + cont, lines, rendered,
            use_color=use_color,
        )


def _format_node(device: ZigbeeDevice, use_color: bool) -> str:
    """Format one device as
    ``<marker> [<role>] <signal bars> <name> <desc> (<model>)``.

    The name is padded to a minimum of 3 characters so short names
    (Z7) and long names (Z17) start their description/model at the
    same column.
    """
    if device.availability == "online":
        marker = colorize("●", _ANSI_ONLINE, use_color)
    elif device.availability == "offline":
        marker = colorize("○", _ANSI_OFFLINE, use_color)
    else:
        marker = colorize("?", _ANSI_UNKNOWN, use_color)

    role = "R" if device.device_type == "Router" else "E"
    if device.link_quality is not None:
        bar = _format_lqi(device.link_quality, use_color)
    else:
        # No reading (e.g. no networkmap parent): blank spacer keeps
        # sibling names aligned.
        bar = " " * len(_LQI_BARS)
    parts = [f"{marker} [{role}] {bar} {device.friendly_name:<3}"]

    if device.description:
        # Z2M descriptions can span multiple lines; join with " / " so
        # the tree layout stays one line per device.
        parts.append(" / ".join(
            line.strip() for line in device.description.splitlines()
            if line.strip()
        ))
    model = device.model or device.model_id
    if model:
        parts.append(f"({model})")
    return " ".join(parts).rstrip()


def _format_lqi(lqi: int, use_color: bool) -> str:
    """Format link quality as a 4-segment signal-strength bar.

    Lit segments are colour-graded by Z2M's thresholds (green good,
    yellow workable, red poor); unlit segments render as ``_``
    placeholders (dim grey on a colour terminal), so the bar is
    always exactly 4 columns wide.
    """
    if lqi >= _LQI_GOOD:
        code = _ANSI_ONLINE   # green: good signal
    elif lqi >= _LQI_POOR:
        code = "33"           # yellow: workable signal
    else:
        code = _ANSI_OFFLINE  # red: poor signal

    if lqi >= _LQI_STRONG:
        level = 4
    elif lqi >= _LQI_GOOD:
        level = 3
    elif lqi >= _LQI_POOR:
        level = 2
    else:
        level = 1

    lit = _LQI_BARS[:level]
    unlit = "_" * (len(_LQI_BARS) - level)
    if use_color:
        out = colorize(lit, code, True)
        if unlit:
            out += colorize(unlit, _ANSI_UNKNOWN, True)
        return out
    return lit + unlit
