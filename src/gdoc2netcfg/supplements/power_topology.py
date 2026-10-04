"""Power-dependency graph engine (read-only).

An edge ``A -> B`` means "A delivers power to B": cutting A contributes to
cutting B. Availability is OR over feeds, so redundancy (>=2 feeds) is
structural. See
docs/superpowers/specs/2026-10-02-power-topology-engine-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gdoc2netcfg.utils.controls import (
    appliance_name,
    parse_controls_cell,
    strip_interface_prefix,
)
from gdoc2netcfg.utils.location import (
    location_key,
    natural_sort_key,
    parse_location_path,
)

_LOCATION_KEYS = ("Physical Location", "Location")


def _record_location(record) -> str:
    """Return a record's location cell (IoT ``Physical Location`` / Network ``Location``)."""
    for key in _LOCATION_KEYS:
        val = record.extra.get(key)
        if val:
            return val
    return ""

CATEGORIES = (
    "host", "tasmota", "zigbee", "poe", "bmc", "appliance",
    "ups", "mains", "busbar", "strip", "unresolved",
)

_INFRA_PREFIXES = ("ups", "mains", "busbar", "strip")


class PowerCycleError(Exception):
    """Raised when the power graph contains a cycle (a data-entry error)."""


def infra_category(name: str) -> str | None:
    """Return the infra category for a kind-prefixed node name, else None."""
    for prefix in _INFRA_PREFIXES:
        if name.startswith(prefix + "-"):
            return prefix
    return None


@dataclass(frozen=True)
class PowerNode:
    id: str        # canonical id: machine name, or "switch ifname" for a PoE port
    category: str  # one of CATEGORIES
    label: str     # display label
    location: tuple[str, ...] = ()  # hierarchy path (e.g. ("Back Shed", "Rack"))
    note: str = ""  # descriptive annotation (e.g. "monitored by rpi4-ups")


@dataclass
class PowerGraph:
    nodes: dict[str, PowerNode] = field(default_factory=dict)
    _children: dict[str, set[str]] = field(default_factory=dict)
    _parents: dict[str, set[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def add_node(self, node: PowerNode) -> None:
        self.nodes.setdefault(node.id, node)
        self._children.setdefault(node.id, set())
        self._parents.setdefault(node.id, set())

    def add_edge(self, parent_id: str, child_id: str) -> None:
        self._children[parent_id].add(child_id)
        self._parents[child_id].add(parent_id)

    def children_of(self, node_id: str) -> set[str]:
        return self._children.get(node_id, set())

    def parents_of(self, node_id: str) -> set[str]:
        return self._parents.get(node_id, set())

    def roots(self) -> list[str]:
        return sorted(nid for nid in self.nodes if not self._parents.get(nid))


def _in_site(record_site: str, site_name: str) -> bool:
    s = (record_site or "").strip().lower()
    return s == "" or s == site_name.strip().lower()


def _node_category(record) -> str:
    # Sheet keys arrive as the lowercase [sheets] TOML key ("iot", "network"),
    # so compare case-insensitively like host_builder does.
    cat = infra_category(record.machine)
    if cat is not None:
        return cat
    sheet = record.sheet_name.lower()
    if sheet == "iot":
        return "tasmota"
    if sheet == "zigbee":
        return "zigbee"
    return "host"


class NameResolver:
    """Resolve a free-text Controls/PoE value to a canonical node id."""

    def __init__(self, node_ids: set[str], site_domain: str):
        self._ids = set(node_ids)
        self._suffix = "." + site_domain if site_domain else ""

    def resolve(self, raw: str) -> str | None:
        name = raw.strip()
        if name in self._ids:
            return name
        if self._suffix and name.endswith(self._suffix):
            trimmed = name[: -len(self._suffix)]
            if trimmed in self._ids:
                return trimmed
        first = name.split(".")[0]
        if first in self._ids:
            return first
        return None


def add_controls_edges(graph: PowerGraph, records, hosts, site) -> None:
    """Add nodes and Controls edges (plugs + infra) for one site.

    Controllers are in-site device rows with a Controls cell; targets are
    resolved to known nodes, else kept as ``unresolved`` leaves with a warning.
    """
    in_site = [r for r in records if _in_site(r.site, site.name)]

    node_ids: set[str] = {r.machine for r in in_site if r.machine}
    for h in hosts:
        node_ids.add(h.machine_name)
        node_ids.add(h.hostname)
    resolver = NameResolver(node_ids, site.domain)

    for r in in_site:
        if not r.machine:
            continue
        # Only infra nodes (ups/mains/busbar/strip) carry their Human Name as a
        # descriptive note; a plug/host Human Name would just clutter the label.
        note = r.extra.get("Human Name", "") if infra_category(r.machine) else ""
        graph.add_node(PowerNode(
            r.machine, _node_category(r), r.machine,
            location=parse_location_path(_record_location(r)),
            note=note,
        ))

    for r in in_site:
        if not r.machine:
            continue
        for raw in parse_controls_cell(r.extra.get("Controls", "")):
            appl = appliance_name(raw)
            if appl is not None:
                # A non-network load (heater/AC/monitors): a valid leaf with no
                # sheet row, inheriting the controller's location.
                appl_id = f"appliance:{appl}"
                graph.add_node(PowerNode(
                    appl_id, "appliance", appl,
                    location=parse_location_path(_record_location(r)),
                ))
                graph.add_edge(r.machine, appl_id)
                continue
            target = resolver.resolve(raw)
            if target is None:
                target = raw
                graph.add_node(PowerNode(raw, "unresolved", raw))
                graph.warnings.append(
                    f"Controls target {raw!r} (from {r.machine}) matches no known host"
                )
            elif target not in graph.nodes:
                graph.add_node(PowerNode(target, "host", target))
            graph.add_edge(r.machine, target)


def _is_bmc_host(host) -> bool:
    """A BMC host is one whose hostname's first label *starts with* ``bmc``.

    A prefix (not substring) test: real BMC hosts are ``bmc.<host>`` /
    ``bmc-alt.<host>`` etc. A substring test would misclassify a host like
    ``webmc`` whose hostname equals its machine name, creating a self-loop
    (``add_edge(x, x)``) that ``check_acyclic`` would reject.
    """
    return host.hostname.split(".")[0].lower().startswith("bmc")


def add_bmc_edges(graph: PowerGraph, hosts) -> None:
    """A BMC can power-cycle its host: edge ``bmc.<host> -> <host>``.

    The BMC inherits its parent host's location. If the parent host has no
    node (dropped/absent), the BMC node is still added and a warning recorded,
    but no dangling edge is created.
    """
    for h in hosts:
        if not _is_bmc_host(h):
            continue
        parent = h.machine_name
        loc = graph.nodes[parent].location if parent in graph.nodes else ()
        graph.add_node(PowerNode(h.hostname, "bmc", h.hostname, location=loc))
        if parent in graph.nodes:
            graph.add_edge(h.hostname, parent)
        else:
            graph.warnings.append(
                f"BMC {h.hostname!r} has no node for its host {parent!r}; "
                f"power-control edge omitted"
            )


_ADMIN_ON, _ADMIN_OFF = 1, 2
_DET_DELIVERING = 3


def _poe_host_name(aliases: dict[int, str], lldp: dict[int, str], port: int,
                   graph: PowerGraph, switch: str) -> str | None:
    """Pick the connected-host name for a port: alias, else LLDP; warn on disagreement."""
    alias = ""
    if aliases.get(port):
        alias = strip_interface_prefix(aliases[port].strip())[1]
    lldp_name = lldp.get(port, "")
    if alias and lldp_name and alias != lldp_name:
        graph.warnings.append(
            f"PoE {switch} port {port}: alias {alias!r} disagrees with LLDP "
            f"{lldp_name!r}; using LLDP"
        )
        return lldp_name
    return alias or lldp_name or None


def _match_switch_node(graph: PowerGraph, switch: str) -> str | None:
    """Find the existing graph node for a bridge switch key, case-insensitively.

    Node ids carry the raw-case ``Machine`` cell; the bridge dict is keyed by
    the lowercased hostname, so an exact match can miss. Returns the matching
    node id, or None if no node exists for this switch yet.
    """
    if switch in graph.nodes:
        return switch
    low = switch.lower()
    for nid in graph.nodes:
        if nid.lower() == low:
            return nid
    return None


def add_poe_edges(graph: PowerGraph, bridge, resolver: NameResolver) -> None:
    """Add switch -> poe-port -> host edges from bridge PoE data."""
    if not bridge:
        return
    for switch, doc in sorted(bridge.items()):
        switch_id = _match_switch_node(graph, switch)
        if switch_id is None:
            # A bridge switch with no node in the current inventory is stale
            # scan history (the bridge scan never tombstones a vanished switch).
            # Exclude its PoE subtree and surface it as a violation.
            graph.warnings.append(
                f"bridge switch {switch!r} is not in current inventory — "
                f"stale scan history; its PoE subtree is excluded"
            )
            continue
        names = dict(doc.get("port_names", ()))
        aliases = {p: a for p, a in doc.get("port_aliases", ())}
        lldp = {lp: sn for lp, sn, *_ in doc.get("lldp_neighbors", ())}
        for port, admin, detection in doc.get("poe_status", ()):
            if admin not in (_ADMIN_ON, _ADMIN_OFF) or not (1 <= detection <= 6):
                raise ValueError(
                    f"PoE {switch} port {port}: admin/detection out of range "
                    f"({admin}, {detection})"
                )
            deliver = admin == _ADMIN_ON and detection == _DET_DELIVERING
            held_off = admin == _ADMIN_OFF
            if not (deliver or held_off):
                if admin == _ADMIN_ON and detection not in (_DET_DELIVERING, 2):
                    graph.warnings.append(
                        f"PoE {switch} port {port}: fault/test state {detection}"
                    )
                continue
            raw = _poe_host_name(aliases, lldp, port, graph, switch)
            if raw is None:
                continue  # delivering/off but no name — empty described port
            if port not in names:
                raise ValueError(
                    f"PoE {switch} port {port} delivering/held-off but has no ifName"
                )
            port_id = f"{switch_id} {names[port]}"
            graph.add_node(PowerNode(port_id, "poe", port_id))
            graph.add_edge(switch_id, port_id)
            target = resolver.resolve(raw)
            if target is None:
                target = raw
                graph.add_node(PowerNode(raw, "unresolved", raw))
                graph.warnings.append(
                    f"PoE {port_id} names {raw!r} which matches no known host"
                )
            elif target not in graph.nodes:
                graph.add_node(PowerNode(target, "host", target))
            graph.add_edge(port_id, target)


def check_acyclic(graph: PowerGraph) -> None:
    """Raise PowerCycleError if the graph contains a cycle."""
    WHITE, GREY, BLACK = 0, 1, 2
    color = dict.fromkeys(graph.nodes, WHITE)

    def visit(nid: str, stack: list[str]) -> None:
        color[nid] = GREY
        for child in sorted(graph.children_of(nid)):
            if color[child] == GREY:
                cyc = stack[stack.index(child):] + [child]
                raise PowerCycleError("power cycle: " + " -> ".join(cyc))
            if color[child] == WHITE:
                visit(child, stack + [child])
        color[nid] = BLACK

    for nid in sorted(graph.nodes):
        if color[nid] == WHITE:
            visit(nid, [nid])


def hosts_not_reaching_mains(graph: PowerGraph) -> list[str]:
    """Node ids whose ancestry contains no `mains` node (chain truncated)."""
    bad: list[str] = []
    for nid in sorted(graph.nodes):
        if graph.nodes[nid].category == "mains":
            continue
        seen: set[str] = set()
        queue = list(graph.parents_of(nid))
        reaches = False
        while queue:
            p = queue.pop()
            if p in seen:
                continue
            seen.add(p)
            if graph.nodes[p].category == "mains":
                reaches = True
                break
            queue.extend(graph.parents_of(p))
        if not reaches:
            bad.append(nid)
            graph.warnings.append(f"{nid}: power chain does not reach a mains node")
    return bad


def powered(graph: PowerGraph, blocked: frozenset[str] = frozenset()) -> set[str]:
    """Nodes reachable from roots via child edges, never entering a blocked node."""
    result: set[str] = set()
    stack = [r for r in graph.roots() if r not in blocked]
    while stack:
        nid = stack.pop()
        if nid in result:
            continue
        result.add(nid)
        for child in graph.children_of(nid):
            if child not in blocked:
                stack.append(child)
    return result


def downstream(graph: PowerGraph, node_id: str) -> set[str]:
    """Nodes that lose power when node_id is toggled off (redundancy-aware)."""
    before = powered(graph)
    after = powered(graph, blocked=frozenset({node_id}))
    return (before - after) - {node_id}


def upstream_levels(graph: PowerGraph, node_id: str) -> list[list[str]]:
    """Ancestors grouped by longest hop-distance from node_id (direct first)."""
    level: dict[str, int] = {}
    frontier = {node_id: 0}
    changed = True
    while changed:
        changed = False
        for nid, dist in list(frontier.items()):
            for parent in graph.parents_of(nid):
                nd = dist + 1
                if nd > level.get(parent, 0):
                    level[parent] = nd
                    frontier[parent] = nd
                    changed = True
    by_level: dict[int, list[str]] = {}
    for nid, lvl in level.items():
        by_level.setdefault(lvl, []).append(nid)
    return [sorted(by_level[d]) for d in sorted(by_level)]


def _label(graph: PowerGraph, nid: str) -> str:
    n = graph.nodes[nid]
    base = f"{n.category}: {n.label}"
    return f"{base} ({n.note})" if n.note else base


def _loc_display(path: tuple[str, ...]) -> str:
    return " - ".join(path)


def _insert_root(tree: dict, path: tuple[str, ...], nid: str) -> None:
    """Insert a root id into the nested location tree under `path`."""
    node = tree
    for seg in path:
        node = node.setdefault("sub", {}).setdefault(seg, {})
    node.setdefault("roots", []).append(nid)


def render_tree(graph: PowerGraph, site_name: str) -> str:
    """Meter-rooted, location-grouped ASCII tree.

    Line 1 is the synthetic site meter. Power roots are grouped under a
    nested location tree keyed by each root's location path; each root's
    power subtree is walked via child edges, siblings natural-sorted. A
    child whose location diverges from its parent's is flagged, as is a
    placed node with no location. Meter/location lines are presentation
    only — no graph nodes or edges are added.
    """
    lines: list[str] = [f"mains: meter-{site_name}"]

    def walk(nid: str, parent_key: str, prefix: str, is_last: bool) -> None:
        n = graph.nodes[nid]
        suffix = ""
        if not n.location:
            suffix = "  ⚠ loc unknown"
        elif location_key(_loc_display(n.location)) != parent_key:
            suffix = f"  ⚠ loc={_loc_display(n.location)}"
        connector = "└─ " if is_last else "├─ "
        lines.append(f"{prefix}{connector}{_label(graph, nid)}{suffix}")
        child_prefix = prefix + ("   " if is_last else "│  ")
        my_key = location_key(_loc_display(n.location))
        kids = sorted(graph.children_of(nid),
                      key=lambda c: natural_sort_key(graph.nodes[c].label))
        for i, child in enumerate(kids):
            walk(child, my_key, child_prefix, i == len(kids) - 1)

    tree: dict = {}
    roots = sorted(graph.roots(),
                   key=lambda r: natural_sort_key(graph.nodes[r].label))
    for r in roots:
        path = graph.nodes[r].location or ("[unknown location]",)
        _insert_root(tree, path, r)

    def render_locs(node: dict, depth: int) -> None:
        indent = "   " * depth
        for name in sorted(node.get("sub", {}), key=natural_sort_key):
            lines.append(f"{indent}[{name}]")
            render_locs(node["sub"][name], depth + 1)
        for r in node.get("roots", []):
            key = location_key(_loc_display(graph.nodes[r].location))
            walk(r, key, indent, True)

    render_locs(tree, 1)
    return "\n".join(lines)


def render_upstream(graph: PowerGraph, node_id: str) -> str:
    """One line per hop-level (direct first -> mains last), same-level comma-joined."""
    levels = upstream_levels(graph, node_id)
    return "\n".join(
        ", ".join(_label(graph, nid) for nid in level) for level in levels
    )


def build_power_graph(records, hosts, bridge, site) -> PowerGraph:
    """Assemble the full power graph for one site and run integrity checks."""
    graph = PowerGraph()
    add_controls_edges(graph, records, hosts, site)
    add_bmc_edges(graph, hosts)
    node_ids = set(graph.nodes)
    for h in hosts:
        node_ids.add(h.machine_name)
        node_ids.add(h.hostname)
    add_poe_edges(graph, bridge, NameResolver(node_ids, site.domain))
    check_acyclic(graph)
    hosts_not_reaching_mains(graph)   # appends warnings
    return graph
