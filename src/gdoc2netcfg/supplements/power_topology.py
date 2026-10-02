"""Power-dependency graph engine (read-only).

An edge ``A -> B`` means "A delivers power to B": cutting A contributes to
cutting B. Availability is OR over feeds, so redundancy (>=2 feeds) is
structural. See
docs/superpowers/specs/2026-10-02-power-topology-engine-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gdoc2netcfg.utils.controls import parse_controls_cell

CATEGORIES = (
    "host", "tasmota", "zigbee", "poe",
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
    cat = infra_category(record.machine)
    if cat is not None:
        return cat
    if record.sheet_name == "Zigbee Info":
        return "zigbee"
    if record.sheet_name == "IoT":
        return "tasmota"
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
        graph.add_node(PowerNode(r.machine, _node_category(r), r.machine))

    for r in in_site:
        if not r.machine:
            continue
        for raw in parse_controls_cell(r.extra.get("Controls", "")):
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
