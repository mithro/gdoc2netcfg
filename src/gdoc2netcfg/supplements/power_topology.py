"""Power-dependency graph engine (read-only).

An edge ``A -> B`` means "A delivers power to B": cutting A contributes to
cutting B. Availability is OR over feeds, so redundancy (>=2 feeds) is
structural. See
docs/superpowers/specs/2026-10-02-power-topology-engine-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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
