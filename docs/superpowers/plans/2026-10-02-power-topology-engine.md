# Power Topology Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only power-dependency graph from existing spreadsheet + bridge data and expose it through `gdoc2netcfg power tree|downstream|upstream`.

**Architecture:** A pure engine module (`supplements/power_topology.py`) builds a directed graph whose edges mean "A powers B" from three sources — IoT/Zigbee `Controls` cells, PoE bridge data, and infra-node `Controls` rows — then computes power *availability* (a node is up while any feed is up, so redundancy is structural) for the up/downstream closures and renders a tree. Shared `Controls`/interface parsing moves to `utils/controls.py`. A thin `power` CLI group wires it up. No sheet or device writes.

**Tech Stack:** Python 3.11+, `uv`, pytest, argparse. Data via existing `_build_pipeline()` (`records`, `hosts`) and `DiscoveryDB.load_latest_bridge()`.

**Spec:** `docs/superpowers/specs/2026-10-02-power-topology-engine-design.md`

## Global Constraints

- **Read-only.** No gspread, no PoE toggling, no DB writes anywhere in this sub-project.
- **Fail loud, never fabricate, never silently discard** (CLAUDE.md). A value that can't be resolved is **warned about and kept as a named `unresolved` leaf node** — never dropped with `continue`, never replaced with a fabricated machine name.
- **PoE admin/detection integers outside the RFC 3621 ranges → raise** (`ValueError`).
- **A PoE port with no matching ifName in `port_names` → raise** (can't fabricate a port label).
- **A graph cycle → raise** (`PowerCycleError`); never loop.
- **Strict single-site per run.** Include only rows whose `Site` is blank or equals `config.site.name` (case-insensitive); PoE from the local `discovery.db` only.
- **Infra node category comes from a kind-prefix name:** `ups-*`→ups, `mains-*`→mains, `busbar-*`→busbar, `strip-*`→strip.
- **PoE port label** = `f"{switch} {ifname}"`, ifname looked up from `port_names` by port index.
- Always `uv run`; keep `uv run ruff check src/ tests/` clean. Small discrete commits on branch `worktree-power-topology`.

## Review Focus

- **A `Controls` target or PoE alias that names a nonexistent device** — a reasonable person expects a warning and the name still shown in the tree, not a crash or a silently-dropped edge. → Task 3 (controls) & Task 4 (PoE) tests.
- **A PoE port index absent from `port_names`** — expects a loud `ValueError` naming the port, never a fabricated `port{N}` label. → Task 4 test.
- **A mis-entered `Controls` cycle (`a→b→a`)** — expects a raised `PowerCycleError`, never an infinite loop or hang. → Task 5 test.
- **`downstream`/`upstream <name>` where `<name>` resolves to nothing** — expects exit code 1 with a clear message, not a traceback. → Task 8 test.
- **No completed `bridge` scan (`load_latest_bridge()` is `None`)** — expects the PoE source to contribute nothing with a visible warning, and the Controls-only graph to still render. → Task 4 & Task 8 tests.

---

### Task 1: Extract shared `Controls`/interface parsing into `utils/controls.py`

**Files:**
- Create: `src/gdoc2netcfg/utils/controls.py`
- Create: `tests/test_utils/test_controls.py`
- Modify: `src/gdoc2netcfg/supplements/tasmota.py:338-342` (use the shared parser)
- Modify: `scripts/ha-create-reachability-dashboard.py:213-253` (use the shared prefix stripper)

**Interfaces:**
- Produces: `parse_controls_cell(value: str) -> tuple[str, ...]` and `strip_interface_prefix(desc: str) -> tuple[str, str]` (returns `(iface, rest)`; `iface` is `""` when no prefix matched).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_utils/test_controls.py
from gdoc2netcfg.utils.controls import parse_controls_cell, strip_interface_prefix


def test_parse_controls_comma_and_newline():
    assert parse_controls_cell("desktop, monitor\nserver\r\nac") == (
        "desktop", "monitor", "server", "ac",
    )


def test_parse_controls_empty():
    assert parse_controls_cell("") == ()
    assert parse_controls_cell("  \n ,") == ()


def test_strip_interface_prefix_eth():
    assert strip_interface_prefix("eth0.rpi5-pmod") == ("eth0", "rpi5-pmod")


def test_strip_interface_prefix_slot_port():
    assert strip_interface_prefix("1/0/49.sw-cisco-shed") == ("1/0/49", "sw-cisco-shed")


def test_strip_interface_prefix_none():
    assert strip_interface_prefix("desktop") == ("", "desktop")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_utils/test_controls.py -v`
Expected: FAIL (module `gdoc2netcfg.utils.controls` not found).

- [ ] **Step 3: Implement `utils/controls.py`**

```python
"""Shared parsing for the spreadsheet `Controls` column and switch port
descriptions. Extracted from supplements/tasmota.py and the reachability
dashboard so the power-topology engine and those consumers agree."""

from __future__ import annotations

import re

# Interface-name prefixes seen in switch port descriptions (ifAlias), e.g.
# "eth0.rpi5-pmod", "1/0/49.sw-cisco-shed". Mirrors the dashboard regex.
_IFACE_PREFIX_RE = re.compile(
    r"^(?:"
    r"eth\d+|eth-\w+"
    r"|eno\d+|enp\w+|en\d+"
    r"|lan\d*"
    r"|(?:10|25|40|100)g\d+"
    r"|oob\d+"
    r"|gi\d+|te\d+|xe\d+|fo\d+"
    r"|lag\d*"
    r"|\d+(?:/[\w]+)+"
    r")\."
)


def parse_controls_cell(value: str) -> tuple[str, ...]:
    """Split a `Controls` cell into target names (comma/newline separated)."""
    return tuple(c.strip() for c in re.split(r"[,\r\n]", value or "") if c.strip())


def strip_interface_prefix(desc: str) -> tuple[str, str]:
    """Split a port description into (interface, rest).

    "eth0.rpi5-pmod" -> ("eth0", "rpi5-pmod"); "desktop" -> ("", "desktop").
    """
    m = _IFACE_PREFIX_RE.match(desc)
    if not m:
        return ("", desc)
    return (desc[: m.end() - 1], desc[m.end():])
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_utils/test_controls.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Refactor `tasmota.py` to use the shared parser (behaviour-preserving)**

In `src/gdoc2netcfg/supplements/tasmota.py`, add near the top: `from gdoc2netcfg.utils.controls import parse_controls_cell`, then replace lines 338-342:

```python
        # Parse controls from spreadsheet extra column (comma or newline separated)
        controls = parse_controls_cell(host.extra.get("Controls", ""))
```

- [ ] **Step 6: Refactor the dashboard to use `strip_interface_prefix`**

In `scripts/ha-create-reachability-dashboard.py`, add `from gdoc2netcfg.utils.controls import strip_interface_prefix` and replace the local `_iface_pfx_re` block (lines 213-253) so lines 251-253 become:

```python
        iface_name, stripped = strip_interface_prefix(desc)
```

Delete the now-unused local `_iface_pfx_re` definition.

- [ ] **Step 7: Run the touched suites to verify no regression**

Run: `uv run pytest tests/test_supplements/test_tasmota.py tests/test_utils/test_controls.py -q` and `uv run ruff check src/ tests/ scripts/`
Expected: PASS; ruff clean.

- [ ] **Step 8: Commit**

```bash
git add src/gdoc2netcfg/utils/controls.py tests/test_utils/test_controls.py src/gdoc2netcfg/supplements/tasmota.py scripts/ha-create-reachability-dashboard.py
git commit -m "refactor: extract shared Controls/interface parsing into utils/controls" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Power node model, graph container, and category detection

**Files:**
- Create: `src/gdoc2netcfg/supplements/power_topology.py`
- Create: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Produces:
  - `CATEGORIES = ("host","tasmota","zigbee","poe","ups","mains","busbar","strip","unresolved")`
  - `infra_category(name: str) -> str | None` — `"ups"` for `ups-*`, etc., else `None`.
  - `@dataclass(frozen=True) PowerNode(id: str, category: str, label: str)`
  - `PowerGraph` with `.nodes: dict[str, PowerNode]`, `.warnings: list[str]`, methods `add_node(node)`, `add_edge(parent_id, child_id)`, `children_of(id) -> set[str]`, `parents_of(id) -> set[str]`, `roots() -> list[str]` (node ids with no parents, sorted).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_supplements/test_power_topology.py
from gdoc2netcfg.supplements.power_topology import (
    PowerGraph, PowerNode, infra_category,
)


def test_infra_category():
    assert infra_category("ups-soundproof") == "ups"
    assert infra_category("mains-welland") == "mains"
    assert infra_category("busbar-aux") == "busbar"
    assert infra_category("strip-bench") == "strip"
    assert infra_category("au-plug-4") is None
    assert infra_category("desktop") is None


def test_graph_add_and_roots():
    g = PowerGraph()
    g.add_node(PowerNode("mains-welland", "mains", "mains-welland"))
    g.add_node(PowerNode("au-plug-4", "tasmota", "au-plug-4"))
    g.add_node(PowerNode("desktop", "host", "desktop"))
    g.add_edge("mains-welland", "au-plug-4")
    g.add_edge("au-plug-4", "desktop")
    assert g.roots() == ["mains-welland"]
    assert g.children_of("au-plug-4") == {"desktop"}
    assert g.parents_of("desktop") == {"au-plug-4"}
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -v`
Expected: FAIL (import error).

- [ ] **Step 3: Implement the model**

```python
"""Power-dependency graph engine (read-only).

An edge A -> B means "A delivers power to B": cutting A contributes to
cutting B. Availability is OR over feeds, so redundancy (>=2 feeds) is
structural. See docs/superpowers/specs/2026-10-02-power-topology-engine-design.md.
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
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/power_topology.py tests/test_supplements/test_power_topology.py
git commit -m "feat(power): power-graph node model + category detection" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Build the graph from `Controls` edges (plugs + infra), site-scoped, with name resolution

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Modify: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Consumes: `parse_controls_cell` (Task 1); `DeviceRecord` (`sheet_name, machine, site, extra`); `Host` (`machine_name, hostname`); `PowerGraph`, `PowerNode`, `infra_category` (Task 2).
- Produces:
  - `NameResolver(node_ids: set[str], site_domain: str)` with `.resolve(raw: str) -> str | None`.
  - `_node_category(record) -> str` — `tasmota` for IoT plugs, `zigbee` for Zigbee rows, infra category by name, else `host`.
  - `add_controls_edges(graph, records, hosts, site) -> None` — adds nodes + `Controls` edges; unresolved targets become `unresolved` leaf nodes with a warning.

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/test_supplements/test_power_topology.py
from types import SimpleNamespace
from gdoc2netcfg.supplements.power_topology import add_controls_edges, NameResolver


def _rec(machine, controls="", site="", sheet="IoT"):
    return SimpleNamespace(sheet_name=sheet, machine=machine, site=site,
                           extra={"Controls": controls} if controls else {})


def _host(machine, hostname=None):
    return SimpleNamespace(machine_name=machine, hostname=hostname or machine)


def _site(name="welland", domain="welland.mithis.com"):
    return SimpleNamespace(name=name, domain=domain)


def test_resolver_strips_domain_and_first_label():
    r = NameResolver({"ten64", "desktop"}, "welland.mithis.com")
    assert r.resolve("desktop") == "desktop"
    assert r.resolve("ten64.welland.mithis.com") == "ten64"
    assert r.resolve("ten64.monarto.mithis.com") == "ten64"   # first-label fallback
    assert r.resolve("nope") is None


def test_controls_plug_to_host_and_chain():
    recs = [
        _rec("au-plug-48", "au-plug-46"),
        _rec("au-plug-46", "sw-bb-25g"),
        _rec("ups-soundproof", "au-plug-48"),
    ]
    hosts = [_host("sw-bb-25g")]
    g = PowerGraph()
    add_controls_edges(g, recs, hosts, _site())
    assert g.children_of("ups-soundproof") == {"au-plug-48"}
    assert g.children_of("au-plug-48") == {"au-plug-46"}
    assert g.children_of("au-plug-46") == {"sw-bb-25g"}
    assert g.nodes["ups-soundproof"].category == "ups"
    assert g.nodes["au-plug-48"].category == "tasmota"


def test_controls_site_scoping_excludes_other_site():
    recs = [_rec("au-plug-9", "ten64", site="monarto")]
    g = PowerGraph()
    add_controls_edges(g, recs, [], _site(name="welland"))
    assert "au-plug-9" not in g.nodes          # monarto controller excluded


def test_controls_unresolved_target_warns_and_keeps_leaf():
    recs = [_rec("au-plug-1", "ac")]            # "ac" is not a known host
    g = PowerGraph()
    add_controls_edges(g, recs, [], _site())
    assert "ac" in g.nodes
    assert g.nodes["ac"].category == "unresolved"
    assert any("ac" in w for w in g.warnings)
    assert g.children_of("au-plug-1") == {"ac"}
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -v`
Expected: FAIL (`add_controls_edges` / `NameResolver` not defined).

- [ ] **Step 3: Implement resolution + controls edges**

```python
# add to src/gdoc2netcfg/supplements/power_topology.py
from gdoc2netcfg.utils.controls import parse_controls_cell


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
    resolved to known nodes, else kept as `unresolved` leaves with a warning.
    """
    in_site = [r for r in records if _in_site(r.site, site.name)]

    # Known node ids for resolution: every in-site row's machine, plus host
    # machine_names and hostnames.
    node_ids: set[str] = {r.machine for r in in_site if r.machine}
    for h in hosts:
        node_ids.add(h.machine_name)
        node_ids.add(h.hostname)
    resolver = NameResolver(node_ids, site.domain)

    # Create a node per in-site controller row.
    for r in in_site:
        if not r.machine:
            continue
        graph.add_node(PowerNode(r.machine, _node_category(r), r.machine))

    # Add edges from each controller's Controls cell.
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
                # A resolved host that wasn't itself a controller row.
                graph.add_node(PowerNode(target, "host", target))
            graph.add_edge(r.machine, target)
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -v`
Expected: PASS (resolver + 3 controls tests + Task 2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/power_topology.py tests/test_supplements/test_power_topology.py
git commit -m "feat(power): build Controls edges (plugs + infra), site-scoped, name resolution" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Add PoE edges from bridge data (`switch → port → host`)

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Modify: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Consumes: `load_latest_bridge()` doc shape — per switch: `poe_status:[(port,admin,det)]`, `port_names:[(port,name)]`, `port_aliases:[(port,alias)]` (optional), `lldp_neighbors:[(local_port,sysname,port_id,chassis,port_desc|None)]`; `strip_interface_prefix` (Task 1); `NameResolver` (Task 3).
- Produces: `add_poe_edges(graph, bridge, resolver) -> None`. A delivering/held-off port becomes a `poe` node `"{switch} {ifname}"` with edge `switch → port → resolved-host`. Raises `ValueError` on an out-of-range status or a port missing from `port_names`.

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/test_supplements/test_power_topology.py
import pytest
from gdoc2netcfg.supplements.power_topology import add_poe_edges


def _bridge(poe, names, aliases=(), lldp=()):
    return {"sw-s1": {
        "poe_status": list(poe), "port_names": list(names),
        "port_aliases": list(aliases), "lldp_neighbors": list(lldp),
    }}


def _resolver(ids):
    return NameResolver(set(ids), "welland.mithis.com")


def test_poe_delivering_alias_edge():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    g.add_node(PowerNode("rpi5-pmod", "host", "rpi5-pmod"))
    add_poe_edges(
        g,
        _bridge([(1, 1, 3)], [(1, "1/0/1")], aliases=[(1, "eth0.rpi5-pmod")]),
        _resolver(["sw-s1", "rpi5-pmod"]),
    )
    assert "sw-s1 1/0/1" in g.nodes
    assert g.nodes["sw-s1 1/0/1"].category == "poe"
    assert g.children_of("sw-s1") == {"sw-s1 1/0/1"}
    assert g.children_of("sw-s1 1/0/1") == {"rpi5-pmod"}


def test_poe_searching_no_edge():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    add_poe_edges(g, _bridge([(4, 1, 2)], [(4, "1/0/4")]), _resolver(["sw-s1"]))
    assert "sw-s1 1/0/4" not in g.nodes


def test_poe_off_with_alias_edge():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    g.add_node(PowerNode("tweed", "host", "tweed"))
    add_poe_edges(
        g, _bridge([(5, 2, 1)], [(5, "1/0/5")], aliases=[(5, "eth0.tweed")]),
        _resolver(["sw-s1", "tweed"]),
    )
    assert g.children_of("sw-s1 1/0/5") == {"tweed"}


def test_poe_alias_unresolved_warns_and_leaf():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    add_poe_edges(
        g, _bridge([(7, 1, 3)], [(7, "1/0/7")], aliases=[(7, "eth0.ghost")]),
        _resolver(["sw-s1"]),
    )
    assert g.nodes["ghost"].category == "unresolved"
    assert g.children_of("sw-s1 1/0/7") == {"ghost"}
    assert any("ghost" in w for w in g.warnings)


def test_poe_missing_portname_raises():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    with pytest.raises(ValueError, match="no ifName"):
        add_poe_edges(g, _bridge([(1, 1, 3)], []), _resolver(["sw-s1"]))


def test_poe_out_of_range_raises():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    with pytest.raises(ValueError, match="out of range"):
        add_poe_edges(g, _bridge([(1, 9, 3)], [(1, "1/0/1")]), _resolver(["sw-s1"]))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k poe -v`
Expected: FAIL (`add_poe_edges` not defined).

- [ ] **Step 3: Implement PoE edges**

```python
# add to src/gdoc2netcfg/supplements/power_topology.py
from gdoc2netcfg.utils.controls import strip_interface_prefix

_ADMIN_ON, _ADMIN_OFF = 1, 2
_DET_DELIVERING = 3


def _poe_host_name(aliases: dict[int, str], lldp: dict[int, str], port: int,
                   graph: PowerGraph, switch: str) -> str | None:
    """Pick the connected-host name for a port: alias, else LLDP; warn on disagreement."""
    alias = strip_interface_prefix(aliases.get(port, "").strip())[1] if aliases.get(port) else ""
    lldp_name = lldp.get(port, "")
    if alias and lldp_name and alias != lldp_name:
        graph.warnings.append(
            f"PoE {switch} port {port}: alias {alias!r} disagrees with LLDP {lldp_name!r}; using LLDP"
        )
        return lldp_name
    return alias or lldp_name or None


def add_poe_edges(graph: PowerGraph, bridge, resolver: NameResolver) -> None:
    """Add switch -> poe-port -> host edges from bridge PoE data."""
    if not bridge:
        return
    for switch, doc in sorted(bridge.items()):
        if switch not in graph.nodes:
            continue  # switch not an in-site node; its PoE is out of scope
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
                if admin == _ADMIN_ON and detection != _DET_DELIVERING and detection != 2:
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
            port_id = f"{switch} {names[port]}"
            graph.add_node(PowerNode(port_id, "poe", port_id))
            graph.add_edge(switch, port_id)
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
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k poe -v`
Expected: PASS (6 PoE tests).

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/power_topology.py tests/test_supplements/test_power_topology.py
git commit -m "feat(power): add PoE switch->port->host edges with the RFC-3621 edge rule" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Graph integrity — cycle detection (raise) + mains-termination warnings

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Modify: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Produces:
  - `check_acyclic(graph) -> None` — raises `PowerCycleError` naming a cycle if one exists.
  - `hosts_not_reaching_mains(graph) -> list[str]` — node ids whose ancestry contains no `mains` node (sorted); each also appended to `graph.warnings`.

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/test_supplements/test_power_topology.py
from gdoc2netcfg.supplements.power_topology import (
    check_acyclic, hosts_not_reaching_mains, PowerCycleError,
)


def test_cycle_raises():
    g = PowerGraph()
    for n in ("a", "b"):
        g.add_node(PowerNode(n, "tasmota", n))
    g.add_edge("a", "b")
    g.add_edge("b", "a")
    with pytest.raises(PowerCycleError):
        check_acyclic(g)


def test_mains_termination_warns():
    g = PowerGraph()
    g.add_node(PowerNode("mains-w", "mains", "mains-w"))
    g.add_node(PowerNode("au-plug-1", "tasmota", "au-plug-1"))
    g.add_node(PowerNode("desktop", "host", "desktop"))   # fed by a parentless plug
    g.add_node(PowerNode("au-plug-2", "tasmota", "au-plug-2"))
    g.add_edge("mains-w", "au-plug-1")
    g.add_edge("au-plug-2", "desktop")   # au-plug-2 has no mains upstream
    bad = hosts_not_reaching_mains(g)
    assert "desktop" in bad
    assert "au-plug-1" not in bad
    assert any("desktop" in w for w in g.warnings)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k "cycle or mains" -v`
Expected: FAIL (names not defined).

- [ ] **Step 3: Implement integrity checks**

```python
# add to src/gdoc2netcfg/supplements/power_topology.py
def check_acyclic(graph: PowerGraph) -> None:
    """Raise PowerCycleError if the graph has a cycle."""
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
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k "cycle or mains" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/power_topology.py tests/test_supplements/test_power_topology.py
git commit -m "feat(power): cycle detection (raise) + mains-termination warnings" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Availability closures — `powered`, `downstream`, `upstream_levels`

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Modify: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Produces:
  - `powered(graph, blocked: frozenset[str] = frozenset()) -> set[str]` — nodes reachable from roots via child edges without entering a blocked node.
  - `downstream(graph, node_id) -> set[str]` — nodes that lose power if `node_id` is toggled off (excludes `node_id` and redundant survivors).
  - `upstream_levels(graph, node_id) -> list[list[str]]` — ancestors grouped by longest hop-distance from the node (level 0 = direct parents … last = mains), ids sorted within a level.

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/test_supplements/test_power_topology.py
from gdoc2netcfg.supplements.power_topology import (
    powered, downstream, upstream_levels,
)


def _chain_graph():
    g = PowerGraph()
    for n, c in [("mains-w", "mains"), ("p47", "tasmota"), ("ups-x", "ups"),
                 ("p48", "tasmota"), ("p46", "tasmota"), ("sw-bb", "host")]:
        g.add_node(PowerNode(n, c, n))
    g.add_edge("mains-w", "p47")
    g.add_edge("p47", "ups-x")
    g.add_edge("ups-x", "p48")
    g.add_edge("p48", "p46")
    g.add_edge("p46", "sw-bb")
    return g


def test_downstream_chain():
    g = _chain_graph()
    assert downstream(g, "p48") == {"p46", "sw-bb"}
    assert downstream(g, "p47") == {"ups-x", "p48", "p46", "sw-bb"}


def test_downstream_redundant_feed_drops_nothing():
    g = PowerGraph()
    for n, c in [("mains-w", "mains"), ("p10", "tasmota"), ("p11", "tasmota"),
                 ("srv", "host")]:
        g.add_node(PowerNode(n, c, n))
    g.add_edge("mains-w", "p10")
    g.add_edge("mains-w", "p11")
    g.add_edge("p10", "srv")
    g.add_edge("p11", "srv")        # redundant second feed
    assert downstream(g, "p10") == set()   # srv still fed by p11


def test_upstream_levels_order():
    g = _chain_graph()
    assert upstream_levels(g, "sw-bb") == [["p46"], ["p48"], ["ups-x"], ["p47"], ["mains-w"]]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k "downstream or upstream or powered" -v`
Expected: FAIL (names not defined).

- [ ] **Step 3: Implement closures**

```python
# add to src/gdoc2netcfg/supplements/power_topology.py
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
    # Longest-path distance: relax until stable (DAG, so it terminates).
    changed = True
    frontier = {node_id: 0}
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
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k "downstream or upstream or powered" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/power_topology.py tests/test_supplements/test_power_topology.py
git commit -m "feat(power): availability-aware downstream/upstream closures" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Rendering — ASCII `tree` + `upstream` hop-level lines

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Modify: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Produces:
  - `render_tree(graph) -> str` — roots at top (sorted), each child subtree indented with `└─ `/`├─ ` connectors; each line `category: label`. A node reached by multiple parents is printed under each (a DAG shown as a tree).
  - `render_upstream(graph, node_id) -> str` — one line per hop-level (direct → mains), same-level nodes comma-joined, each `category: label`.

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/test_supplements/test_power_topology.py
from gdoc2netcfg.supplements.power_topology import render_tree, render_upstream


def test_render_upstream_lines():
    g = _chain_graph()
    assert render_upstream(g, "sw-bb") == (
        "tasmota: p46\n"
        "tasmota: p48\n"
        "ups: ups-x\n"
        "tasmota: p47\n"
        "mains: mains-w"
    )


def test_render_tree_shape():
    g = PowerGraph()
    for n, c in [("mains-w", "mains"), ("p1", "tasmota"), ("d", "host")]:
        g.add_node(PowerNode(n, c, n))
    g.add_edge("mains-w", "p1")
    g.add_edge("p1", "d")
    assert render_tree(g) == (
        "mains: mains-w\n"
        "└─ tasmota: p1\n"
        "   └─ host: d"
    )
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k render -v`
Expected: FAIL (names not defined).

- [ ] **Step 3: Implement rendering**

```python
# add to src/gdoc2netcfg/supplements/power_topology.py
def _label(graph: PowerGraph, nid: str) -> str:
    n = graph.nodes[nid]
    return f"{n.category}: {n.label}"


def render_tree(graph: PowerGraph) -> str:
    lines: list[str] = []

    def walk(nid: str, prefix: str, is_root: bool, is_last: bool) -> None:
        if is_root:
            lines.append(_label(graph, nid))
            child_prefix = ""
        else:
            connector = "└─ " if is_last else "├─ "
            lines.append(f"{prefix}{connector}{_label(graph, nid)}")
            child_prefix = prefix + ("   " if is_last else "│  ")
        kids = sorted(graph.children_of(nid))
        for i, child in enumerate(kids):
            walk(child, child_prefix, False, i == len(kids) - 1)

    for root in graph.roots():
        walk(root, "", True, True)
    return "\n".join(lines)


def render_upstream(graph: PowerGraph, node_id: str) -> str:
    levels = upstream_levels(graph, node_id)
    return "\n".join(
        ", ".join(_label(graph, nid) for nid in level) for level in levels
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_supplements/test_power_topology.py -k render -v`
Expected: PASS. Then run the full engine suite: `uv run pytest tests/test_supplements/test_power_topology.py -q`.

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/power_topology.py tests/test_supplements/test_power_topology.py
git commit -m "feat(power): ASCII tree + upstream hop-level rendering" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: CLI — `gdoc2netcfg power tree|downstream|upstream`

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py` (add the one orchestration entry point)
- Modify: `src/gdoc2netcfg/cli/main.py` (parser group + dispatch + 3 handlers)
- Create: `tests/test_cli/test_power.py`

**Interfaces:**
- Consumes: `_load_config`, `_build_pipeline`, `_load_latest_from_db` (all in `cli/main.py`); the engine functions from Tasks 2-7.
- Produces:
  - `build_power_graph(records, hosts, bridge, site) -> PowerGraph` — nodes+Controls edges (Task 3), PoE edges (Task 4), `check_acyclic`, `hosts_not_reaching_mains`.
  - `cmd_power_tree/_downstream/_upstream(args) -> int`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli/test_power.py
from types import SimpleNamespace
from unittest.mock import patch
from gdoc2netcfg.cli.main import main


def _rec(machine, controls="", site="welland", sheet="IoT"):
    return SimpleNamespace(sheet_name=sheet, machine=machine, site=site,
                           extra={"Controls": controls} if controls else {})


def _host(machine):
    return SimpleNamespace(machine_name=machine, hostname=machine)


def _cfg():
    return SimpleNamespace(site=SimpleNamespace(name="welland",
                                                domain="welland.mithis.com"))


def _patch(records, bridge=None):
    return [
        patch("gdoc2netcfg.cli.main._load_config", return_value=_cfg()),
        patch("gdoc2netcfg.cli.main._build_pipeline",
              return_value=(records, [_host("desktop")], None, None)),
        patch("gdoc2netcfg.cli.main._load_latest_from_db", return_value=bridge),
    ]


def test_power_tree(capsys):
    recs = [_rec("mains-welland", "au-plug-4"), _rec("au-plug-4", "desktop")]
    ctx = _patch(recs)
    for p in ctx:
        p.start()
    try:
        assert main(["power", "tree"]) == 0
    finally:
        for p in ctx:
            p.stop()
    out = capsys.readouterr().out
    assert "mains: mains-welland" in out
    assert "tasmota: au-plug-4" in out


def test_power_downstream(capsys):
    recs = [_rec("mains-welland", "au-plug-4"), _rec("au-plug-4", "desktop")]
    ctx = _patch(recs)
    for p in ctx:
        p.start()
    try:
        assert main(["power", "downstream", "au-plug-4"]) == 0
    finally:
        for p in ctx:
            p.stop()
    assert "desktop" in capsys.readouterr().out


def test_power_upstream_unknown_node_exit_1(capsys):
    ctx = _patch([_rec("au-plug-4", "desktop")])
    for p in ctx:
        p.start()
    try:
        assert main(["power", "upstream", "nonexistent"]) == 1
    finally:
        for p in ctx:
            p.stop()
    assert "nonexistent" in capsys.readouterr().err
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_cli/test_power.py -v`
Expected: FAIL (no `power` command).

- [ ] **Step 3: Add `build_power_graph` to the engine**

```python
# add to src/gdoc2netcfg/supplements/power_topology.py
def build_power_graph(records, hosts, bridge, site) -> PowerGraph:
    """Assemble the full power graph for one site and run integrity checks."""
    graph = PowerGraph()
    add_controls_edges(graph, records, hosts, site)
    node_ids = set(graph.nodes)
    for h in hosts:
        node_ids.add(h.machine_name)
        node_ids.add(h.hostname)
    add_poe_edges(graph, bridge, NameResolver(node_ids, site.domain))
    check_acyclic(graph)
    hosts_not_reaching_mains(graph)   # appends warnings
    return graph
```

- [ ] **Step 4: Wire the CLI parser group** (`src/gdoc2netcfg/cli/main.py`, immediately before the `commands = {...}` dict at line ~3799)

Add to the parser-building section (near the `db` group, ~line 3675):

```python
    # power (read-only power-topology engine)
    power_parser = subparsers.add_parser(
        "power", help="Power-dependency topology (read-only)",
    )
    power_subparsers = power_parser.add_subparsers(dest="power_command")
    power_subparsers.add_parser("tree", help="Print the power hierarchy as a tree")
    power_down = power_subparsers.add_parser(
        "downstream", help="What loses power if a node is toggled off",
    )
    power_down.add_argument("node", help="Controller node (plug/port/ups/switch)")
    power_up = power_subparsers.add_parser(
        "upstream", help="What controls power to a host",
    )
    power_up.add_argument("host", help="Host machine name")
```

Add the dispatch block (with the other `if args.command == ...` blocks, ~line 3752):

```python
    if args.command == "power":
        if args.power_command == "tree":
            return cmd_power_tree(args)
        elif args.power_command == "downstream":
            return cmd_power_downstream(args)
        elif args.power_command == "upstream":
            return cmd_power_upstream(args)
        else:
            power_parser.print_help()
            return 0
```

- [ ] **Step 5: Add the handlers** (`src/gdoc2netcfg/cli/main.py`, near `cmd_tasmota_show`)

```python
def _power_graph(args):
    from gdoc2netcfg.supplements.power_topology import build_power_graph
    config = _load_config(args)
    records, hosts, _inventory, _result = _build_pipeline(config)
    bridge = _load_latest_from_db(config, "load_latest_bridge")
    if bridge is None:
        print("warning: no completed 'bridge' scan — PoE contributes nothing "
              "(run: sudo .venv/bin/gdoc2netcfg bridge --force)", file=sys.stderr)
    graph = build_power_graph(records, hosts, bridge, config.site)
    for w in graph.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return graph


def cmd_power_tree(args: argparse.Namespace) -> int:
    from gdoc2netcfg.supplements.power_topology import render_tree
    print(render_tree(_power_graph(args)))
    return 0


def cmd_power_downstream(args: argparse.Namespace) -> int:
    from gdoc2netcfg.supplements.power_topology import downstream
    graph = _power_graph(args)
    if args.node not in graph.nodes:
        print(f"error: {args.node!r} is not a node in the power graph",
              file=sys.stderr)
        return 1
    for nid in sorted(downstream(graph, args.node)):
        print(f"{graph.nodes[nid].category}: {graph.nodes[nid].label}")
    return 0


def cmd_power_upstream(args: argparse.Namespace) -> int:
    from gdoc2netcfg.supplements.power_topology import render_upstream
    graph = _power_graph(args)
    if args.host not in graph.nodes:
        print(f"error: {args.host!r} is not a node in the power graph",
              file=sys.stderr)
        return 1
    print(render_upstream(graph, args.host))
    return 0
```

- [ ] **Step 6: Run to verify pass**

Run: `uv run pytest tests/test_cli/test_power.py -v`
Expected: PASS (3 tests).

- [ ] **Step 7: Full suite + lint**

Run: `uv run pytest -q` and `uv run ruff check src/ tests/ scripts/`
Expected: PASS; ruff clean.

- [ ] **Step 8: Commit**

```bash
git add src/gdoc2netcfg/supplements/power_topology.py src/gdoc2netcfg/cli/main.py tests/test_cli/test_power.py
git commit -m "feat(power): wire 'power' CLI group (tree/downstream/upstream)" \
  -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Notes for the executor

- `tests/test_utils/` and `tests/test_cli/` already exist; add an `__init__.py` only if sibling dirs have one (they don't — pytest uses rootdir discovery).
- The engine is **pure** (no I/O): all three edge builders take plain data (`records`, `hosts`, `bridge` dict, `site`), so every engine test constructs inputs directly with `SimpleNamespace`/dicts — no DB, no network.
- Real-data smoke check once Task 8 lands (optional, read-only, uses the prod cache): from the worktree, `uv run gdoc2netcfg -c /opt/gdoc2netcfg/gdoc2netcfg.toml power tree` — expect the soundproof-rack chain and warnings for unresolved appliances (`ac`, `bar header`). Do **not** write anything.
- Site scoping uses `config.site.name`; the spec's cross-site domain-suffix stripping is covered by the first-DNS-label fallback in `NameResolver` plus site filtering (monarto rows excluded by `Site`), so re-parsing the Sites sheet for other domains is not needed in this sub-project.
