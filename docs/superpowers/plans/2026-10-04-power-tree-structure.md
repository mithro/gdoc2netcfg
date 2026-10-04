# Power-Tree Structure, Locations & Validation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `gdoc2netcfg power tree` render a meter-rooted, location-grouped power hierarchy that flags cross-location nonsense and stale switches, models the UPS and BMCs, and enforce well-formed `Controls`/`Location` sheet data at CSV ingest.

**Architecture:** The power graph stays **pure power semantics** (nodes = power points, edges = "A powers B"). The meter root and location hierarchy are a **render-time grouping layer** over that graph — they are *not* graph nodes, so `downstream`/`upstream`/`powered` are untouched. Controls/Location validity is enforced in the constraint layer (`validate_all`), so it rides the existing sheet contract (`fetch` refuses / `generate` exits 1). BMCs and locations are sourced only from the structured pipeline (`records`, `hosts`), never by re-parsing CSVs.

**Tech Stack:** Python 3.11+, `uv`, pytest, ruff. Builds on `src/gdoc2netcfg/supplements/power_topology.py`, `src/gdoc2netcfg/constraints/validators.py`, `src/gdoc2netcfg/utils/controls.py`, `src/gdoc2netcfg/cli/main.py`.

**Spec:** `docs/superpowers/specs/2026-10-03-power-tree-structure-design.md`

## Global Constraints

- **Branch:** `power-tree-structure`, stacked on PR #58 (`worktree-power-topology`); worktree `.claude/worktrees/power-tree-structure`. Never commit to the primary (`origin/main`) checkout.
- **Always `uv run`** — never bare python/pip. Dates ISO 8601 / day-first, never American.
- **Fail loud, never fabricate, never silently discard.** A port name, location, or Controls target that can't be resolved is an error, not a guess or a `continue`.
- **Switch-sourced port names only** — the PoE port label is the bridge `port_names` ifName. Never regex-derive a port number.
- **Small, incremental commits** — one concern per commit; commit subject needing "and" → split.
- **ERROR validators must not ship before the data is clean** — Task 8 (data-fix) gates merge; a clean `validate` over the full all-sites row set is the gate.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` then `Claude-Session: https://claude.ai/code/session_01Rk5TS5wUeQN9a9tbHdNfLd`.
- Run the full suite (`uv run pytest`) and `uv run ruff check src/ tests/` before completing each task; report any failure by name.

## Review Focus

Spec-implied inputs no task's happy-path test exercises — each gets a pinned test in its owning task:
1. **A host with two feeds in different locations** (e.g. plug + BMC, or redundant plugs) — the node appears under each parent; the cross-location flag must fire per edge independently, not globally. (Task 7)
2. **A node with no location** (Zigbee plugs carry no location column; an infra row with a blank location) — must be flagged `⚠ feed/loc unknown` and placed under a stable `[unknown location]` bucket, never crash or vanish. (Tasks 4, 7)
3. **`--best-effort` on the very data that fails validation** — unresolved Controls / confusable locations must still render (flagged), not raise. (Task 8)
4. **A BMC whose parent machine has no node** (parent row absent/dropped) — add the BMC node and flag it, never create a dangling edge to a missing node. (Task 5)
5. **Natural sort across heterogeneous ifName formats at one location** (`1/0/2`, `1/g10`, `gi1`) and non-port siblings (`au-plug-2` vs `au-plug-10`) — ordering must be total and stable, never raise on a name with no digits. (Tasks 1, 7)

---

## File Structure

- `src/gdoc2netcfg/utils/location.py` — **new**: `parse_location_path`, `location_key`, `natural_sort_key`. Pure, dependency-free string helpers shared by the validator and the renderer.
- `src/gdoc2netcfg/constraints/validators.py` — **modify**: add `validate_controls` and `validate_locations`; register both in `validate_all`.
- `src/gdoc2netcfg/supplements/power_topology.py` — **modify**: `PowerNode` gains `location`/`note`; location sourcing; BMC edges; stale-switch exclusion; `render_tree` rewrite (meter + location tree + natural sort + cross-location flag + note).
- `src/gdoc2netcfg/cli/main.py` — **modify**: `--best-effort` flag; refuse on graph-level violations.
- `tests/test_utils/test_location.py`, `tests/test_constraints/…`, `tests/test_supplements/test_power_topology.py`, `tests/test_cli/test_power.py` — tests.
- `scripts/power_data_fix.py` — **new, throwaway** (Task 8): one-off, dry-run-default sheet edits; committed as evidence then removed.

---

### Task 1: Location & natural-sort string utilities

**Files:**
- Create: `src/gdoc2netcfg/utils/location.py`
- Test: `tests/test_utils/test_location.py`

**Interfaces:**
- Produces:
  - `parse_location_path(cell: str) -> tuple[str, ...]` — split a location cell on ` - ` into a trimmed path; `""`/whitespace → `()`.
  - `location_key(cell: str) -> str` — a normalized confusable key: casefold, collapse internal whitespace, drop non-alphanumeric except the path separator. Two cells that differ only by spelling/spacing/case share a key.
  - `natural_sort_key(s: str) -> tuple` — split into digit / non-digit runs; digits compared as ints, text casefolded. Total order; never raises on digit-less input.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_utils/test_location.py
from gdoc2netcfg.utils.location import (
    parse_location_path, location_key, natural_sort_key,
)


def test_parse_location_path_splits_on_dash():
    assert parse_location_path("Back Shed - Soundproof Rack") == ("Back Shed", "Soundproof Rack")


def test_parse_location_path_blank_is_empty():
    assert parse_location_path("   ") == ()


def test_location_key_collapses_confusable_spellings():
    assert location_key("Sound Proof Rack") == location_key("Soundproof Rack")
    assert location_key("Back Shed - Soundproof Rack") != location_key("Office")


def test_natural_sort_orders_numeric_segments():
    data = ["1/0/11", "1/0/2", "1/0/1"]
    assert sorted(data, key=natural_sort_key) == ["1/0/1", "1/0/2", "1/0/11"]
    assert sorted(["au-plug-10", "au-plug-2"], key=natural_sort_key) == ["au-plug-2", "au-plug-10"]


def test_natural_sort_handles_no_digits():
    assert natural_sort_key("gi") == natural_sort_key("gi")  # does not raise
    assert sorted(["gi", "1/0/1"], key=natural_sort_key)  # total order, no crash
```

- [ ] **Step 2: Run, verify they fail** — `uv run pytest tests/test_utils/test_location.py -v` → ImportError / fails.

- [ ] **Step 3: Implement**

```python
# src/gdoc2netcfg/utils/location.py
"""Location-path and natural-sort string helpers (pure, dependency-free)."""

from __future__ import annotations

import re

_LOCATION_SEP = " - "
_WS = re.compile(r"\s+")
_NONALNUM = re.compile(r"[^0-9a-z ]")
_DIGITS = re.compile(r"(\d+)")


def parse_location_path(cell: str) -> tuple[str, ...]:
    """Split a location cell into a trimmed hierarchy path (`A - B - C`)."""
    if not cell or not cell.strip():
        return ()
    return tuple(part.strip() for part in cell.split(_LOCATION_SEP) if part.strip())


def location_key(cell: str) -> str:
    """Normalized confusable key: casefold, collapse whitespace, drop punctuation.

    Two location cells that differ only by case/spacing/punctuation map to the
    same key — used ONLY to detect confusable duplicates, never to merge them.
    """
    parts = []
    for seg in parse_location_path(cell):
        seg = _NONALNUM.sub(" ", seg.casefold())
        parts.append(_WS.sub(" ", seg).strip().replace(" ", ""))
    return "/".join(p for p in parts if p)


def natural_sort_key(s: str) -> tuple:
    """Key for human/natural ordering: numeric runs compare as ints."""
    out: list[tuple[int, object]] = []
    for tok in _DIGITS.split(s):
        if tok.isdigit():
            out.append((0, int(tok)))
        elif tok:
            out.append((1, tok.casefold()))
    return tuple(out)
```

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/test_utils/test_location.py -v` → PASS.

- [ ] **Step 5: Commit** — `feat(utils): location-path and natural-sort helpers`

---

### Task 2: Controls validator (ERROR) at CSV ingest

**Files:**
- Modify: `src/gdoc2netcfg/constraints/validators.py`
- Test: `tests/test_constraints/test_controls_validator.py`

**Interfaces:**
- Consumes: `parse_controls_cell` (utils/controls), `NameResolver` (supplements/power_topology).
- Produces: `validate_controls(records, hosts, site) -> ValidationResult` — one ERROR per `Controls` value that resolves to no known node (code `controls_unresolved`); registered in `validate_all`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_constraints/test_controls_validator.py
from types import SimpleNamespace
from gdoc2netcfg.constraints.validators import validate_controls
from gdoc2netcfg.models.constraints import Severity


def _rec(machine, controls="", sheet="iot", site="welland", row=1):
    return SimpleNamespace(sheet_name=sheet, machine=machine, site=site,
                           row_number=row, extra={"Controls": controls} if controls else {})


def _host(machine, hostname=None):
    return SimpleNamespace(machine_name=machine, hostname=hostname or machine)


def _site():
    return SimpleNamespace(name="welland", domain="welland.mithis.com")


def test_unresolved_controls_target_is_error():
    recs = [_rec("au-plug-3", "bar heater")]
    res = validate_controls(recs, [_host("au-plug-3")], _site())
    codes = [(v.code, v.severity) for v in res.violations]
    assert ("controls_unresolved", Severity.ERROR) in codes


def test_resolvable_controls_target_is_clean():
    recs = [_rec("au-plug-4", "desktop")]
    res = validate_controls(recs, [_host("au-plug-4"), _host("desktop")], _site())
    assert res.violations == []
```

- [ ] **Step 2: Run, verify it fails** — `uv run pytest tests/test_constraints/test_controls_validator.py -v` → fails (no `validate_controls`).

- [ ] **Step 3: Implement** — add to `validators.py`:

```python
def validate_controls(records, hosts, site) -> ValidationResult:
    """Every Controls target must resolve to a known node (ERROR, sheet contract)."""
    from gdoc2netcfg.supplements.power_topology import NameResolver
    from gdoc2netcfg.utils.controls import parse_controls_cell

    result = ValidationResult()
    node_ids = {r.machine for r in records if getattr(r, "machine", "")}
    for h in hosts:
        node_ids.add(h.machine_name)
        node_ids.add(h.hostname)
    resolver = NameResolver(node_ids, site.domain)

    for r in records:
        for raw in parse_controls_cell(r.extra.get("Controls", "")):
            if resolver.resolve(raw) is None:
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="controls_unresolved",
                    message=(f"Controls target {raw!r} (from {r.machine!r}) "
                             f"matches no known host/plug/infra node"),
                    record_id=f"{r.sheet_name}:{r.row_number}",
                    field="Controls",
                ))
    return result
```

- [ ] **Step 4: Register in `validate_all`** — add `validate_controls(records, hosts, inventory.site),` to the list (passing `inventory.site`). Run `uv run pytest tests/test_constraints/ -v`.

- [ ] **Step 5: Run full suite + ruff** — `uv run pytest`, `uv run ruff check src/ tests/`. Confirm pre-existing suite still green.

- [ ] **Step 6: Commit** — `feat(constraints): enforce Controls targets resolve (sheet contract)`

---

### Task 3: Location validator (ERROR) at CSV ingest

**Files:**
- Modify: `src/gdoc2netcfg/constraints/validators.py`
- Test: `tests/test_constraints/test_location_validator.py`

**Interfaces:**
- Consumes: `parse_location_path`, `location_key` (utils/location).
- Produces: `validate_locations(records) -> ValidationResult` — ERROR `location_confusable` when two records' location cells share a `location_key` but differ raw; registered in `validate_all`. Reads the per-sheet location column (`Physical Location` or `Location`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_constraints/test_location_validator.py
from types import SimpleNamespace
from gdoc2netcfg.constraints.validators import validate_locations
from gdoc2netcfg.models.constraints import Severity


def _rec(machine, loc, key="Physical Location", sheet="iot", row=1):
    return SimpleNamespace(sheet_name=sheet, machine=machine, row_number=row,
                           extra={key: loc})


def test_confusable_locations_are_error():
    recs = [_rec("a", "Sound Proof Rack"), _rec("b", "Soundproof Rack", row=2)]
    res = validate_locations(recs)
    assert any(v.code == "location_confusable" and v.severity == Severity.ERROR
               for v in res.violations)


def test_consistent_locations_are_clean():
    recs = [_rec("a", "Back Shed - Soundproof Rack"),
            _rec("b", "Back Shed - Soundproof Rack", row=2)]
    assert validate_locations(recs).violations == []
```

- [ ] **Step 2: Run, verify it fails.**

- [ ] **Step 3: Implement** — add to `validators.py`:

```python
_LOCATION_KEYS = ("Physical Location", "Location")


def _record_location(record) -> str:
    for key in _LOCATION_KEYS:
        val = record.extra.get(key)
        if val:
            return val
    return ""


def validate_locations(records) -> ValidationResult:
    """Confusable location spellings are an ERROR to reconcile (sheet contract)."""
    from gdoc2netcfg.utils.location import location_key

    result = ValidationResult()
    by_key: dict[str, set[str]] = {}
    first_seen: dict[str, object] = {}
    for r in records:
        loc = _record_location(r)
        if not loc:
            continue
        k = location_key(loc)
        if not k:
            continue
        by_key.setdefault(k, set()).add(loc)
        first_seen.setdefault(k, r)

    for k, raws in by_key.items():
        if len(raws) > 1:
            r = first_seen[k]
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="location_confusable",
                message=("Confusable location spellings for one place: "
                         + ", ".join(sorted(repr(x) for x in raws))
                         + " — make them identical"),
                record_id=f"{r.sheet_name}:{r.row_number}",
                field="Location",
            ))
    return result
```

- [ ] **Step 4: Register in `validate_all`** — add `validate_locations(records),`. Run `uv run pytest tests/test_constraints/ -v`.

- [ ] **Step 5: Full suite + ruff.**

- [ ] **Step 6: Commit** — `feat(constraints): flag confusable location spellings (sheet contract)`

---

### Task 4: `PowerNode` carries location + note; source location onto nodes

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Test: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Consumes: `parse_location_path` (utils/location), `_record_location` logic (duplicate the two-key lookup locally — do not import from constraints).
- Produces:
  - `PowerNode(id, category, label, location: tuple[str, ...] = (), note: str = "")`.
  - `add_controls_edges` sets `location`/`note` on each sheet-backed node from its record (`Physical Location`/`Location`; `note` from `Human Name` when present). An unlocated placed node keeps `location=()` (rendered under `[unknown location]`).

- [ ] **Step 1: Write the failing test**

```python
def test_node_carries_location_from_record():
    from gdoc2netcfg.supplements.power_topology import PowerGraph, add_controls_edges
    from types import SimpleNamespace
    rec = SimpleNamespace(sheet_name="iot", machine="au-plug-46", site="welland",
                          row_number=1,
                          extra={"Controls": "sw-bb-25g",
                                 "Physical Location": "Back Shed - Soundproof Rack"})
    g = PowerGraph()
    add_controls_edges(g, [rec], [], SimpleNamespace(name="welland", domain="welland.mithis.com"))
    assert g.nodes["au-plug-46"].location == ("Back Shed", "Soundproof Rack")
```

- [ ] **Step 2: Run, verify it fails** (PowerNode has no `location`).

- [ ] **Step 3: Implement** — add fields to `PowerNode`; in `add_controls_edges`, when creating a node from a record, compute `location=parse_location_path(_record_location(r))` and `note=r.extra.get("Human Name", "")`. Keep the existing id/category/label. (Target/unresolved leaf nodes created for Controls targets keep `location=()` until their own row is seen — last-writer by node id via a two-pass: create all record nodes first, which the code already does.)

- [ ] **Step 4: Run, verify pass.** Also assert an unlocated record yields `location == ()`.

- [ ] **Step 5: Full suite + ruff.**

- [ ] **Step 6: Commit** — `feat(power): PowerNode carries location + note, sourced from records`

---

### Task 5: BMC nodes + power-control edges

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Test: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Consumes: `hosts` (each BMC host has `hostname` whose first label contains `bmc` and `machine_name` = the parent machine).
- Produces: `add_bmc_edges(graph, hosts) -> None` — for each BMC host, add node `PowerNode(host.hostname, "bmc", host.hostname, location=<parent's location>)` and edge `host.hostname -> host.machine_name`. If the parent machine is not a node, add the BMC node, add a warning, and skip the edge (Review Focus #4). Called from `build_power_graph` after `add_controls_edges`.

- [ ] **Step 1: Write the failing test**

```python
def test_bmc_powers_its_host():
    from gdoc2netcfg.supplements.power_topology import PowerGraph, PowerNode, add_bmc_edges
    from types import SimpleNamespace
    g = PowerGraph()
    g.add_node(PowerNode("big-storage", "host", "big-storage"))
    bmc = SimpleNamespace(hostname="bmc.big-storage", machine_name="big-storage")
    add_bmc_edges(g, [bmc])
    assert g.nodes["bmc.big-storage"].category == "bmc"
    assert "bmc.big-storage" in g.parents_of("big-storage")


def test_bmc_without_parent_node_warns_no_edge():
    from gdoc2netcfg.supplements.power_topology import PowerGraph, add_bmc_edges
    from types import SimpleNamespace
    g = PowerGraph()
    add_bmc_edges(g, [SimpleNamespace(hostname="bmc.ghost", machine_name="ghost")])
    assert "bmc.ghost" in g.nodes
    assert g.children_of("bmc.ghost") == set()
    assert any("ghost" in w for w in g.warnings)
```

- [ ] **Step 2: Run, verify it fails.**

- [ ] **Step 3: Implement**

```python
def _is_bmc_host(host) -> bool:
    return "bmc" in host.hostname.split(".")[0].lower()


def add_bmc_edges(graph: PowerGraph, hosts) -> None:
    """A BMC can power-cycle its host: edge bmc.<host> -> <host>."""
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
```

Add `"bmc"` to `CATEGORIES`. Call `add_bmc_edges(graph, hosts)` in `build_power_graph` after `add_controls_edges`, before `add_poe_edges`.

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Full suite + ruff.**

- [ ] **Step 6: Commit** — `feat(power): model BMCs as power-control nodes (bmc.X -> X)`

---

### Task 6: Stale-switch exclusion in PoE edges

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Test: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Changes `add_poe_edges`: a bridge switch that does **not** resolve to an existing graph node (`_match_switch_node` returns None) is **stale scan history** → append a warning and `continue` (do NOT add it as a root). Replaces the current "add as root + warn" behaviour.

- [ ] **Step 1: Write the failing test** (asserts the new behaviour: a bridge-only switch absent from inventory produces no node and a stale warning)

```python
def test_stale_bridge_switch_excluded():
    from gdoc2netcfg.supplements.power_topology import PowerGraph, add_poe_edges, NameResolver
    g = PowerGraph()  # empty inventory
    bridge = {"sw-ghost": {"port_names": [(1, "1/0/1")],
                           "poe_status": [(1, 1, 3)],
                           "lldp_neighbors": [(1, "somehost", "x", "y", None)]}}
    add_poe_edges(g, bridge, NameResolver(set(), "welland.mithis.com"))
    assert "sw-ghost" not in g.nodes
    assert any("sw-ghost" in w and "stale" in w.lower() for w in g.warnings)
```

- [ ] **Step 2: Run, verify it fails** (today it adds `sw-ghost` as a root).

- [ ] **Step 3: Implement** — in `add_poe_edges`, replace the `switch_id is None` branch:

```python
        switch_id = _match_switch_node(graph, switch)
        if switch_id is None:
            graph.warnings.append(
                f"bridge switch {switch!r} is not in current inventory — "
                f"stale scan history; its PoE subtree is excluded"
            )
            continue
```

- [ ] **Step 4: Run, verify pass.** Confirm a switch that IS in inventory still gets its PoE subtree (existing tests stay green).

- [ ] **Step 5: Full suite + ruff.**

- [ ] **Step 6: Commit** — `fix(power): exclude bridge switches absent from inventory (stale history)`

---

### Task 7: `render_tree` rewrite — meter root, nested locations, natural sort, flags, note

**Files:**
- Modify: `src/gdoc2netcfg/supplements/power_topology.py`
- Test: `tests/test_supplements/test_power_topology.py`

**Interfaces:**
- Consumes: `natural_sort_key`, `location_key` (utils/location); `PowerNode.location`, `.note`.
- Produces: `render_tree(graph, site_name: str) -> str` (signature gains `site_name`). CLI passes `config.site.name`. Output:
  - line 1: `mains: meter-<site_name>`;
  - power **roots** (parentless nodes) grouped under a nested location tree keyed by each root's `location` path (`[unknown location]` bucket for `()`); location headers rendered `[Name]` indented by depth;
  - each root's power subtree walked via child edges, siblings ordered by `natural_sort_key(child label)`;
  - a child whose `location_key` differs from its parent's gets a trailing `  ⚠ loc=<child location display>`; a placed node with empty location gets `  ⚠ loc unknown`;
  - a node with a non-empty `note` renders `category: label (note)`.

**Design note (keep the graph pure):** the meter and `[location]` lines are render-time only; no graph nodes/edges are added, so `downstream`/`upstream`/`powered` are unchanged.

- [ ] **Step 1: Write the failing tests**

```python
def _g_rack():
    from gdoc2netcfg.supplements.power_topology import PowerGraph, PowerNode
    g = PowerGraph()
    rack = ("Back Shed", "Soundproof Rack")
    g.add_node(PowerNode("au-plug-47", "tasmota", "au-plug-47", location=rack))
    g.add_node(PowerNode("ups-apc-srv3k", "ups", "ups-apc-srv3k", location=rack,
                         note="monitored by rpi4-ups"))
    g.add_node(PowerNode("au-plug-48", "tasmota", "au-plug-48", location=rack))
    g.add_node(PowerNode("sw-bb-25g", "host", "sw-bb-25g", location=rack))
    g.add_edge("au-plug-47", "ups-apc-srv3k")
    g.add_edge("ups-apc-srv3k", "au-plug-48")
    g.add_edge("au-plug-48", "sw-bb-25g")
    return g


def test_render_meter_root_and_location_nesting():
    from gdoc2netcfg.supplements.power_topology import render_tree
    out = render_tree(_g_rack(), "welland")
    lines = out.splitlines()
    assert lines[0] == "mains: meter-welland"
    assert any(line.strip() == "[Back Shed]" for line in lines)
    assert any(line.strip() == "[Soundproof Rack]" for line in lines)
    assert any("ups: ups-apc-srv3k (monitored by rpi4-ups)" in line for line in lines)


def test_render_cross_location_flag():
    from gdoc2netcfg.supplements.power_topology import PowerGraph, PowerNode, render_tree
    g = PowerGraph()
    g.add_node(PowerNode("au-plug-20", "tasmota", "au-plug-20", location=("Office",)))
    g.add_node(PowerNode("monitors", "host", "monitors", location=("Lounge",)))
    g.add_edge("au-plug-20", "monitors")
    out = render_tree(g, "welland")
    assert "⚠ loc=Lounge" in out


def test_render_ports_natural_sorted():
    from gdoc2netcfg.supplements.power_topology import PowerGraph, PowerNode, render_tree
    g = PowerGraph()
    g.add_node(PowerNode("sw", "host", "sw", location=("Rack",)))
    for p in ("sw 1/0/11", "sw 1/0/2", "sw 1/0/1"):
        g.add_node(PowerNode(p, "poe", p, location=("Rack",)))
        g.add_edge("sw", p)
    out = render_tree(g, "welland")
    order = [l for l in out.splitlines() if "poe:" in l]
    assert order == sorted(order, key=lambda l: ["1/0/1" in l, "1/0/2" in l, "1/0/11" in l]) \
        and "1/0/1" in order[0] and "1/0/2" in order[1] and "1/0/11" in order[2]
```

- [ ] **Step 2: Run, verify they fail** (signature + behaviour change).

- [ ] **Step 3: Implement** the rewrite:

```python
from gdoc2netcfg.utils.location import location_key, natural_sort_key


def _label(graph: PowerGraph, nid: str) -> str:
    n = graph.nodes[nid]
    base = f"{n.category}: {n.label}"
    return f"{base} ({n.note})" if n.note else base


def _loc_display(path: tuple[str, ...]) -> str:
    return " - ".join(path) if path else ""


def _insert(tree: dict, path: tuple[str, ...], nid: str) -> None:
    node = tree
    for seg in path:
        node = node.setdefault("sub", {}).setdefault(seg, {})
    node.setdefault("roots", []).append(nid)


def render_tree(graph: PowerGraph, site_name: str) -> str:
    lines: list[str] = [f"mains: meter-{site_name}"]

    def walk(nid: str, parent_key: str | None, prefix: str, is_last: bool) -> None:
        n = graph.nodes[nid]
        suffix = ""
        if parent_key is not None:
            if not n.location:
                suffix = "  ⚠ loc unknown"
            elif location_key(_loc_display(n.location)) != parent_key:
                suffix = f"  ⚠ loc={_loc_display(n.location)}"
        connector = "└─ " if is_last else "├─ "
        lines.append(f"{prefix}{connector}{_label(graph, nid)}{suffix}")
        child_prefix = prefix + ("   " if is_last else "│  ")
        kids = sorted(graph.children_of(nid),
                      key=lambda c: natural_sort_key(graph.nodes[c].label))
        my_key = location_key(_loc_display(n.location))
        for i, child in enumerate(kids):
            walk(child, my_key, child_prefix, i == len(kids) - 1)

    # Group power roots by their location path into a nested tree.
    tree: dict = {}
    roots = sorted(graph.roots(), key=lambda r: natural_sort_key(graph.nodes[r].label))
    for r in roots:
        path = graph.nodes[r].location or ("[unknown location]",)
        _insert(tree, path, r)

    def render_locs(node: dict, depth: int) -> None:
        indent = "   " * depth
        for name in sorted(node.get("sub", {}), key=natural_sort_key):
            lines.append(f"{indent}[{name}]")
            render_locs(node["sub"][name], depth + 1)
        for r in node.get("roots", []):
            key = location_key(_loc_display(graph.nodes[r].location))
            walk(r, key, "   " * depth, True)

    render_locs(tree, 1)
    return "\n".join(lines)
```

(Note: the top-level root walk passes the root's own location key as `parent_key`, so a root never self-flags; only its descendants whose location diverges are flagged.)

- [ ] **Step 4: Run, verify pass** including the three Review-Focus tests (multi-feed node flags per edge; unlocated node → `⚠ loc unknown`; heterogeneous ifName sort). Add a test for a node with two parents in different locations appearing under each with the correct independent flag.

- [ ] **Step 5: Update `render_upstream`** if it shares `_label` (it does) — no signature change needed; confirm its tests still pass.

- [ ] **Step 6: Full suite + ruff.**

- [ ] **Step 7: Commit** — `feat(power): meter-rooted, location-grouped tree with cross-location flags`

---

### Task 8: CLI `--best-effort`, refusal wiring, and the data-fix

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py`
- Create (throwaway): `scripts/power_data_fix.py`
- Test: `tests/test_cli/test_power.py`

**Interfaces:**
- Consumes: `build_power_graph`, `render_tree(graph, site_name)`.
- Produces: `power tree|downstream|upstream` gain `--best-effort`. `_power_graph` collects graph-level violations (stale-switch + cycle warnings) and, unless `--best-effort`, prints them to stderr and returns a sentinel causing the command to exit non-zero **before** printing a tree. `render_tree` is called with `args`-derived `config.site.name`.

- [ ] **Step 1: Write the failing tests** — extend `tests/test_cli/test_power.py`:

```python
def test_power_tree_refuses_on_stale_switch(capsys):
    # bridge switch absent from inventory -> stale warning -> exit 1 by default
    recs = [_rec("au-plug-4", "desktop")]
    bridge = {"sw-ghost": {"port_names": [(1, "1/0/1")], "poe_status": [(1, 1, 3)],
                           "lldp_neighbors": [(1, "desktop", "x", "y", None)]}}
    ctx = _patchers(recs, bridge=bridge)
    for p in ctx: p.start()
    try:
        assert main(["power", "tree"]) == 1
    finally:
        for p in ctx: p.stop()
    assert "stale" in capsys.readouterr().err.lower()


def test_power_tree_best_effort_renders_anyway(capsys):
    recs = [_rec("au-plug-4", "desktop")]
    bridge = {"sw-ghost": {"port_names": [(1, "1/0/1")], "poe_status": [(1, 1, 3)],
                           "lldp_neighbors": [(1, "desktop", "x", "y", None)]}}
    ctx = _patchers(recs, bridge=bridge)
    for p in ctx: p.start()
    try:
        assert main(["power", "tree", "--best-effort"]) == 0
    finally:
        for p in ctx: p.stop()
    assert "mains: meter-welland" in capsys.readouterr().out
```

(Update the existing `_patchers`/`cmd_power_*` tests for the new `render_tree(graph, site_name)` signature.)

- [ ] **Step 2: Run, verify failures.**

- [ ] **Step 3: Implement** — add `--best-effort` to each `power` subparser; in `_power_graph`, after `build_power_graph`, partition warnings into graph-level violations (those containing `"stale scan history"` or `"power cycle"`) and informational ones; print all to stderr; if violations exist and not `args.best_effort`, print `error: refusing to render on N violation(s) (use --best-effort to override)` and signal the caller to return 1. Pass `config.site.name` to `render_tree`.

- [ ] **Step 4: Run, verify pass; full suite + ruff.**

- [ ] **Step 5: Commit** — `feat(power): --best-effort flag; refuse on stale-switch/cycle by default`

- [ ] **Step 6: Data-fix (operational — NOT TDD; done interactively with the user).**
  - Write `scripts/power_data_fix.py`: dry-run-default, prints the exact cell edits — (a) location consistency (e.g. `rpi4-ups` `Sound Proof Rack` → `Back Shed - Soundproof Rack`; strip `au-plug-47`'s `Mains -> UPS` from the location cell; any other confusable pairs the Location validator reports); (b) decommission the `sw-cisco-shed` row; (c) add infra row `ups-apc-srv3k` (Human Name noting APC/Voltronic SRV 3kVA, monitored by rpi4-ups), set `au-plug-47.Controls = ups-apc-srv3k`, `ups-apc-srv3k.Controls = au-plug-48`, and reconcile `au-plug-48`'s direct-to-device Controls with the two-level reality.
  - **Gate:** show the dry-run diff to the user; apply only on explicit confirmation, via the service-account write path as root. Then `uv run gdoc2netcfg fetch` and `uv run gdoc2netcfg validate` → **must be clean** over the full row set (this is the gate that lets the ERROR validators merge).
  - Commit the script as evidence, then remove it in a follow-up commit.
  - Real-data smoke: `uv run gdoc2netcfg power tree` against the prod cache shows the meter-rooted, location-grouped tree with the UPS in-chain and no stale switches.

---

## Self-Review

- **Spec coverage:** meter root (T7), hierarchical locations (T4/T7), cross-location flag (T7), switch-sourced port names + natural sort (T1/T7), UPS in-chain + note (T4/T7 + data-fix T8), BMC (T5), stale switch (T6), Controls/Location ingest contract (T2/T3), `--best-effort` (T8), data-fix (T8). All covered.
- **Interface consistency:** `render_tree` gains `site_name` (T7) — T8 updates the CLI call and the existing CLI tests. `PowerNode` gains `location`/`note` (T4) before they're read (T5/T7). `NameResolver`/`parse_controls_cell` reused by T2.
- **Placeholder scan:** none — every code step has runnable code; T8's data-fix is explicitly operational with its gate stated.
- **Review Focus:** each of the five has a pinned test in its owning task.
