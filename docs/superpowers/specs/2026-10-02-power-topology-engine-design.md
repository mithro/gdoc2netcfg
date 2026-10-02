# Power Topology Engine — Design (sub-project 1)

**Branch:** `worktree-power-topology`  ·  **Date:** 2026-10-02

## Context and goal

The Network sheet has a **"Controlled By"** column that is currently empty. The
broader goal is to populate it, per host, with **everything that controls power
to that host** — so that filtering the column by any control device shows every
device that would lose power if you toggled it off.

Reaching that requires modelling the real **power-distribution topology**, not a
flat list: plugs control other plugs, a UPS sits mid-chain, PoE ports power
hosts, and a switch's own plug powers all of that switch's PoE ports. The work
therefore splits into two sub-projects:

1. **This spec — a read-only power-topology engine + CLI tool.** Build the power
   graph from existing data, compute power availability and the up/downstream
   closures, and expose them through read-only commands (`tree`, `downstream`,
   `upstream`). **No sheet or device writes.** This is how the topology is
   *calculated and verified* before anything is written anywhere.
2. **Future (its own spec→plan→build) — the "Controlled By" column writer.**
   Render each host's upstream closure into the Network sheet via gspread, with
   conflict/`--force`/`--dry-run` handling. Built directly on this engine.

Splitting this way matches the guiding principle — *calculate the topology
first, then describe it* — and keeps every mutation out of the first,
independently verifiable deliverable. The read-only tool is also how a
truncated or mis-entered chain is spotted *before* it is ever written to the
sheet.

## The model: a power-dependency graph

### Nodes

Every entity that distributes or consumes power is a node:

- **Network hosts** — Network sheet. Consumers; some (a PoE switch) also
  distribute.
- **Tasmota plugs** — IoT sheet. Controllable toggle-points.
- **Zigbee plugs** — Zigbee Info sheet. Controllable toggle-points.
- **PoE switch ports** — from bridge/SNMP data in `discovery.db`. Independently
  controllable toggle-points (PoE is switchable per port).
- **Power-infrastructure nodes with no network identity** — UPS, mains feed,
  busbar, power strip. They exist only in the real world (e.g. the APC Easy UPS
  reachable only over serial/USB from `rpi4-ups`), but must be **named and
  visible** in the topology. Declared as rows (see *Reuse Controls everywhere*).

**Node identity.** Sheet-backed nodes are keyed by canonical machine name. PoE
ports are keyed as `(switch-host, ifName)` and rendered `switch ifName`.

### Edges

A directed edge `A → B` means **"A delivers power to B"** — cutting A's power
contributes to cutting B's. Edge sources:

- **IoT `Controls` cell** — `host.extra["Controls"]`, split on comma/newline
  (the existing parse in `supplements/tasmota.py:339`). Controller = the IoT
  row's machine; each listed target is a downstream node. **Targets may be
  other plugs or infra nodes**, so chains (plug→plug, plug→UPS→plug) are
  first-class.
- **Zigbee `Controls` cell** — a `Controls` column on the Zigbee Info sheet,
  located by header name; **absent → contributes nothing, silently**. Same split.
- **PoE ports** — from `DiscoveryDB.load_latest_bridge()`: per port, PoE
  admin/detection status, ifName, ifAlias (description), and LLDP neighbour.
  The port sits **between the switch and the powered host**:
  `switch-host → poe-port → connected-host`. So the switch's own plug powers the
  switch, which powers all its PoE ports, which power their hosts — toggling the
  switch's plug drops every PoE-powered host behind it, and that chain is
  explicit in the graph.
- **Infra-node `Controls`** — infra rows carry a `Controls` cell too
  (`mains-welland → au-plug-47`, `ups-soundproof → au-plug-48`), so the whole
  chain is expressed with one uniform mechanism.

### Reuse Controls everywhere

There is exactly **one** edge-declaration mechanism for plug/infra edges: a
node's `Controls` cell lists what it powers. Infra nodes (no network identity)
are **rows with blank MAC/IP** on whichever device sheet is convenient (IoT),
identified by a kind-prefix name (below). The engine treats every row that has a
`Controls` cell as a potential node with outgoing edges, regardless of sheet.
PoE edges are the one exception — they come from bridge data, not a `Controls`
cell.

**Data sourcing (load-bearing).** Infra nodes have blank MAC/IP. Verified on
current `main`: `sources/parser.py::parse_csv` keeps a machine-only row (no
IP/MAC guard — `parser.py:201`), so infra rows survive as `DeviceRecord`s; but
`derivations/host_builder.py::build_hosts` **drops any record without an IP**
(`host_builder.py:157`), so they never become `Host`s. The engine must
therefore build the graph from the **`records` (DeviceRecords with `.extra`)**
returned by `_build_pipeline`, not from the built `hosts`. The `hosts` /
`inventory` are still used — for name→machine resolution and for matching PoE
aliases/LLDP names to hosts — but node and `Controls`-edge enumeration comes
from `records` so infra nodes are not silently lost.

### Node category (rendering prefix)

Each node has a category, used as its rendered prefix:
`host` · `tasmota` · `zigbee` · `poe` · `ups` · `mains` · `busbar` · `strip`.

- PoE ports → `poe`.
- IoT-sheet smart plugs → `tasmota`; Zigbee-sheet plugs → `zigbee`.
- Infra nodes → category from a **kind-prefix on the node name**:
  `ups-*`→ups, `mains-*`→mains, `busbar-*`→busbar, `strip-*`→strip. Self-
  documenting; no new column.
- Plain Network hosts → `host`.

### Availability semantics (redundancy falls out of the graph)

The engine models **power availability**, not reachability:

- A node is **powered** iff **at least one** incoming feed is powered (logical
  OR over its parents). A node with no parent is a **root** (expected to be a
  `mains-*` node).
- **Redundancy is therefore structural**: a device with ≥2 independent feeds
  (≥2 parents) stays up while any one feed is up. A series dependency is a chain
  of single-parent nodes. No special syntax — the structure *is* the model, so
  the source data must reflect reality (e.g. the real
  `au-plug-48 → au-plug-46 → sw-bb-25g` chain, not the current hand-flattened
  `48 → sw-bb-25g` and `46 → sw-bb-25g`).
- **"Cutting node X"** = force X unpowered, recompute availability; a node is
  *dropped* iff all its feeds become unpowered. This is what `downstream`
  reports, and it correctly **excludes redundant survivors**.

### Integrity checks

- **Cycle** → **fail loud** (raise). A power graph is a DAG; a cycle is a
  data-entry error, never fabricated around.
- **A host whose ancestry never reaches a `mains-*` root** → **warn**
  (truncation / completeness audit). Not fatal; it flags a missing upstream
  edge. Going "all the way to mains" is what proves a chain is complete.
- **A `Controls` target or PoE alias that resolves to no node** → **warn and
  keep it as an unresolved leaf node** (named, shown in the tree), never
  fabricated or silently dropped. The IoT sheet legitimately lists non-host
  appliances (`ac`, `bar header`, `monitors.desktop`).

### PoE edge rule

RFC 3621 values — admin: 1=on, 2=off; detection: 1=disabled, 2=searching,
3=deliveringPower, 4=fault, 5=test, 6=otherFault.

| admin | detection | edge? | host-name source |
|---|---|---|---|
| on | deliveringPower | **yes** | ifAlias; LLDP if alias empty; both present & disagree → use LLDP + warn |
| on | searching | no — empty port or self-powered host | — |
| off | any | **yes** if the alias names a host (deliberately held off; stable across power state; LLDP is gone while the device is down) | alias only |
| on | fault / test / otherFault / disabled | no — **warn**, naming the port | — |

Integer values outside the RFC 3621 ranges → **raise** (fail loud).

**Port label** = `{switch-hostname} {ifName}` — e.g. `sw-netgear-gsm7252ps-s1
1/0/1`, `sw-cisco-shed gi1`. ifName is joined from `bridge_port_names` by port
index; verified live that the PoE port index aligns **1:1** with the ifName
index across all four PoE switches (0 missing).

### Name resolution (a Controls/PoE value → a node)

Resolve a free-text target to a canonical node, in order:

1. exact machine/hostname match in the site inventory;
2. value minus a site-domain suffix (from the Sites sheet), retry
   (`ten64.monarto.mithis.com` → `ten64`);
3. first DNS label, retry;
4. raw Network-sheet Machine-cell match (catches site-filtered and
   parser-dropped rows);
5. infra kind-prefix name (`ups-*`, `mains-*`, …) matching a declared infra row;
6. otherwise → an **unresolved leaf**: kept as a named node (so the tree shows
   it) and warned about; it has no Network row.

### Site scoping

**Strictly single-site per run.** For site S:

- Rows/hosts: only those whose `Site` is S.
- Plug/Zigbee edges: only where the controller row's `Site` is S — so a welland
  run excludes `au-plug-9`'s monarto targets.
- PoE edges: only from switches in S's `discovery.db`.
- Placeholder / blank-`Site` rows that exist at both sites (`10.X.Y.Z`): one
  sheet cell cannot hold two sites' chains → **warn and skip** (primarily
  sub-project 2's concern; noted here so the engine marks them).

## Commands (all read-only)

Command group **`gdoc2netcfg power`** (name to confirm; alt `controlled-by`).
No sheet or device writes anywhere in this sub-project.

### `power tree [--site S]`
ASCII tree of the power hierarchy: roots (`mains-*`, and any parentless node) at
top, descending through plugs / UPS / busbars / switches / PoE ports to leaf
hosts. Each line is `category: name`. This is how a chain that fails to reach
mains is *seen* (it hangs under a non-mains root), and how structural mistakes
surface.

```
mains-welland
└─ tasmota: au-plug-47
   └─ ups: ups-soundproof
      └─ tasmota: au-plug-48
         ├─ tasmota: au-plug-46
         │  └─ host: sw-bb-25g
         ├─ host: openmesh-96-00
         └─ host: rpi4-ups
```

### `power downstream <node> [--site S]`
Everything that loses power if `<node>` is toggled off — the set of nodes that
become unpowered when `<node>` is forced down. **Respects redundancy**: a node
with another live feed is not listed. Output as a list and/or subtree.

### `power upstream <host> [--site S]`
The host's full upstream power chain — every ancestor that feeds it, ordered by
hop distance (**direct first → mains last**), with redundant feeds grouped and
labelled. This is exactly what sub-project 2 will render into the "Controlled
By" cell: one line per hop-level, same-level controllers comma-joined, each
`category: name`.

## Module layout

- `src/gdoc2netcfg/supplements/power_topology.py` — the engine: node/edge model,
  graph build from inventory + `load_latest_bridge()` + `Controls`, availability
  and up/downstream closures, cycle + mains-termination checks, rendering
  helpers (tree, hop-level lines).
- `src/gdoc2netcfg/utils/controls.py` — small shared helper extracted from the
  duplication in `supplements/tasmota.py` (Controls split) and the dashboard's
  `scripts/ha-create-reachability-dashboard.py::_build_controls_map`
  (interface-prefix strip, name→machine map). The dashboard's `_build_controls_map`
  is the closest prior art for the plug + PoE edge building and should be
  refactored onto the shared helper in the same change (same output).
- CLI wiring in `cli/main.py` — a `power` subcommand group (`tree` /
  `downstream` / `upstream`).

## Testing

Use existing patterns (`@patch(...reachability.subprocess.run)` style fixtures,
`_host()` builders, bridge-document fixtures, `_build_pipeline` patching).

- **Graph build** from fixture inventories: plug→host; plug→plug chain;
  PoE `switch→port→host`; infra `mains→plug→ups→plug→…` chain; a redundant
  (≥2-parent) device.
- **Availability / closure**: `downstream` of a chain node drops all
  descendants; `downstream` of **one** redundant feed drops nothing; `upstream`
  of a host lists the full chain to mains.
- **Integrity**: a cycle → raises; a host chain not reaching a `mains-*` root →
  warns.
- **PoE edge rule**: every row of the table plus the out-of-range raise, from
  bridge-document fixtures (not HA).
- **Name resolution**: machine / subdomain hostname (`rpi-sdr-kraken.iot`) /
  FQDN+site (`ten64.monarto.mithis.com`) / raw-sheet fallback / infra kind-prefix
  / unresolved-leaf (warn, e.g. `ac`).
- **PoE label**: ifName join (port index → `1/0/1`, `gi1`).
- **Site scoping**: a welland run excludes monarto-site controllers and targets.
- **Tree rendering**: golden-output test; ASCII shape stable; redundancy shown.

## Out of scope (this sub-project)

- Writing the Network sheet "Controlled By" column — **sub-project 2**.
- Any device or sheet mutation (no gspread, no PoE toggling).
- Cron scheduling.
- Monarto PoE from a welland run: PoE edges exist only for locally-scanned
  switches, so monarto PoE comes from a monarto run (plug/Zigbee edges from the
  shared sheet are site-filtered and cover both from either run).
