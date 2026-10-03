# Power-Tree Structure, Locations & Validation — Design

**Status:** approved-pending-review
**Date:** 2026-10-03
**Builds on:** the read-only power-topology engine from
`docs/superpowers/specs/2026-10-02-power-topology-engine-design.md` (PR #58):
`src/gdoc2netcfg/supplements/power_topology.py`, `gdoc2netcfg power
tree|downstream|upstream`.

This is **sub-project 1 of two** follow-ups. This spec (Spec A) covers
everything computable from already-cached data: tree structure, location
grouping, the UPS/BMC/stale-switch modelling, and fail-loud validation.
The online/offline filtering that needs a **live HA/MQTT query** (plug relay
state) is **Spec B**, specified separately.

## Goal

Make `power tree` render a correct, readable power hierarchy rooted at the
site's electricity meter, grouped by physical location, that exposes
data-entry nonsense (a plug powering two locations, a decommissioned switch,
an unwired UPS) loudly instead of hiding it.

## Problems addressed

1. **Meter root + location grouping.** Today the tree has no single root and
   no location structure — plugs, UPS rows and bare hosts all float as
   lexically-sorted roots. It should start at one site meter and nest by
   physical location, so a plug whose children live in a different location
   is visibly wrong.
2. **Port names from switch data, natural-sorted.** Ports already use the
   switch-reported ifName (`port_names`), but siblings are lexically sorted
   (`1/0/11` before `1/0/2`). Fix the ordering; never regex-derive a port
   number.
4. **The active UPS is invisible.** The real unit (NUT name `apc-srv3k`,
   see *Verified facts*) sits between `au-plug-47` and `au-plug-48` but has
   no sheet row and nothing wires it, so it never appears.
5. **BMCs are power-control points.** A BMC can cut/restore power to its
   host (IPMI soft power), so `bmc.<host>` must appear as a controller of
   `<host>`.
6. **Stale switches leak in.** `sw-netgear-m4300-16x-poe` appears though it
   is not in the current inventory — stale bridge-scan history that is never
   tombstoned, surfaced because the engine adds any bridge switch as a node.

(Problem 3 — online/offline filtering — is Spec B.)

## Verified facts (2026-10-03, via the structured pipeline + `upsc`)

- **The "APC" UPS is a Voltronic unit.** `upsc apc-srv3k` on `rpi4-ups`:
  `driver.name=nutdrv_qx`, `driver.version.data=Voltronic 0.08`,
  `device.model=WPHVR3K0`, `ups.type=online`, `ups.status=OL`. Branded
  "APC Easy UPS SRV 3000VA"; electrically Voltronic. Operator NUT name
  `apc-srv3k`. → node id `ups-apc-srv3k`.
- **Rack chain** (operator-stated, matches the sheet): `mains → au-plug-47 →
  UPS → au-plug-48 → aux bus → {au-plug-46→sw-bb-25g, Z9→openmesh-96-00,
  Z7→rpi4-ups}`. `rpi4-ups` *monitors* the UPS over serial/USB and is itself
  fed from the aux bus (downstream) — "monitors" is **not** a power edge.
- **BMCs:** the pipeline already builds 19 `bmc.<host>` hosts (machine_name =
  the parent host).
- **Stale bridge data:** `load_latest_bridge()` returns 9 switches; of these
  `sw-netgear-m4300-16x-poe` is **not** in the current host inventory.
  `sw-cisco-shed` **is** still in the Network sheet (so the sheet itself is
  stale — the physical switch is gone).
- **Ports:** `port_names` maps SNMP ifIndex → ifName (`1/0/1`, `1/g1`,
  `gi1`). NSDP physical port numbers exist only for the `gs110emx` switches,
  not the PoE switches — so ifName is the authoritative port name here.

## Design

### Node sourcing (recap + additions)

Nodes come from the structured pipeline (`records`, `hosts`) and the bridge
supplement — never from re-parsing CSVs.

- **BMC nodes (new).** For every host the pipeline marks as a BMC
  (`hostname` begins `bmc`/`bmc-…`, machine_name = parent), add a node of a
  new category `bmc` and an edge `bmc.<host> → <parent-host>`: the BMC is a
  power toggle-point for its host. No power-usage data is read.
- **Stale-switch exclusion (new).** `add_poe_edges` uses a bridge switch
  **only if it resolves to a node already in the graph** (i.e. present in the
  current inventory via Controls/records/hosts). A bridge switch with no
  inventory node is **stale scan history** → excluded, and recorded as a
  validation violation (not silently dropped, not added as a root). A
  bridge-scan-level tombstone for vanished switches is a noted follow-up,
  out of scope here.

### The meter root

The engine synthesises exactly one root per site: a node `meter-<site>` of
category `mains` (e.g. `meter-welland`). It is the parent of every top-level
power **source** and the top of the location tree.

### Location model

Every node carries a **location path**, parsed from the sheet location cell
(IoT `Physical Location`, Network `Location`; infra/UPS from their own row;
a PoE port inherits its switch's location; a BMC inherits its host's).

- **Separator:** ` - ` splits a location into a nested path
  (`Back Shed - Soundproof Rack` → `["Back Shed", "Soundproof Rack"]`). This
  is the house convention; the data is cleaned to match (see *Data-fix*).
- **Placement:** under the meter the engine builds the location tree; each
  maximal power-subtree root (and each standalone located host) hangs at its
  own location node. Power edges nest below their placed root unchanged.
- **Cross-location flag:** when a power edge's child location diverges from
  its parent's, the child line is marked `⚠ loc=<child-location>`. This is
  how "a plug controlling devices in two locations" becomes visible.

The meter's direct children are location nodes; a located host with no known
power feed hangs under its location (every powered host has *a* feed —
missing one is a violation to fix, not an orphan bucket).

### Ports

Keep the switch-provided ifName as the port label (`poe: <switch> <ifName>`).
Order siblings by a **natural-sort key** (split ifName into numeric/non-
numeric runs, compare numerically) so `1/0/2` precedes `1/0/11`. Applies to
all sibling ordering, not only ports. No regex extraction of a "front-panel
number".

### UPS

Declared `ups-*` infra nodes render in-chain like any power node. The UPS
label carries its human identity and, where known, a `(monitored by
<host>)` suffix — a descriptive note sourced from the row, **not** a power
edge. Making the APC appear is a **data-fix** (below): the engine already
supports the node; nothing is wired to render today.

### Validation — enforced at CSV input (the sheet contract)

Controls and Location well-formedness is enforced at **data ingest**, in the
constraint layer (`constraints/validators.py`, run by `validate_all` over the
parsed records — all rows, every site, before site filtering), **not** in the
`power` command. This makes them part of the existing **sheet contract**: an
ERROR means `fetch` refuses to cache the sheet set (previous CSVs stay; cron
mails root), `generate` exits 1, and the daemon refuses to publish — exactly
as a missing MAC does today. The power engine then consumes already-valid
data.

New validators:

- **Controls well-formed & resolvable** — every `Controls` value, split on
  comma/newline, resolves to a known node (host / machine / declared infra
  row). An unresolved target is an error naming the cell. Empty is fine.
- **Location well-formed & consistent** — every location cell parses into a
  ` - `-separated path; no two cells are *confusable* (normalise to one key
  but differ in raw form — e.g. `Sound Proof Rack` vs `Soundproof Rack`);
  a node that needs placement has a location. Normalisation (casefold +
  collapse internal whitespace/punctuation) is used **only to detect
  near-duplicates**, never to silently merge them — the fix makes the raw
  values identical.

Two engine-side checks remain in the power command (they are about the graph,
not a single cell): **stale in-graph switch** (a bridge switch absent from
current inventory) and **cycle** (`PowerCycleError`). The command
**refuses and exits non-zero** on these, and a `--best-effort` flag renders
anyway with violations flagged inline — for inspecting a half-wired topology
or while cleaning data.

**Blast radius & rollout.** Both sites share one spreadsheet, so cleaning it
cleans both; but an ERROR-severity contract gates the **whole pipeline for
both sites** — a malformed Controls/Location cell would block fetch caching
and DNS generation, like the MAC contract. The validators therefore land
**directly at ERROR**, but only after the data is clean, enforced by task
ordering within this branch:

1. **Data-fix first.** Clean the shared sheet (locations, decommissioned
   switch, UPS wiring) until a `validate` over the full all-sites row set is
   clean. This is a prerequisite task.
2. **Then land the ERROR validators + engine changes.** Because the sheet is
   already clean, enforcement is safe the instant it merges.

The validators must not merge while any row still violates them — a clean
`validate` run over all rows is the gate on the validator task. (A cleaned
sheet is picked up by prod's next 15-minute fetch immediately and is harmless
on its own; the enforcement code merges afterwards.)

## Data-fix workstream (companion, done carefully)

Spec A's engine passes validation only once the sheet is consistent. These
sheet edits are a **separate, confirmed** step — proposed as exact cell
changes, dry-run, confirmed, then written via the service-account path:

1. **Location consistency:** reconcile confusable locations, e.g. `rpi4-ups`
   `Sound Proof Rack` → `Back Shed - Soundproof Rack`; move `au-plug-47`'s
   `Mains -> UPS` annotation out of the location cell; sweep for other
   near-duplicates the validator flags.
2. **Decommissioned switch:** remove/decommission the `sw-cisco-shed` row
   (physically gone).
3. **UPS wiring:** add infra row `ups-apc-srv3k` (human name noting
   APC/Voltronic SRV 3kVA, monitored by rpi4-ups);
   `au-plug-47.Controls = ups-apc-srv3k`; `ups-apc-srv3k.Controls =
   au-plug-48`. Reconcile `au-plug-48`'s existing direct-to-device Controls
   with the two-level rack reality.

## Out of scope

- **Spec B:** online/offline host filtering (needs a live HA/MQTT query for
  Tasmota relay state); BMC/host power-usage reporting.
- **Bridge-scan tombstone** for vanished switches (DB-side; a follow-up).
- The Network-sheet "Controlled By" column **writer** (the original
  sub-project 2).

## Testing

- Pure-engine unit tests over synthetic graphs: meter synthesis; nested
  location placement; cross-location flag; natural sort; BMC→host edges;
  stale-switch exclusion → engine refusal; cycle → refusal; `--best-effort`
  renders with flags.
- Constraint tests: the Controls validator flags an unresolved target
  (ERROR); the Location validator flags a confusable-duplicate and a missing
  location (ERROR). `validate_all` aggregates them; a clean row set produces
  none (the gate that lets the validators merge).
- Real-data smoke against the welland prod cache before/after the data-fix,
  and a `validate` run over the full (all-sites) row set to confirm clean
  before ERROR promotion.
