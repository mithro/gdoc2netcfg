# Tasmota sheet-MAC identity, discrepancy reporting, and tombstone cleanup

> Design doc — 2026-06-16. Fixes the au-plug-13 phantom and the au-plug-10
> mistaken-identity discovered during the #28 MQTT-credential cutover.

## Background

The Tasmota supplement scans the IoT VLAN and stores per-device data in
`discovery.db` (`tasmota_devices`, delta-based). Two production data-quality
problems surfaced while migrating au-plugs to per-device MQTT credentials:

1. **Phantom duplicate (au-plug-13).** `tasmota show` listed au-plug-13 at two
   IPs — `10.1.90.63` (live) and `10.1.90.214` (stale). Both rows carry the
   same MAC `24:EC:4A:B0:A9:B0`: one device that changed DHCP lease (.214 → .63)
   early in its life. The `.214` row was recorded as `_unknown/10.1.90.214` at
   scan 8 (subnet sweep, before it matched a sheet host) and has been resurrected
   on every scan since, because:
   - `scan_tasmota` expires stale `_unknown/` keys only *in memory* (drops them
     from the carried-forward baseline), and
   - the storage layer (`_save_entities`) never tombstones a key that vanishes
     from the scan, so `_latest_entity_scans` keeps returning the scan-8 row
     forever.

2. **Mistaken identity (au-plug-10).** The Welland sweep finds a device at
   `10.1.90.149` self-reporting `DeviceName=au-plug-10`. Its MAC is
   `7C:2C:67:D7:D3:CC` — the sheet's au-plug-10, which the sheet assigns to
   **Monarto** (`10.X.90.60`). A Monarto device is physically on the Welland
   network, and the scan surfaces it under the misleading self-reported name
   rather than flagging it.

Root cause: the scan establishes identity from **IP** (Phase 1 probes the sheet
IP) and from the device's **self-reported `DeviceName`** (Phase 2 sweep). Both
drift. The spreadsheet already carries the one stable identity — the **MAC**.

## Principle

The spreadsheet is the golden source of truth. Device identity is established by
matching the device's MAC against the sheet's IoT-host MACs. Self-reported
`DeviceName` and current IP are evidence, never identity. Network state the sheet
does not sanction is reported as a clear error; no observed data is silently
discarded.

## Requirements

- **R1** A device whose MAC is a sheet IoT host's MAC is identified as that host,
  regardless of its IP or self-reported name.
- **R2** A device whose MAC is not in this site's sheet is recorded as
  `_unknown/{mac}` (stable MAC key) and reported as a discrepancy.
- **R3** Sheet hosts not seen in a scan are carried forward (last-known data) if
  still in the sheet; if removed from the sheet, they are tombstoned (dropped
  from reads).
- **R4** Stale `_unknown/` entries (no longer on the network) are tombstoned.
- **R5** Discrepancies are reported as clear errors (not hidden warnings);
  `tasmota scan` exits non-zero when any exist. Observed data is still persisted.
- **R6** The existing IP-keyed phantom (`_unknown/10.1.90.214`) and any removed
  hosts self-heal on the first post-deploy scan — no data migration.
- **R7** History is never deleted; removals are recorded as tombstone deltas
  (consistent with zigbee and the deltas-not-pruning storage design).

## Design

### Identity matching — `supplements/tasmota.py::scan_tasmota`

- Build `mac_to_host: dict[MACAddress, str]` from this site's IoT hosts
  (`host.sheet_type == "IoT"`) via `host.all_macs()`. A MAC mapping to two hosts
  is a sheet error → discrepancy `duplicate_sheet_mac`.
- Target IPs = known sheet IPs (`host.first_ipv4`) ∪ the IoT `/24` sweep. Probe
  all; collect responders as `{ip: parsed}` (dedupe by IP).
- Group responders by normalized MAC. A MAC seen at >1 IP → discrepancy
  `duplicate_network_mac`; do not auto-key it.
- For each found device (MAC → single `(ip, parsed)`):
  - MAC ∈ `mac_to_host` → key = **sheet hostname**; store `parsed` (with the
    device's *actual* IP).
  - else → key = `_unknown/{normalized_mac}`; store `parsed`; discrepancy
    `unknown_device` (mac, ip, self-reported name).
  - matched **and** `parsed["ip"] != str(host.first_ipv4)` → discrepancy
    `ip_mismatch` (host, sheet ip, actual ip).
  - reported MAC missing/unparseable → discrepancy `unidentifiable` (cannot key
    by MAC); **not** stored under a fabricated key.
- Carry-forward: `valid_known = {host.hostname for IoT hosts}`. For each baseline
  key in `valid_known` not found this scan, carry its baseline entry forward
  (offline host keeps last-known data). Baseline keys ∉ `valid_known`
  (removed-from-sheet hosts) and stale `_unknown/` keys are *not* carried forward
  — `save_tasmota` tombstones them.
- Return `TasmotaScanResult(data: dict[str, dict],
  discrepancies: list[TasmotaDiscrepancy])`.

Matching is **site-scoped**: at Welland the `.149` device's MAC is not a Welland
host, so it is `unknown_device`. This design does not cross-reference the other
site's rows to name it "Monarto's au-plug-10"; that, and resolving the
physical/site discrepancy, is operator action / the `audit/` module.

### Discrepancy reporting — `cli/main.py::cmd_tasmota_scan`

- `TasmotaDiscrepancy(kind, mac, ip, hostname, detail)` dataclass. Kinds:
  `unknown_device`, `ip_mismatch`, `duplicate_sheet_mac`,
  `duplicate_network_mac`, `unidentifiable`.
- After persisting the scan, print a clearly-labelled block
  (`ERROR: N discrepancies`) to stderr, one line per discrepancy, and **exit
  non-zero** when any exist. Data is persisted regardless (unknowns as
  `_unknown/{mac}` — never discarded).

### Storage — `storage/discovery_db.py`

- Schema **v7 → v8**:
  `ALTER TABLE tasmota_devices ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0`
  (`SCHEMA_UPGRADES[8]`). Lightweight `ADD COLUMN`, no table rewrite. Also add the
  column to the fresh-DB DDL (`_entity_table_ddl` for `tasmota_devices`), last,
  mirroring `zigbee_devices`.
- `_insert_tasmota_rows` writes `is_tombstone=0`.
- `_tombstone_value(typ)`: NOT-NULL-satisfying sentinel derived from
  `_sql_type(typ)` — `None` if nullable, `""` for `TEXT`, `0` otherwise.
  (Reconstruction skips tombstones, so the sentinel is never read; same pattern
  as `_insert_zigbee_device_tombstone`.)
- `_insert_tasmota_tombstone(cur, scan_id, device_key)`: row of sentinels +
  `is_tombstone=1`.
- `tombstone_missing_tasmota(scan_id, present: set[str]) -> int`: mirrors the
  existing `tombstone_missing_reachability` — tombstones `set(_latest_tasmota) -
  present` with INSERT-only tombstone rows, raising `ValueError` on an empty
  `present` set (a failed scan, not a wholesale removal). `save_tasmota` itself
  stays a pure delta save (unchanged signature).
- `cli/main.py::_save_tasmota_to_db(config, data)`: mirrors
  `_save_reachability_to_db` — one scan row that runs `save_tasmota` then
  `tombstone_missing_tasmota(scan_id, set(data))`, cleaning up the scan row on
  failure. `cmd_tasmota_scan` calls it instead of the generic
  `_save_to_discovery_db`.
- `_latest_tasmota`: select `is_tombstone`; skip tombstoned keys. A later real row
  resurrects a key.

### Safety

A known host is tombstoned only when absent from the current sheet's IoT hosts;
offline-but-in-sheet hosts are always carried forward, so unreachability never
tombstones. The empty-`data` guard backstops a pipeline/CSV-load failure (which
already fails loud elsewhere). `_unknown/` keyed by MAC means IP churn can no
longer orphan an unknown device into a new row each scan.

## Testing (TDD)

**Storage (`tests/test_storage/`):** tombstone on removal; resurrect on return;
unchanged not tombstoned; empty-`data` guard raises; tombstone row satisfies
NOT NULL across `str`/`int`/`module`/optional columns; `_latest_tasmota` skips
tombstoned; v7→v8 migration adds the column and preserves existing rows
(is_tombstone=0).

**Scan (`tests/test_supplements/test_tasmota.py`):** match by MAC despite IP
change; match by MAC ignoring self-reported `DeviceName`; unknown device keyed by
`_unknown/{mac}` + `unknown_device` discrepancy; carry-forward offline in-sheet
host; removed-from-sheet host dropped from `data` (→ tombstone on save);
`duplicate_sheet_mac`; `duplicate_network_mac`; `ip_mismatch`; dedupe across
known-IP probe + sweep; unparseable MAC → `unidentifiable`, not stored.

**CLI (`tests/`):** discrepancies → non-zero exit + clear error block; clean scan
→ zero exit; data persisted even when discrepancies exist.

## Deployment (both sites)

1. Merge to `main`; `sudo -E git pull` on each site.
2. Restart the reachability daemon (opens `discovery.db` → runs the v8 migration).
3. `sudo .venv/bin/gdoc2netcfg tasmota scan --force` once per site:
   - self-heals: tombstones `_unknown/10.1.90.214` (welland) + any removed hosts;
   - prints discrepancies — expect Welland to report the `.149` unknown device
     (Monarto's au-plug-10 physically on Welland).
4. Confirm `tasmota show` no longer lists the phantom.

## Out of scope

- Cross-site identification (naming the `.149` device as Monarto's au-plug-10) and
  auto-resolving site/IP discrepancies — operator action / `audit/` module.
- Applying the tombstone/identity model to other supplements (snmp, bridge) —
  they do not carry forward the same way; `_save_entities` gains an opt-in only.
- The au-plug-10 physical/site discrepancy itself (relocate the device or correct
  the sheet's Site/IP).
