# SQLite Storage Migration — Implementation Plan (reconstructed)

> **Reconstructed 2026-06-03** from this branch's git history and code. The
> original plan (`~/.claude/plans/tidy-kindling-lollipop.md`) was lost — no copy
> survives in the repo or `~/.claude`. This documents work that is **already
> implemented** on branch `sqlite-storage` (21 commits, 2026-04-09 → 2026-04-10)
> and the **remaining production cutover**. Completed items are checked `[x]`;
> outstanding items are `[ ]`.

**Goal:** Replace flat-file caching (`.cache/*.csv`, `.cache/*.json`, which
overwrite on every scan) with two SQLite databases that retain full history via
delta-based storage, so changes over time — SSH key rotations, reachability
flaps, SSL cert expiries, device add/remove — become queryable.

**Architecture:** Two SQLite databases under `.cache/`: `config.db` (spreadsheet
truth) and `discovery.db` (scan results). Both extend a shared `BaseDatabase`
(WAL mode, `PRAGMA foreign_keys=ON`, schema versioning, and a `scans` audit
table). Every scan/fetch inserts one `scans` row; data tables reference it via
`scan_id` and insert a new row **only when a key's value actually changes**
(delta storage). The pipeline reads from the DB and transparently falls back to
the flat files while both coexist.

**Tech stack:** Python standard-library `sqlite3` only — no new dependencies.
Explicit `BEGIN`/`COMMIT`/`ROLLBACK` transactions (`isolation_level=None`). CLI
via the existing argparse tree in `cli/main.py`.

---

## Design decisions

1. **Two databases, not one.** `config.db` is spreadsheet-derived truth;
   `discovery.db` is live-network scan results. Different lifecycles, different
   write frequencies, cleanly separable.
2. **Delta-based storage.** A new data row is inserted only when that key's value
   differs from the latest stored row. Keeps the DB naturally small; **no pruning
   needed**. (CSV snapshots are the deliberate exception — always stored.)
3. **`scans` audit table.** Every scan inserts a row (even when nothing changed),
   recording `scan_type`, `started_at`, `finished_at`, `host_count`,
   `changed_count`. Data rows FK to `scans(id)`. "Latest value" = the row from
   the most recent *completed* scan that changed that key.
4. **Reachability delta ignores RTT noise.** Change detection keys on
   `(interface_idx, ip, is_reachable)` only — RTT fluctuation never creates a new
   row, but the measured RTT is still stored when a status change does.
5. **Structured tables vs JSON blobs.** Simple, queryable data
   (reachability, ssh_host_keys, ssl_certs, bmc_firmware) gets typed columns;
   deeply nested data (snmp, bridge, nsdp, tasmota) is stored as canonical JSON
   (`json.dumps(sort_keys=True)`) and compared as a string for delta detection.
6. **Fail loud (per CLAUDE.md).** `finish_scan()` raises if `host_count == 0`
   (a likely outage/misconfig); migration rejects `reachability.json` that isn't
   v2 and CSVs with no data rows. No silent fallbacks that hide data loss.
7. **DB-with-flat-file fallback during transition.** The pipeline tries the DB
   first, then the flat file. This lets the DB roll out without a flag day; the
   fallback is removed only at cutover (see Remaining work).
8. **Explicit migration, never automatic.** `gdoc2netcfg db migrate` imports the
   existing flat files as the initial history, preserving each file's mtime as
   the scan timestamp. Nothing auto-migrates on a normal run.
9. **Crash recovery on open.** Opening any DB runs `cleanup_incomplete_scans()`,
   deleting scans with no `finished_at` older than 1 hour (a crashed run leaves
   an orphaned `scans` row; in-progress scans are protected by the age cutoff).
10. **Schema versioning.** `_meta.schema_version` is checked on open; a mismatch
    raises `SchemaVersionError` directing the user to `db migrate`. Current
    `SCHEMA_VERSION = 1`.

## File structure

| File | Responsibility |
|------|----------------|
| `src/gdoc2netcfg/storage/__init__.py` | `DatabasePair` + `open_databases(cache_dir, migrate=False)` — open/create both DBs, optionally importing flat files into a fresh DB |
| `src/gdoc2netcfg/storage/base.py` | `BaseDatabase`: connection/WAL setup, schema init + version check, `scans` audit table, scan lifecycle (`begin_scan`/`finish_scan`/`latest_scan_id`/`latest_scan_age`/`cleanup_incomplete_scans`/`scan_history`) |
| `src/gdoc2netcfg/storage/config_db.py` | `ConfigDB`: `csv_snapshots` (always stored), `device_records` (delta per `machine`+`interface`), `vlan_definitions` (delta per `vlan_id`); scan_type `csv_fetch` |
| `src/gdoc2netcfg/storage/discovery_db.py` | `DiscoveryDB`: structured tables (reachability, ssh_host_keys, ssl_certs, bmc_firmware) + JSON-blob tables (snmp, bridge, nsdp, tasmota); `host_changes()` time-travel for blob tables |
| `src/gdoc2netcfg/storage/migration.py` | `import_flat_files()` — one-time import of `.cache/*.csv` and `*.json` as the initial historical snapshot, preserving file mtimes |
| `src/gdoc2netcfg/config.py` | `CacheConfig.config_db_path` / `.discovery_db_path` properties (`.cache/config.db`, `.cache/discovery.db`) |
| `src/gdoc2netcfg/cli/main.py` | `db migrate` / `db info` / `db history` subcommands; `cmd_fetch` → ConfigDB; supplement/reachability/daemon writes → DiscoveryDB; pipeline supplement loader reads DB-then-flat-file |
| `tests/test_storage/` | Unit tests for base, config_db, discovery_db, migration |

## Phase 1 — Storage foundation  `[x]`

Built the storage layer bottom-up, test-first (module + tests committed
together), followed by three code-review passes.

- [x] `storage/base.py` — `BaseDatabase` with WAL, `scans` + `_meta` tables,
      explicit-transaction schema init, scan lifecycle, schema-version guard,
      `cleanup_incomplete_scans()`. `begin_scan()` accepts an explicit
      `started_at` so the migration can preserve flat-file timestamps.
- [x] `storage/config_db.py` — `ConfigDB`; CSV snapshots stored verbatim;
      device records & VLAN definitions delta-compared via
      `_latest_*_by_key()` lookups.
- [x] `storage/discovery_db.py` — `DiscoveryDB`; per-supplement `save_*` /
      `load_latest_*`; generic `_save_json_blob` / `_load_latest_json_blob`
      helpers; `host_changes()` with a `_HISTORY_TABLES` allow-list guarding
      against SQL injection on table names.
- [x] `storage/migration.py` + `storage/__init__.py` — `import_flat_files()` and
      `open_databases()`.
- [x] Tests: `tests/test_storage/{test_base,test_config_db,test_discovery_db,test_migration}.py`.

Commits: `c9b3835` `d96e213` `404adac` `f32d07d` `d1151e7` `fb30ff7` `7a63d6a`
`9a32c08` → reviews `eca79d0` `1086031` `a0d37ea`.

## Phase 2 — Config + pipeline wiring  `[x]`

- [x] `CacheConfig.config_db_path` / `.discovery_db_path` (`1be4210`).
- [x] Pipeline supplement loader reads **DiscoveryDB first, flat-file fallback**
      (`d9ccb4e`) — `cli/main.py` ~line 560 (`Tries DiscoveryDB first (if
      available), then flat-file cache`).
- [x] `cmd_fetch` saves CSV snapshots to ConfigDB, only when ≥1 sheet was
      fetched (`4a77c6b`, ~line 301).
- [x] Robustness: clean up the orphaned `scans` row if a `cmd_fetch` save fails
      (`1a1f30a`); Phase 2 review fixes (`7f2a331`).

## Phase 3 — Supplement & daemon wiring  `[x]`

- [x] Reachability scan writes to DiscoveryDB (`6c6eb91`).
- [x] All remaining supplements write to DiscoveryDB via a shared
      `_save_supplement_to_db` helper (`7bbba2f`, ~line 117).
- [x] The MQTT reachability **daemon** (`run_daemon`) writes each scan to
      DiscoveryDB (`5550d16`).

## Phase 4 — CLI  `[x]`

- [x] `gdoc2netcfg db migrate` — `open_databases(cache_dir, migrate=True)`
      (`cmd_db_migrate`).
- [x] `gdoc2netcfg db info` — per-DB file size and, per `scan_type`, completed
      scan count and oldest→newest date span (`cmd_db_info`).
- [x] `gdoc2netcfg db history [--type T] [--since ISO_DATE] [--limit N=50]` —
      merges `scan_history()` from both DBs, newest first, as a table
      (`cmd_db_history`).
- [x] Phase 4 review fixes (`efbee8f`).

Commits: `f6ff5e8` `efbee8f`.

## Remaining work — production cutover  `[ ]`

The feature is implemented and unit-tested. Deployment to welland began
2026-06-08: the branch is rebased and FF-able, and `/opt/gdoc2netcfg/.cache/`
was chowned **entirely to `root`** (the only recurring writer is the root
reachability daemon; no `tim` cron touches `.cache`). Because reads currently
require *write* access (see the read-pathway task below), "everything root" is
the chosen access model — all CLI on `/opt` must run via `sudo`. Both flat files
and the DB are still written in parallel. To finish:

- [x] **Verify green:** full suite **1524 passed** and `ruff` clean on the
      rebased branch (2026-06-08).
- [x] **Rebase onto `origin/main`.** Rebased onto `c6fd05d`; the single
      `cli/main.py` conflict (db vs. zigbee subparsers) was resolved keeping
      both. Now 0-behind / 22-ahead of `main`, FF-able (2026-06-08).
- [ ] **Fix the read pathway to not require RW access to the DB.**
      `BaseDatabase.__init__` (`base.py:67`) issues `PRAGMA journal_mode=WAL` — a
      *write* — on every open, and WAL readers also need write access to the
      `-shm` wal-index. So every read (`load_latest_*` in `_build_pipeline`,
      `db info`, `db history`) needs read **and write** access to the DB, which is
      what forces all CLI through `sudo` under the root-owned model. Decouple
      reads from write access:
      - Add a read-only connection that opens
        `sqlite3.connect("file:{path}?mode=ro", uri=True)` and does **not** run
        the WAL pragma (journal mode is a persisted DB property set by the
        writer; a reader must not try to change it).
      - Resolve the WAL `-shm` constraint: a plain `mode=ro` open of a *live* WAL
        database still wants to map/create `-shm`. Evaluate (a) `immutable=1` —
        unsafe here, the daemon writes concurrently; (b) reader tolerates a
        missing/read-only `-shm`; (c) a rollback journal instead of WAL for this
        low-write-rate workload. Pick one, with a test.
      - Route all read-only entry points (`load_latest_*`, `db info`,
        `db history`) through the RO connection; keep writers (fetch, supplements,
        daemon, migrate) on the existing RW + WAL path.
      - **Acceptance:** as a non-owner user, `uv run gdoc2netcfg db info` and a
        `generate`/`validate` against a `root`-owned `discovery.db` succeed
        **without `sudo`**. Add a test that reads a DB the test process cannot
        write.
- [ ] **Migrate on each site:** `cd /opt/gdoc2netcfg && uv run gdoc2netcfg db
      migrate`, then `db info` to confirm the imported history. (Run as the user
      that owns `.cache/` — currently `root` on both sites.)
- [ ] **Burn-in:** let the DB and flat files run in parallel for a period;
      compare `load_latest_*` output against the flat files to confirm parity.
- [ ] **Cut over:** once trusted, remove the flat-file fallback in the pipeline
      loader and stop writing the flat files, making the DB the single source of
      truth. (This is the step that turns on the "Fail loud" guarantee fully —
      no silent flat-file fallback masking a DB problem.)
- [ ] **Restart the daemon** after deploy so it loads the new code
      (`sudo systemctl restart gdoc2netcfg-reachability.service`).
- [ ] **Docs:** update `CLAUDE.md` (the `.cache/` description and a `db`
      command reference) once the flat files are gone.

## Schema reference (v1)

Shared (both DBs), from `base.py`:

```sql
scans(id PK, scan_type, started_at, finished_at, host_count, changed_count, metadata)
  -- index: (scan_type, finished_at)
_meta(key PK, value)            -- holds schema_version = 1
```

`config.db` (`config_db.py`), scan_type `csv_fetch`:

```sql
csv_snapshots(id PK, scan_id→scans, sheet_name, csv_text)            -- always stored
device_records(id PK, scan_id→scans, sheet_name, row_number, machine,
               mac_address, ip, interface, site, extra_json)         -- delta per (machine, interface)
vlan_definitions(id PK, scan_id→scans, vlan_id, name, ip_range,
                 netmask, cidr, color, description)                  -- delta per vlan_id
```

`discovery.db` (`discovery_db.py`), one scan_type per supplement:

```sql
reachability(id PK, scan_id→scans, hostname, interface_idx, ip,
             is_reachable, transmitted, received, rtt_avg_ms)        -- delta on status, not RTT
ssh_host_keys(id PK, scan_id→scans, hostname, key_type, key_data)    -- delta per host
ssl_certs(id PK, scan_id→scans, hostname, issuer, self_signed,
          valid, expiry, sans_json)                                  -- delta per host
bmc_firmware(id PK, scan_id→scans, hostname, product_name,
             firmware_revision, ipmi_version, series, snmp_capable)  -- delta per host
snmp_data / bridge_data / nsdp_data / tasmota_data
  (id PK, scan_id→scans, hostname, data_json)                        -- delta on canonical JSON
```

## Provenance

Reconstructed by reading the 21 commits in `git log main..sqlite-storage` plus
the source of `src/gdoc2netcfg/storage/*.py`, the `config.py` diff, and the `db`
CLI handlers in `cli/main.py`. Original session transcripts from 2026-04-09/10
have been purged; the surviving record is this branch's code and history.
