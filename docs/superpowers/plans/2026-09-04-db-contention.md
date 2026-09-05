# discovery.db Contention Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the reachability daemon and the cron scan jobs from failing each other with `sqlite3.OperationalError: database is locked`, so every supplement scan lands in `discovery.db` and the generated SSHFP / `known_hosts` / dashboards stop going stale.

**Architecture:** The lock holder is not "too many writers" — it is one query. Every `load_latest_*` / `_latest_*` reconstruction in `storage/discovery_db.py` uses a *correlated scalar subquery per row* to find "the latest finished scan holding this entity's rows". On the `reachability` table (65 866 rows, hosts with up to 5 094 rows each) that is O(Σ n_host²) ≈ 9×10⁷ index steps: **331 s** on the 2026-09-04 production copy, versus **0.23 s** for the equivalent `GROUP BY entity, MAX(scan_id)` join. The daemon runs it inside `save_reachability` every cycle and every cron job runs it in `_load_or_run_reachability`, each holding a SQLite SHARED lock for the whole duration; in DELETE-journal mode any other process's COMMIT needs EXCLUSIVE, waits `busy_timeout` (5 s) and dies. Fix = one shared `WITH latest AS (... GROUP BY ...)` query builder used by every reconstruction, a larger busy timeout as a safety net, a daemon that survives a bad sheet row instead of re-running its slow first cycle every 13 minutes, and a lock-watch script so the fix (and any regression) is observable on the box.

**Tech Stack:** Python 3.12+ (`uv run`), sqlite3 3.53 (CTEs), pytest, `/proc/locks` for verification.

**Spec:** This document is its own spec — the *Design* section below is the contract; there is no separate design doc. The investigation evidence lives in the ten64 session notes (`~/local/tmp/lock_watch_2026-09-03.log`, `~/local/tmp/sshfp_manual_2026-09-03.log`) and in the PR #28 description.

**Worktree:** `.worktrees/db-contention` (branch `db-contention`, created from `origin/main` at `1762567`). Each task is one PR-sized commit series; open one PR per task group as noted (Tasks 1–3 = PR "latest-query", Task 4A = PR "mqtt-dns-only", Task 4B = PR "sheet-mac-contract" (merge LAST, after the sheet triage), Task 5 = PR "db-lock-watch", Task 6 = PR "docs" folded into the first PR).

## Global Constraints

- `journal_mode=DELETE` stays. **WAL is rejected**: a non-root read-only open of a root-owned WAL DB fails with `attempt to write a readonly database` whenever `-wal`/`-shm` are absent (they vanish on every clean close; verified 2026-09-04 with a root-owned 0755 dir). Sudo-free reads (`generate`, `validate`, `db info`, …) are a documented design property (`CLAUDE.md` → *Journal mode*; `tests/test_storage/test_base.py::test_delete_journal_mode`).
- No schema change, no new index, no data migration. The `GROUP BY` form already runs in 0.23 s on `idx_reach_host` + the `scans` primary key; add an index only if a measured need appears.
- Semantics of every `load_latest_*` must be byte-for-byte unchanged: "each entity's rows from the most recent **finished** scan that holds rows for that entity; a tombstone as the latest row removes the entity; unfinished scans are invisible". Existing tests in `tests/test_storage/test_discovery_db.py` encode this and must keep passing untouched.
- Never delete history (INSERT-only storage). Retention/pruning of `reachability` is out of scope (growth is ~28 k rows/month; the fixed query is linear, so this is a years-away concern).
- Commit per task step group; `uv run pytest -q` and `uv run ruff check src/ tests/` clean before every commit.

## Design

### Measured facts (2026-09-04, ten64 production copy)

| Reconstruction | rows in table | time |
|---|---|---|
| `load_latest_reachability` | 65 866 | **331 s** |
| `load_latest_zigbee` | 1 055 | 1.08 s |
| `load_latest_tasmota` | — | 0.59 s |
| `load_latest_snmp` | — | 0.47 s |
| all others | ≤ 269 | ≤ 0.15 s |
| raw reachability SQL, correlated form | 65 866 | 249 s |
| raw reachability SQL, `GROUP BY MAX(scan_id)` join | 65 866 | 0.23 s |

Lock timeline captured with a 1 s `/proc/locks` sampler while a manual `sshfp` ran: daemon held SHARED continuously 13:15:08 → 13:25:42 (10.5 min, then crashed and restarted, holding again by 13:28:31); the `sshfp` writer sat in PENDING 13:17:10 → 13:17:15 (exactly `busy_timeout`) and died. `cron.log` holds 751 `database is locked` tracebacks (677 zigbee, 74 sshfp, 35 bridge, 30 tasmota, 26 snmp-host, 23 generate, 20 ssl-certs, 9 fetch). `ssh_host_keys` has had no completed scan since 2026-08-20.

Second, independent multiplier: the daemon dies every cycle with `ValueError: VirtualInterface None for 'power9-b' has no MACs` (raised in `mqtt_ha.build_interface_state`; 714 systemd restarts; earlier the same for `au-plug-49`). `Restart=on-failure` brings it back after 30 s and it re-runs its full cycle — so the slow query runs every ~13 min instead of every 5 min sleep-inclusive, and the bridge availability flaps.

### The one query shape

Every "latest per entity" reconstruction becomes:

```sql
WITH latest AS (
    SELECT t.<entity cols>, MAX(t.scan_id) AS scan_id
    FROM <table> t
    JOIN scans s ON s.id = t.scan_id
    WHERE s.finished_at IS NOT NULL
    GROUP BY t.<entity cols>
)
SELECT <select cols>
FROM <table> t
JOIN latest l ON l.scan_id = t.scan_id AND l.<col> = t.<col> [AND ...]
[ORDER BY ...]
```

`MAX(scan_id)` is exactly the old `ORDER BY s.id DESC LIMIT 1` because `scans.id` is the autoincrement primary key and `t.scan_id = s.id`. Tables that key on `id` instead of `scan_id` (`ssl_certs`, `bmc_firmware`) have one row per entity per scan, so joining on `scan_id` selects the same row.

One builder, `DiscoveryDB._latest_rows_sql(table, entity_cols, select_cols, order_by)`, produces the string; callers pass column names only (all are hard-coded identifiers, never user input — keep the existing `# noqa: S608`).

### Rejected alternatives

- **WAL** — see Global Constraints.
- **Materialised `*_latest` tables maintained on save** — correct but adds write-path complexity and a migration; linear GROUP BY is already 1 000× faster. Revisit only if `reachability` passes ~2 M rows.
- **Re-scheduling cron to avoid the daemon** — impossible; the daemon held the lock >75 % of wall-clock.
- **Retry loops around `begin_scan`** — papering over a 4-minute lock with retries would still lose. A larger `busy_timeout` is kept only as a safety net for the sub-second windows that remain.

## File structure

| File | Responsibility |
|---|---|
| `src/gdoc2netcfg/storage/discovery_db.py` (modify) | `_latest_rows_sql` builder; every reconstruction rewritten onto it |
| `tests/test_storage/test_discovery_db.py` (modify) | Perf regression test + "latest from different scans" coverage for the rewritten paths |
| `src/gdoc2netcfg/storage/base.py` (modify) | `BUSY_TIMEOUT_MS = 30_000` constant, both open paths |
| `tests/test_storage/test_base.py` (modify) | Assert the new timeout |
| `src/gdoc2netcfg/supplements/mqtt_ha.py` (modify) | DNS-only interfaces get no MAC entity/state (4A); `_rebuild_hosts` refuses invalid data (4B) |
| `tests/test_supplements/test_mqtt_ha.py` (modify) | DNS-only interface tests |
| `src/gdoc2netcfg/sources/parser.py` (modify) | `DNS_ONLY_MARKER`, `DeviceRecord.dns_only` |
| `src/gdoc2netcfg/derivations/host_builder.py` (modify) | shared `macced_ips()` |
| `src/gdoc2netcfg/constraints/validators.py` (modify) | `missing_mac` ERROR on interface rows |
| `src/gdoc2netcfg/cli/main.py` (modify) | `fetch` validation gate |
| `tests/test_sources/test_parser.py`, `tests/test_constraints/test_validators.py`, `tests/test_cli/test_fetch_validation.py` | 4B tests |
| `scripts/db_lock_watch.py` (create) | `/proc/locks` sampler for the SQLite DBs (diagnostic) |
| `CLAUDE.md` (modify) | Query-shape rule, busy timeout, lock-watch tool, contention post-mortem pointer |

---

### Task 1: `_latest_rows_sql` builder + reachability rewrite (the 331 s → 0.2 s fix)

**Files:**
- Modify: `src/gdoc2netcfg/storage/discovery_db.py` — `_latest_reachability_rows` (≈ lines 868–901), new method `_latest_rows_sql` placed just above it
- Test: `tests/test_storage/test_discovery_db.py`

**Interfaces:**
- Produces: `DiscoveryDB._latest_rows_sql(table: str, entity_cols: tuple[str, ...], select_cols: str, order_by: str = "") -> str` (used by Tasks 2 and 3)

Context: `DiscoveryDB(path)` in tests is a fresh temp DB (fixture `db`); `db.begin_scan("reachability")` returns a scan id, `db.save_reachability(scan_id, data)` stores `{hostname: {"interfaces": [[{ip, transmitted, received, rtt_avg_ms}, ...]]}}`, `db.finish_scan(scan_id, host_count=..., changed_count=...)` marks it finished. `load_latest_reachability()` returns the same dict shape or `None`. Rows are delta-stored: a host only gets rows in scans where its status changed, so "latest" legitimately comes from a different scan per host — that is what the tests below pin down.

- [ ] **Step 1: Write the failing performance test**

Append to `tests/test_storage/test_discovery_db.py` inside `class TestReachability` (after `test_load_returns_none_with_no_scans`):

```python
    def test_load_latest_is_linear_in_table_size(self, db: DiscoveryDB):
        """Regression for the 2026-09 outage: the old correlated-subquery
        form was O(rows-per-host^2) — 331 s on 65k production rows — and
        held a SHARED lock that long, starving every writer.  30k rows must
        reconstruct in well under a few seconds."""
        import time

        hosts = [f"host{i:03d}" for i in range(200)]
        conn = db.connection
        for scan_no in range(150):
            s = db.begin_scan("reachability")
            conn.executemany(
                "INSERT INTO reachability (scan_id, hostname, interface_idx, "
                "ip, is_reachable, transmitted, received, rtt_avg_ms) "
                "VALUES (?, ?, 0, ?, 1, 10, 10, 1.0)",
                [(s, h, f"10.0.{scan_no % 250}.{i}") for i, h in enumerate(hosts)],
            )
            conn.commit()
            db.finish_scan(s, host_count=len(hosts), changed_count=len(hosts))
        assert conn.execute("SELECT count(*) FROM reachability").fetchone()[0] == 30_000

        t0 = time.monotonic()
        loaded = db.load_latest_reachability()
        elapsed = time.monotonic() - t0

        assert loaded is not None and len(loaded) == 200
        # every host's rows must come from the LAST scan (ip encodes scan 149)
        assert loaded["host000"]["interfaces"][0][0]["ip"] == "10.0.149.0"
        assert elapsed < 3.0, f"load_latest_reachability took {elapsed:.1f}s"

    def test_latest_rows_come_from_different_scans_per_host(self, db: DiscoveryDB):
        """Delta storage: host-a changed in scan 1 only, host-b in scans 1
        and 2 — the reconstruction must mix scans per host, ignore an
        unfinished scan, and drop a host whose latest row is a tombstone."""
        s1 = db.begin_scan("reachability")
        db.save_reachability(s1, {
            **self._make_data("host-a", [("10.1.10.1", 10, 10, 1.0)]),
            **self._make_data("host-b", [("10.1.10.2", 10, 10, 1.0)]),
            **self._make_data("host-c", [("10.1.10.3", 10, 10, 1.0)]),
        })
        db.finish_scan(s1, host_count=3, changed_count=3)

        s2 = db.begin_scan("reachability")
        db.save_reachability(s2, {
            **self._make_data("host-a", [("10.1.10.1", 10, 10, 1.0)]),   # unchanged
            **self._make_data("host-b", [("10.1.10.2", 10, 0, None)]),   # went down
        })
        db.tombstone_missing_reachability(s2, {"host-a", "host-b"})       # host-c removed
        db.finish_scan(s2, host_count=2, changed_count=2)

        s3 = db.begin_scan("reachability")                                # never finished
        db.save_reachability(s3, self._make_data("host-b", [("10.1.10.2", 10, 10, 1.0)]))

        loaded = db.load_latest_reachability()
        assert set(loaded) == {"host-a", "host-b"}
        assert loaded["host-a"]["interfaces"][0][0]["received"] == 10      # from s1
        assert loaded["host-b"]["interfaces"][0][0]["received"] == 0       # from s2, not s3
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_storage/test_discovery_db.py -k "linear_in_table_size or different_scans_per_host" -v`

Expected: `test_latest_rows_come_from_different_scans_per_host` PASSES already (it pins current semantics — keep it, it guards the rewrite). `test_load_latest_is_linear_in_table_size` FAILS on the `elapsed < 3.0` assertion — the old query takes on the order of a minute on 30 k rows. (If it is slow enough to be annoying, run it once and note the time; do not lower the row count.)

- [ ] **Step 3: Add the builder and rewrite `_latest_reachability_rows`**

In `src/gdoc2netcfg/storage/discovery_db.py`, immediately above `def _latest_reachability_rows`, add:

```python
    @staticmethod
    def _latest_rows_sql(
        table: str,
        entity_cols: tuple[str, ...],
        select_cols: str,
        order_by: str = "",
    ) -> str:
        """SQL selecting, for every entity, its rows from the latest
        FINISHED scan that holds rows for that entity.

        Delta storage means each entity's latest data may sit in a
        different scan.  This is the ONLY sanctioned shape for that
        question: a GROUP BY over (entity, MAX(scan_id)) joined back to
        the table — linear in table size.  Never write it as a correlated
        ``WHERE t.scan_id = (SELECT ... ORDER BY s.id DESC LIMIT 1)``:
        that is O(rows-per-entity²), took 331 s on 65k production
        reachability rows, and held a SHARED lock that long so every
        concurrent writer died with "database is locked" (2026-09).

        *entity_cols* / *select_cols* / *table* are code-literal
        identifiers, never user input.  ``MAX(scan_id)`` equals the old
        ``ORDER BY s.id DESC LIMIT 1`` because scans.id is the
        autoincrement key and t.scan_id = s.id.
        """
        group = ", ".join(f"t.{c}" for c in entity_cols)
        join = " AND ".join(f"l.{c} = t.{c}" for c in entity_cols)
        tail = f" {order_by}" if order_by else ""
        return (
            f"WITH latest AS ("
            f"  SELECT {group}, MAX(t.scan_id) AS scan_id"
            f"  FROM {table} t"
            f"  JOIN scans s ON s.id = t.scan_id"
            f"  WHERE s.finished_at IS NOT NULL"
            f"  GROUP BY {group}"
            f") "
            f"SELECT {select_cols} FROM {table} t "
            f"JOIN latest l ON l.scan_id = t.scan_id AND {join}"
            f"{tail}"
        )
```

Then replace the body of `_latest_reachability_rows` so the `execute` reads:

```python
        cur = self._conn.execute(
            self._latest_rows_sql(
                "reachability", ("hostname",),
                "t.hostname, t.interface_idx, t.ip, t.is_reachable, "
                "t.transmitted, t.received, t.rtt_avg_ms, t.is_tombstone",
                order_by="ORDER BY t.hostname, t.interface_idx, t.ip",
            )
        )
```

Leave the Python that follows (`hosts`/`tombstoned` loop) exactly as it is.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_storage/test_discovery_db.py -v`

Expected: all PASS, including the perf test in well under 3 s (typically ~0.2 s).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/storage/discovery_db.py tests/test_storage/test_discovery_db.py
git commit -m "storage: linear 'latest per host' query for reachability (331s -> 0.2s)

_latest_reachability_rows used a correlated scalar subquery per row —
O(rows-per-host^2), 331 s on 65k production rows — and held a SHARED
lock that long inside save_reachability (the daemon, every 5 min) and
_load_or_run_reachability (every cron scan).  In DELETE-journal mode a
concurrent writer's COMMIT waits busy_timeout=5s and dies: 751
'database is locked' tracebacks in cron.log, no ssh_host_keys scan
completed since 2026-08-20.

Add _latest_rows_sql — one GROUP BY (entity, MAX(scan_id)) CTE joined
back to the table — and use it here.  Same rows, same order.  A perf
regression test pins 30k rows under 3 s."
```

---

### Task 2: Move every other correlated reconstruction onto the builder

**Files:**
- Modify: `src/gdoc2netcfg/storage/discovery_db.py` — `load_latest_ssh_host_keys`, `_latest_ssh_keys_by_host` (≈ 1003–1050), `load_latest_ssl_certs`, `_latest_ssl_certs_by_host` (≈ 1097–1140), `load_latest_bmc_firmware`, `_latest_bmc_by_host` (≈ 1184–1230), `_latest_entity_scans` (≈ 1233–1250), `_latest_zigbee` device query (≈ 1615–1630)
- Test: `tests/test_storage/test_discovery_db.py`

**Interfaces:**
- Consumes: `DiscoveryDB._latest_rows_sql` from Task 1.

These tables are small today (≤ 1 055 rows) so they are not the outage, but they share the O(n²) shape and `zigbee` already costs 1.08 s and grows hourly. Same query, same semantics; the existing tests for each supplement stay untouched and are the safety net.

- [ ] **Step 1: Write the failing test for the generic entity helper**

Append to `tests/test_storage/test_discovery_db.py` (new class at the end of the file):

```python
class TestLatestEntityScans:
    """_latest_entity_scans must map each entity to the latest FINISHED
    scan holding its rows, mixing scans across entities.  ssh_host_keys is
    used as the fixture table because its columns are trivial; the helper
    is table-agnostic (any table with scan_id + an entity column)."""

    def _row(self, db: DiscoveryDB, scan_id: int, hostname: str, key: str) -> None:
        db.connection.execute(
            "INSERT INTO ssh_host_keys (scan_id, hostname, key_type, key_data) "
            "VALUES (?, ?, 'ssh-ed25519', ?)",
            (scan_id, hostname, key),
        )
        db.connection.commit()

    def test_mixes_scans_and_ignores_unfinished(self, db: DiscoveryDB):
        s1 = db.begin_scan("ssh_host_keys")
        self._row(db, s1, "a", "AAAA1")
        self._row(db, s1, "b", "BBBB1")
        db.finish_scan(s1, host_count=2, changed_count=2)

        s2 = db.begin_scan("ssh_host_keys")
        self._row(db, s2, "b", "BBBB2")
        db.finish_scan(s2, host_count=1, changed_count=1)

        s3 = db.begin_scan("ssh_host_keys")      # never finished — invisible
        self._row(db, s3, "a", "AAAA3")

        assert db._latest_entity_scans("ssh_host_keys", "hostname") == {"a": s1, "b": s2}
```

- [ ] **Step 2: Run it to verify it passes on the old code** (it pins semantics)

Run: `uv run pytest tests/test_storage/test_discovery_db.py::TestLatestEntityScans -v` → PASS.

- [ ] **Step 3: Rewrite each query**

`_latest_entity_scans`:

```python
    def _latest_entity_scans(
        self, table: str, entity_col: str,
    ) -> dict[str, int]:
        """entity -> the latest completed scan_id holding its rows.

        Each entity's latest data may come from a different scan (delta
        storage — an entity only gets rows in the scans that changed it).
        """
        cur = self._conn.execute(
            f"SELECT t.{entity_col}, MAX(t.scan_id) "  # noqa: S608
            f"FROM {table} t JOIN scans s ON s.id = t.scan_id "
            f"WHERE s.finished_at IS NOT NULL GROUP BY t.{entity_col}",
        )
        return dict(cur.fetchall())
```

`load_latest_ssh_host_keys` and `_latest_ssh_keys_by_host` — replace each `self._conn.execute("SELECT k.hostname ... ")` with:

```python
        cur = self._conn.execute(
            self._latest_rows_sql(
                "ssh_host_keys", ("hostname",),
                "t.hostname, t.key_type, t.key_data",
                order_by="ORDER BY t.hostname, t.key_type",   # omit in _latest_ssh_keys_by_host
            )
        )
```

`load_latest_ssl_certs` and `_latest_ssl_certs_by_host`:

```python
        cur = self._conn.execute(
            self._latest_rows_sql(
                "ssl_certs", ("hostname",),
                "t.hostname, t.issuer, t.self_signed, t.valid, t.expiry, t.sans_json",
                order_by="ORDER BY t.hostname",               # omit in the _by_host variant
            )
        )
```

`load_latest_bmc_firmware` and `_latest_bmc_by_host`:

```python
        cur = self._conn.execute(
            self._latest_rows_sql(
                "bmc_firmware", ("hostname",),
                "t.hostname, t.product_name, t.firmware_revision, "
                "t.ipmi_version, t.series, t.snmp_capable",
                order_by="ORDER BY t.hostname",               # omit in the _by_host variant
            )
        )
```

`_latest_zigbee` device query (`device_cols` is a pre-built `"a, b, c"` string — prefix each with `t.`):

```python
        device_select = ", ".join(f"t.{key}" for key, _t in _ZIGBEE_DEVICE_FIELDS)
        cur = self._conn.execute(
            self._latest_rows_sql(
                "zigbee_devices", ("site", "ieee_address"),
                f"t.site, t.is_tombstone, {device_select}",
                order_by="ORDER BY t.site, t.ieee_address",
            )
        )
```

The per-row Python after each `execute` stays as it is (the selected column order is unchanged).

- [ ] **Step 4: Run the whole storage suite**

Run: `uv run pytest tests/test_storage/ -v`

Expected: all PASS (these tests already cover per-supplement delta/tombstone behaviour; a red test here means the rewrite changed semantics — fix the query, not the test).

- [ ] **Step 5: Verify no correlated form remains**

Run: `grep -n "ORDER BY s.id DESC LIMIT 1" src/gdoc2netcfg/storage/discovery_db.py`

Expected: no output. (`config_db.py` / `credentials_db.py` keep theirs — those tables are tiny and single-row-per-key; out of scope.)

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/storage/discovery_db.py tests/test_storage/test_discovery_db.py
git commit -m "storage: use the linear latest-rows query for every supplement

ssh_host_keys, ssl_certs, bmc_firmware, the generic _latest_entity_scans
(snmp/bridge/nsdp/tasmota/zigbee sites) and zigbee_devices had the same
correlated-subquery shape as reachability.  Small today, same O(n^2)
growth; zigbee already 1.08 s and scanned hourly.  One shape everywhere."
```

---

### Task 3: Busy timeout as a safety net

**Files:**
- Modify: `src/gdoc2netcfg/storage/base.py` — the two `PRAGMA busy_timeout=5000` lines (≈ 94 and 127)
- Test: `tests/test_storage/test_base.py::test_busy_timeout_set` (≈ line 118)

With Task 1 the longest lock is the daemon's `save_reachability` transaction (hundreds of small INSERTs, well under a second) and `_verify_writable`'s `BEGIN IMMEDIATE` at every RW open. 5 s is still plenty in principle, but a cron job that has just spent ten minutes key-scanning should not throw the result away over a momentary overlap. 30 s costs nothing when uncontended.

- [ ] **Step 1: Tighten the test**

In `tests/test_storage/test_base.py` replace `test_busy_timeout_set` with:

```python
    def test_busy_timeout_set(self, db: ConcreteDB):
        # DELETE mode serializes writers against readers.  The timeout must
        # cover the longest legitimate lock hold (a save transaction, <1 s)
        # with a wide margin: a cron job that just spent ten minutes
        # scanning must not discard its result over a momentary overlap.
        from gdoc2netcfg.storage.base import BUSY_TIMEOUT_MS

        assert BUSY_TIMEOUT_MS == 30_000
        cur = db.connection.execute("PRAGMA busy_timeout")
        assert cur.fetchone()[0] == BUSY_TIMEOUT_MS
```

- [ ] **Step 2: Run it to verify it fails** — `uv run pytest tests/test_storage/test_base.py::TestBaseDatabase::test_busy_timeout_set -v` (adjust the class name to the file's) → FAIL with `ImportError: cannot import name 'BUSY_TIMEOUT_MS'`.

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/storage/base.py`, add a module constant near the top (after the imports):

```python
#: SQLite busy_timeout for every open.  DELETE-journal mode serializes
#: writers against readers; this must cover the longest legitimate lock
#: hold (a save transaction, well under a second) with a wide margin.  It
#: is a safety net, NOT a fix for slow queries — see
#: DiscoveryDB._latest_rows_sql for the 2026-09 outage that taught us that.
BUSY_TIMEOUT_MS = 30_000
```

and replace both `self._conn.execute("PRAGMA busy_timeout=5000")` lines with

```python
        self._conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
```

Also update the comment block above the first one (≈ lines 89–92, "busy_timeout absorbs the brief writer/reader …") to say `BUSY_TIMEOUT_MS` instead of `5s`.

- [ ] **Step 4: Run** `uv run pytest tests/test_storage/ -q` → all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/storage/base.py tests/test_storage/test_base.py
git commit -m "storage: busy_timeout 5s -> 30s (BUSY_TIMEOUT_MS) as a contention safety net"
```

Open PR "storage: linear latest-per-entity queries + busy timeout (fixes database-is-locked)" from the branch at this point (Tasks 1–3). Reference PR #28 and this plan.

---

### Task 4A: The MQTT publisher models DNS-only interfaces faithfully (no MAC entity, no crash)

**Files:**
- Modify: `src/gdoc2netcfg/supplements/mqtt_ha.py` — `_iface_entities` (≈ line 169), the interface-discovery loop in `_publish_hosts_to_client` (≈ lines 620–632), `build_interface_state` (≈ lines 513–520, the `if not vi.macs: raise ValueError` block)
- Test: `tests/test_supplements/test_mqtt_ha.py`

**Design decision (2026-09-05, with the owner):** a `VirtualInterface` with `macs == ()` is a *designed* state, not a bug: `derivations/host_builder.py` documents "Records without a MAC (wg tunnels, tailscale) become DNS-only interfaces" and there are 68 of them in production today (ten64's `wg-*`/`tailscale0`, phones on the IoT sheet, planned hardware). The publisher's `raise ValueError(... has no MACs — bug in host-builder pipeline)` asserts an invariant the model does not have, so the daemon has crash-looped on the first MAC-less host in sort order since at least July (au-plug-49, then bmc.power9-b; 714 restarts). The faithful representation is: **no MAC entity at all** for such an interface — not an empty string, not a stderr warning. Whether a MAC *should* have been recorded is decided at the sheet boundary by Task 4B, not guessed here. Everything else in `build_interface_state` (IPv4 must exist, interface counts must match) stays a hard assertion.

- [ ] **Step 1: Write the failing tests**

In `tests/test_supplements/test_mqtt_ha.py`, add `VirtualInterface` to the `gdoc2netcfg.models.host` import line, then add inside `class TestEntityDefs` (next to `test_iface_entities_count`):

```python
    def test_iface_entities_omit_mac_for_dns_only_interface(self):
        """A DNS-only interface (no MAC in the sheet) has no MAC entity —
        the model has no MAC, so HA gets none, rather than a fake ''."""
        entities = _iface_entities("wg0", "wg0", has_mac=False)
        assert len(entities) == 5
        assert not [e for e in entities if e.suffix == "wg0_mac"]

    def test_iface_entities_include_mac_by_default(self):
        entities = _iface_entities("eth0", "eth0")
        assert [e for e in entities if e.suffix == "eth0_mac"]
```

and inside `class TestBuildInterfaceState`:

```python
    def test_dns_only_interface_has_no_mac_state_and_does_not_raise(self):
        """macs == () is a designed state (wg/tailscale/DNS-only rows); the
        publisher must not crash the daemon on it (714 restarts, 2026-07..09)
        and must not fabricate a MAC state either."""
        host = _make_host(machine_name="ten64", hostname="ten64", iface_name="wg-desktop")
        vi = VirtualInterface(
            name="wg-desktop",
            ip_addresses=(IPv4Address("10.98.5.1"),),
            macs=(),
        )
        ir = InterfaceReachability(pings=(("10.98.5.1", PingResult(10, 10, 1.5)),))

        states = build_interface_state(host, vi, ir)

        nid = node_id(host.hostname)
        assert states[f"{STATE_PREFIX}/{nid}/wg-desktop/ipv4/state"] == "10.98.5.1"
        assert f"{STATE_PREFIX}/{nid}/wg-desktop/mac/state" not in states
```

- [ ] **Step 2: Run them** — `uv run pytest tests/test_supplements/test_mqtt_ha.py -k "dns_only or include_mac_by_default" -v` → the first two FAIL (`TypeError: unexpected keyword argument 'has_mac'`), the third FAILS with `ValueError: ... has no MACs`.

- [ ] **Step 3: Implement**

`_iface_entities` gains a keyword-only flag and drops the MAC `EntityDef` when it is false:

```python
def _iface_entities(
    iface_slug: str, iface_name: str | None, *, has_mac: bool = True,
) -> list[EntityDef]:
    """Build entity definitions for a single interface.

    *has_mac* False = a DNS-only interface (no MAC in the sheet: wg /
    tailscale tunnels, rows marked ``none``).  Such an interface has no
    MAC entity at all — the model has no MAC, so HA is told nothing,
    rather than a fabricated empty value.
    """
    display = iface_name or "default"
    entities = [
        ...existing connectivity, stack_mode, ipv4, ipv6 EntityDefs unchanged...
    ]
    if has_mac:
        entities.append(EntityDef(
            component="sensor",
            suffix=f"{iface_slug}_mac",
            name=f"{display} MAC",
            entity_category="diagnostic",
            icon="mdi:ethernet",
            expire_after=600,
        ))
    entities.append(EntityDef(
        ...existing rtt EntityDef unchanged...
    ))
    return entities
```

(Keep the entity order connectivity, stack_mode, ipv4, ipv6, [mac], rtt — `test_iface_entities_count` still expects 6 with a MAC.)

In `_publish_hosts_to_client`'s interface-discovery loop, pass the flag and clear any discovery HA still retains for a MAC entity this interface no longer has (retained empty payload = HA deletes the entity; otherwise the old `_mac` sensor lingers as "unavailable"):

```python
        for vi in host.virtual_interfaces:
            slug = _iface_slug(vi)
            has_mac = bool(vi.macs)
            for entity in _iface_entities(slug, vi.name, has_mac=has_mac):
                ...existing publish unchanged...
            if not has_mac:
                # Remove a MAC entity HA may retain from before DNS-only
                # interfaces were modelled (empty retained config = delete).
                stale = EntityDef(component="sensor", suffix=f"{slug}_mac", name="")
                client.publish(discovery_topic(stale, nid), "", retain=True)
```

(Check `EntityDef`'s required fields with `grep -n "class EntityDef" -A20 src/gdoc2netcfg/supplements/mqtt_ha.py` and fill only what `discovery_topic` needs — it uses `component` and `suffix`.)

In `build_interface_state` replace the `if not vi.macs: raise ValueError(...)` / `states[...mac/state] = ...` block with:

```python
    # MAC — absent for DNS-only interfaces (no MAC in the sheet: wg /
    # tailscale, rows marked `none`).  Such an interface has no MAC
    # entity (see _iface_entities), so publish no MAC state either.
    # Whether a MAC *should* have been recorded is enforced at the sheet
    # boundary (constraints/validators.py missing_mac ERROR + fetch gate),
    # not guessed here.
    if vi.macs:
        states[f"{prefix}/mac/state"] = str(vi.macs[0]).lower()
```

- [ ] **Step 4: Run** `uv run pytest tests/test_supplements/test_mqtt_ha.py -q` → all PASS.

- [ ] **Step 5: Commit** and open PR "mqtt: model DNS-only interfaces (no MAC entity) instead of crashing the daemon"

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/supplements/mqtt_ha.py tests/test_supplements/test_mqtt_ha.py
git commit -m "mqtt: DNS-only interfaces get no MAC entity instead of crashing the daemon

VirtualInterface.macs == () is a designed state (host_builder: rows
without a MAC are DNS-only interfaces — wg, tailscale, planned hosts;
68 in production).  build_interface_state asserted the opposite and
raised, so the publisher died on the first MAC-less host in sort order
every cycle (au-plug-49, then bmc.power9-b; 714 systemd restarts).

Model it instead: no MAC EntityDef and no MAC state for such an
interface, plus a retained-empty publish to delete any MAC entity HA
still holds from before.  Nothing is fabricated and nothing is warned
to stderr — whether the MAC *should* exist is enforced at the sheet
boundary (validators missing_mac ERROR + fetch gate)."
```

---

### Task 4B: A missing MAC is an ERROR unless the sheet says `none`; `fetch` refuses to cache invalid sheets

**Files:**
- Modify: `src/gdoc2netcfg/sources/parser.py` — `DeviceRecord` (≈ line 16) and the MAC extraction in `parse_csv` (≈ lines 157–159)
- Modify: `src/gdoc2netcfg/derivations/host_builder.py` — factor the inline `macced_ips` set (≈ lines 135–137) into a function
- Modify: `src/gdoc2netcfg/constraints/validators.py` — `validate_field_constraints` (≈ lines 31–50)
- Modify: `src/gdoc2netcfg/cli/main.py` — `cmd_fetch` (≈ lines 500–612)
- Test: `tests/test_sources/test_parser.py`, `tests/test_constraints/test_validators.py`, `tests/test_cli/test_fetch_credentials.py` (add a sibling file `tests/test_cli/test_fetch_validation.py`)

**Design decision (2026-09-05, with the owner):** the sheet contract becomes *"an interface row (Machine + IP present) must carry a MAC, or the literal `none` in the MAC cell meaning DNS-only on purpose"*. Anything else is `missing_mac` at **ERROR** severity. Two existing exemptions stay: rows with no Machine or no IP (headings, blanks — those keep their existing WARNINGs) and *cross-reference rows* (a MAC-less row whose IP is claimed by a MAC'd row on another sheet, e.g. the IoT sheet listing a Network-sheet machine for plug bookkeeping — `host_builder` already skips those; 53 exist). The gate is `fetch`: like the existing lost-credential-cell check, a sheet set with validation errors is **not cached and not stored** — the previous good CSVs stay in place and, via PR #28, root gets a mail every 15 minutes until the sheet is fixed. `generate` already exits 1 on errors; the daemon's `_rebuild_hosts` gets the same check so it can never publish from invalid data (it should never see any — `fetch` blocks it — so a failure there is a bug and is allowed to be a hard failure).

Production impact at rollout: 71 rows are missing a MAC today and are neither blank nor cross-references (list in Phase 2 step 5). They must be triaged — `none` for the deliberate ones, a MAC for the placeholders — **before** this ships, or `fetch` will refuse every run.

- [ ] **Step 1: Failing tests — parser marker**

Add to `tests/test_sources/test_parser.py` (copy the file's CSV-fixture idiom; the header row must contain `Machine` and `MAC`):

```python
class TestDnsOnlyMarker:
    def test_none_marker_yields_empty_mac_and_dns_only(self):
        csv_text = (
            "Machine,MAC Address,IP,Interface\n"
            "ten64,none,10.98.5.1,wg-desktop\n"
            "ten64,NONE,10.98.6.1,wg-x1c-work\n"
            "desk,aa:bb:cc:dd:ee:ff,10.1.10.5,eth0\n"
            "planned,,10.1.10.6,eth0\n"
        )
        recs = parse_csv(csv_text, "network")
        by_if = {r.interface: r for r in recs}
        assert by_if["wg-desktop"].mac_address == "" and by_if["wg-desktop"].dns_only is True
        assert by_if["wg-x1c-work"].mac_address == "" and by_if["wg-x1c-work"].dns_only is True
        assert by_if["eth0"].dns_only is False           # 'desk' row: real MAC
        assert by_if["eth0"].mac_address == "aa:bb:cc:dd:ee:ff"
        planned = [r for r in recs if r.machine == "planned"][0]
        assert planned.mac_address == "" and planned.dns_only is False
```

- [ ] **Step 2: Failing tests — validator**

In `tests/test_constraints/test_validators.py`, extend `_record` with `dns_only=False` and `interface=""` parameters (pass them through to `DeviceRecord`), replace `test_missing_mac`, and add:

```python
    def test_missing_mac_on_interface_row_is_an_error(self):
        result = validate_field_constraints([_record(mac="")])
        assert not result.is_valid
        assert result.errors[0].code == "missing_mac"
        assert "none" in result.errors[0].message   # tells the user how to mark DNS-only

    def test_none_marker_is_not_an_error(self):
        result = validate_field_constraints([_record(mac="", dns_only=True)])
        assert result.is_valid
        assert not [v for v in result.violations if v.code == "missing_mac"]

    def test_missing_mac_on_row_without_ip_stays_a_warning(self):
        result = validate_field_constraints([_record(mac="", ip="")])
        assert result.is_valid
        assert {v.code for v in result.warnings} == {"missing_mac", "missing_ip"}

    def test_cross_reference_row_is_exempt(self):
        """A MAC-less row whose IP is claimed by a MAC'd row is bookkeeping
        (host_builder skips it), not a missing MAC."""
        owner = _record(machine="plug-1", mac="aa:bb:cc:dd:ee:01", ip="10.1.90.10")
        xref = DeviceRecord(sheet_name="iot", row_number=9, machine="plug-1",
                            mac_address="", ip="10.1.90.10")
        result = validate_field_constraints([owner, xref])
        assert result.is_valid
```

- [ ] **Step 3: Failing test — fetch gate**

Create `tests/test_cli/test_fetch_validation.py` (reuse the `fetch_config` fixture by importing it: `from tests.test_cli.test_fetch_credentials import fetch_config  # noqa: F401`, or copy it):

```python
"""fetch must refuse to cache a sheet set that fails validation."""

from __future__ import annotations

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import SheetData

from tests.test_cli.test_fetch_credentials import fetch_config  # noqa: F401


def test_fetch_refuses_sheet_with_unmarked_missing_mac(fetch_config, monkeypatch, capsys):
    config, cache_dir = fetch_config

    def fake_fetch(name, url):
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\n"
            "ten64,none,10.98.5.1,wg-desktop\n"          # marked: fine
            "power9-b,,10.1.11.184,enP5p1s0f0\n"         # unmarked: ERROR
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    rc = cli.main(["-c", str(config), "fetch"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "missing_mac" in err
    assert "power9-b" in err
    assert "network:3" in err or "row 3" in err
    assert "Nothing was stored" in err
    assert not (cache_dir / "network.csv").exists()


def test_fetch_caches_sheet_when_dns_only_rows_are_marked(fetch_config, monkeypatch):
    config, cache_dir = fetch_config

    def fake_fetch(name, url):
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\n"
            "ten64,none,10.98.5.1,wg-desktop\n"
            "desk,aa:bb:cc:dd:ee:ff,10.1.10.5,eth0\n"
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    assert cli.main(["-c", str(config), "fetch"]) == 0
    assert (cache_dir / "network.csv").exists()


def test_fetch_validates_against_cached_copy_of_a_sheet_that_failed_to_fetch(
    fetch_config, monkeypatch, tmp_path,
):
    """Partial fetch: the post-write cache = fetched sheets + the cached copy
    of the failed ones.  Validate exactly that set, so a cross-reference
    row whose owner lives in the failed sheet is still recognised."""
    config, cache_dir = fetch_config
    config.write_text(config.read_text().replace(
        'network = "https://example.com/network"',
        'network = "https://example.com/network"\niot = "https://example.com/iot"',
    ))
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\nplug-1,aa:bb:cc:dd:ee:01,10.1.90.10,\n"
    )

    def fake_fetch(name, url):
        if name == "network":
            raise RuntimeError("HTTP 503")
        return SheetData(name=name, csv_text=(
            "Machine,MAC Address,IP,Interface\nplug-1,,10.1.90.10,\n"   # xref of cached owner
        ))

    monkeypatch.setattr("gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=True)

    assert cli.main(["-c", str(config), "fetch"]) == 0
    assert (cache_dir / "iot.csv").exists()
```

- [ ] **Step 4: Run all three groups to verify they fail**

`uv run pytest tests/test_sources/test_parser.py::TestDnsOnlyMarker tests/test_constraints/test_validators.py::TestFieldConstraints tests/test_cli/test_fetch_validation.py -v` → parser: `AttributeError: dns_only`; validator: the new tests FAIL (warning vs error); fetch: the refuse test FAILS (rc 0).

- [ ] **Step 5: Implement — parser**

In `src/gdoc2netcfg/sources/parser.py`:

```python
#: Literal MAC-cell value meaning "this interface has no MAC on purpose"
#: (wg / tailscale tunnels, DNS-only entries).  Compared case-insensitively.
DNS_ONLY_MARKER = "none"
```

Add to `DeviceRecord` after `site: str = ""`:

```python
    #: True when the MAC cell held DNS_ONLY_MARKER: a deliberately MAC-less
    #: (DNS-only) interface.  A row with machine+IP, no MAC and dns_only
    #: False is a validation ERROR (missing_mac).
    dns_only: bool = False
```

In `parse_csv`, replace the MAC extraction with:

```python
        mac = ""
        dns_only = False
        if mac_col is not None and mac_col < len(row):
            mac = row[mac_col].strip()
            if mac.lower() == DNS_ONLY_MARKER:
                mac = ""
                dns_only = True
```

and pass `dns_only=dns_only` into the `DeviceRecord(...)` constructor.

- [ ] **Step 6: Implement — shared cross-reference helper**

In `src/gdoc2netcfg/derivations/host_builder.py`, add a module-level function and use it where the inline set is built (≈ line 135):

```python
def macced_ips(records: list[DeviceRecord]) -> set[str]:
    """IPs claimed by a row that has machine, IP and a MAC.

    A MAC-less row on such an IP is a cross-reference (e.g. the IoT sheet
    listing a Network-sheet machine for plug bookkeeping), not a host:
    build_hosts skips it and validators do not report it as missing_mac.
    ONE definition, used by both, so they cannot drift.
    """
    return {r.ip for r in records if r.machine and r.ip and r.mac_address}
```

```python
    macced_ips_set = macced_ips(records)
    ...
        if not record.mac_address and record.ip in macced_ips_set:
            continue  # cross-reference row for a MAC'd interface
```

- [ ] **Step 7: Implement — validator**

In `src/gdoc2netcfg/constraints/validators.py`, `validate_field_constraints` becomes:

```python
def validate_field_constraints(records: list[DeviceRecord]) -> ValidationResult:
    """Validate field-level constraints on raw device records.

    Checks:
    - MAC address must be present on every interface row (machine + IP),
      unless the MAC cell says ``none`` (DNS_ONLY_MARKER: a deliberately
      DNS-only interface) or the row is a cross-reference of a MAC'd row
      on the same IP.  ERROR — fetch refuses to cache the sheet set.
    - Machine name must be present (WARNING)
    - IP address must be present (WARNING)
    """
    from gdoc2netcfg.derivations.host_builder import macced_ips
    from gdoc2netcfg.sources.parser import DNS_ONLY_MARKER

    result = ValidationResult()
    claimed = macced_ips(records)

    for record in records:
        record_id = f"{record.sheet_name}:{record.row_number}"

        if not record.mac_address and not record.dns_only:
            is_interface_row = bool(record.machine and record.ip)
            if is_interface_row and record.ip in claimed:
                pass  # cross-reference row; host_builder skips it
            elif is_interface_row:
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="missing_mac",
                    message=(
                        f"No MAC address (machine={record.machine!r}, "
                        f"interface={record.interface!r}, ip={record.ip!r}); "
                        f"record the MAC, or put '{DNS_ONLY_MARKER}' in the "
                        f"MAC cell for a deliberately DNS-only interface"
                    ),
                    record_id=record_id,
                    field="mac_address",
                ))
            else:
                result.add(ConstraintViolation(
                    severity=Severity.WARNING,
                    code="missing_mac",
                    message=f"No MAC address (machine={record.machine!r})",
                    record_id=record_id,
                    field="mac_address",
                ))

        ...missing_machine / missing_ip blocks unchanged...
```

(If `validators.py` importing from `derivations.host_builder` creates an import cycle — check with `uv run python -c "import gdoc2netcfg.constraints.validators"` — move `macced_ips` to `gdoc2netcfg/sources/parser.py` next to `DeviceRecord` and import it from there in both places.)

- [ ] **Step 8: Implement — fetch gate**

In `cmd_fetch`, after step 1 (all sheets attempted) and **before** step 3 (credentials) insert:

```python
    # 2a. Validate the sheet set the cache will hold after this run:
    #     the sheets just fetched plus the CACHED copy of any sheet that
    #     failed to fetch.  Invalid data is never cached — the previous
    #     good CSVs stay and the cron mail says why (fail loud, early).
    from gdoc2netcfg.constraints.validators import validate_field_constraints
    from gdoc2netcfg.sources.cache import CSVCache

    cache = CSVCache(config.cache.directory)
    fetched_names = {name for name, _ in raw_csvs}
    to_validate = list(raw_csvs)
    for sheet in config.sheets:
        if sheet.name not in fetched_names and cache.has(sheet.name):
            to_validate.append((sheet.name, cache.read(sheet.name)))
    field_result = validate_field_constraints(_parse_device_records(to_validate))
    if field_result.has_errors:
        print(
            "Error: the fetched sheets fail validation; refusing to cache "
            "or store them (the previous cached copies stay in place):",
            file=sys.stderr,
        )
        print(field_result.report(), file=sys.stderr)
        print("Fix the spreadsheet rows above, then re-run fetch. Nothing was stored.",
              file=sys.stderr)
        return 1
```

(`_parse_device_records` already skips non-device sheets. Remove the later duplicate `cache = CSVCache(...)` line in step 4 or reuse the variable. Confirm `ValidationResult.report()` prints `code`, `record_id` and message — that is what `cmd_generate` prints; the fetch-gate test asserts `missing_mac`, `power9-b` and the row reference appear.)

- [ ] **Step 9: Implement — daemon rebuild never publishes from invalid data**

In `src/gdoc2netcfg/supplements/mqtt_ha.py::_rebuild_hosts`, act on the validation result `_build_pipeline` already returns:

```python
    _, hosts, _inventory, result = _build_pipeline(config)
    if result.has_errors:
        raise ValueError(
            "Cached sheets fail validation — refusing to publish from "
            "invalid data (fetch should have refused to cache this):\n"
            + result.report()
        )
    return hosts
```

Keep the existing `previous_hosts` fallback for *other* exceptions untouched.

- [ ] **Step 10: Run** `uv run pytest -q` (full suite) and `uv run ruff check src/ tests/` → all PASS, clean. Then run the validator against today's production sheets from the worktree to produce the triage list for Phase 2: `uv run gdoc2netcfg -c /opt/gdoc2netcfg/gdoc2netcfg.toml validate | grep "ERROR"` — expect the 71 rows listed under Phase 2 step 5 and no others.

- [ ] **Step 11: Docs + commit** — in `CLAUDE.md` *Fail Loud, Never Fabricate* section add one bullet: "*Sheet contract:* every interface row (Machine + IP) carries a MAC or the literal `none` (deliberately DNS-only). Anything else is `missing_mac` at ERROR: `fetch` refuses to cache the sheet set (previous CSVs stay; cron mails root), `generate` exits 1, the daemon refuses to publish." Then:

```bash
git add src/gdoc2netcfg/sources/parser.py src/gdoc2netcfg/derivations/host_builder.py \
        src/gdoc2netcfg/constraints/validators.py src/gdoc2netcfg/cli/main.py \
        src/gdoc2netcfg/supplements/mqtt_ha.py CLAUDE.md tests/
git commit -m "sheets: a missing MAC is an ERROR unless the cell says 'none'; fetch refuses invalid sheets

Contract: every interface row (Machine + IP) carries a MAC, or the
literal 'none' meaning deliberately DNS-only (wg, tailscale).  Blank
and heading rows keep their WARNINGs; a MAC-less row whose IP is
claimed by a MAC'd row (cross-reference bookkeeping) stays exempt via
the shared macced_ips() helper host_builder already used.

fetch validates the sheet set the cache will hold (fetched sheets +
cached copies of any that failed) and, like the lost-credential check,
stores nothing on ERROR — the previous good CSVs stay and the cron
mail says which rows to fix.  The daemon's rebuild refuses to publish
from invalid cached data too."
```

Open PR "sheets: missing MAC is an ERROR unless marked none; fetch refuses invalid sheets". **Do not merge before the Phase 2 sheet triage is done.**

---

### Task 5: `scripts/db_lock_watch.py` — see who holds the DB

**Files:**
- Create: `scripts/db_lock_watch.py`
- Test: none (diagnostic, root-only, reads `/proc`); document usage in the docstring and CLAUDE.md (Task 6)

This is the tool that found the outage; keep it in the repo so the rollout (below) and any future "database is locked" report can be diagnosed in seconds. It maps SQLite's fcntl byte-range locks to their names.

- [ ] **Step 1: Create the script**

```python
#!/usr/bin/env python3
"""Sample /proc/locks for the gdoc2netcfg SQLite DBs and print lock holders.

Usage (as root — /proc/<pid>/cmdline of root daemons needs it):

    sudo .venv/bin/python scripts/db_lock_watch.py [SECONDS] [DB ...]

Defaults: 600 s, .cache/discovery.db and .cache/config.db.  Prints a line
whenever the set of (pid, lock) changes, with how long the previous state
lasted.  SQLite (unix VFS) byte-range locks, relative to 0x40000000:

    PENDING   = byte 0        RESERVED = byte 1       SHARED = bytes 2..511 (READ)
    EXCLUSIVE = bytes 2..511 as WRITE

A SHARED holder that stays for minutes is a long read query; a writer in
PENDING behind it is about to die with "database is locked" after
busy_timeout.  That combination was the 2026-09 outage.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

BASE = 0x40000000


def _lock_name(kind: str, lo: int, hi: int) -> str:
    if (lo, hi) == (0, 0):
        return "PENDING"
    if (lo, hi) == (1, 1):
        return "RESERVED"
    if (lo, hi) == (2, 511):
        return "EXCLUSIVE" if kind == "WRITE" else "SHARED"
    return f"bytes {lo}-{hi} ({kind})"


def _holders(inodes: dict[int, str]) -> set[tuple[str, str, str, str]]:
    out = set()
    for line in Path("/proc/locks").read_text().splitlines():
        f = line.split()
        if len(f) < 8 or f[3] not in ("READ", "WRITE"):
            continue
        inode = int(f[5].rsplit(":", 1)[1])
        if inode not in inodes:
            continue
        pid, kind = f[4], f[3]
        lo, hi = int(f[6]) - BASE, int(f[7]) - BASE
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
            cmd = cmd.decode(errors="replace").strip()[-80:]
        except OSError:
            cmd = "?"
        out.add((inodes[inode], pid, _lock_name(kind, lo, hi), cmd))
    return out


def main(argv: list[str]) -> int:
    seconds = float(argv[1]) if len(argv) > 1 else 600.0
    dbs = argv[2:] or [".cache/discovery.db", ".cache/config.db"]
    inodes = {os.stat(p).st_ino: Path(p).name for p in dbs}
    deadline = time.monotonic() + seconds
    prev: set | None = None
    since = time.monotonic()
    while time.monotonic() < deadline:
        cur = _holders(inodes)
        if cur != prev:
            held = f"{time.monotonic() - since:.0f}s" if prev is not None else "-"
            print(f"{time.strftime('%H:%M:%S')} (previous state held {held})", flush=True)
            for db, pid, name, cmd in sorted(cur):
                print(f"    {db}: pid={pid} {name} :: {cmd}", flush=True)
            if not cur:
                print("    (no locks)", flush=True)
            prev, since = cur, time.monotonic()
        time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 2: Smoke-test on the box** — from `/opt/gdoc2netcfg`: `sudo .venv/bin/python scripts/db_lock_watch.py 20` while the daemon is mid-cycle; expect at least one `SHARED` line naming `reachability publish --daemon`. `chmod +x scripts/db_lock_watch.py`.

- [ ] **Step 3: Commit** — `git add scripts/db_lock_watch.py && git commit -m "scripts: db_lock_watch — map /proc/locks to SQLite lock names per holder"`. Open PR "scripts: db_lock_watch".

---

### Task 6: Documentation

**Files:**
- Modify: `CLAUDE.md` — *SQLite Storage* (≈ lines 284–288) and *Production Deployment → SQLite databases* (≈ line 404–413)

- [ ] **Step 1: Amend the Journal-mode note** (≈ line 288) to:

```markdown
> **Journal mode:** the DBs use `journal_mode=DELETE` (not WAL), so a read-only open (`mode=ro` URI) needs no write access at all — a non-root user can read the root-owned production DBs. (WAL was re-tested 2026-09-04 and rejected: a non-root reader fails with "attempt to write a readonly database" whenever `-wal`/`-shm` are absent, which they are after every clean close.) Writes serialize against reads; `BUSY_TIMEOUT_MS` (30 s) absorbs the momentary contention.
>
> **Query shape rule:** "latest rows per entity" is ALWAYS `DiscoveryDB._latest_rows_sql` (a `GROUP BY entity, MAX(scan_id)` CTE joined back) — never a correlated `WHERE t.scan_id = (SELECT … ORDER BY s.id DESC LIMIT 1)`. The correlated form is O(rows-per-entity²); on 65k reachability rows it took 331 s and, because SQLite holds a SHARED lock for the whole SELECT, every concurrent writer (the cron scans) died with `database is locked` for two weeks (2026-08-21 → 09-04, plan `docs/superpowers/plans/2026-09-04-db-contention.md`). Diagnose lock holders with `sudo .venv/bin/python scripts/db_lock_watch.py`.
```

- [ ] **Step 2: Add one paragraph to *SQLite databases* under Production Deployment** (after the "Ownership" paragraph):

```markdown
**"database is locked":** run `sudo .venv/bin/python scripts/db_lock_watch.py 120` to see which process holds which lock and for how long. A `SHARED` holder lasting more than a second or two is a slow read query (see the *Query shape rule* under *SQLite Storage*); a writer stuck in `PENDING` behind it is the victim. Failed cron jobs mail root (`cron run`, see *Scheduled jobs*), so a locked-DB failure is an email, not a silent log line.
```

- [ ] **Step 3: Commit** — `git add CLAUDE.md && git commit -m "docs: SQLite query-shape rule, WAL rejection, lock-watch diagnosis"` (fold into the Task 1–3 PR).

---

## Phase 2: Rollout (controller-run on ten64 and monarto — NOT subagent work)

1. Merge the PRs (`git merge --no-ff`, ask first), then on each site: `cd /opt/gdoc2netcfg && sudo -E git pull && sudo systemctl restart gdoc2netcfg-reachability.service`.
2. **Prove the hold time is gone:** `sudo .venv/bin/python scripts/db_lock_watch.py 420` across one full daemon cycle. Expect the daemon's `SHARED` lines to last ≤ 2 s; no `PENDING` line older than a second.
3. **Prove a scan now lands:** `sudo /usr/local/bin/uv --quiet --directory /opt/gdoc2netcfg run gdoc2netcfg cron run sshfp` → exit 0, and `sudo sqlite3 .cache/discovery.db "SELECT id, finished_at, host_count FROM scans WHERE scan_type='ssh_host_keys' ORDER BY id DESC LIMIT 1"` shows today.
4. **Refresh the stale artefacts that started all this:** `sudo make deploy-known-hosts` and `sudo make deploy-dns` in `/opt/gdoc2netcfg`; then `dig +short SSHFP tweed.welland.mithis.com @10.1.0.1` must list `4 2 F0931A45…` (tweed's post-2026-08-26 ed25519 key) and `ssh -o BatchMode=yes root@eth-uplink.tweed.welland.mithis.com hostname` must no longer warn.
5. **Sheet triage (before merging Task 4B):** 71 interface rows have no MAC and are neither blank nor cross-references (`validate` will list them as `missing_mac` ERRORs once 4B is on a branch — run it from the worktree against `/opt/gdoc2netcfg/gdoc2netcfg.toml`). For each, the owner decides: put `none` in the MAC cell (deliberately DNS-only) or record the MAC. As of 2026-09-05 they are: ten64 `tailscale0`/`wg-*` (network:88–89, 105, 122–126) and x1c-work `tailscale` (network:9) — tunnels, expect `none`; `ports.sw-bb-100g swp10s1` (network:216); power9-b bmc/enP5p1s0f0/enP5p1s0f1 (network:354–356); the eight `x10/x11-*.sm` machines' bmc/rpi/esp32 rows (network:375–398) and sm-pcie-1 rpi/esp32 (network:400–401); `piN.fpgas eth-uplink` for N ∈ {3,5,8,15,18,19,20,22,24,28,30,32,34,35,36,37,38,39,40} (network:413–450); rpi-sdr-rtlsdr-v4 eth0/wlan0 (network:456–457); kindle-monarto-dash / kindle-welland-dash wlan0 (network:479–480); opi1pc-d/e/f eth0 (network:577–579); IoT sheet ha, sdr-mqtt, pixel6, pixel-7-pro, x1c-work, pixel-3a-xl (iot:3–9). Then merge 4B, deploy, and confirm `fetch` succeeds and `journalctl -u gdoc2netcfg-reachability` shows no restarts (`systemctl show -p NRestarts`).
6. **Next morning:** no cron failure mail from either site; `grep -c "database is locked" .cache/cron.log` unchanged from the pre-deploy count.

## Follow-ups (separate issues, not this plan)

- `validate` should flag interface rows with an IP but no MAC (the `power9-b` class of sheet error) so `generate` reports it instead of the daemon discovering it.
- `generate` should warn or fail when a supplement's latest completed scan is older than its cron cadence (e.g. `ssh_host_keys` > 36 h) — the stale-SSHFP failure mode would then be a mail, not a surprise.
- `_load_or_run_reachability` opens `DiscoveryDB` read-write just to read the daemon's cache; a read-only open for the cached path would let the supplement scans' pre-flight run without `_verify_writable`'s `BEGIN IMMEDIATE`.
- Reachability history retention (currently ~28 k rows/month, INSERT-only).
