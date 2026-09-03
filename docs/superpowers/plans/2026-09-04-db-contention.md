# discovery.db Contention Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the reachability daemon and the cron scan jobs from failing each other with `sqlite3.OperationalError: database is locked`, so every supplement scan lands in `discovery.db` and the generated SSHFP / `known_hosts` / dashboards stop going stale.

**Architecture:** The lock holder is not "too many writers" — it is one query. Every `load_latest_*` / `_latest_*` reconstruction in `storage/discovery_db.py` uses a *correlated scalar subquery per row* to find "the latest finished scan holding this entity's rows". On the `reachability` table (65 866 rows, hosts with up to 5 094 rows each) that is O(Σ n_host²) ≈ 9×10⁷ index steps: **331 s** on the 2026-09-04 production copy, versus **0.23 s** for the equivalent `GROUP BY entity, MAX(scan_id)` join. The daemon runs it inside `save_reachability` every cycle and every cron job runs it in `_load_or_run_reachability`, each holding a SQLite SHARED lock for the whole duration; in DELETE-journal mode any other process's COMMIT needs EXCLUSIVE, waits `busy_timeout` (5 s) and dies. Fix = one shared `WITH latest AS (... GROUP BY ...)` query builder used by every reconstruction, a larger busy timeout as a safety net, a daemon that survives a bad sheet row instead of re-running its slow first cycle every 13 minutes, and a lock-watch script so the fix (and any regression) is observable on the box.

**Tech Stack:** Python 3.12+ (`uv run`), sqlite3 3.53 (CTEs), pytest, `/proc/locks` for verification.

**Spec:** This document is its own spec — the *Design* section below is the contract; there is no separate design doc. The investigation evidence lives in the ten64 session notes (`~/local/tmp/lock_watch_2026-09-03.log`, `~/local/tmp/sshfp_manual_2026-09-03.log`) and in the PR #28 description.

**Worktree:** `.worktrees/db-contention` (branch `db-contention`, created from `origin/main` at `1762567`). Each task is one PR-sized commit series; open one PR per task group as noted (Tasks 1–3 = PR "latest-query", Task 4 = PR "daemon-no-macs", Task 5 = PR "db-lock-watch", Task 6 = PR "docs" folded into the first PR).

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
| `src/gdoc2netcfg/supplements/mqtt_ha.py` (modify) | `build_interface_state` tolerates an interface with no MACs |
| `tests/test_supplements/test_mqtt_ha.py` (modify) | Test for the no-MAC interface |
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

### Task 4: Daemon survives an interface with no MACs

**Files:**
- Modify: `src/gdoc2netcfg/supplements/mqtt_ha.py` — `build_interface_state` (≈ lines 480–525, the `if not vi.macs: raise ValueError(...)` block)
- Test: `tests/test_supplements/test_mqtt_ha.py`

Context: `power9-b` in the Network sheet has three interface rows with IPs but empty MAC cells, so the host builder yields a `VirtualInterface` with `macs == []`. `build_interface_state` raises, the daemon's `run_daemon` loop does not catch it, `MQTT daemon stopped` is printed, systemd restarts it 30 s later — 714 restarts. The IPv6 branch two lines above already publishes `""` when absent; MAC should behave the same and shout on stderr, once per cycle, so the sheet bug is visible in `journalctl` without taking the whole publisher down. The data fix (fill in the MACs) is a rollout item below; the validator improvement is a follow-up.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_supplements/test_mqtt_ha.py` inside `class TestBuildInterfaceState` (the file already imports `IPv4Address`, `IPv6Address`, `MACAddress`, `Host`, `NetworkInterface`, `build_interface_state`, `STATE_PREFIX`, `InterfaceReachability`, `PingResult`, `node_id`; add `VirtualInterface` to the `gdoc2netcfg.models.host` import). `VirtualInterface` is a plain dataclass `(name, ip_addresses, macs, dhcp_names=(), vlan_id=None)`, so the MAC-less case is built directly rather than through the host builder:

```python
    def test_interface_without_macs_publishes_empty_mac_and_warns(self, capsys):
        """A sheet row with an IP but no MAC yields a VirtualInterface with
        macs == ().  That is a data bug to report, not a reason to kill the
        daemon (714 restarts on 'power9-b', 2026-08/09): publish mac='' and
        warn on stderr."""
        from gdoc2netcfg.models.host import VirtualInterface

        host = _make_host(machine_name="power9-b", hostname="power9-b", iface_name="eth0")
        vi = VirtualInterface(
            name="eth0",
            ip_addresses=(IPv4Address("10.1.5.10"),),
            macs=(),
        )
        ir = InterfaceReachability(pings=(("10.1.5.10", PingResult(10, 10, 1.5)),))

        states = build_interface_state(host, vi, ir)

        nid = node_id(host.hostname)
        assert states[f"{STATE_PREFIX}/{nid}/eth0/mac/state"] == ""
        assert states[f"{STATE_PREFIX}/{nid}/eth0/ipv4/state"] == "10.1.5.10"
        err = capsys.readouterr().err
        assert "has no MACs" in err
        assert "power9-b" in err
```

- [ ] **Step 2: Run it** — `uv run pytest tests/test_supplements/test_mqtt_ha.py -k without_macs -v` → FAIL with `ValueError: VirtualInterface ... has no MACs`.

- [ ] **Step 3: Implement**

Replace the raise block in `build_interface_state` with:

```python
    # MAC — a VirtualInterface groups physical NICs and normally has one.
    # A sheet row with an IP but an empty MAC cell yields macs == []; that
    # is a data bug to surface, not a reason to take the publisher down
    # (the daemon crash-looped 714 times on one such host).  Publish an
    # empty MAC, like the IPv6 branch above, and say so loudly.
    if vi.macs:
        states[f"{prefix}/mac/state"] = str(vi.macs[0]).lower()
    else:
        print(
            f"Warning: VirtualInterface {vi.name!r} for "
            f"{host.machine_name!r} has no MACs — fix the spreadsheet row "
            f"(IP without MAC); publishing an empty MAC.",
            file=sys.stderr,
        )
        states[f"{prefix}/mac/state"] = ""
```

(`sys` is already imported at the top of `mqtt_ha.py`.)

- [ ] **Step 4: Run** `uv run pytest tests/test_supplements/test_mqtt_ha.py -q` → all PASS.

- [ ] **Step 5: Commit and open PR "mqtt: daemon tolerates an interface with no MACs"**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/supplements/mqtt_ha.py tests/test_supplements/test_mqtt_ha.py
git commit -m "mqtt: publish an empty MAC and warn instead of crashing the daemon

A sheet row with an IP but no MAC (power9-b, earlier au-plug-49) made
build_interface_state raise; run_daemon has no per-host guard, so the
whole publisher died and systemd restarted it every ~13 min (714
restarts), re-running the full first cycle each time.  Treat it like
the IPv6 branch: empty state + loud stderr warning."
```

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
5. **Data fix:** fill in the MAC addresses for `power9-b`'s three interface rows in the Network sheet (they have IPs but empty MAC cells); after the next `fetch`, `journalctl -u gdoc2netcfg-reachability` must stop printing the no-MACs warning and `systemctl show -p NRestarts gdoc2netcfg-reachability` must stop increasing.
6. **Next morning:** no cron failure mail from either site; `grep -c "database is locked" .cache/cron.log` unchanged from the pre-deploy count.

## Follow-ups (separate issues, not this plan)

- `validate` should flag interface rows with an IP but no MAC (the `power9-b` class of sheet error) so `generate` reports it instead of the daemon discovering it.
- `generate` should warn or fail when a supplement's latest completed scan is older than its cron cadence (e.g. `ssh_host_keys` > 36 h) — the stale-SSHFP failure mode would then be a mail, not a surprise.
- `_load_or_run_reachability` opens `DiscoveryDB` read-write just to read the daemon's cache; a read-only open for the cached path would let the supplement scans' pre-flight run without `_verify_writable`'s `BEGIN IMMEDIATE`.
- Reachability history retention (currently ~28 k rows/month, INSERT-only).
