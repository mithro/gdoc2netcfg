# Tasmota sheet-MAC identity, discrepancy reporting & tombstone cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Tasmota scan identify devices by their spreadsheet MAC (not IP or self-reported name), report sheet/network discrepancies as clear errors with a non-zero exit, and tombstone vanished/removed devices so stale rows stop resurrecting.

**Architecture:** Identity becomes MAC-driven in `scan_tasmota`, which returns a `TasmotaScanResult(data, discrepancies)`. Storage gains an `is_tombstone` column (schema v8) and a `tombstone_missing_tasmota(scan_id, present)` method mirroring the existing `tombstone_missing_reachability`; the CLI's new `_save_tasmota_to_db` saves + tombstones in one scan row. The existing `_unknown/{ip}` keys become `_unknown/{mac}`, and the now-redundant `match_unknown_devices` helper is removed.

**Tech Stack:** Python 3, SQLite (`sqlite3`), `uv` for all commands, pytest.

**Spec:** `docs/superpowers/specs/2026-06-16-tasmota-mac-identity-design.md`

---

## File Structure

- `src/gdoc2netcfg/storage/discovery_db.py` — schema v8 + `is_tombstone` column; `_tombstone_value`, `_insert_tasmota_tombstone`; `_insert_tasmota_rows`/`_latest_tasmota` updated; new `tombstone_missing_tasmota`. (Tasks 1–2)
- `src/gdoc2netcfg/supplements/tasmota.py` — `TasmotaDiscrepancy` + `TasmotaScanResult`; `scan_tasmota` rewritten to MAC identity; `_unknown_key(mac)`; `match_unknown_devices` removed. (Tasks 3–4)
- `src/gdoc2netcfg/cli/main.py` — `_save_tasmota_to_db`; `_report_tasmota_discrepancies`; `cmd_tasmota_scan` rewired; `cmd_tasmota_show` unknown-display fix. (Task 5)
- `tests/test_storage/test_discovery_db.py` — migration + tombstone tests. (Tasks 1–2)
- `tests/test_supplements/test_tasmota.py` — dataclass, scan-identity, CLI-helper tests; remove `match_unknown_devices` import/tests; fix `_unknown_key` test. (Tasks 3–5)

Run the full suite before starting to confirm a green baseline: `uv run pytest -q`.

---

## Task 1: Add `is_tombstone` column + schema v8 migration

**Files:**
- Modify: `src/gdoc2netcfg/storage/discovery_db.py` (DDL ~314-319; `SCHEMA_VERSION`/`SCHEMA_UPGRADES` ~726-735)
- Test: `tests/test_storage/test_discovery_db.py`

- [ ] **Step 1: Write the failing migration test**

Add at the end of `tests/test_storage/test_discovery_db.py` (the module already imports `sqlite3`, `Path`, `pytest`, `DiscoveryDB`, and defines `_tasmota_doc`):

```python
class TestTasmotaTombstoneMigration:
    def test_v8_adds_is_tombstone_and_preserves_data(self, tmp_path: Path):
        path = tmp_path / "discovery.db"
        # Build a current DB with a tasmota row.
        db = DiscoveryDB(path)
        s = db.begin_scan("tasmota")
        db.save_tasmota(s, {"plug1": _tasmota_doc()})
        db.finish_scan(s, host_count=1, changed_count=1)
        db.close()

        # Simulate a pre-v8 DB: drop the column and reset the schema version.
        raw = sqlite3.connect(path)
        raw.execute("ALTER TABLE tasmota_devices DROP COLUMN is_tombstone")
        raw.execute("UPDATE _meta SET value = '7' WHERE key = 'schema_version'")
        raw.commit()
        raw.close()

        # Reopening runs the v8 upgrade.
        db2 = DiscoveryDB(path)
        cols = [r[1] for r in db2.connection.execute(
            "PRAGMA table_info(tasmota_devices)")]
        assert "is_tombstone" in cols
        version = db2.connection.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert int(version) == 8
        # Pre-existing row defaults to live (is_tombstone=0) and round-trips.
        assert db2.load_latest_tasmota() == {"plug1": _tasmota_doc()}
        db2.close()

    def test_fresh_db_has_is_tombstone_column(self, tmp_path: Path):
        db = DiscoveryDB(tmp_path / "fresh.db")
        cols = [r[1] for r in db.connection.execute(
            "PRAGMA table_info(tasmota_devices)")]
        assert "is_tombstone" in cols
        db.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_storage/test_discovery_db.py::TestTasmotaTombstoneMigration -v`
Expected: FAIL — `test_fresh_db_has_is_tombstone_column` asserts a column that doesn't exist yet; the migration test fails at the version assertion (SCHEMA_VERSION still 7).

- [ ] **Step 3: Add the column to the fresh-DB DDL**

In `src/gdoc2netcfg/storage/discovery_db.py`, replace the tasmota DDL block (currently lines ~314-319):

```python
    stmts += _entity_table_ddl("tasmota_devices", "device_key", tuple(
        (key,
         _sql_type(typ).replace(" NOT NULL", "")
         if key in _TASMOTA_OPTIONAL_FIELDS else _sql_type(typ))
        for key, typ in _TASMOTA_FIELDS
    ))
```

with (append `is_tombstone` last, mirroring `zigbee_devices`):

```python
    stmts += _entity_table_ddl("tasmota_devices", "device_key", (
        *((key,
           _sql_type(typ).replace(" NOT NULL", "")
           if key in _TASMOTA_OPTIONAL_FIELDS else _sql_type(typ))
          for key, typ in _TASMOTA_FIELDS),
        ("is_tombstone", "INTEGER NOT NULL DEFAULT 0"),
    ))
```

- [ ] **Step 4: Bump the schema version and add the upgrade step**

In the same file, update the version-lineage comment and the constants (currently ~726-735):

```python
    # v7: nullable traffic counters; vendor PoE power, box sensors,
    #     bridge MAC, LLDP port descriptions.
    # v8: tasmota_devices.is_tombstone (sheet-MAC identity tombstones).
    SCHEMA_VERSION = 8
    SCHEMA_UPGRADES = {
        5: ["ALTER TABLE tasmota_devices ADD COLUMN mqtt_count INTEGER"],
        6: [_upgrade_v6_port_aliases],
        7: [_upgrade_v7_extended_bridge_data],
        8: ["ALTER TABLE tasmota_devices "
            "ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0"],
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_storage/test_discovery_db.py::TestTasmotaTombstoneMigration -v`
Expected: PASS (both tests).

Note: `ALTER TABLE ... DROP COLUMN` in the test requires SQLite ≥ 3.35 (standard on current Debian/macOS). If the runner's SQLite is older the test errors loudly — acceptable, the production DBs are on a current SQLite.

- [ ] **Step 6: Commit**

```bash
git add src/gdoc2netcfg/storage/discovery_db.py tests/test_storage/test_discovery_db.py
git commit -m "storage: tasmota_devices.is_tombstone column (schema v8)"
```

---

## Task 2: Tombstone write/read + `tombstone_missing_tasmota`

**Files:**
- Modify: `src/gdoc2netcfg/storage/discovery_db.py` (`_insert_tasmota_rows` ~557-575; `_latest_tasmota` ~1421-1437; add `_tombstone_value`, `_insert_tasmota_tombstone`, `tombstone_missing_tasmota`)
- Test: `tests/test_storage/test_discovery_db.py`

- [ ] **Step 1: Write the failing tombstone tests**

Add to `tests/test_storage/test_discovery_db.py`:

```python
class TestTasmotaTombstone:
    def test_tombstone_drops_vanished_device(self, db: DiscoveryDB):
        s1 = db.begin_scan("tasmota")
        db.save_tasmota(s1, {
            "plug1": _tasmota_doc("plug1"),
            "_unknown/aa:bb:cc:00:00:01": _tasmota_doc("ghost"),
        })
        db.finish_scan(s1, host_count=2, changed_count=2)

        s2 = db.begin_scan("tasmota")
        db.save_tasmota(s2, {"plug1": _tasmota_doc("plug1")})
        n = db.tombstone_missing_tasmota(s2, {"plug1"})
        db.finish_scan(s2, host_count=1, changed_count=1 + n)

        assert n == 1
        assert set(db.load_latest_tasmota()) == {"plug1"}

    def test_tombstoned_device_resurrects(self, db: DiscoveryDB):
        s1 = db.begin_scan("tasmota")
        db.save_tasmota(s1, {"plug1": _tasmota_doc("plug1")})
        db.finish_scan(s1, 1, 1)

        s2 = db.begin_scan("tasmota")
        db.save_tasmota(s2, {"plug2": _tasmota_doc("plug2")})
        db.tombstone_missing_tasmota(s2, {"plug2"})
        db.finish_scan(s2, 1, 2)
        assert set(db.load_latest_tasmota()) == {"plug2"}

        s3 = db.begin_scan("tasmota")
        db.save_tasmota(s3, {
            "plug1": _tasmota_doc("plug1"), "plug2": _tasmota_doc("plug2"),
        })
        db.tombstone_missing_tasmota(s3, {"plug1", "plug2"})
        db.finish_scan(s3, 2, 2)
        assert db.load_latest_tasmota() == {
            "plug1": _tasmota_doc("plug1"), "plug2": _tasmota_doc("plug2"),
        }

    def test_empty_present_raises(self, db: DiscoveryDB):
        s = db.begin_scan("tasmota")
        with pytest.raises(ValueError, match="empty present"):
            db.tombstone_missing_tasmota(s, set())

    def test_no_missing_returns_zero(self, db: DiscoveryDB):
        s1 = db.begin_scan("tasmota")
        db.save_tasmota(s1, {"plug1": _tasmota_doc("plug1")})
        db.finish_scan(s1, 1, 1)
        s2 = db.begin_scan("tasmota")
        db.save_tasmota(s2, {"plug1": _tasmota_doc("plug1")})
        assert db.tombstone_missing_tasmota(s2, {"plug1"}) == 0

    def test_tombstone_row_satisfies_not_null_columns(self, db: DiscoveryDB):
        # module is a NOT NULL no-affinity column, mqtt_port/wifi_* are NOT
        # NULL INTEGER — the tombstone's sentinels must satisfy all of them.
        s1 = db.begin_scan("tasmota")
        db.save_tasmota(s1, {"plug1": _tasmota_doc("plug1", module=43)})
        db.finish_scan(s1, 1, 1)
        s2 = db.begin_scan("tasmota")
        db.save_tasmota(s2, {"plug2": _tasmota_doc("plug2")})
        db.tombstone_missing_tasmota(s2, {"plug2"})  # must not raise
        db.finish_scan(s2, 1, 2)
        assert "plug1" not in db.load_latest_tasmota()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_storage/test_discovery_db.py::TestTasmotaTombstone -v`
Expected: FAIL — `tombstone_missing_tasmota` does not exist (`AttributeError`).

- [ ] **Step 3: Add `_tombstone_value` helper**

In `src/gdoc2netcfg/storage/discovery_db.py`, add near `_sql_type` (after its definition, ~line 235):

```python
def _tombstone_value(typ: object) -> object:
    """A NOT-NULL-satisfying placeholder for a tombstone row's data columns.

    Tombstone rows are skipped by reconstruction, so the value is never read;
    it exists only so NOT NULL columns accept the row.  Derived from the same
    ``_sql_type`` used for the DDL, so it cannot drift from the column type.
    """
    sql = _sql_type(typ)
    if "NOT NULL" not in sql:
        return None
    return "" if "TEXT" in sql else 0
```

- [ ] **Step 4: Write `is_tombstone=0` in `_insert_tasmota_rows` and add the tombstone insert**

Replace the `_insert_row(...)` call at the end of `_insert_tasmota_rows` (currently ~571-575):

```python
    _insert_row(
        cur, "tasmota_devices", "device_key", scan_id, device_key,
        tuple(key for key, _t in _TASMOTA_FIELDS),
        tuple(doc.get(key) for key, _t in _TASMOTA_FIELDS),
    )
```

with:

```python
    _insert_row(
        cur, "tasmota_devices", "device_key", scan_id, device_key,
        (*(key for key, _t in _TASMOTA_FIELDS), "is_tombstone"),
        (*(doc.get(key) for key, _t in _TASMOTA_FIELDS), 0),
    )
```

Then add a tombstone insert helper immediately after `_insert_tasmota_rows`:

```python
def _insert_tasmota_tombstone(
    cur: sqlite3.Cursor, scan_id: int, device_key: str,
) -> None:
    """A device removed from the sheet, or a stale sweep find: INSERT-only
    tombstone (history is never deleted) that drops it from reads; a later
    real row resurrects it.  NOT NULL data columns get never-read sentinels."""
    _insert_row(
        cur, "tasmota_devices", "device_key", scan_id, device_key,
        (*(key for key, _t in _TASMOTA_FIELDS), "is_tombstone"),
        (*(_tombstone_value(typ) for _key, typ in _TASMOTA_FIELDS), 1),
    )
```

- [ ] **Step 5: Skip tombstoned rows in `_latest_tasmota`**

Replace `_latest_tasmota` (currently ~1421-1437):

```python
    def _latest_tasmota(self) -> dict[str, dict]:
        field_cols = ", ".join(key for key, _t in _TASMOTA_FIELDS)
        result = {}
        for device_key, scan_id in sorted(
            self._latest_entity_scans("tasmota_devices", "device_key").items()
        ):
            row = self._conn.execute(
                f"SELECT is_tombstone, {field_cols} FROM tasmota_devices "  # noqa: S608
                "WHERE scan_id = ? AND device_key = ?",
                (scan_id, device_key),
            ).fetchone()
            if row[0]:
                continue
            result[device_key] = {
                key: value
                for (key, _t), value in zip(_TASMOTA_FIELDS, row[1:])
                if not (key in _TASMOTA_OPTIONAL_FIELDS and value is None)
            }
        return result
```

- [ ] **Step 6: Add `tombstone_missing_tasmota`**

Add as a method on `DiscoveryDB`, right after `save_tasmota` (~line 1414):

```python
    def tombstone_missing_tasmota(
        self, scan_id: int, present: set[str],
    ) -> int:
        """Tombstone tasmota device_keys that vanished from the scan.

        *present* must be the FULL set of device_keys this scan produced
        (matched sheet hostnames, ``_unknown/<mac>`` markers, and carried-
        forward offline hosts).  A key in the DB's latest state but absent
        from *present* — a host removed from the sheet, or a stale sweep
        find no longer on the network — gets a single INSERT-only tombstone
        row under *scan_id* (history is never deleted) that drops it from
        ``load_latest_tasmota()``.  A later real row supersedes it.

        Raises ValueError on an empty *present* set — that means the scan
        itself failed, not that every device was removed.

        Returns the number of device_keys tombstoned.
        """
        if not present:
            raise ValueError(
                "tombstone_missing_tasmota called with an empty present "
                "set — refusing to tombstone every device."
            )
        missing = sorted(set(self._latest_tasmota()) - set(present))
        if not missing:
            return 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for device_key in missing:
                _insert_tasmota_tombstone(cur, scan_id, device_key)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return len(missing)
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest tests/test_storage/test_discovery_db.py -v`
Expected: PASS (new `TestTasmotaTombstone` + all existing storage tests, including the parametrized `TestStructuredSupplements` tasmota cases which still round-trip).

- [ ] **Step 8: Commit**

```bash
git add src/gdoc2netcfg/storage/discovery_db.py tests/test_storage/test_discovery_db.py
git commit -m "storage: tombstone_missing_tasmota + tombstone-aware tasmota rows"
```

---

## Task 3: `TasmotaDiscrepancy` + `TasmotaScanResult`

**Files:**
- Modify: `src/gdoc2netcfg/supplements/tasmota.py` (add dataclasses near the top, after imports)
- Test: `tests/test_supplements/test_tasmota.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_supplements/test_tasmota.py`:

```python
class TestTasmotaDiscrepancy:
    def test_format_includes_kind_and_detail(self):
        from gdoc2netcfg.supplements.tasmota import TasmotaDiscrepancy
        d = TasmotaDiscrepancy(
            kind="unknown_device", mac="aa:bb:cc:dd:ee:ff",
            ip="10.1.90.9", hostname="", detail="not in this site's sheet",
        )
        text = d.format()
        assert "unknown_device" in text
        assert "not in this site's sheet" in text
        # falls back to mac when there's no hostname
        assert "aa:bb:cc:dd:ee:ff" in text

    def test_scan_result_holds_data_and_discrepancies(self):
        from gdoc2netcfg.supplements.tasmota import (
            TasmotaDiscrepancy, TasmotaScanResult,
        )
        r = TasmotaScanResult(data={"plug1": {}}, discrepancies=[])
        assert r.data == {"plug1": {}}
        assert r.discrepancies == []
        r2 = TasmotaScanResult(
            data={},
            discrepancies=[TasmotaDiscrepancy("ip_mismatch", "m", "i", "h", "d")],
        )
        assert r2.discrepancies[0].kind == "ip_mismatch"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_supplements/test_tasmota.py::TestTasmotaDiscrepancy -v`
Expected: FAIL — `ImportError` (dataclasses don't exist).

- [ ] **Step 3: Add the dataclasses**

In `src/gdoc2netcfg/supplements/tasmota.py`, add `from dataclasses import dataclass` to the imports, and add after the `_UNKNOWN_PREFIX` constant (~line 28):

```python
@dataclass(frozen=True)
class TasmotaDiscrepancy:
    """A mismatch between the network and the golden spreadsheet.

    kind is one of: "unknown_device", "ip_mismatch", "duplicate_sheet_mac",
    "duplicate_network_mac", "unidentifiable".
    """

    kind: str
    mac: str
    ip: str
    hostname: str  # sheet hostname when known, else ""
    detail: str

    def format(self) -> str:
        loc = self.hostname or self.mac or self.ip or "?"
        return f"[{self.kind}] {loc}: {self.detail}"


@dataclass(frozen=True)
class TasmotaScanResult:
    """Outcome of a Tasmota scan: per-device data plus discrepancies."""

    data: dict[str, dict]
    discrepancies: list[TasmotaDiscrepancy]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_supplements/test_tasmota.py::TestTasmotaDiscrepancy -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/tasmota.py tests/test_supplements/test_tasmota.py
git commit -m "tasmota: TasmotaDiscrepancy + TasmotaScanResult dataclasses"
```

---

## Task 4: Rewrite `scan_tasmota` for MAC identity; remove `match_unknown_devices`

**Files:**
- Modify: `src/gdoc2netcfg/supplements/tasmota.py` (`_unknown_key` ~31-33; `scan_tasmota` ~156-255; delete `match_unknown_devices` ~306-334)
- Test: `tests/test_supplements/test_tasmota.py`

- [ ] **Step 1: Write the failing scan tests**

Add these helpers and test class to `tests/test_supplements/test_tasmota.py` (note `MagicMock`, `patch`, `_make_host` are already available):

```python
def _parsed(mac="24:ec:4a:b0:a9:b0", ip="10.1.90.63", name="dev", **kw):
    """A parsed Tasmota dict matching _parse_tasmota_status output."""
    d = {
        "device_name": name, "friendly_name": name,
        "hostname": f"tasmota-{name}", "firmware_version": "13.1.0",
        "mqtt_host": "ha", "mqtt_port": 1883, "mqtt_topic": name,
        "mqtt_client": "DVES_X", "mqtt_user": "DVES_USER", "mac": mac,
        "ip": ip, "wifi_ssid": "iot", "wifi_rssi": 80, "wifi_signal": -55,
        "uptime": "1T00:00:00", "module": 1, "mqtt_count": 1,
    }
    d.update(kw)
    return d


def _raw(mac, ip, name="dev"):
    """A minimal raw Status 0 response (what _fetch_tasmota_status returns)."""
    return {
        "Status": {"DeviceName": name, "FriendlyName": [name],
                   "Topic": name, "Module": 1},
        "StatusNET": {"Hostname": f"tasmota-{name}", "Mac": mac,
                      "IPAddress": ip},
        "StatusMQT": {"MqttHost": "ha", "MqttPort": 1883,
                      "MqttClient": "DVES_X", "MqttUser": "DVES_USER"},
        "StatusFWR": {"Version": "13.1.0"},
        "StatusSTS": {"Uptime": "1T00:00:00", "MqttCount": 1,
                      "Wifi": {"SSId": "iot", "RSSI": 80, "Signal": -55}},
    }


def _iot_site(prefix="10.1.90."):
    site = MagicMock()
    site.ip_prefix_for_vlan.return_value = prefix
    return site


@patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
@patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
class TestScanTasmotaMacIdentity:
    def test_match_by_mac_despite_ip_change(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("au-plug-13", ip="10.1.90.63",
                          mac="24:ec:4a:b0:a9:b0")
        mock_fetch.return_value = None  # not at its sheet IP
        mock_sweep.return_value = {
            "10.1.90.99": _parsed(mac="24:EC:4A:B0:A9:B0", ip="10.1.90.99",
                                  name="au-plug-13"),
        }
        result = scan_tasmota([host], None, _iot_site())
        assert "au-plug-13" in result.data
        assert result.data["au-plug-13"]["ip"] == "10.1.90.99"
        assert any(d.kind == "ip_mismatch" for d in result.discrepancies)

    def test_match_ignores_self_reported_name(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("au-plug-13", ip="10.1.90.63",
                          mac="24:ec:4a:b0:a9:b0")
        mock_fetch.return_value = None
        mock_sweep.return_value = {
            "10.1.90.63": _parsed(mac="24:EC:4A:B0:A9:B0", ip="10.1.90.63",
                                  name="bogus-self-name"),
        }
        result = scan_tasmota([host], None, _iot_site())
        assert "au-plug-13" in result.data
        assert "_unknown/24:ec:4a:b0:a9:b0" not in result.data
        assert not result.discrepancies  # at sheet IP, MAC matches

    def test_unknown_device_keyed_by_mac(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("au-plug-13", ip="10.1.90.63",
                          mac="24:ec:4a:b0:a9:b0")
        mock_fetch.return_value = None
        mock_sweep.return_value = {
            "10.1.90.149": _parsed(mac="7C:2C:67:D7:D3:CC", ip="10.1.90.149",
                                   name="au-plug-10"),
        }
        result = scan_tasmota([host], None, _iot_site())
        assert "_unknown/7c:2c:67:d7:d3:cc" in result.data
        assert any(d.kind == "unknown_device" for d in result.discrepancies)

    def test_carry_forward_offline_in_sheet_host(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("au-plug-13", ip="10.1.90.63",
                          mac="24:ec:4a:b0:a9:b0")
        mock_fetch.return_value = None
        mock_sweep.return_value = {}
        baseline = {"au-plug-13": _parsed(name="au-plug-13")}
        result = scan_tasmota([host], baseline, _iot_site())
        assert result.data == {"au-plug-13": baseline["au-plug-13"]}

    def test_removed_from_sheet_host_dropped(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("au-plug-13", ip="10.1.90.63",
                          mac="24:ec:4a:b0:a9:b0")
        mock_fetch.return_value = None
        mock_sweep.return_value = {}
        # "old-plug" is in the baseline but NOT in the current host set.
        baseline = {
            "au-plug-13": _parsed(name="au-plug-13"),
            "old-plug": _parsed(name="old-plug"),
        }
        result = scan_tasmota([host], baseline, _iot_site())
        assert "old-plug" not in result.data
        assert "au-plug-13" in result.data

    def test_duplicate_sheet_mac(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        h1 = _make_host("plug-a", ip="10.1.90.10", mac="aa:bb:cc:dd:ee:01")
        h2 = _make_host("plug-b", ip="10.1.90.11", mac="aa:bb:cc:dd:ee:01")
        mock_fetch.return_value = None
        mock_sweep.return_value = {}
        result = scan_tasmota([h1, h2], None, _iot_site())
        assert any(d.kind == "duplicate_sheet_mac" for d in result.discrepancies)

    def test_duplicate_network_mac(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("plug-a", ip="10.1.90.10", mac="aa:bb:cc:dd:ee:01")
        mock_fetch.return_value = None
        mock_sweep.return_value = {
            "10.1.90.10": _parsed(mac="AA:BB:CC:DD:EE:01", ip="10.1.90.10"),
            "10.1.90.20": _parsed(mac="AA:BB:CC:DD:EE:01", ip="10.1.90.20"),
        }
        result = scan_tasmota([host], None, _iot_site())
        assert any(d.kind == "duplicate_network_mac"
                   for d in result.discrepancies)
        assert "plug-a" not in result.data  # ambiguous, not auto-keyed

    def test_unparseable_mac_is_unidentifiable(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("plug-a", ip="10.1.90.10", mac="aa:bb:cc:dd:ee:01")
        mock_fetch.return_value = None
        mock_sweep.return_value = {"10.1.90.55": _parsed(mac="", ip="10.1.90.55")}
        result = scan_tasmota([host], None, _iot_site())
        assert any(d.kind == "unidentifiable" for d in result.discrepancies)
        assert result.data == {}  # not stored under a fabricated key

    def test_known_ip_probe_path(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("plug-a", ip="10.1.90.10", mac="aa:bb:cc:dd:ee:01")
        mock_fetch.return_value = _raw("AA:BB:CC:DD:EE:01", "10.1.90.10",
                                       "plug-a")
        mock_sweep.return_value = {}
        result = scan_tasmota([host], None, _iot_site())
        assert "plug-a" in result.data
        assert not result.discrepancies

    def test_dedupe_probe_and_sweep(self, mock_fetch, mock_sweep):
        from gdoc2netcfg.supplements.tasmota import scan_tasmota
        host = _make_host("plug-a", ip="10.1.90.10", mac="aa:bb:cc:dd:ee:01")
        # Found by BOTH the known-IP probe and the sweep, at the same IP.
        mock_fetch.return_value = _raw("AA:BB:CC:DD:EE:01", "10.1.90.10",
                                       "plug-a")
        mock_sweep.return_value = {
            "10.1.90.10": _parsed(mac="AA:BB:CC:DD:EE:01", ip="10.1.90.10"),
        }
        result = scan_tasmota([host], None, _iot_site())
        assert "plug-a" in result.data
        assert not any(d.kind == "duplicate_network_mac"
                       for d in result.discrepancies)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_tasmota.py::TestScanTasmotaMacIdentity -v`
Expected: FAIL — current `scan_tasmota` returns a plain dict (no `.data`/`.discrepancies`) and keys unmatched devices by IP, not MAC.

- [ ] **Step 3: Update `_unknown_key` to key by MAC**

In `src/gdoc2netcfg/supplements/tasmota.py`, replace `_unknown_key` (~31-33):

```python
def _unknown_key(mac: str) -> str:
    """Storage key for a device not in the sheet, by its normalized MAC."""
    return f"{_UNKNOWN_PREFIX}{mac}"
```

- [ ] **Step 4: Rewrite `scan_tasmota`**

Add `from gdoc2netcfg.models.addressing import MACAddress` to the imports. Replace the entire `scan_tasmota` function (from its `def` ~line 156 through `return tasmota_data` ~line 255) with:

```python
def scan_tasmota(
    hosts: list[Host],
    baseline: dict[str, dict] | None,
    site: Site,
    *,
    verbose: bool = False,
) -> TasmotaScanResult:
    """Scan the IoT VLAN and identify devices by their spreadsheet MAC.

    Identity comes from the sheet: a device whose MAC matches a sheet IoT
    host is keyed by that host's hostname (regardless of its IP or self-
    reported name); a device whose MAC is not in this site's sheet is keyed
    ``_unknown/<mac>``.  Sheet hosts not seen this scan are carried forward
    from *baseline* (offline hosts keep last-known data) if still in the
    sheet.  Discrepancies (unknown devices, IP mismatches, duplicate MACs,
    unidentifiable devices) are collected, not hidden.

    Returns a TasmotaScanResult(data, discrepancies).  The caller persists
    ``data`` and tombstones whatever is absent from it.
    """
    baseline = baseline or {}
    discrepancies: list[TasmotaDiscrepancy] = []

    # Build the sheet MAC -> hostname index for this site's IoT hosts.
    mac_to_host: dict[str, str] = {}
    valid_known: set[str] = set()
    host_by_name: dict[str, Host] = {}
    known_ips: list[str] = []
    for host in hosts:
        if host.sheet_type != "IoT":
            continue
        valid_known.add(host.hostname)
        host_by_name[host.hostname] = host
        if host.first_ipv4 is not None:
            known_ips.append(str(host.first_ipv4))
        for mac in host.all_macs():
            key = str(mac)
            existing = mac_to_host.get(key)
            if existing is not None and existing != host.hostname:
                discrepancies.append(TasmotaDiscrepancy(
                    kind="duplicate_sheet_mac", mac=key, ip="",
                    hostname=host.hostname,
                    detail=f"MAC also on sheet host {existing}",
                ))
                continue
            mac_to_host[key] = host.hostname

    # Probe known sheet IPs (reliable) and sweep the IoT /24 (discovery);
    # collect every responder keyed by IP.
    found: dict[str, dict] = {}
    if verbose:
        print(f"Probing {len(known_ips)} known IoT IP(s)...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures: dict[str, Future[dict | None]] = {
            ip: pool.submit(_fetch_tasmota_status, ip, 3.0) for ip in known_ips
        }
        for ip, future in futures.items():
            raw = future.result()
            if raw is not None:
                found[ip] = _parse_tasmota_status(raw)

    iot_prefix = site.ip_prefix_for_vlan("iot")
    if iot_prefix is not None:
        if verbose:
            print(f"Sweeping {iot_prefix}0/24...", file=sys.stderr)
        for ip, parsed in _scan_subnet(
            iot_prefix, max_workers=32, timeout=2.0, verbose=verbose
        ).items():
            found.setdefault(ip, parsed)  # probe result wins on duplicate IP
    elif verbose:
        print("Sweep skipped — no 'iot' VLAN in site config.", file=sys.stderr)

    # Group responders by normalized MAC.
    by_mac: dict[str, list[tuple[str, dict]]] = {}
    for ip, parsed in found.items():
        raw_mac = parsed.get("mac", "")
        try:
            mac = str(MACAddress.parse(raw_mac))
        except ValueError:
            discrepancies.append(TasmotaDiscrepancy(
                kind="unidentifiable", mac=raw_mac, ip=ip, hostname="",
                detail=f"device reported an unparseable MAC {raw_mac!r}",
            ))
            continue
        by_mac.setdefault(mac, []).append((ip, parsed))

    data: dict[str, dict] = {}
    seen_hosts: set[str] = set()
    for mac, sightings in sorted(by_mac.items()):
        if len(sightings) > 1:
            ips = ", ".join(sorted(ip for ip, _ in sightings))
            discrepancies.append(TasmotaDiscrepancy(
                kind="duplicate_network_mac", mac=mac, ip=ips, hostname="",
                detail=f"same MAC answered at multiple IPs: {ips}",
            ))
            continue
        ip, parsed = sightings[0]
        matched = mac_to_host.get(mac)
        if matched is not None:
            data[matched] = parsed
            seen_hosts.add(matched)
            host = host_by_name[matched]
            sheet_ip = str(host.first_ipv4) if host.first_ipv4 is not None else ""
            if sheet_ip and parsed.get("ip", "") != sheet_ip:
                discrepancies.append(TasmotaDiscrepancy(
                    kind="ip_mismatch", mac=mac, ip=parsed.get("ip", ""),
                    hostname=matched,
                    detail=f"device at {parsed.get('ip', '?')}, "
                           f"sheet says {sheet_ip}",
                ))
        else:
            data[_unknown_key(mac)] = parsed
            discrepancies.append(TasmotaDiscrepancy(
                kind="unknown_device", mac=mac, ip=ip, hostname="",
                detail=f"device {parsed.get('device_name', '?')!r} at {ip} "
                       f"not in this site's sheet",
            ))

    # Carry forward offline hosts still in the sheet (keep last-known data).
    # Baseline keys not in the sheet (removed hosts) and stale _unknown/ keys
    # are intentionally dropped so the caller tombstones them.
    for key, info in baseline.items():
        if key in valid_known and key not in seen_hosts:
            data[key] = info

    return TasmotaScanResult(data=data, discrepancies=discrepancies)
```

- [ ] **Step 5: Delete `match_unknown_devices`**

Remove the entire `match_unknown_devices` function (~lines 306-334). Then update the existing `_unknown_key` test and imports:

In `tests/test_supplements/test_tasmota.py`, change the import block (lines ~13-19) to drop `match_unknown_devices`:

```python
from gdoc2netcfg.supplements.tasmota import (
    _UNKNOWN_PREFIX,
    _parse_tasmota_status,
    _unknown_key,
    enrich_hosts_with_tasmota,
)
```

Update `TestUnknownKey` (~258-263) to reflect MAC keying:

```python
class TestUnknownKey:
    def test_unknown_key(self):
        assert _unknown_key("aa:bb:cc:dd:ee:ff") == "_unknown/aa:bb:cc:dd:ee:ff"

    def test_prefix_constant(self):
        assert _UNKNOWN_PREFIX == "_unknown/"
```

Then check for any remaining references to `match_unknown_devices`:

Run: `grep -rn "match_unknown_devices" src/ tests/`
Expected: only `src/gdoc2netcfg/cli/main.py` (fixed in Task 5). Remove any test that exercised it (search `tests/test_supplements/test_tasmota.py` for a `match_unknown` test class/function and delete it).

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/test_supplements/test_tasmota.py -v`
Expected: PASS for the new scan tests and the updated `TestUnknownKey`. The CLI (`cmd_tasmota_scan`) still imports `match_unknown_devices` at this point, but that import is inside the function body, so the module imports fine and these tests pass; Task 5 fixes the CLI.

- [ ] **Step 7: Commit**

```bash
git add src/gdoc2netcfg/supplements/tasmota.py tests/test_supplements/test_tasmota.py
git commit -m "tasmota: identify devices by sheet MAC; collect discrepancies"
```

---

## Task 5: Wire the CLI — save+tombstone, discrepancy reporting, show fix

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (add `_save_tasmota_to_db`, `_report_tasmota_discrepancies`; rewrite `cmd_tasmota_scan` ~1799-1860; fix `cmd_tasmota_show` unknown block ~1909-1919)
- Test: `tests/test_supplements/test_tasmota.py`

- [ ] **Step 1: Write the failing CLI tests**

Add to `tests/test_supplements/test_tasmota.py`:

```python
class TestTasmotaCliHelpers:
    def test_report_discrepancies_returns_one_and_prints(self, capsys):
        from gdoc2netcfg.cli.main import _report_tasmota_discrepancies
        from gdoc2netcfg.supplements.tasmota import TasmotaDiscrepancy
        d = TasmotaDiscrepancy("unknown_device", "aa:bb:cc:dd:ee:ff",
                               "10.1.90.9", "", "not in this site's sheet")
        rc = _report_tasmota_discrepancies([d])
        assert rc == 1
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "unknown_device" in err

    def test_report_no_discrepancies_returns_zero(self, capsys):
        from gdoc2netcfg.cli.main import _report_tasmota_discrepancies
        assert _report_tasmota_discrepancies([]) == 0

    def test_save_tasmota_to_db_tombstones_vanished(self, tmp_path):
        from unittest.mock import MagicMock
        from gdoc2netcfg.cli.main import _save_tasmota_to_db
        from gdoc2netcfg.storage.discovery_db import DiscoveryDB
        config = MagicMock()
        config.cache.discovery_db_path = tmp_path / "discovery.db"

        _save_tasmota_to_db(config, {
            "plug1": _parsed(name="plug1"), "plug2": _parsed(name="plug2"),
        })
        _save_tasmota_to_db(config, {"plug1": _parsed(name="plug1")})

        with DiscoveryDB(config.cache.discovery_db_path) as db:
            assert set(db.load_latest_tasmota()) == {"plug1"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_tasmota.py::TestTasmotaCliHelpers -v`
Expected: FAIL — `_report_tasmota_discrepancies` and `_save_tasmota_to_db` don't exist.

- [ ] **Step 3: Add `_save_tasmota_to_db` and `_report_tasmota_discrepancies`**

In `src/gdoc2netcfg/cli/main.py`, add `_save_tasmota_to_db` right after `_save_reachability_to_db` (~line 240):

```python
def _save_tasmota_to_db(config: PipelineConfig, data: dict) -> None:
    """Save a tasmota scan and tombstone vanished device_keys.

    Mirrors _save_reachability_to_db: a tasmota scan's `data` is the full
    present set (matched hosts, _unknown/<mac> markers, carried-forward
    offline hosts), so keys in the DB's latest state but absent from it have
    been removed from the sheet or left the network, and are tombstoned
    under the same scan row.
    """
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    with DiscoveryDB(config.cache.discovery_db_path) as db:
        scan_id = db.begin_scan("tasmota")
        try:
            changed = db.save_tasmota(scan_id, data)
            changed += db.tombstone_missing_tasmota(scan_id, set(data))
            db.finish_scan(
                scan_id, host_count=len(data), changed_count=changed,
            )
        except Exception:
            db.connection.execute(
                "DELETE FROM scans WHERE id = ?", (scan_id,),
            )
            raise
```

Add `_report_tasmota_discrepancies` just above `cmd_tasmota_scan` (~line 1798):

```python
def _report_tasmota_discrepancies(discrepancies: list) -> int:
    """Print discrepancies as clear errors; return the process exit code.

    The spreadsheet is the source of truth, so anything the network shows
    that the sheet doesn't sanction is an error, not a hidden warning.
    """
    if not discrepancies:
        return 0
    print(
        f"\nERROR: {len(discrepancies)} discrepancies vs the spreadsheet "
        f"(the golden source of truth):",
        file=sys.stderr,
    )
    for d in discrepancies:
        print(f"  {d.format()}", file=sys.stderr)
    return 1
```

- [ ] **Step 4: Rewrite `cmd_tasmota_scan`**

Replace `cmd_tasmota_scan` (~1799-1860) with:

```python
def cmd_tasmota_scan(args: argparse.Namespace) -> int:
    """Scan for Tasmota devices on the IoT VLAN."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.tasmota import (
        _UNKNOWN_PREFIX,
        enrich_hosts_with_tasmota,
        scan_tasmota,
    )

    # Minimal pipeline to get hosts with IPs.
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        all_records.extend(parse_csv(csv_text, name))
    hosts = build_hosts(all_records, config.site)

    discrepancies: list = []
    age = None if args.force else _fresh_scan_age(config, "tasmota")
    if age is not None:
        print(f"Using cached tasmota scan ({age:.0f}s old).", file=sys.stderr)
        tasmota_data = _load_latest_from_db(config, "load_latest_tasmota") or {}
    else:
        result = scan_tasmota(
            hosts,
            _load_latest_from_db(config, "load_latest_tasmota"),
            site=config.site,
            verbose=True,
        )
        tasmota_data = result.data
        discrepancies = result.discrepancies
        if tasmota_data:
            _save_tasmota_to_db(config, tasmota_data)

    enrich_hosts_with_tasmota(hosts, tasmota_data)

    iot_hosts = [h for h in hosts if h.sheet_type == "IoT"]
    hosts_with_data = sum(1 for h in iot_hosts if h.tasmota_data is not None)
    unknown = [k for k in tasmota_data if k.startswith(_UNKNOWN_PREFIX)]
    print(
        f"\nTasmota data for {hosts_with_data}/{len(iot_hosts)} IoT hosts; "
        f"{len(unknown)} unknown device(s) on the subnet."
    )

    return _report_tasmota_discrepancies(discrepancies)
```

- [ ] **Step 5: Fix the `cmd_tasmota_show` unknown block**

In `cmd_tasmota_show`, the unknown block (~1913-1919) strips the key as an IP. The suffix is now a MAC; show the device's IP from its data. Replace:

```python
        for key in sorted(unknown.keys()):
            ip = key[len(_UNKNOWN_PREFIX):]
            data = unknown[key]
            name = data.get("device_name", "?")
            mac = data.get("mac", "?")
            fw = data.get("firmware_version", "?")
            print(f"  {ip:15s}  {name:20s}  MAC={mac}  fw={fw}")
```

with:

```python
        for key in sorted(unknown.keys()):
            data = unknown[key]
            ip = data.get("ip", "?")
            name = data.get("device_name", "?")
            mac = data.get("mac", key[len(_UNKNOWN_PREFIX):])
            fw = data.get("firmware_version", "?")
            print(f"  {ip:15s}  {name:20s}  MAC={mac}  fw={fw}")
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/test_supplements/test_tasmota.py::TestTasmotaCliHelpers -v`
Expected: PASS.

- [ ] **Step 7: Verify no dangling references and lint**

Run: `grep -rn "match_unknown_devices" src/ tests/`
Expected: no output (all references removed).

Run: `uv run ruff check src/ tests/`
Expected: clean (no unused imports — confirm `_unknown_key` is no longer imported in `cli/main.py` if unused there, and `Future` is still used in `tasmota.py`).

- [ ] **Step 8: Commit**

```bash
git add src/gdoc2netcfg/cli/main.py tests/test_supplements/test_tasmota.py
git commit -m "cli: tasmota scan saves+tombstones, reports discrepancies, non-zero exit"
```

---

## Final verification

- [ ] **Run the full suite**

Run: `uv run pytest -q`
Expected: all tests pass (the pre-existing count plus the new tests).

- [ ] **Lint**

Run: `uv run ruff check src/ tests/`
Expected: clean.

- [ ] **Sanity-check the CLI loads**

Run: `uv run gdoc2netcfg tasmota --help`
Expected: subcommands listed, no import errors.

---

## Deployment (after merge — both sites)

Per the project's deploy-via-merge rule (never copy to prod):

1. Merge `feature/tasmota-mac-identity` to `main` (proper `--no-ff` merge) and push.
2. On each site: `ssh -A <site> "cd /opt/gdoc2netcfg && sudo -E git pull"`.
3. Restart the reachability daemon so the v8 migration runs on the next DB open:
   `sudo systemctl restart gdoc2netcfg-reachability.service`.
4. Self-heal + see discrepancies (writes the DB, so run as root with the venv binary):
   `cd /opt/gdoc2netcfg && sudo .venv/bin/gdoc2netcfg tasmota scan --force`.
   - Expect Welland to tombstone `_unknown/10.1.90.214` and report the `.149`
     unknown device (Monarto's au-plug-10 physically on Welland) as an
     `unknown_device` discrepancy (non-zero exit).
5. Confirm cleanup: `cd /opt/gdoc2netcfg && .venv/bin/gdoc2netcfg tasmota show`
   no longer lists au-plug-13 twice.
