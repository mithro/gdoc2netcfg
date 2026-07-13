# Tasmota Remote Syslog Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture Tasmota device logs on ten64 via rsyslog per-device files, and push `LogHost`/`LogPort`/`SysLog` settings to devices through `gdoc2netcfg tasmota configure` with drift detection.

**Architecture:** A static rsyslog drop-in (repo-tracked, deployed by a new `make deploy-syslog` target) receives UDP syslog into `/var/log/tasmota/<hostname>.log`. On the pipeline side, the existing scan already fetches `Status 0` whose `StatusLOG` section reports the three settings; they flow into `TasmotaData`, the `tasmota_devices` table (schema v8→v9), and the established `compute_desired_config` → `compute_drift` → push path in `tasmota_configure.py`. The configured `syslog_host` is a hostname resolved per-device to the sink's IP **on that device's VLAN** using the host list + `Site` VLAN data (never live DNS).

**Tech Stack:** Python 3.11+ (stdlib only in these modules), pytest, SQLite, rsyslog 8.x, logrotate, GNU make.

**Spec:** `docs/superpowers/specs/2026-07-12-tasmota-syslog-design.md`

## Global Constraints

- Always `uv run pytest` / `uv run ruff check src/ tests/` — never bare `python`/`pip`.
- Fail loud, never fabricate: unresolvable values raise; no silent skips or fallbacks (CLAUDE.md).
- One commit per task (or smaller); commit messages in repo style (`area: summary`).
- Work happens in the `.worktrees/tasmota-syslog` worktree on branch `tasmota-syslog`.
- Never redirect stderr to `/dev/null`.
- `/usr/sbin` is not in the user PATH — call `/usr/sbin/rsyslogd`, `/usr/sbin/logrotate` by absolute path.
- Verified device behaviour (au-plug-4, 2026-07-12): `Status 0` → `"StatusLOG": {"SerialLog": 2, "WebLog": 2, "MqttLog": 0, "SysLog": 0, "LogHost": "", "LogPort": 514, ...}`. Tasmota defaults: `SysLog` 0, `LogHost` "", `LogPort` 514.

---

### Task 1: rsyslog + logrotate configs and `make deploy-syslog`

**Files:**
- Create: `etc/rsyslog-tasmota.conf`
- Create: `etc/logrotate-tasmota`
- Modify: `Makefile` (insert after the `deploy-known-hosts` target, before the aggregate `deploy` target, ~line 112–118)

**Interfaces:**
- Consumes: existing Makefile vars `ETCKEEPER_COMMIT`, `GDOC2NETCFG_VERSION`.
- Produces: `make deploy-syslog` target (used by rollout docs in Task 8). NOT added to the aggregate `deploy` target (spec §1: `deploy` covers sheet-derived generator outputs only).

- [ ] **Step 1: Write `etc/rsyslog-tasmota.conf`**

```
# Tasmota IoT device remote syslog capture.
# Repo-tracked at etc/rsyslog-tasmota.conf in gdoc2netcfg; deployed to
# /etc/rsyslog.d/tasmota.conf by `sudo make deploy-syslog`.
#
# Remote UDP input is bound to its own ruleset: remote messages only
# reach the per-device files below (never /var/log/syslog), and local
# messages never reach these files. securepath prevents a hostile
# hostname from escaping /var/log/tasmota/.

module(load="imudp")

template(name="TasmotaDeviceLog" type="string"
         string="/var/log/tasmota/%hostname:::secpath-replace%.log")

ruleset(name="remote-tasmota") {
    action(type="omfile" dynaFile="TasmotaDeviceLog"
           fileOwner="root" fileGroup="adm"
           fileCreateMode="0640" dirCreateMode="0755")
    stop
}

input(type="imudp" port="514" ruleset="remote-tasmota")
```

- [ ] **Step 2: Validate rsyslog syntax**

Run: `/usr/sbin/rsyslogd -N1 -f etc/rsyslog-tasmota.conf`
Expected: prints `rsyslogd: version 8.…, config validation run…` and `End of config validation run. Bye.`, exit code 0. (A warning that it is not running as root is acceptable; any `error` line is not.)

- [ ] **Step 3: Write `etc/logrotate-tasmota`**

```
# Tasmota remote syslog logs (see etc/rsyslog-tasmota.conf).
# Repo-tracked at etc/logrotate-tasmota in gdoc2netcfg; deployed to
# /etc/logrotate.d/tasmota by `sudo make deploy-syslog`.
/var/log/tasmota/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
}
```

- [ ] **Step 4: Validate logrotate syntax**

Run: `/usr/sbin/logrotate -d etc/logrotate-tasmota`
Expected: debug output `reading config file etc/logrotate-tasmota` and a `rotating pattern: /var/log/tasmota/*.log` block, exit code 0. (`log /var/log/tasmota/*.log doesn't exist -- skipping` is fine — the directory is created at deploy time.)

- [ ] **Step 5: Add the Makefile target**

Insert between `deploy-known-hosts` and the aggregate `deploy` target:

```make
RSYSLOG_TASMOTA_CONF := /etc/rsyslog.d/tasmota.conf
LOGROTATE_TASMOTA_CONF := /etc/logrotate.d/tasmota
TASMOTA_LOG_DIR := /var/log/tasmota

.PHONY: deploy-syslog
deploy-syslog: ## Deploy rsyslog + logrotate config for Tasmota remote syslog (run with sudo)
	install -d $(TASMOTA_LOG_DIR)
	cp etc/rsyslog-tasmota.conf $(RSYSLOG_TASMOTA_CONF)
	cp etc/logrotate-tasmota $(LOGROTATE_TASMOTA_CONF)
	systemctl restart rsyslog
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy syslog: $(GDOC2NETCFG_VERSION)" $(RSYSLOG_TASMOTA_CONF) $(LOGROTATE_TASMOTA_CONF)
```

(`scripts/etckeeper_commit.py` takes `paths` with `nargs="+"` — one call covers both files.)

Do NOT add `deploy-syslog` to the `deploy:` prerequisite list.

- [ ] **Step 6: Verify recipe expansion**

Run: `make -n deploy-syslog`
Expected: the five recipe lines printed with variables expanded (`install -d /var/log/tasmota`, `cp etc/rsyslog-tasmota.conf /etc/rsyslog.d/tasmota.conf`, …), exit 0.

- [ ] **Step 7: Commit**

```bash
git add etc/rsyslog-tasmota.conf etc/logrotate-tasmota Makefile
git commit -m "etc, make: rsyslog capture + deploy-syslog for tasmota remote logs"
```

---

### Task 2: `[tasmota]` syslog settings in config

**Files:**
- Modify: `src/gdoc2netcfg/config.py` (`TasmotaConfig` ~line 58–67, `_build_tasmota` ~line 245–250)
- Test: `tests/test_config.py` (create — no config-loading test file exists yet)

**Interfaces:**
- Produces: `TasmotaConfig.syslog_host: str = ""` (empty ⇒ feature disabled), `TasmotaConfig.syslog_port: int = 514`, `TasmotaConfig.syslog_level: int = 2`. `_build_tasmota` raises `ValueError` on out-of-range values. Tasks 5–7 consume these attributes.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config.py`:

```python
"""Tests for TOML section builders in config.py."""

import pytest

from gdoc2netcfg.config import _build_tasmota


class TestBuildTasmota:
    def test_missing_section_gives_defaults(self):
        cfg = _build_tasmota({})
        assert cfg.mqtt_secret == ""
        assert cfg.syslog_host == ""
        assert cfg.syslog_port == 514
        assert cfg.syslog_level == 2

    def test_parses_syslog_settings(self):
        cfg = _build_tasmota({"tasmota": {
            "mqtt_secret": "0123456789abcdef0123456789abcdef",
            "syslog_host": "ten64",
            "syslog_port": 1514,
            "syslog_level": 3,
        }})
        assert cfg.syslog_host == "ten64"
        assert cfg.syslog_port == 1514
        assert cfg.syslog_level == 3

    def test_syslog_defaults_when_only_secret_set(self):
        cfg = _build_tasmota({"tasmota": {"mqtt_secret": "x"}})
        assert cfg.syslog_host == ""
        assert cfg.syslog_port == 514
        assert cfg.syslog_level == 2

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="syslog_level"):
            _build_tasmota({"tasmota": {"syslog_level": 7}})

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError, match="syslog_port"):
            _build_tasmota({"tasmota": {"syslog_port": 0}})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL — `AttributeError: 'TasmotaConfig' object has no attribute 'syslog_host'` (and the raise tests fail with `DID NOT RAISE`).

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/config.py`, extend the dataclass (keep the existing docstring's first lines, add the new attributes):

```python
@dataclass
class TasmotaConfig:
    """Tasmota per-device MQTT credential derivation + syslog ([tasmota]).

    `mqtt_secret` derives each device's MqttUser (`tas-<id>`) and MqttPassword
    (`sha256(secret+<id>)`); the broker stores the pre-hashed form. Replaces the
    #30 interim shared `mqtt_user`/`mqtt_password` static login.

    `syslog_host` names the syslog sink by inventory hostname; the configure
    step resolves it to the sink's IP on each device's VLAN and pushes
    LogHost/LogPort/SysLog. Empty disables syslog configuration entirely.
    `syslog_level` (0-4) is the site default; the sheet's "Syslog Level"
    column overrides it per device.
    """

    mqtt_secret: str = ""
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_level: int = 2
```

And replace `_build_tasmota`:

```python
def _build_tasmota(data: dict) -> TasmotaConfig:
    """Build Tasmota config from parsed TOML data."""
    section = data.get("tasmota", {})
    if not section:
        return TasmotaConfig()
    syslog_port = section.get("syslog_port", 514)
    if not isinstance(syslog_port, int) or not 1 <= syslog_port <= 65535:
        raise ValueError(
            f"[tasmota] syslog_port must be an integer 1-65535, got {syslog_port!r}"
        )
    syslog_level = section.get("syslog_level", 2)
    if syslog_level not in (0, 1, 2, 3, 4):
        raise ValueError(
            f"[tasmota] syslog_level must be 0-4, got {syslog_level!r}"
        )
    return TasmotaConfig(
        mqtt_secret=section.get("mqtt_secret", ""),
        syslog_host=section.get("syslog_host", ""),
        syslog_port=syslog_port,
        syslog_level=syslog_level,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_config.py -v`
Expected: 5 passed.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/config.py tests/test_config.py
git commit -m "config: add [tasmota] syslog_host/syslog_port/syslog_level"
```

---

### Task 3: discovery.db schema v9 — tasmota syslog columns

**Files:**
- Modify: `src/gdoc2netcfg/storage/discovery_db.py` (`_TASMOTA_FIELDS` ~line 165, `_TASMOTA_OPTIONAL_FIELDS` ~line 188, `SCHEMA_VERSION`/`SCHEMA_UPGRADES` ~lines 758–765)
- Test: `tests/test_storage/test_discovery_db.py`

**Interfaces:**
- Consumes: existing `_entity_table_ddl` machinery — adding to `_TASMOTA_FIELDS` + `_TASMOTA_OPTIONAL_FIELDS` automatically updates DDL, validation, insertion, and reconstruction.
- Produces: `tasmota_devices` columns `syslog_level INTEGER`, `log_host TEXT`, `log_port INTEGER` (nullable/optional); docs from `save_tasmota`/`load_latest_tasmota` may carry keys `syslog_level: int`, `log_host: str`, `log_port: int` (absent stays absent). Task 4's scan docs rely on save accepting these keys.

This task MUST land before Task 4: save validates docs strictly against `_TASMOTA_FIELDS`, so a scan producing the new keys against old storage would raise.

- [ ] **Step 1: Write the failing tests**

In `tests/test_storage/test_discovery_db.py`:

(a) Extend `_tasmota_doc` (~line 461) with the new fields, mirroring real-device defaults:

```python
        "module": module,
        "mqtt_count": 3,
        "syslog_level": 0,
        "log_host": "",
        "log_port": 514,
    }
```

(b) Add a `_strip_v9` helper immediately above the existing `_strip_v8` (~line 823):

```python
def _strip_v9(conn: sqlite3.Connection) -> None:
    """Regress a current DB's v9 features back to the v8 shape."""
    conn.execute("ALTER TABLE tasmota_devices DROP COLUMN syslog_level")
    conn.execute("ALTER TABLE tasmota_devices DROP COLUMN log_host")
    conn.execute("ALTER TABLE tasmota_devices DROP COLUMN log_port")
```

(c) Every helper that regresses a **current** DB to an older schema must strip v9 first. Run `grep -n "_strip_v8(d.connection)" tests/test_storage/test_discovery_db.py` and insert `_strip_v9(d.connection)` on the line BEFORE each hit (the v4 maker ~line 859, the v6 maker ~line 926, and the v7/v8 makers found by the grep).

(d) Add the upgrade + absent-field tests (place next to the existing `TestSchemaUpgradeV8`-style classes):

```python
class TestSchemaUpgradeV9:
    def _make_v8_db(self, path: Path) -> None:
        """Create a current DB, then strip it back to schema v8."""
        d = DiscoveryDB(path)
        _strip_v9(d.connection)
        d.connection.execute(
            "UPDATE _meta SET value = '8' WHERE key = 'schema_version'"
        )
        d.connection.commit()
        d.close()

    def test_rw_open_upgrades_v8(self, tmp_path: Path):
        path = tmp_path / "v8.db"
        self._make_v8_db(path)

        d = DiscoveryDB(path)  # read-write open applies the upgrade
        cols = [r[1] for r in d.connection.execute(
            "PRAGMA table_info(tasmota_devices)"
        )]
        assert "syslog_level" in cols
        assert "log_host" in cols
        assert "log_port" in cols
        version = d.connection.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert int(version) == DiscoveryDB.SCHEMA_VERSION
        d.close()

    def test_pre_v9_tasmota_rows_load_without_syslog_fields(self, tmp_path: Path):
        """Tasmota scans written before the upgrade never captured
        syslog settings — the reconstructed document omits the keys."""
        path = tmp_path / "v8.db"
        self._make_v8_db(path)

        conn = sqlite3.connect(str(path))
        cur = conn.execute(
            "INSERT INTO scans (scan_type, started_at, finished_at, "
            "host_count, changed_count) VALUES ('tasmota', "
            "'2026-06-01T00:00:00+00:00', '2026-06-01T00:01:00+00:00', 1, 1)"
        )
        scan_id = cur.lastrowid
        conn.execute(
            "INSERT INTO tasmota_devices (scan_id, device_key, device_name, "
            "friendly_name, hostname, firmware_version, mqtt_host, mqtt_port, "
            "mqtt_topic, mqtt_client, mqtt_user, mac, ip, wifi_ssid, wifi_rssi, "
            "wifi_signal, uptime, module, mqtt_count) VALUES "
            "(?, 'plug-old', 'plug-old', 'plug-old', 'tasmota-plug-old', "
            "'13.2.0', 'mqtt.example', 1883, 'plug-old', 'DVES_old', 'tasmota', "
            "'AA:BB:CC:00:11:22', '10.1.90.10', 'iot', 80, -55, '1T00:00:00', "
            "43, 3)",
            (scan_id,),
        )
        conn.commit()
        conn.close()

        d = DiscoveryDB(path)  # applies the v9 upgrade
        loaded = d.load_latest_tasmota()
        assert "syslog_level" not in loaded["plug-old"]
        assert "log_host" not in loaded["plug-old"]
        assert "log_port" not in loaded["plug-old"]
        d.close()
```

(e) Add the absent-key round-trip test next to `test_doc_without_mqtt_count_roundtrips` (~line 795):

```python
    def test_doc_without_syslog_fields_roundtrips(self, db: DiscoveryDB):
        """Syslog fields were added after rows already existed: a
        baseline document reconstructed from a pre-v9 row lacks them,
        and saving such a document keeps them absent."""
        doc = _tasmota_doc("plug1")
        del doc["syslog_level"]
        del doc["log_host"]
        del doc["log_port"]
        s = db.begin_scan("tasmota")
        changed = db.save_tasmota(s, {"plug-old": doc})
        db.finish_scan(s, host_count=1, changed_count=changed)

        loaded = db.load_latest_tasmota()
        assert loaded == {"plug-old": doc}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_storage/test_discovery_db.py -v`
Expected: FAIL — the extended `_tasmota_doc` makes `save_tasmota` raise on unknown keys (`syslog_level`), `_strip_v9` fails with `no such column: syslog_level`, and `TestSchemaUpgradeV9` fails.

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/storage/discovery_db.py`:

(a) Append to `_TASMOTA_FIELDS` (after `("mqtt_count", int)`):

```python
    ("mqtt_count", int),
    ("syslog_level", int),
    ("log_host", str),
    ("log_port", int),
)
```

(b) Update `_TASMOTA_OPTIONAL_FIELDS` and its comment:

```python
# Fields added to the scanner after rows already existed: optional in
# documents (absent stays absent — baseline documents reconstructed
# from pre-v5/pre-v9 rows lack them), stored as NULL when absent.
_TASMOTA_OPTIONAL_FIELDS = frozenset({
    "mqtt_count", "syslog_level", "log_host", "log_port",
})
```

(c) Bump the version and add the upgrade (~line 758):

```python
    SCHEMA_VERSION = 9

    SCHEMA_UPGRADES = {
        5: ["ALTER TABLE tasmota_devices ADD COLUMN mqtt_count INTEGER"],
        6: [_upgrade_v6_port_aliases],
        7: [_upgrade_v7_extended_bridge_data],
        8: ["ALTER TABLE tasmota_devices "
            "ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0"],
        9: ["ALTER TABLE tasmota_devices ADD COLUMN syslog_level INTEGER",
            "ALTER TABLE tasmota_devices ADD COLUMN log_host TEXT",
            "ALTER TABLE tasmota_devices ADD COLUMN log_port INTEGER"],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_storage/ -v`
Expected: all pass, including every pre-existing upgrade test (they now strip v9 before regressing further).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/storage/discovery_db.py tests/test_storage/test_discovery_db.py
git commit -m "storage: schema v9 — tasmota syslog_level/log_host/log_port columns"
```

---

### Task 4: scan parsing + `TasmotaData` fields

**Files:**
- Modify: `src/gdoc2netcfg/supplements/tasmota.py` (`_parse_tasmota_status` ~line 94–141, `enrich_hosts_with_tasmota` ~line 313)
- Modify: `src/gdoc2netcfg/models/host.py` (`TasmotaData` ~line 277–324)
- Test: `tests/test_supplements/test_tasmota.py`

**Interfaces:**
- Consumes: Task 3's storage columns (scan docs now include the new keys).
- Produces: `TasmotaData.syslog_level: int = 0`, `TasmotaData.log_host: str = ""`, `TasmotaData.log_port: int = 514` — the defaults equal Tasmota factory defaults, so pre-v9 cached scans (absent keys) behave as "unconfigured device" in drift. Tasks 5–6 consume these attributes.

- [ ] **Step 1: Write the failing tests**

In `tests/test_supplements/test_tasmota.py`:

(a) Extend the realistic `Status 0` fixture (the dict directly below the comment `# A realistic Tasmota Status 0 JSON response`, ~line 100) with a `StatusLOG` section (shape verified against a live device):

```python
    "StatusLOG": {
        "SerialLog": 2,
        "WebLog": 2,
        "MqttLog": 0,
        "SysLog": 2,
        "LogHost": "10.1.90.1",
        "LogPort": 514,
    },
```

(b) Add parse tests next to the existing `_parse_tasmota_status` tests (find with `grep -n "_parse_tasmota_status" tests/test_supplements/test_tasmota.py`):

```python
    def test_parse_syslog_fields(self):
        parsed = _parse_tasmota_status(SAMPLE_STATUS_0)
        assert parsed["syslog_level"] == 2
        assert parsed["log_host"] == "10.1.90.1"
        assert parsed["log_port"] == 514

    def test_parse_missing_statuslog_defaults(self):
        parsed = _parse_tasmota_status({})
        assert parsed["syslog_level"] == 0
        assert parsed["log_host"] == ""
        assert parsed["log_port"] == 514
```

(c) Add an enrich pass-through test next to the existing `enrich_hosts_with_tasmota` tests:

```python
    def test_enrich_carries_syslog_fields(self):
        host = _make_host(hostname="au-plug-10")
        enrich_hosts_with_tasmota([host], {"au-plug-10": {
            "syslog_level": 2, "log_host": "10.1.90.1", "log_port": 514,
        }})
        assert host.tasmota_data.syslog_level == 2
        assert host.tasmota_data.log_host == "10.1.90.1"
        assert host.tasmota_data.log_port == 514

    def test_enrich_syslog_fields_default_when_absent(self):
        """Pre-v9 cached scans lack the keys — defaults mirror Tasmota
        factory defaults (unconfigured device)."""
        host = _make_host(hostname="au-plug-10")
        enrich_hosts_with_tasmota([host], {"au-plug-10": {}})
        assert host.tasmota_data.syslog_level == 0
        assert host.tasmota_data.log_host == ""
        assert host.tasmota_data.log_port == 514
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_tasmota.py -v -k "syslog or statuslog"`
Expected: FAIL — `KeyError: 'syslog_level'` / `AttributeError: 'TasmotaData' object has no attribute 'syslog_level'`.

- [ ] **Step 3: Implement**

(a) `src/gdoc2netcfg/models/host.py` — add to `TasmotaData` after `mqtt_count` (and document in the class docstring's Attributes section):

```python
    mqtt_count: int = 0
    syslog_level: int = 0
    log_host: str = ""
    log_port: int = 514
    controls: tuple[str, ...] = ()
```

Docstring additions:

```
        syslog_level: Remote syslog verbosity (SysLog command, 0=off .. 4).
        log_host: Remote syslog target (LogHost command); "" if unset.
        log_port: Remote syslog UDP port (LogPort command).
```

(b) `src/gdoc2netcfg/supplements/tasmota.py` — in `_parse_tasmota_status`, add `log = data.get("StatusLOG", {})` next to the other section extractions, extend the docstring's section list with `StatusLOG.SysLog, LogHost, LogPort`, and add to the returned dict:

```python
        "mqtt_count": sts.get("MqttCount", 0),
        "syslog_level": log.get("SysLog", 0),
        "log_host": log.get("LogHost", ""),
        "log_port": log.get("LogPort", 514),
    }
```

(c) In `enrich_hosts_with_tasmota`, add to the `TasmotaData(...)` construction:

```python
            mqtt_count=info.get("mqtt_count", 0),
            syslog_level=info.get("syslog_level", 0),
            log_host=info.get("log_host", ""),
            log_port=info.get("log_port", 514),
            controls=controls,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_supplements/test_tasmota.py tests/test_storage/ -v`
Expected: all pass (storage round-trips the new scan keys thanks to Task 3).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/models/host.py src/gdoc2netcfg/supplements/tasmota.py tests/test_supplements/test_tasmota.py
git commit -m "tasmota: parse StatusLOG syslog settings into TasmotaData"
```

---

### Task 5: `SyslogTarget` + `resolve_syslog_target`

**Files:**
- Modify: `src/gdoc2netcfg/supplements/tasmota_configure.py`
- Test: `tests/test_supplements/test_tasmota.py`

**Interfaces:**
- Consumes: `TasmotaConfig.syslog_host/syslog_port/syslog_level` (Task 2), `TasmotaData.ip`, `NetworkInterface.vlan_id`/`ipv4`, `ip_to_vlan_id(ipv4: IPv4Address, site: Site) -> int | None` from `gdoc2netcfg.derivations.vlan`.
- Produces (Tasks 6–7 rely on these exact names):
  - `@dataclass(frozen=True) SyslogTarget(ip: str, port: int, level: int)`
  - `resolve_syslog_target(host: Host, all_hosts: list[Host], site: Site, tasmota_config: TasmotaConfig) -> SyslogTarget | None` — `None` only when disabled; raises `ValueError` on any resolution failure.
  - `_SYSLOG_LEVEL_COLUMN = "Syslog Level"` (sheet column name).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_supplements/test_tasmota.py`. New imports at the top (merge into existing import blocks):

```python
from gdoc2netcfg.models.network import VLAN, Site
from gdoc2netcfg.supplements.tasmota_configure import (
    SyslogTarget,
    resolve_syslog_target,
)
```

Shared helpers (place next to `_make_host`):

```python
def _make_site():
    """Welland-shaped site: VLAN 10 (int) and VLAN 90 (iot)."""
    return Site(
        name="welland",
        domain="welland.mithis.com",
        site_octet=1,
        vlans={
            10: VLAN(id=10, name="int", subdomain="int"),
            90: VLAN(id=90, name="iot", subdomain="iot"),
        },
    )


def _make_sink(interfaces=None):
    """The syslog sink host (ten64) with one interface per VLAN."""
    if interfaces is None:
        interfaces = [
            NetworkInterface(
                name="int",
                mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
                ip_addresses=(IPv4Address("10.1.10.1"),),
                vlan_id=10,
            ),
            NetworkInterface(
                name="iot",
                mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
                ip_addresses=(IPv4Address("10.1.90.1"),),
                vlan_id=90,
            ),
        ]
    return Host(
        machine_name="ten64",
        hostname="ten64",
        sheet_type="Server",
        interfaces=interfaces,
    )
```

Test class:

```python
class TestResolveSyslogTarget:
    def _device(self, ip="10.1.90.10", extra=None):
        host = _make_host(hostname="au-plug-10", extra=extra)
        host.tasmota_data = _make_tasmota_data(ip=ip)
        return host

    def test_disabled_returns_none(self):
        config = _make_tasmota_config()  # syslog_host defaults to ""
        host = self._device()
        assert resolve_syslog_target(
            host, [host, _make_sink()], _make_site(), config) is None

    def test_resolves_sink_ip_on_device_vlan(self):
        config = _make_tasmota_config(syslog_host="ten64")
        host = self._device(ip="10.1.90.10")
        target = resolve_syslog_target(
            host, [host, _make_sink()], _make_site(), config)
        assert target == SyslogTarget(ip="10.1.90.1", port=514, level=2)

    def test_sink_matched_by_machine_name_or_hostname(self):
        config = _make_tasmota_config(syslog_host="ten64")
        sink = _make_sink()
        sink.hostname = "ten64.int"  # hostname differs; machine_name matches
        host = self._device()
        target = resolve_syslog_target(host, [host, sink], _make_site(), config)
        assert target.ip == "10.1.90.1"

    def test_unknown_sink_raises(self):
        config = _make_tasmota_config(syslog_host="no-such-host")
        host = self._device()
        with pytest.raises(ValueError, match="no-such-host"):
            resolve_syslog_target(host, [host, _make_sink()], _make_site(), config)

    def test_device_ip_without_vlan_raises(self):
        config = _make_tasmota_config(syslog_host="ten64")
        host = self._device(ip="10.9.9.9")  # matches no VLAN
        with pytest.raises(ValueError, match="no known VLAN"):
            resolve_syslog_target(host, [host, _make_sink()], _make_site(), config)

    def test_sink_without_interface_on_vlan_raises(self):
        config = _make_tasmota_config(syslog_host="ten64")
        sink = _make_sink(interfaces=[
            NetworkInterface(
                name="int",
                mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
                ip_addresses=(IPv4Address("10.1.10.1"),),
                vlan_id=10,
            ),
        ])
        host = self._device(ip="10.1.90.10")
        with pytest.raises(ValueError, match="no interface on VLAN 90"):
            resolve_syslog_target(host, [host, sink], _make_site(), config)

    def test_host_without_tasmota_ip_raises(self):
        config = _make_tasmota_config(syslog_host="ten64")
        host = _make_host(hostname="au-plug-10")  # no tasmota_data
        with pytest.raises(ValueError, match="no Tasmota IP"):
            resolve_syslog_target(host, [host, _make_sink()], _make_site(), config)

    def test_level_override_from_sheet_column(self):
        config = _make_tasmota_config(syslog_host="ten64")
        host = self._device(extra={"Syslog Level": "0"})
        target = resolve_syslog_target(
            host, [host, _make_sink()], _make_site(), config)
        assert target.level == 0

    def test_blank_override_uses_site_default(self):
        config = _make_tasmota_config(syslog_host="ten64", syslog_level=3)
        host = self._device(extra={"Syslog Level": "  "})
        target = resolve_syslog_target(
            host, [host, _make_sink()], _make_site(), config)
        assert target.level == 3

    def test_invalid_override_raises(self):
        config = _make_tasmota_config(syslog_host="ten64")
        host = self._device(extra={"Syslog Level": "9"})
        with pytest.raises(ValueError, match="Syslog Level"):
            resolve_syslog_target(host, [host, _make_sink()], _make_site(), config)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_tasmota.py -v -k "ResolveSyslog"`
Expected: FAIL at import — `ImportError: cannot import name 'SyslogTarget'`.

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/supplements/tasmota_configure.py`, add imports:

```python
from gdoc2netcfg.derivations.vlan import ip_to_vlan_id
from gdoc2netcfg.models.addressing import IPv4Address
```

and under `TYPE_CHECKING`:

```python
    from gdoc2netcfg.models.network import Site
```

Then, below `ConfigDrift`:

```python
# Sheet column carrying a per-device SysLog level override (0-4).
_SYSLOG_LEVEL_COLUMN = "Syslog Level"


@dataclass(frozen=True)
class SyslogTarget:
    """Resolved remote-syslog settings for one device.

    Attributes:
        ip: Syslog sink IPv4 on the device's VLAN (pushed as LogHost).
        port: Syslog UDP port (pushed as LogPort).
        level: SysLog verbosity 0-4 (pushed as SysLog).
    """

    ip: str
    port: int
    level: int


def _syslog_level(host: Host, tasmota_config: TasmotaConfig) -> int:
    """Per-device SysLog level: sheet column override or site default."""
    raw = host.extra.get(_SYSLOG_LEVEL_COLUMN, "").strip()
    if not raw:
        return tasmota_config.syslog_level
    if raw not in ("0", "1", "2", "3", "4"):
        raise ValueError(
            f"{host.hostname}: invalid {_SYSLOG_LEVEL_COLUMN!r} value "
            f"{raw!r} (must be 0-4)"
        )
    return int(raw)


def resolve_syslog_target(
    host: Host,
    all_hosts: list[Host],
    site: Site,
    tasmota_config: TasmotaConfig,
) -> SyslogTarget | None:
    """Resolve the syslog sink IP on *host*'s network.

    The configured ``[tasmota] syslog_host`` names the sink by hostname;
    devices must log to the sink's address on their own VLAN, so the
    sink's interfaces are matched against the VLAN of the device's live
    Tasmota IP (inventory data, never live DNS).

    Returns:
        None when syslog configuration is disabled (empty syslog_host).

    Raises:
        ValueError: if the device has no Tasmota IP, the IP maps to no
            VLAN, the sink is not in the inventory, or the sink has no
            interface on the device's VLAN.
    """
    if not tasmota_config.syslog_host:
        return None
    if host.tasmota_data is None or not host.tasmota_data.ip:
        raise ValueError(
            f"{host.hostname}: no Tasmota IP to resolve a syslog target for"
        )
    device_ip = IPv4Address(host.tasmota_data.ip)
    vlan_id = ip_to_vlan_id(device_ip, site)
    if vlan_id is None:
        raise ValueError(
            f"{host.hostname}: Tasmota IP {device_ip} maps to no known VLAN"
        )
    name = tasmota_config.syslog_host
    sink = next(
        (h for h in all_hosts if name in (h.hostname, h.machine_name)), None,
    )
    if sink is None:
        raise ValueError(
            f"[tasmota] syslog_host {name!r} not found in the inventory"
        )
    for iface in sink.interfaces:
        if iface.vlan_id == vlan_id:
            return SyslogTarget(
                ip=str(iface.ipv4),
                port=tasmota_config.syslog_port,
                level=_syslog_level(host, tasmota_config),
            )
    raise ValueError(
        f"[tasmota] syslog_host {name!r} has no interface on VLAN {vlan_id} "
        f"(device {host.hostname} @ {device_ip})"
    )
```

(`TasmotaConfig` is already imported under `TYPE_CHECKING`; `dataclass` is already imported.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_supplements/test_tasmota.py -v -k "ResolveSyslog"`
Expected: 11 passed.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/supplements/tasmota_configure.py tests/test_supplements/test_tasmota.py
git commit -m "tasmota: resolve per-device syslog target from inventory"
```

---

### Task 6: syslog fields in desired config + drift

**Files:**
- Modify: `src/gdoc2netcfg/supplements/tasmota_configure.py` (`compute_desired_config` ~line 47, `_get_current_value` ~line 82, `compute_drift` ~line 103)
- Test: `tests/test_supplements/test_tasmota.py`

**Interfaces:**
- Consumes: `SyslogTarget` (Task 5), `TasmotaData.syslog_level/log_host/log_port` (Task 4).
- Produces (Task 7 relies on these): `compute_desired_config(host, mqtt_config, tasmota_config, syslog: SyslogTarget | None = None)` and `compute_drift(host, mqtt_config, tasmota_config, syslog: SyslogTarget | None = None)`. Desired values are strings (`"SysLog"`, `"LogHost"`, `"LogPort"`), matching the existing `MqttPort` convention.

- [ ] **Step 1: Write the failing tests**

Add to `TestComputeDesiredConfig`:

```python
    def test_no_syslog_keys_when_disabled(self):
        host = _make_host()
        desired = compute_desired_config(host, _MQTT, _make_tasmota_config())
        assert "SysLog" not in desired
        assert "LogHost" not in desired
        assert "LogPort" not in desired

    def test_syslog_keys_from_target(self):
        host = _make_host()
        target = SyslogTarget(ip="10.1.90.1", port=514, level=2)
        desired = compute_desired_config(
            host, _MQTT, _make_tasmota_config(), syslog=target)
        assert desired["SysLog"] == "2"
        assert desired["LogHost"] == "10.1.90.1"
        assert desired["LogPort"] == "514"
```

Add to `TestGetCurrentValue` (mirror the style of its existing test, extending the `_make_tasmota_data` call):

```python
    def test_syslog_fields(self):
        td = _make_tasmota_data(syslog_level=2, log_host="10.1.90.1", log_port=514)
        assert _get_current_value("SysLog", td) == "2"
        assert _get_current_value("LogHost", td) == "10.1.90.1"
        assert _get_current_value("LogPort", td) == "514"
```

Add a drift test class (next to the existing `compute_drift` tests):

```python
class TestSyslogDrift:
    def test_unconfigured_device_drifts(self):
        """Factory-default device (SysLog 0, empty LogHost) drifts on
        SysLog + LogHost but not LogPort (514 == 514)."""
        host = _make_host()
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10", friendly_name="au-plug-10",
            hostname="au-plug-10", mqtt_topic="au-plug-10",
            mqtt_host=_MQTT.host, mqtt_port=1883,
            mqtt_user=username(PREFIX, host),
            syslog_level=0, log_host="", log_port=514,
        )
        target = SyslogTarget(ip="10.1.90.1", port=514, level=2)
        drifts = compute_drift(host, _MQTT, _make_tasmota_config(), syslog=target)
        fields = {d.field: d for d in drifts}
        assert fields["SysLog"].current == "0"
        assert fields["SysLog"].desired == "2"
        assert fields["LogHost"].desired == "10.1.90.1"
        assert "LogPort" not in fields

    def test_configured_device_has_no_syslog_drift(self):
        host = _make_host()
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10", friendly_name="au-plug-10",
            hostname="au-plug-10", mqtt_topic="au-plug-10",
            mqtt_host=_MQTT.host, mqtt_port=1883,
            mqtt_user=username(PREFIX, host),
            syslog_level=2, log_host="10.1.90.1", log_port=514,
        )
        target = SyslogTarget(ip="10.1.90.1", port=514, level=2)
        drifts = compute_drift(host, _MQTT, _make_tasmota_config(), syslog=target)
        assert not any(d.field in ("SysLog", "LogHost", "LogPort") for d in drifts)
```

NOTE: check the existing drift tests first (`grep -n "class.*Drift\|def test_.*drift" tests/test_supplements/test_tasmota.py`) — if `_make_tasmota_data`'s defaults already produce a no-drift device against `_MQTT`, reuse that construction instead of the explicit kwargs above; the intent is "no drift except the syslog fields under test".

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_tasmota.py -v -k "syslog or Syslog"`
Expected: new tests FAIL — `compute_desired_config() got an unexpected keyword argument 'syslog'`.

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/supplements/tasmota_configure.py`:

(a) `compute_desired_config` — new signature and tail:

```python
def compute_desired_config(
    host: Host,
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
    syslog: SyslogTarget | None = None,
) -> dict[str, str]:
```

Docstring gains:

```
        syslog: Resolved remote-syslog target, or None when syslog
            configuration is disabled.
```

Before `return desired`:

```python
    if syslog is not None:
        desired.update({
            "SysLog": str(syslog.level),
            "LogHost": syslog.ip,
            "LogPort": str(syslog.port),
        })
```

(b) `_get_current_value` field map gains:

```python
        "MqttPassword": None,  # Can't be read back from device
        "SysLog": "syslog_level",
        "LogHost": "log_host",
        "LogPort": "log_port",
    }
```

(c) `compute_drift` — new signature, pass-through, docstring line matching (a):

```python
def compute_drift(
    host: Host,
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
    syslog: SyslogTarget | None = None,
) -> list[ConfigDrift]:
    ...
    desired = compute_desired_config(host, mqtt_config, tasmota_config, syslog)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_supplements/test_tasmota.py -v`
Expected: all pass (existing tests unaffected — the new parameter defaults to None).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/supplements/tasmota_configure.py tests/test_supplements/test_tasmota.py
git commit -m "tasmota: syslog settings in desired config and drift detection"
```

---

### Task 7: push path + CLI wiring

**Files:**
- Modify: `src/gdoc2netcfg/supplements/tasmota_configure.py` (`configure_tasmota_device` ~line 184, `configure_all_tasmota_devices` ~line 308)
- Modify: `src/gdoc2netcfg/cli/main.py` (`cmd_tasmota_configure` ~line 2013–2080)
- Test: `tests/test_supplements/test_tasmota.py`

**Interfaces:**
- Consumes: `resolve_syslog_target` (Task 5), `compute_drift(..., syslog=)` (Task 6), `config.site` (VLAN-enriched by `_enrich_site_from_sheets` inside `_tasmota_hosts`).
- Produces:
  - `configure_tasmota_device(host, mqtt_config, tasmota_config, dry_run=False, verbose=False, force=False, syslog: SyslogTarget | None = None) -> bool`
  - `configure_all_tasmota_devices(hosts, mqtt_config, tasmota_config, site: Site, all_hosts: list[Host], dry_run=False, verbose=False, force=False) -> tuple[int, int]` — `site`/`all_hosts` are REQUIRED (no silent-disable default); resolution failures raise and abort the run (fail loud).

- [ ] **Step 1: Write the failing tests**

(a) Update the one existing `configure_all_tasmota_devices` call — in `TestConfigureAllTasmotaDevices.test_counts` (~line 1367) — to the new signature:

```python
        success, fail = configure_all_tasmota_devices(
            [h1, h2], _MQTT, config, _make_site(), [h1, h2])
```

(`config` there has an empty `syslog_host`, so resolution is disabled and the test's counting behaviour is unchanged.)

(b) Add a push test (mirror the existing `configure_tasmota_device` mock style — `grep -n "patch.*_send_tasmota_command" tests/test_supplements/test_tasmota.py` and reuse that pattern):

```python
class TestConfigureSyslogPush:
    def _drifted_host(self):
        """Device correct except for factory-default syslog settings."""
        host = _make_host()
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10", friendly_name="au-plug-10",
            hostname="au-plug-10", mqtt_topic="au-plug-10",
            mqtt_host=_MQTT.host, mqtt_port=1883,
            mqtt_user=username(PREFIX, host), mqtt_count=1,
            syslog_level=0, log_host="", log_port=514,
        )
        return host

    def test_pushes_syslog_commands(self):
        host = self._drifted_host()
        target = SyslogTarget(ip="10.1.90.1", port=514, level=2)
        with patch(
            "gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command",
            return_value={},
        ) as send:
            ok = configure_tasmota_device(
                host, _MQTT, _make_tasmota_config(), syslog=target)
        assert ok
        commands = [c.args[1] for c in send.call_args_list]
        assert "SysLog 2" in commands
        assert "LogHost 10.1.90.1" in commands
        assert "LogPort 514" not in commands  # 514 == 514, no drift

    def test_all_resolves_per_device(self):
        host = self._drifted_host()
        config = _make_tasmota_config(syslog_host="ten64")
        sink = _make_sink()
        with patch(
            "gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command",
            return_value={},
        ) as send:
            success, fail = configure_all_tasmota_devices(
                [host], _MQTT, config, _make_site(), [host, sink])
        assert (success, fail) == (1, 0)
        commands = [c.args[1] for c in send.call_args_list]
        assert "LogHost 10.1.90.1" in commands

    def test_all_resolution_failure_raises(self):
        """A bogus sheet value or missing sink aborts loudly."""
        host = self._drifted_host()
        config = _make_tasmota_config(syslog_host="no-such-host")
        with pytest.raises(ValueError, match="no-such-host"):
            configure_all_tasmota_devices(
                [host], _MQTT, config, _make_site(), [host])
```

NOTE: `_send_tasmota_command` is called as `_send_tasmota_command(ip, command)` — if the existing mocks assert differently, follow their calling-convention (`c.args`/`c.kwargs`) exactly.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_tasmota.py -v`
Expected: new tests FAIL (`unexpected keyword argument 'syslog'` / `takes 3 positional arguments`); the updated call in (a) fails until the signature changes.

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/supplements/tasmota_configure.py`:

(a) `configure_tasmota_device` — append parameter and thread it through:

```python
def configure_tasmota_device(
    host: Host,
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
    dry_run: bool = False,
    verbose: bool = False,
    force: bool = False,
    syslog: SyslogTarget | None = None,
) -> bool:
```

Docstring gains: `syslog: Resolved remote-syslog target for this device, or None when disabled.` Replace both internal calls:

```python
    drifts = compute_drift(host, mqtt_config, tasmota_config, syslog)
    ...
    desired = compute_desired_config(host, mqtt_config, tasmota_config, syslog)
```

(b) `configure_all_tasmota_devices`:

```python
def configure_all_tasmota_devices(
    hosts: list[Host],
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
    site: Site,
    all_hosts: list[Host],
    dry_run: bool = False,
    verbose: bool = False,
    force: bool = False,
) -> tuple[int, int]:
```

Docstring gains:

```
        site: Site topology (VLAN definitions) for syslog target resolution.
        all_hosts: Full host list (the syslog sink is usually not a
            Tasmota device, so it is not in *hosts*).
```

Loop body:

```python
    for host in hosts:
        syslog = None
        if host.tasmota_data is not None and host.tasmota_data.ip:
            syslog = resolve_syslog_target(host, all_hosts, site, tasmota_config)
        ok = configure_tasmota_device(
            host, mqtt_config, tasmota_config, dry_run=dry_run, verbose=verbose,
            force=force, syslog=syslog,
        )
```

(Hosts without Tasmota data/IP keep their existing skip-and-report path inside `configure_tasmota_device`.)

(c) `src/gdoc2netcfg/cli/main.py` `cmd_tasmota_configure`:

`--all` branch:

```python
        success, fail = configure_all_tasmota_devices(
            tasmota_hosts, config.homeassistant.mqtt, config.tasmota,
            config.site, hosts,
            dry_run=dry_run, verbose=True, force=force,
        )
```

Single-host branch (after the existing `target.tasmota_data is None` check; import `resolve_syslog_target` alongside the existing `configure_*` imports at the top of the function):

```python
        syslog = None
        if target.tasmota_data.ip:
            syslog = resolve_syslog_target(
                target, hosts, config.site, config.tasmota)
```

and pass `syslog=syslog` to the existing `configure_tasmota_device(...)` call.

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest`
Expected: all pass (includes CLI-level tests exercising `main()`).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/ tests/
git add src/gdoc2netcfg/supplements/tasmota_configure.py src/gdoc2netcfg/cli/main.py tests/test_supplements/test_tasmota.py
git commit -m "tasmota: push syslog settings via configure, wire CLI"
```

---

### Task 8: example toml + CLAUDE.md docs

**Files:**
- Modify: `gdoc2netcfg.toml.example` (`[tasmota]` section, ~line 109)
- Modify: `CLAUDE.md` (Production Deployment section; SQLite Storage section)

**Interfaces:**
- Consumes: everything above (documents the finished feature).

- [ ] **Step 1: Extend `gdoc2netcfg.toml.example`**

```toml
[tasmota]
mqtt_secret = ""
# Remote syslog: hostname (in the sheet) of the syslog sink. The configure
# step resolves it to the sink's IP on each device's VLAN and pushes
# LogHost/LogPort/SysLog to every device. Empty disables syslog config.
# The sink host runs the rsyslog drop-in deployed by `make deploy-syslog`.
syslog_host = ""
syslog_port = 514
# Site default SysLog level (0=off, 1=error, 2=info, 3=debug, 4=more debug);
# override per device via the sheet's "Syslog Level" column.
syslog_level = 2
```

- [ ] **Step 2: Update CLAUDE.md**

(a) In the *SQLite Storage* section, no version numbers are recorded — no change needed there. Verify with `grep -n "schema" CLAUDE.md` and leave version-free text alone.

(b) Add a subsection to *Production Deployment*, after the *nginx* subsection:

```markdown
### Tasmota remote syslog

Tasmota devices send their logs (UDP syslog) to the site router. The
rsyslog drop-in (`etc/rsyslog-tasmota.conf` → `/etc/rsyslog.d/tasmota.conf`)
receives on UDP 514 into per-device files `/var/log/tasmota/<hostname>.log`
(rotated daily, 14 kept — `etc/logrotate-tasmota`). Deploy both with
`sudo make deploy-syslog` (path-scoped etckeeper commit included).

Device-side settings are pushed by `tasmota configure`: `[tasmota]
syslog_host` names the sink by sheet hostname and is resolved to the
sink's IP on each device's VLAN from inventory data (never DNS);
`syslog_level` (default 2) can be overridden per device via the sheet's
"Syslog Level" column (0 silences one device). Empty `syslog_host`
disables the feature (monarto until it opts in).
```

- [ ] **Step 3: Verify docs are consistent**

Run: `uv run pytest -q && uv run ruff check src/ tests/`
Expected: all pass (docs-only change; confirms nothing else regressed).

- [ ] **Step 4: Commit**

```bash
git add gdoc2netcfg.toml.example CLAUDE.md
git commit -m "docs: tasmota remote syslog configuration and deployment"
```

---

## Post-merge rollout (manual, welland — NOT part of this plan's execution)

1. Merge branch → main (PR + CI), `sudo -E git pull` in `/opt/gdoc2netcfg`.
2. `sudo make deploy-syslog`.
3. Add `syslog_host = "ten64"` (+ port/level if non-default) to welland's `/opt/gdoc2netcfg/gdoc2netcfg.toml` `[tasmota]`.
4. `sudo systemctl stop gdoc2netcfg-reachability.service`, then `sudo .venv/bin/gdoc2netcfg tasmota scan --force` (applies the v9 migration), then restart the daemon.
5. `sudo .venv/bin/gdoc2netcfg tasmota configure --dry-run --all` — review the SysLog/LogHost drift list.
6. `sudo .venv/bin/gdoc2netcfg tasmota configure --all`; confirm files appear: `ls -la /var/log/tasmota/`.
7. Update the `project_sqlite_migration` memory (schema v9) after deployment.
