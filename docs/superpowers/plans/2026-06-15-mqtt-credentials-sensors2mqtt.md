# sensors2mqtt Credentials — Implementation Plan (Plan 2 of 3 for #28)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add `gdoc2netcfg sensors2mqtt` (`list` / `register` / `status`) — issue per-host MQTT broker logins for the `local` sensors2mqtt collectors (derive → register pre-hashed via the Plan 1 core) and verify their HA sensors are fresh. gdoc2netcfg generates **no** client-side config (Ansible recomputes + installs the env, §12 of the spec).

**Architecture:** A thin adapter on the merged Plan 1 core. `derivations/sensors2mqtt.py` (pure): classify hosts by the `sensors2mqtt` sheet column (`local`/`remote`/blank) and `build_logins(secret, hosts)` = `{username("s2m-", h): password(secret, h)}` for `local` hosts. `supplements/mqtt_broker.py::register_logins(..., "s2m-", …)` does the broker side (already built). `status` queries HA `/api/states` (mirroring `tasmota_ha._fetch_all_states`) and classifies fresh/stale/missing. New `Sensors2mqttConfig` (`mqtt_secret`, `freshness_seconds`).

**Tech Stack:** Python 3.11+, pytest, `urllib` (HA REST), `uv run`. Builds on `gdoc2netcfg.derivations.mqtt_credentials` + `gdoc2netcfg.supplements.mqtt_broker` (merged in Plan 1).

**Spec:** `docs/superpowers/specs/2026-06-14-mqtt-credentials-design.md` §4.1, §4.3, §4.6, §4.8, §6, §11.2, §12.

## Prerequisites & deferrals (read before executing)
- **Sheet column not yet present.** The `sensors2mqtt` column (`local`/`remote`/blank per host) is a one-off **operator step** (the user owns the sheet + knows which hosts run the collector). Code + unit tests here use synthetic `host.extra`; the **live** `register`/`status` runs only after the column is populated. Task 7 produces a paste-ready proposal for that population.
- **§11.2 spike (Task 1)** confirms how sensors2mqtt names its HA discovery entities (drives `status` matching) AND folds in the **live PBKDF2 format-validation deferred from Plan 1** (register one throwaway `s2m-` login against the real broker, confirm a paho client authenticates, prune it). This is the one live-broker touchpoint — run by the controller, not a subagent.
- **Cutover** (after this plan merges + the column is populated): `register` (broker restart) → Ansible installs/recomputes env on collectors → restart collectors (ten64 + canary first) → `status` to confirm. Per spec §8.

---

## File Structure

| File | Responsibility | Status |
|---|---|---|
| `src/gdoc2netcfg/config.py` | add `Sensors2mqttConfig` + `_build_sensors2mqtt` + `PipelineConfig.sensors2mqtt` + `load_config` wiring | modify |
| `src/gdoc2netcfg/derivations/sensors2mqtt.py` | `classify(host)`, `select_local`/`select_non_blank`, `build_logins(secret, hosts)` | **create** |
| `src/gdoc2netcfg/supplements/sensors2mqtt_status.py` | `query_status(ha_config, hosts, freshness_seconds, now)` → fresh/stale/missing | **create** |
| `src/gdoc2netcfg/cli/main.py` | `cmd_sensors2mqtt_list/register/status` + argparse subcommand | modify |
| `tests/test_sources/test_config.py` | `[sensors2mqtt]` parsing | modify |
| `tests/test_derivations/test_sensors2mqtt.py` | classify/select/build_logins | **create** |
| `tests/test_supplements/test_sensors2mqtt_status.py` | status classification (mocked HA) | **create** |
| `tests/test_cli/test_sensors2mqtt_cli.py` | list/register/status command wiring (mocked) | **create** |
| `gdoc2netcfg.toml.example` | `[sensors2mqtt]` section | modify |

Establish a `feature/mqtt-credentials-sensors2mqtt` branch off `main` first.

---

## Task 1: SPIKE — HA entity naming + live format-validation (controller-run)

**Why first:** `status` (Task 6) needs the real host↔entity match pattern, and Plan 1's PBKDF2 format still needs ONE live confirmation. Both require the live HA/broker — the controller does this, not a subagent.

- [ ] **Step 1: Discover sensors2mqtt's HA entity naming.** Query the live HA and inspect how the collector's sensors are named, to find the host→entity match rule:
```bash
ssh -o ControlPath=none ha.welland.mithis.com \
  'curl -sS -H "Authorization: Bearer $(cat /run/s6/container_environment/SUPERVISOR_TOKEN)" http://supervisor/core/api/states' \
  | uv run python -c "import sys,json; [print(e['entity_id']) for e in json.load(sys.stdin) if 'sensors2mqtt' in e['entity_id'].lower() or 'sensor2mqtt' in e['entity_id'].lower()]" | head -40
```
(Or use `config.homeassistant.url` + token directly with `tasmota_ha._fetch_all_states`.) If the naming isn't obvious, check a known collector host (e.g. `rpi5`) — list entities whose id contains its `node_id`. Record the exact rule (e.g. "entity_id contains `<id>`" or "device identifier == `s2m-<id>`").

- [ ] **Step 2: Live PBKDF2 format-validation** (the deferred Plan 1 check). Using the real merged core:
```python
from gdoc2netcfg.supplements.mqtt_broker import register_logins
register_logins("ha.welland.mithis.com", "s2m-", {"s2m-canary": "spike-pw-123"},
                verify=("ha.welland.mithis.com", 1883))   # restarts broker; verify connects
register_logins("ha.welland.mithis.com", "s2m-", {}, prune=True)  # remove the canary; restart
```
Expect `register_logins` to return without raising (the `verify` connect proves the `PBKDF2$sha512$…` hash is accepted). This causes 2 broker restarts — acceptable for the one-time confirmation. Confirm `s2m-canary` is gone afterward (`_supervisor_get_logins`).

- [ ] **Step 3: Record outcomes** in this plan (amend Task 6 with the confirmed entity-match rule). No code commit. If the verify fails, STOP — the format is wrong and must be fixed in `mqtt_broker._prehash` before continuing.

---

## Task 2: `Sensors2mqttConfig`

**Files:** Modify `src/gdoc2netcfg/config.py`; modify `tests/test_sources/test_config.py`.

- [ ] **Step 1: Failing test** — append to `tests/test_sources/test_config.py` inside `TestHomeAssistantConfig` or a new class:
```python
class TestSensors2mqttConfig:
    def _write(self, tmp_path, body):
        p = tmp_path / "gdoc2netcfg.toml"; p.write_text(body); return p

    def test_parsed(self, tmp_path):
        from gdoc2netcfg.config import load_config
        c = load_config(self._write(tmp_path,
            '[site]\nname="t"\ndomain="t.example"\n\n'
            '[sensors2mqtt]\nmqtt_secret="s"\nfreshness_seconds=600\n'))
        assert c.sensors2mqtt.mqtt_secret == "s"
        assert c.sensors2mqtt.freshness_seconds == 600

    def test_defaults(self, tmp_path):
        from gdoc2netcfg.config import load_config
        c = load_config(self._write(tmp_path, '[site]\nname="t"\ndomain="t.example"\n'))
        assert c.sensors2mqtt.mqtt_secret == ""
        assert c.sensors2mqtt.freshness_seconds == 900
```

- [ ] **Step 2: Run — FAIL** (`AttributeError: ... 'sensors2mqtt'`). `uv run pytest tests/test_sources/test_config.py -q`

- [ ] **Step 3: Implement.** In `config.py`, after `TasmotaConfig` (line ~68) add:
```python
@dataclass
class Sensors2mqttConfig:
    """sensors2mqtt credential issuance settings ([sensors2mqtt]).

    `mqtt_secret` derives each `local` collector's broker password; it is also
    mirrored into the Ansible vault so Ansible recomputes the identical value.
    `freshness_seconds` is the `status` stale threshold.
    """

    mqtt_secret: str = ""
    freshness_seconds: int = 900
```
Add to `PipelineConfig` (next to `tasmota`): `sensors2mqtt: Sensors2mqttConfig = field(default_factory=Sensors2mqttConfig)`. Add the builder (next to `_build_tasmota`):
```python
def _build_sensors2mqtt(data: dict) -> Sensors2mqttConfig:
    """Build sensors2mqtt config from parsed TOML data."""
    section = data.get("sensors2mqtt", {})
    if not section:
        return Sensors2mqttConfig()
    return Sensors2mqttConfig(
        mqtt_secret=section.get("mqtt_secret", ""),
        freshness_seconds=section.get("freshness_seconds", 900),
    )
```
Wire into `load_config(...)` return: `sensors2mqtt=_build_sensors2mqtt(data),`.

- [ ] **Step 4: Run — PASS.** **Step 5: ruff + commit** (`config: add [sensors2mqtt] section (#28)`).

---

## Task 3: `derivations/sensors2mqtt.py` (selection + build_logins)

**Files:** Create `src/gdoc2netcfg/derivations/sensors2mqtt.py` + `tests/test_derivations/test_sensors2mqtt.py`.

- [ ] **Step 1: Failing tests:**
```python
"""Tests for sensors2mqtt host selection + login building."""
import pytest

from gdoc2netcfg.derivations.sensors2mqtt import (
    build_logins, classify, select_local, select_non_blank,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _host(hostname, s2m=None):
    extra = {} if s2m is None else {"sensors2mqtt": s2m}
    return Host(machine_name=hostname.split(".")[0], hostname=hostname,
                sheet_type="Network", interfaces=[NetworkInterface(
                    name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.5.10"),), dhcp_name=hostname)],
                extra=extra)


class TestClassify:
    def test_values(self):
        assert classify(_host("a", "local")) == "local"
        assert classify(_host("a", "remote")) == "remote"
        assert classify(_host("a", "")) == "blank"
        assert classify(_host("a", None)) == "blank"

    def test_case_and_whitespace(self):
        assert classify(_host("a", " Local ")) == "local"

    def test_unrecognized_raises(self):
        with pytest.raises(ValueError, match="sensors2mqtt"):
            classify(_host("a", "maybe"))


class TestSelect:
    def test_select_local(self):
        hosts = [_host("a", "local"), _host("b", "remote"), _host("c")]
        assert [h.hostname for h in select_local(hosts)] == ["a"]

    def test_select_non_blank(self):
        hosts = [_host("a", "local"), _host("b", "remote"), _host("c")]
        assert sorted(h.hostname for h in select_non_blank(hosts)) == ["a", "b"]


class TestBuildLogins:
    def test_local_only_with_prefix_and_password(self):
        hosts = [_host("rpi5.iot", "local"), _host("srv", "remote")]
        logins = build_logins("0123456789abcdef0123456789abcdef", hosts)
        assert set(logins) == {"s2m-rpi5_iot"}
        assert logins["s2m-rpi5_iot"] == \
            __import__("hashlib").sha256(("0123456789abcdef0123456789abcdef" + "rpi5_iot").encode()).hexdigest()

    def test_weak_secret_raises(self):
        with pytest.raises(ValueError, match="secret"):
            build_logins("short", [_host("a", "local")])

    def test_collision_raises(self):
        with pytest.raises(ValueError, match="collide"):
            build_logins("0123456789abcdef0123456789abcdef",
                         [_host("a.b", "local"), _host("a-b", "local")])
```

- [ ] **Step 2: Run — FAIL** (module missing).

- [ ] **Step 3: Implement `src/gdoc2netcfg/derivations/sensors2mqtt.py`:**
```python
"""sensors2mqtt host selection (sheet column) + broker login building.

Pure. Reads the `sensors2mqtt` column from `host.extra` (local/remote/blank)
and builds the `{s2m-<id>: password}` map for `register`, reusing the shared
credential core.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.mqtt_credentials import (
    check_collisions, password, require_strong_secret, username,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

PREFIX = "s2m-"
_COLUMN = "sensors2mqtt"
_VALID = {"local", "remote", ""}


def classify(host: Host) -> str:
    """Return 'local' / 'remote' / 'blank' for a host's sensors2mqtt column.

    Fails loud on an unrecognized non-blank value (never silently skipped)."""
    value = host.extra.get(_COLUMN, "").strip().lower()
    if value not in _VALID:
        raise ValueError(
            f"host {host.hostname}: unrecognized sensors2mqtt value "
            f"{value!r} (expected 'local', 'remote', or blank)"
        )
    return "blank" if value == "" else value


def select_local(hosts: list[Host]) -> list[Host]:
    """Hosts running sensors2mqtt locally (get a broker login)."""
    return [h for h in hosts if classify(h) == "local"]


def select_non_blank(hosts: list[Host]) -> list[Host]:
    """Hosts involved with sensors2mqtt at all (checked by `status`)."""
    return [h for h in hosts if classify(h) != "blank"]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{s2m-<id>: sha256(secret+<id>)}` for the `local` hosts. Fails loud on a
    weak secret or a node_id collision among the selected hosts."""
    require_strong_secret(secret)
    local = select_local(hosts)
    check_collisions(local)
    return {username(PREFIX, h): password(secret, h) for h in local}
```

- [ ] **Step 4: Run — PASS. Step 5: ruff + commit** (`sensors2mqtt: host selection + login building (#28)`).

---

## Task 4: `cmd_sensors2mqtt list` + argparse subcommand

**Files:** Modify `src/gdoc2netcfg/cli/main.py`; create `tests/test_cli/test_sensors2mqtt_cli.py`.

- [ ] **Step 1: Failing test** (`tests/test_cli/test_sensors2mqtt_cli.py`):
```python
"""Tests for the sensors2mqtt CLI."""
from unittest.mock import patch
import argparse

from gdoc2netcfg.cli.main import cmd_sensors2mqtt_list


def _cfg_and_hosts():
    # build a PipelineConfig + 3 hosts (local/remote/blank) — see test_tasmota.py
    # for the Host/Config construction helpers to copy.
    ...


def test_list_classifies(capsys):
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._sensors2mqtt_hosts", return_value=hosts):
        rc = cmd_sensors2mqtt_list(args)
    out = capsys.readouterr().out
    assert rc == 0 and "local" in out and "remote" in out
    assert "secret" not in out.lower() and "password" not in out.lower()
```
(The implementer should flesh out `_cfg_and_hosts` using the `Host`/`PipelineConfig` construction already used in `tests/test_supplements/test_tasmota.py` and `tests/test_cli/test_zigbee_db.py`.)

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** in `cli/main.py`:
  - A helper `_sensors2mqtt_hosts(config)` that returns the host list via the minimal pipeline (copy the `cmd_tasmota_scan` pattern, lines ~1811-1821: `_fetch_or_load_csvs` → `parse_csv` per sheet (skip `vlan_allocations`) → `build_hosts`).
  - `cmd_sensors2mqtt_list(args)`: load config, get hosts, print a table of `hostname` + `classify(h)` (use `derivations.sensors2mqtt.classify`; catch its `ValueError` and fail loud with rc=1). No secrets.
  - argparse: after the `tasmota` block (~line 2701), add:
    ```python
    s2m_parser = subparsers.add_parser("sensors2mqtt", help="sensors2mqtt MQTT credentials")
    s2m_subparsers = s2m_parser.add_subparsers(dest="s2m_command")
    s2m_subparsers.add_parser("list", help="Show sensors2mqtt host classification")
    ```
  - dispatch (after the `tasmota` dispatch, ~line 2839):
    ```python
    if args.command == "sensors2mqtt":
        if args.s2m_command == "list":
            return cmd_sensors2mqtt_list(args)
        ...
        else:
            s2m_parser.print_help(); return 0
    ```

- [ ] **Step 4: Run — PASS. Step 5: ruff + commit** (`sensors2mqtt: list subcommand (#28)`).

---

## Task 5: `cmd_sensors2mqtt register`

**Files:** Modify `src/gdoc2netcfg/cli/main.py`; modify `tests/test_cli/test_sensors2mqtt_cli.py`.

- [ ] **Step 1: Failing test** — `register` builds logins from `local` hosts and calls `register_logins` with prefix `s2m-`; `--dry-run`/`--prune` pass through; gates on empty secret / empty `ssh_host`:
```python
def test_register_calls_core(capsys):
    config, hosts = _cfg_and_hosts()          # config.sensors2mqtt.mqtt_secret set strong; config.homeassistant.ssh_host set
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._sensors2mqtt_hosts", return_value=hosts), \
         patch("gdoc2netcfg.supplements.mqtt_broker.register_logins") as reg:
        rc = cmd_sensors2mqtt_register(args)
    assert rc == 0
    ssh_host, prefix, logins = reg.call_args.args[:3]
    assert prefix == "s2m-" and set(logins) == {"s2m-<id of the local host>"}

def test_register_empty_secret_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.sensors2mqtt.mqtt_secret = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._sensors2mqtt_hosts", return_value=hosts):
        rc = cmd_sensors2mqtt_register(args)
    assert rc == 1 and "secret" in capsys.readouterr().err.lower()
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** `cmd_sensors2mqtt_register(args)`:
  - Gate: if `not config.homeassistant.ssh_host` → error rc=1 ("[homeassistant] ssh_host not configured").
  - `from gdoc2netcfg.derivations.sensors2mqtt import build_logins, PREFIX` and `from gdoc2netcfg.supplements.mqtt_broker import register_logins`.
  - `logins = build_logins(config.sensors2mqtt.mqtt_secret, hosts)` — `build_logins` already fails loud on weak secret/collision; catch `ValueError` → print to stderr, rc=1.
  - `register_logins(config.homeassistant.ssh_host, PREFIX, logins, dry_run=args.dry_run, prune=args.prune, verify=(config.homeassistant.mqtt.host, config.homeassistant.mqtt.port) if not args.dry_run else None)`.
  - argparse: `reg = s2m_subparsers.add_parser("register", ...)`; `reg.add_argument("--dry-run", action="store_true")`; `reg.add_argument("--prune", action="store_true")`. Dispatch `cmd_sensors2mqtt_register`.

- [ ] **Step 4: Run — PASS. Step 5: ruff + commit** (`sensors2mqtt: register subcommand (#28)`).

---

## Task 6: `cmd_sensors2mqtt status` + `sensors2mqtt_status.py`

Uses the entity-match rule confirmed in Task 1. **Files:** create `src/gdoc2netcfg/supplements/sensors2mqtt_status.py`; modify `cli/main.py`; create `tests/test_supplements/test_sensors2mqtt_status.py`.

- [ ] **Step 1: Failing test** (mocked HA states) — classify each non-blank host fresh/stale/missing:
```python
"""Tests for sensors2mqtt status classification."""
from unittest.mock import patch
from datetime import datetime, timezone
from gdoc2netcfg.supplements.sensors2mqtt_status import query_status
# build hosts (local/remote/blank) + a fake /api/states list; patch _fetch_all_states
# fresh: matching entity last_updated within window; stale: older; missing: none.
```
(Implementer: model the test on `tests/test_supplements/test_tasmota.py`'s `check_ha_status` tests, which mock `_fetch_all_states`.)

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement `sensors2mqtt_status.py`:** `query_status(ha_config, hosts, freshness_seconds, now)`:
  - reuse `gdoc2netcfg.supplements.tasmota_ha._fetch_all_states(ha_config)` to GET `/api/states`.
  - for each `select_non_blank(hosts)`, find matching entities using the **Task 1-confirmed rule** (e.g. `node_id(host.hostname)` appears in `entity_id`); parse the newest `last_updated`; classify `fresh` (within `freshness_seconds` of `now`), `stale` (older), or `missing` (no entity). Return a dict keyed by hostname. No secrets.
  - `now` is a parameter (inject `datetime.now(timezone.utc)` from the caller) so tests are deterministic.

- [ ] **Step 4: Implement `cmd_sensors2mqtt_status(args)`** in `cli/main.py`: gate on `config.homeassistant.url`+`token` (copy `cmd_tasmota_ha_status`, line ~2015); call `query_status`; print a review table (hostname, class, last-updated). argparse `status` sub-action + dispatch.

- [ ] **Step 5: Run — PASS. Step 6: ruff + commit** (`sensors2mqtt: status subcommand (#28)`).

---

## Task 7: Example config + operator population proposal

**Files:** Modify `gdoc2netcfg.toml.example`.

- [ ] **Step 1:** Add to `gdoc2netcfg.toml.example` (after `[tasmota]`):
```toml
# ── Optional: sensors2mqtt per-host MQTT credentials ─────────
# mqtt_secret: high-entropy (openssl rand -hex 32); 0600 toml + Ansible vault.
[sensors2mqtt]
mqtt_secret = ""
freshness_seconds = 900
```
- [ ] **Step 2:** Confirm `uv run pytest tests/test_sources/test_config.py::TestLoadConfig::test_load_project_config -q` still passes (example loads).
- [ ] **Step 3:** Commit (`config example: [sensors2mqtt] section (#28)`).
- [ ] **Step 4 (controller, non-code):** Produce a paste-ready `local`/`remote`/blank value per current host for the operator to fill the new `sensors2mqtt` sheet column. (The collector fleet is the ~30 welland RPis + ten64 = `local`; polled servers/switches = `remote`; everything else blank; SDR Pis blank.) This is delivered to the user, not committed.

---

## Task 8: Full suite + lint gate, final review

- [ ] **Step 1:** `uv run pytest -q` (expect baseline + new; 0 failures). **Step 2:** `uv run ruff check src/ tests/` clean.
- [ ] **Step 3:** Dispatch a final whole-implementation reviewer over the branch diff.
- [ ] **Step 4:** `superpowers:finishing-a-development-branch`.

---

## Self-Review

**Spec coverage:** §4.1 sensors2mqtt adapter (derivations/sensors2mqtt.py + cmd) → Tasks 3,4,5,6 ✓. §4.3 column local/remote/blank + unrecognized→error → Task 3 `classify` ✓. §4.6 status presence+freshness via /api/states → Task 6 ✓. §4.8 `[sensors2mqtt]` config → Tasks 2,7 ✓. §6 fail-loud (weak secret, unrecognized column, ssh failure) → Tasks 3,5 + core ✓. §11.2 entity-naming spike → Task 1 ✓. §12 Ansible interop → already documented in the spec; the `s2m-<id>`/`sha256(secret+<id>)` contract is exactly `derivations.sensors2mqtt.build_logins`, so Ansible's `(secret ~ inventory_hostname)|hash('sha256')` with `inventory_hostname == node_id(host.hostname)` matches ✓. Deferred (correctly): live cutover + the sheet-column population (operator) + Plan 1's format-validation folded into Task 1.

**Placeholder scan:** Task 4/6 tests leave `_cfg_and_hosts`/state fixtures for the implementer to flesh out from the cited existing tests — these are pointers to real, existing patterns (not vague TODOs); the assertions and behavior are fully specified. Task 1 entity-match rule is a genuine spike output that Task 6 consumes.

**Type consistency:** `classify`/`select_local`/`select_non_blank`/`build_logins` (Task 3) consumed by `cmd_sensors2mqtt_*` (Tasks 4-6). `build_logins` returns `{username: plaintext}` exactly matching `register_logins(ssh_host, prefix, logins, …)` (Plan 1). `Sensors2mqttConfig.mqtt_secret`/`freshness_seconds` (Task 2) used by register/status. `PREFIX = "s2m-"` single source.
