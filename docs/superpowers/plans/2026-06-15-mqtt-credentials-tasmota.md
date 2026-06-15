# Tasmota Credentials — Implementation Plan (Plan 3 of 3 for #28)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give every Tasmota device its own MQTT login. Derive `tas-<id>` / `sha256(secret+<id>)` from `[tasmota] mqtt_secret`, register the **pre-hashed** logins on the HA Mosquitto broker via a new `gdoc2netcfg tasmota register-broker`, and push the per-device `MqttUser`/`MqttPassword` over the existing `tasmota configure` HTTP path — retiring the #30 interim shared login.

**Architecture:** A thin adapter on the merged Plan 1 core, parallel to Plan 2's sensors2mqtt adapter. `derivations/tasmota_credentials.py` (pure): `select_tasmota(hosts)` (devices with last-known scan data) + `build_logins(secret, hosts)` = `{username("tas-", h): password(secret, h)}`. `supplements/tasmota_configure.py::compute_desired_config` derives `MqttUser`/`MqttPassword` instead of reading the static `[tasmota]` login. New `tasmota register-broker [--dry-run] [--prune]` calls the already-built `supplements/mqtt_broker.py::register_logins(..., "tas-", …)`. `TasmotaConfig` switches from `mqtt_user`/`mqtt_password` to `mqtt_secret`.

**Tech Stack:** Python 3.11+, pytest, `uv run`. Builds on `gdoc2netcfg.derivations.mqtt_credentials` + `gdoc2netcfg.supplements.mqtt_broker` (merged in Plan 1). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-06-14-mqtt-credentials-design.md` §4.2, §4.4, §4.7, §4.8, §6, §7.

## Prerequisites & deferrals (read before executing)
- **Stacked on Plan 2.** This branch (`feature/mqtt-credentials-tasmota`) was created off the unmerged `feature/mqtt-credentials-sensors2mqtt`, so it already contains Plan 2's commits and the merged Plan 1 core. Both halves of #28 finish together from this branch.
- **No new selection column.** Tasmota-ness is derived from `host.tasmota_data is not None` (last-known scan data; an offline device still appears and still gets a login). This mirrors the existing `configure` selection — §4.4.
- **`MqttUser` migration is automatic.** `MqttUser` is readable from the device, so the change from the old shared user (`tasmota`) to `tas-<id>` shows up as drift and is pushed by the normal `configure` flow. `MqttPassword` is write-only (can't be read back) — the existing `MqttCount==0` re-push path covers a device that can't authenticate.
- **Cutover deferred (outward-facing).** The live `register-broker` (restarts the HA Mosquitto broker) and the `configure` push (restarts each device) are bundled with the sensors2mqtt cutover, run on prod with the user's OK. The deferred Plan 2 live PBKDF2-format validation covers the `tas-` prefix too (identical hash format).
- **One broker restart per consumer.** `register-broker` and `sensors2mqtt register` each restart the add-on once; run them back-to-back at cutover.

---

## File Structure

| File | Responsibility | Status |
|---|---|---|
| `src/gdoc2netcfg/config.py` | `TasmotaConfig`: replace `mqtt_user`/`mqtt_password` with `mqtt_secret`; update `_build_tasmota` | modify |
| `src/gdoc2netcfg/derivations/tasmota_credentials.py` | `PREFIX`, `select_tasmota(hosts)`, `build_logins(secret, hosts)` | **create** |
| `src/gdoc2netcfg/supplements/tasmota_configure.py` | `compute_desired_config` derives `MqttUser`/`MqttPassword` from the core | modify |
| `src/gdoc2netcfg/cli/main.py` | `cmd_tasmota_register_broker` + `register-broker` subcommand + dispatch | modify |
| `tests/test_derivations/test_tasmota_credentials.py` | select/build_logins | **create** |
| `tests/test_supplements/test_tasmota.py` | update `_make_config` + `compute_desired_config`/drift expectations to derived values | modify |
| `tests/test_cli/test_tasmota_register_broker.py` | register-broker command wiring (mocked) | **create** |
| `gdoc2netcfg.toml.example` | `[tasmota]` → `mqtt_secret` | modify |

---

## Task 1: `TasmotaConfig` → `mqtt_secret`

**Files:** Modify `src/gdoc2netcfg/config.py`.

- [ ] **Step 1: Update `TasmotaConfig`** (currently `mqtt_user`/`mqtt_password`, ~line 59-68) to:
```python
@dataclass
class TasmotaConfig:
    """Tasmota per-device MQTT credential derivation ([tasmota]).

    `mqtt_secret` derives each device's MqttUser (`tas-<id>`) and MqttPassword
    (`sha256(secret+<id>)`); the broker stores the pre-hashed form. Replaces the
    #30 interim shared `mqtt_user`/`mqtt_password` static login.
    """

    mqtt_secret: str = ""
```

- [ ] **Step 2: Update `_build_tasmota`** (~line 245-253) to:
```python
def _build_tasmota(data: dict) -> TasmotaConfig:
    """Build Tasmota config from parsed TOML data."""
    section = data.get("tasmota", {})
    if not section:
        return TasmotaConfig()
    return TasmotaConfig(mqtt_secret=section.get("mqtt_secret", ""))
```

- [ ] **Step 3: Verify no other reader breaks.** `grep -rn "\.mqtt_user\|\.mqtt_password" src/gdoc2netcfg/` — confirm the only `config.tasmota` consumers are `tasmota_configure.py` (fixed in Task 3). The `mqtt_user` on `TasmotaData` (`models/host.py`, `supplements/tasmota.py`, `storage/discovery_db.py`) is the device's *reported* user — leave it. Run `uv run pytest tests/test_sources/test_config.py -q` (expect PASS — no tasmota config test exists; this is a structural change).

- [ ] **Step 4: ruff + commit** (`config: [tasmota] uses mqtt_secret for per-device creds (#28)`). NOTE: the full suite will be red until Task 3 (existing `test_tasmota.py` constructs `TasmotaConfig(mqtt_user=…)`). That is expected and fixed in Task 3 — do NOT run the full suite as a gate here; only the config test.

---

## Task 2: `derivations/tasmota_credentials.py`

**Files:** Create `src/gdoc2netcfg/derivations/tasmota_credentials.py` + `tests/test_derivations/test_tasmota_credentials.py`.

- [ ] **Step 1: Failing tests** (`tests/test_derivations/test_tasmota_credentials.py`):
```python
"""Tests for Tasmota credential derivation."""
import hashlib

import pytest

from gdoc2netcfg.derivations.tasmota_credentials import (
    PREFIX, build_logins, select_tasmota,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, TasmotaData


def _host(hostname, tasmota=False):
    return Host(
        machine_name=hostname.split(".")[0], hostname=hostname,
        sheet_type="IoT", interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.40.10"),), dhcp_name=hostname)],
        tasmota_data=(TasmotaData(ip="10.1.40.10") if tasmota else None),
    )


def test_prefix():
    assert PREFIX == "tas-"


def test_select_tasmota_only_scanned():
    hosts = [_host("au-plug-1.iot", tasmota=True), _host("desktop", tasmota=False)]
    assert [h.hostname for h in select_tasmota(hosts)] == ["au-plug-1.iot"]


def test_build_logins_derives_for_tasmota_only():
    secret = "0123456789abcdef0123456789abcdef"
    hosts = [_host("au-plug-1.iot", tasmota=True), _host("desktop", tasmota=False)]
    logins = build_logins(secret, hosts)
    assert set(logins) == {"tas-au_plug_1_iot"}
    expected = hashlib.sha256((secret + "au_plug_1_iot").encode()).hexdigest()
    assert logins["tas-au_plug_1_iot"] == expected


def test_build_logins_weak_secret_raises():
    with pytest.raises(ValueError, match="secret"):
        build_logins("short", [_host("au-plug-1.iot", tasmota=True)])


def test_build_logins_collision_raises():
    with pytest.raises(ValueError, match="collide"):
        build_logins("0123456789abcdef0123456789abcdef",
                     [_host("a.b", tasmota=True), _host("a-b", tasmota=True)])
```
**NOTE:** the `_host` helper above is a sketch. Read `src/gdoc2netcfg/models/host.py` for the real `Host`/`NetworkInterface`/`TasmotaData` constructors (e.g. the exact `TasmotaData` required fields — `ip` may not be the only one; pass whatever minimal valid set the dataclass needs) and the `ip_addresses`/`tasmota_data` field names, and adapt `_host` so it builds VALID objects. Keep every assertion, the hostnames, and the `tasmota=True/False` distinction. Crib the `Host`/`NetworkInterface` construction from `tests/test_derivations/test_sensors2mqtt.py` (Plan 2) and the `TasmotaData` construction from `tests/test_supplements/test_tasmota.py`.

- [ ] **Step 2: Run — FAIL** (module missing). `uv run pytest tests/test_derivations/test_tasmota_credentials.py -q`

- [ ] **Step 3: Implement `src/gdoc2netcfg/derivations/tasmota_credentials.py`:**
```python
"""Tasmota per-device MQTT credential derivation.

Pure. Selects the Tasmota devices (those with last-known scan data) and builds
the `{tas-<id>: password}` map for `register-broker`, reusing the shared
credential core. The same `username`/`password` are pushed to each device by
`tasmota_configure.compute_desired_config`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.mqtt_credentials import (
    check_collisions, password, require_strong_secret, username,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

PREFIX = "tas-"


def select_tasmota(hosts: list[Host]) -> list[Host]:
    """Tasmota devices = hosts with last-known scan data (`host.tasmota_data`)."""
    return [h for h in hosts if h.tasmota_data is not None]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{tas-<id>: sha256(secret+<id>)}` for every Tasmota device. Fails loud on a
    weak secret or a node_id collision among the selected devices."""
    require_strong_secret(secret)
    devices = select_tasmota(hosts)
    check_collisions(devices)
    return {username(PREFIX, h): password(secret, h) for h in devices}
```

- [ ] **Step 4: Run — PASS. Step 5: ruff + commit** (`tasmota: per-device credential derivation (#28)`).

---

## Task 3: `compute_desired_config` derives `MqttUser`/`MqttPassword`

**Files:** Modify `src/gdoc2netcfg/supplements/tasmota_configure.py`; modify `tests/test_supplements/test_tasmota.py`.

This is BEHAVIOR-CHANGE TDD: update the expectations to the derived values first (red), then change the impl (green).

- [ ] **Step 1: Update the test fixtures + expectations in `tests/test_supplements/test_tasmota.py`.**
  - The `_make_config` helper (~line 60-89) currently builds `TasmotaConfig(mqtt_user="tasmota", mqtt_password="secret123")`. Change it to `TasmotaConfig(mqtt_secret=_TASMOTA_SECRET)` where `_TASMOTA_SECRET = "0123456789abcdef0123456789abcdef"` (module constant, ≥32 chars). Remove the `mqtt_user`/`mqtt_password` defaults from that helper.
  - `compute_desired_config` assertions (~line 825-851): replace `assert desired["MqttUser"] == "tasmota"` / `assert desired["MqttPassword"] == "secret123"` with the derived values for the test host. Compute them with the SAME core the impl uses:
    ```python
    from gdoc2netcfg.derivations.mqtt_credentials import password, username
    from gdoc2netcfg.derivations.tasmota_credentials import PREFIX
    assert desired["MqttUser"] == username(PREFIX, host)
    assert desired["MqttPassword"] == password(_TASMOTA_SECRET, host)
    ```
    (Asserting via the core proves wiring, not the hash math — the hash math is already golden-vector-tested in Task 2 and Plan 1.)
  - Any other hardcoded `"MqttUser": "tasmota"` expectation (e.g. ~line 147 in a desired-dict fixture): change to `username(PREFIX, host)` for that test's host.
  - **Drift/apply tests (~line 940-1165): fix the "no-drift" device fixtures.** Several tests set the device's reported `mqtt_user` to represent a baseline. Where a test intends "MqttUser is NOT drifted / NOT pushed" (e.g. the test around line 1122 that asserts `"MqttUser" not in sent_fields`), the device's `mqtt_user` must equal the NEW desired `username(PREFIX, host)` — set it to that instead of `"tasmota"`. Where a test intends "MqttUser IS drifted" (e.g. `mqtt_user="wrong"` → `"MqttUser" in fields`), leave it (anything != the derived value still drifts). Read each affected test's intent and update the device-state `mqtt_user` accordingly so the assertion still reflects the test's purpose.

- [ ] **Step 2: Run the tasmota tests — FAIL** (impl still returns the static login). `uv run pytest tests/test_supplements/test_tasmota.py -q`

- [ ] **Step 3: Change `compute_desired_config`** in `tasmota_configure.py`. Add imports at the top of the file:
```python
from gdoc2netcfg.derivations.mqtt_credentials import password, username
from gdoc2netcfg.derivations.tasmota_credentials import PREFIX
```
and replace the two login lines (~line 72-73) in the `desired.update({...})`:
```python
        "MqttUser": username(PREFIX, host),
        "MqttPassword": password(tasmota_config.mqtt_secret, host),
```
Everything else in the file (drift detection, `_get_current_value`, the `MqttCount==0` re-push, the `MqttPassword`-masking) is unchanged — `compute_drift`/`configure_*` still receive `tasmota_config` and now derive the login through it. Update the `compute_desired_config`/`compute_drift`/`configure_*` docstrings that say "Tasmota device MQTT login (MqttUser/MqttPassword)" to "Tasmota credential secret (derives MqttUser/MqttPassword)".

- [ ] **Step 4: Run the tasmota tests — PASS.** Then the FULL suite `uv run pytest -q` (0 failures — this clears the Task 1 red).
- [ ] **Step 5: ruff + commit** (`tasmota: derive per-device MqttUser/MqttPassword (#28)`).

---

## Task 4: `tasmota register-broker`

**Files:** Modify `src/gdoc2netcfg/cli/main.py`; create `tests/test_cli/test_tasmota_register_broker.py`.

- [ ] **Step 1: Failing test** (`tests/test_cli/test_tasmota_register_broker.py`) — mirror Plan 2's `test_sensors2mqtt_cli.py::test_register_*`:
```python
"""Tests for `tasmota register-broker`."""
import argparse
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_tasmota_register_broker


def _cfg_and_hosts():
    """PipelineConfig (strong tasmota.mqtt_secret + homeassistant.ssh_host + mqtt)
    and a list with one Tasmota host (tasmota_data set) and one non-Tasmota host.
    Crib Host/TasmotaData/PipelineConfig construction from
    tests/test_supplements/test_tasmota.py and tests/test_cli/test_sensors2mqtt_cli.py."""
    ...


def test_register_broker_calls_core():
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._tasmota_hosts", return_value=hosts), \
         patch("gdoc2netcfg.supplements.mqtt_broker.register_logins") as reg:
        rc = cmd_tasmota_register_broker(args)
    assert rc == 0
    _ssh, prefix, logins = reg.call_args.args[:3]
    assert prefix == "tas-"
    assert set(logins) == {"tas-<id of the tasmota host>"}  # replace with real node_id


def test_register_broker_empty_secret_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.tasmota.mqtt_secret = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._tasmota_hosts", return_value=hosts):
        rc = cmd_tasmota_register_broker(args)
    assert rc == 1 and "secret" in capsys.readouterr().err.lower()
```
Replace `<id of the tasmota host>` with the real `node_id` of the Tasmota host (e.g. `au-plug-1.iot` → `au_plug_1_iot`). Flesh out `_cfg_and_hosts` per the cited tests.

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** in `cli/main.py`:
  - A helper `_tasmota_hosts(config)` returning the enriched host list with `tasmota_data` attached — **reuse exactly how `cmd_tasmota_configure` obtains its Tasmota hosts** (find `cmd_tasmota_configure`, ~line 1929; copy its host-loading/enrichment, which loads `load_latest_tasmota` so `host.tasmota_data` is populated). If `cmd_tasmota_configure` already has such a helper, reuse it rather than duplicating.
  - `cmd_tasmota_register_broker(args)` — model on `cmd_sensors2mqtt_register` (Plan 2):
    ```python
    def cmd_tasmota_register_broker(args: argparse.Namespace) -> int:
        """Register Tasmota broker logins on the HA Mosquitto add-on."""
        from gdoc2netcfg.derivations.tasmota_credentials import PREFIX, build_logins
        from gdoc2netcfg.supplements.mqtt_broker import register_logins

        config = _load_config(args)
        hosts = _tasmota_hosts(config)
        if not config.homeassistant.ssh_host:
            print("Error: [homeassistant] ssh_host not configured", file=sys.stderr)
            return 1
        try:
            logins = build_logins(config.tasmota.mqtt_secret, hosts)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        verify = (
            (config.homeassistant.mqtt.host, config.homeassistant.mqtt.port)
            if not args.dry_run else None
        )
        register_logins(
            config.homeassistant.ssh_host, PREFIX, logins,
            dry_run=args.dry_run, prune=args.prune, verify=verify,
        )
        return 0
    ```
    (Import `register_logins`/`build_logins` function-locally so the test patch on `gdoc2netcfg.supplements.mqtt_broker.register_logins` intercepts — same reason as Plan 2's register.)
  - argparse: on the existing `tasmota_subparsers` (~line 2764), add `rb = tasmota_subparsers.add_parser("register-broker", help="Register Tasmota broker logins on HA Mosquitto")`; `rb.add_argument("--dry-run", action="store_true")`; `rb.add_argument("--prune", action="store_true")`.
  - dispatch: where `tasmota` subcommands dispatch (~line 2952 area), add `elif args.tasmota_command == "register-broker": return cmd_tasmota_register_broker(args)`.

- [ ] **Step 4: Run — PASS** (`uv run pytest tests/test_cli/test_tasmota_register_broker.py -q`), then full suite. **Step 5: ruff + commit** (`tasmota: register-broker subcommand (#28)`).

---

## Task 5: Example config

**Files:** Modify `gdoc2netcfg.toml.example`.

- [ ] **Step 1:** In `gdoc2netcfg.toml.example`, replace the `[tasmota]` body (`mqtt_user`/`mqtt_password`) with:
```toml
# ── Optional: Tasmota IoT device per-device MQTT credentials ──
# Broker host/port come from [homeassistant.mqtt]. mqtt_secret derives each
# device's MqttUser (tas-<id>) + MqttPassword; keep the toml 0600.
# `gdoc2netcfg tasmota register-broker` registers the pre-hashed logins;
# `gdoc2netcfg tasmota configure` pushes the per-device login.
[tasmota]
mqtt_secret = ""
```
Keep the existing comment lines above `[tasmota]` consistent (don't leave a dangling reference to the broker login).

- [ ] **Step 2:** Confirm the example still loads: `uv run pytest tests/test_sources/test_config.py -q` (PASS).
- [ ] **Step 3:** Commit (`config example: [tasmota] mqtt_secret (#28)`).

---

## Task 6: Full suite + lint gate, final review, finish

- [ ] **Step 1:** `uv run pytest -q` (0 failures) and `uv run ruff check src/ tests/` (clean).
- [ ] **Step 2: Smoke (read-only):** `uv run gdoc2netcfg tasmota register-broker --dry-run` — with the dev toml (no `ssh_host`, no `mqtt_secret`) this must exit rc=1 on the `ssh_host` gate (confirms wiring, no broker contact). `uv run gdoc2netcfg tasmota configure --dry-run --all` should still run (now showing `MqttUser tas-<id>` drift).
- [ ] **Step 3:** Dispatch a final whole-branch reviewer (opus) over the Tasmota diff (the commits Task 1-5 add on top of the sensors2mqtt branch): focus on security (no secret/password leak; plaintext only to `register_logins`/device push, masked in logs), fail-loud, correct core reuse, the `MqttUser` migration-as-drift, and that the existing tasmota tests were updated to derived values (not weakened/deleted).
- [ ] **Step 4:** `superpowers:finishing-a-development-branch`. Because this branch is stacked, "finish #28 as a whole" = merge this branch (it carries both sensors2mqtt + tasmota) to `main`, OR merge `feature/mqtt-credentials-sensors2mqtt` first then this. Present the options to the user.

---

## Cutover (after #28 merges — operator, deferred; with the sensors2mqtt cutover)
1. Set `[tasmota] mqtt_secret` (`openssl rand -hex 32`, 0600) on each site.
2. `gdoc2netcfg tasmota register-broker --dry-run` → review the `tas-` username diff → `register-broker` (restarts the broker; folds in the deferred Plan 2 live PBKDF2 check for the `tas-` prefix).
3. `gdoc2netcfg tasmota configure --all` → pushes `MqttUser=tas-<id>` (drift) + `MqttPassword` (write-only) to each device; `MqttCount==0` devices get a forced credential push.
4. Manually retire the old shared broker login once all devices show `MqttCount>0` (spec Decision 10).

---

## Self-Review

**Spec coverage:** §4.2 derivation core reuse → Task 2 (`build_logins` via `mqtt_credentials`) ✓. §4.4 selection = `tasmota_data is not None` → Task 2 `select_tasmota` ✓. §4.7 `compute_desired_config` derives `MqttUser`/`MqttPassword`; new `register-broker` → Tasks 3, 4 ✓. §4.8 `[tasmota] mqtt_secret` replaces the interim login → Tasks 1, 5 ✓. §6 fail-loud (weak secret, collision, ssh/broker failure) → Tasks 2, 4 + core ✓. §7 two-hashing-layers (plaintext to device + pre-hashed to broker) → Tasks 3 (device push) + 4 (`register_logins` pre-hash) ✓. Deferred (correctly): the live cutover (broker + device restarts).

**Placeholder scan:** Task 2/4 test helpers (`_host`, `_cfg_and_hosts`) are sketches the implementer fleshes out from cited existing tests — pointers to real patterns, with assertions/behavior fully specified. No vague TODOs.

**Type consistency:** `PREFIX = "tas-"` is the single source (Task 2), imported by both `compute_desired_config` (Task 3) and `register-broker` (Task 4) — no second `"tas-"` literal. `build_logins(secret, hosts) -> dict[str,str]` matches `register_logins(ssh_host, prefix, logins, …)` (Plan 1). `TasmotaConfig.mqtt_secret` (Task 1) consumed by `compute_desired_config` + `register-broker`. `select_tasmota` filter (`tasmota_data is not None`) matches the existing `configure` selection.
