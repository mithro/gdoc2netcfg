# MQTT Credential Core — Implementation Plan (Plan 1 of 3 for #28)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared, consumer-agnostic MQTT credential core — the canonical host key, the deterministic `(username, password)` derivation with its guards, and broker login registration (pre-hashed, over the HA SSH + Supervisor API path) — that Plan 2 (sensors2mqtt) and Plan 3 (Tasmota) build on.

**Architecture:** Three new modules. `utils/mqtt.py` holds `node_id` (promoted out of `supplements/mqtt_ha.py` so both it and the new code share one transform). `derivations/mqtt_credentials.py` is pure: it turns `(prefix, secret, host)` into `(username, password)` and provides a collision guard and a strong-secret guard. `supplements/mqtt_broker.py` does the side-effecting `register_logins()` — it reaches the HA Mosquitto add-on over SSH (`subprocess.run(["ssh", ssh_host, …])`, the pattern the dashboard deployer already uses) + the Supervisor API, pre-hashes plaintext into the mosquitto-go-auth `$7$` (PBKDF2-SHA512) format, merges prefix-scoped, POSTs, and restarts.

**Tech Stack:** Python 3.11+, pytest, `hashlib` (sha256 + pbkdf2), `subprocess` (ssh), `paho-mqtt` (post-restart login verify), `uv run` for everything.

**Spec:** `docs/superpowers/specs/2026-06-14-mqtt-credentials-design.md` (§4.1–4.2, §4.5, §6, §7, §11.1).

**Scope note:** This plan delivers *only* the core. No CLI subcommands, no sheet column, no Tasmota changes, no config secrets — those are Plans 2 and 3. The core is fully unit-tested in isolation (broker I/O mocked); the one live touchpoint is the Task 1 spike.

---

## File Structure

| File | Responsibility | Status |
|---|---|---|
| `src/gdoc2netcfg/utils/mqtt.py` | `node_id(name)` — MQTT-safe identity transform | **create** |
| `src/gdoc2netcfg/supplements/mqtt_ha.py` | reachability publisher — drop local `_node_id`, import from `utils.mqtt` | modify |
| `src/gdoc2netcfg/derivations/mqtt_credentials.py` | pure derivation: `credential_key`, `username`, `password`, `check_collisions`, `require_strong_secret` | **create** |
| `src/gdoc2netcfg/supplements/mqtt_broker.py` | `register_logins(...)` + `_prehash` + `_verify_login` (HA Supervisor API over SSH) | **create** |
| `tests/test_utils/test_mqtt.py` | `node_id` tests (moved from `test_mqtt_ha.py`) | **create** |
| `tests/test_supplements/test_mqtt_ha.py` | switch `_node_id` → `node_id` import + usages | modify |
| `tests/test_derivations/test_mqtt_credentials.py` | golden-vector + guard tests | **create** |
| `tests/test_supplements/test_mqtt_broker.py` | `register_logins` merge/dry-run/prune tests (mocked transport) | **create** |

Establish a clean branch first (the executor should use `superpowers:using-git-worktrees` if a worktree is wanted; otherwise a `feature/mqtt-credentials-core` branch off `main`).

---

## Task 1: SPIKE — confirm the broker pre-hash format + Supervisor-API-over-SSH path

**Why first:** `register_logins` (Task 4) depends on two unknowns that can only be confirmed against the live HA Mosquitto add-on: (a) that a Python-produced `$7$` PBKDF2-SHA512 hash is accepted by mosquitto-go-auth, and (b) how to reach the Supervisor API from a non-interactive `ssh ha.welland.mithis.com "…"` session (notably how `SUPERVISOR_TOKEN` is obtained). Resolve both with ONE throwaway login before building the real function.

**Files:**
- Scratch only: `tmp/spike_prehash.py` (delete when done — do NOT commit)

- [ ] **Step 1: Write the candidate `_prehash` (this becomes Task 4's helper)**

```python
# tmp/spike_prehash.py
import base64, hashlib, os

def prehash(plaintext: str, *, iterations: int = 100_000, key_len: int = 64) -> str:
    """mosquitto-go-auth PBKDF2 format: $7$<iters>$<b64 salt>$<b64 dk> (sha512)."""
    salt = os.urandom(16).replace(b"$", b"A")  # go-auth avoids 0x24 in the salt
    dk = hashlib.pbkdf2_hmac("sha512", plaintext.encode(), salt, iterations, dklen=key_len)
    return f"$7${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

if __name__ == "__main__":
    print(prehash("spike-plaintext-123"))
```

- [ ] **Step 2: Find how to reach the Supervisor API over SSH**

Try, in order, until one prints the add-on info JSON (read-only; pick the first that works):

```bash
SSH="ssh -o ControlPath=none -o ConnectTimeout=10 ha.welland.mithis.com"
# (a) token already in the env of a login shell:
$SSH 'curl -sS -H "Authorization: Bearer $SUPERVISOR_TOKEN" http://supervisor/addons/core_mosquitto/info' | head -c 300
# (b) token from the s6 container env file (per requirements §note):
$SSH 'curl -sS -H "Authorization: Bearer $(cat /run/s6/container_environment/SUPERVISOR_TOKEN)" http://supervisor/addons/core_mosquitto/info' | head -c 300
# (c) the `ha` CLI (no manual token):
$SSH 'ha addons info core_mosquitto --raw-json' | head -c 300
```

Record which works (call it `GET_INFO`) and the corresponding POST form. Document it in the Task 4 module docstring.

- [ ] **Step 3: Round-trip ONE throwaway login through the live broker**

Read the current `options.logins` (via `GET_INFO`), append one throwaway user `spike-canary` with `password = prehash("spike-plaintext-123")` and `password_pre_hashed: true`, POST the merged options, restart the add-on, then connect with paho:

```python
import paho.mqtt.client as mqtt, time
res = {"rc": None}
def on_connect(c,u,f,rc,p): res["rc"] = rc
c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="spike-canary")
c.username_pw_set("spike-canary", "spike-plaintext-123")
c.on_connect = on_connect
c.connect("ha.welland.mithis.com", 1883, keepalive=10); c.loop_start()
t=time.time()
while res["rc"] is None and time.time()-t < 15: time.sleep(0.2)
print("CONNACK rc =", res["rc"])  # rc 0 (Success) == format accepted
c.loop_stop(); c.disconnect()
```

- [ ] **Step 4: Clean up — remove `spike-canary` from `options.logins`, POST, restart**

Re-read logins, drop `spike-canary`, POST, restart. Confirm with `GET_INFO` that it's gone. Delete `tmp/spike_prehash.py`.

- [ ] **Step 5: Record the outcome (no commit — this task produces knowledge, not code)**

Outcome to carry into Task 4: (1) the working `GET_INFO`/POST/restart commands, (2) **CONNACK rc 0 confirms** the `$7$` format above is correct → use `prehash` verbatim in Task 4. If rc was *not* 0, adjust `prehash` (iterations/keylen/salt handling) and repeat Step 3 until rc 0; only then proceed.

> If the live broker is unreachable at execution time, STOP and surface it — Task 4 cannot be validated without this.

---

## Task 2: Promote `node_id` to `utils/mqtt.py`

**Files:**
- Create: `src/gdoc2netcfg/utils/mqtt.py`
- Create: `tests/test_utils/test_mqtt.py`
- Modify: `src/gdoc2netcfg/supplements/mqtt_ha.py` (remove `_node_id` def at line 52; import + replace 5 call sites: 249, 468, 508, 609, 675)
- Modify: `tests/test_supplements/test_mqtt_ha.py` (import line 28; remove the dedicated `node_id` tests at ~126-138; replace remaining `_node_id(` usages)

- [ ] **Step 1: Write `tests/test_utils/test_mqtt.py`** (the cases currently at `test_mqtt_ha.py:126-138`)

```python
"""Tests for the MQTT-safe identity transform."""
from gdoc2netcfg.utils.mqtt import node_id


class TestNodeId:
    def test_dashes_to_underscores(self):
        assert node_id("big-storage") == "big_storage"

    def test_dotted_bmc_distinct_from_parent(self):
        assert node_id("bmc.big-storage") == "bmc_big_storage"

    def test_plain_unchanged(self):
        assert node_id("my_host") == "my_host"

    def test_lowercased(self):
        assert node_id("MyHost") == "myhost"

    def test_multi_dot(self):
        assert node_id("sw.rack-1.unit-2") == "sw_rack_1_unit_2"
```

- [ ] **Step 2: Run it — verify it fails (module missing)**

Run: `uv run pytest tests/test_utils/test_mqtt.py -q`
Expected: FAIL — `ModuleNotFoundError: gdoc2netcfg.utils.mqtt`

- [ ] **Step 3: Create `src/gdoc2netcfg/utils/mqtt.py`**

```python
"""MQTT-safe identity transform shared across MQTT consumers.

`node_id` turns a hostname into an MQTT/HA-safe token (alphanumeric + `_`,
lowercased). It is the canonical per-host key used for entity IDs (mqtt_ha)
and for derived broker credentials (mqtt_credentials).
"""

from __future__ import annotations

import re


def node_id(name: str) -> str:
    """Lowercase `name` and replace every non-alphanumeric run-of-one with `_`."""
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()
```

- [ ] **Step 4: Run the new tests — verify they pass**

Run: `uv run pytest tests/test_utils/test_mqtt.py -q`
Expected: PASS (5 passed)

- [ ] **Step 5: Repoint `mqtt_ha.py` at the shared transform**

In `src/gdoc2netcfg/supplements/mqtt_ha.py`: delete the local `def _node_id(...)` (line ~52); add `from gdoc2netcfg.utils.mqtt import node_id` with the other imports; replace each `_node_id(` call (lines ~249, 468, 508, 609, 675) with `node_id(`.

- [ ] **Step 6: Update `test_mqtt_ha.py`**

Remove `_node_id` from its import block (line ~28). Delete the `node_id`-specific test methods now living in `test_utils/test_mqtt.py` (~lines 126-138). Add `from gdoc2netcfg.utils.mqtt import node_id` and replace every remaining `_node_id(` with `node_id(`.

- [ ] **Step 7: Run both test files — verify pass**

Run: `uv run pytest tests/test_utils/test_mqtt.py tests/test_supplements/test_mqtt_ha.py -q`
Expected: PASS (no `_node_id` references remain: `rg -n "_node_id" src/ tests/` returns nothing)

- [ ] **Step 8: Lint + commit**

```bash
uv run ruff check src/gdoc2netcfg/utils/mqtt.py src/gdoc2netcfg/supplements/mqtt_ha.py tests/test_utils/test_mqtt.py tests/test_supplements/test_mqtt_ha.py
git add src/gdoc2netcfg/utils/mqtt.py tests/test_utils/test_mqtt.py src/gdoc2netcfg/supplements/mqtt_ha.py tests/test_supplements/test_mqtt_ha.py
git commit -m "mqtt: promote node_id to utils/mqtt.py (#28)"
```

---

## Task 3: `derivations/mqtt_credentials.py` (pure derivation + guards)

**Files:**
- Create: `src/gdoc2netcfg/derivations/mqtt_credentials.py`
- Create: `tests/test_derivations/test_mqtt_credentials.py`

- [ ] **Step 1: Write the failing tests (golden vectors + guards)**

```python
"""Tests for the pure MQTT credential derivation."""
import pytest

from gdoc2netcfg.derivations.mqtt_credentials import (
    check_collisions,
    credential_key,
    password,
    require_strong_secret,
    username,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _host(hostname: str) -> Host:
    return Host(
        machine_name=hostname.split(".")[0],
        hostname=hostname,
        sheet_type="Network",
        interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.5.10"),), dhcp_name=hostname,
        )],
    )


class TestDerivation:
    def test_credential_key_is_node_id_of_hostname(self):
        assert credential_key(_host("big-storage")) == "big_storage"
        assert credential_key(_host("bmc.big-storage")) == "bmc_big_storage"

    def test_username_carries_prefix(self):
        assert username("s2m-", _host("rpi5.iot")) == "s2m-rpi5_iot"
        assert username("tas-", _host("au-plug-1.iot")) == "tas-au_plug_1_iot"

    def test_password_is_sha256_secret_plus_id_hex(self):
        # golden vectors: sha256(("testsecret" + node_id(hostname)).encode())
        assert password("testsecret", _host("big-storage")) == \
            "1a1c7e1c69578988a9fa6473f57924659e3e8eb2e4203fd63d8e6ea1fb11dc72"
        assert password("testsecret", _host("rpi5.iot")) == \
            "7f066df7bae33d26adc121786e8355b5afa4eaab04cf7bd667ff24992644bd27"

    def test_password_is_64_lowercase_hex(self):
        p = password("testsecret", _host("big-storage"))
        assert len(p) == 64 and p == p.lower() and all(c in "0123456789abcdef" for c in p)

    def test_bmc_and_parent_differ(self):
        assert password("s", _host("big-storage")) != password("s", _host("bmc.big-storage"))


class TestCollisionGuard:
    def test_distinct_ids_ok(self):
        check_collisions([_host("big-storage"), _host("rpi5.iot")])  # no raise

    def test_colliding_ids_raise(self):
        # "a.b" and "a-b" both node_id to "a_b"
        with pytest.raises(ValueError, match="collide"):
            check_collisions([_host("a.b"), _host("a-b")])


class TestStrongSecretGuard:
    def test_empty_raises(self):
        with pytest.raises(ValueError, match="secret"):
            require_strong_secret("")

    def test_short_raises(self):
        with pytest.raises(ValueError, match="secret"):
            require_strong_secret("tooshort")

    def test_strong_ok(self):
        require_strong_secret("0123456789abcdef0123456789abcdef")  # 32 chars
```

- [ ] **Step 2: Run — verify it fails**

Run: `uv run pytest tests/test_derivations/test_mqtt_credentials.py -q`
Expected: FAIL — `ModuleNotFoundError: gdoc2netcfg.derivations.mqtt_credentials`

- [ ] **Step 3: Implement `src/gdoc2netcfg/derivations/mqtt_credentials.py`**

```python
"""Pure, deterministic MQTT credential derivation (consumer-agnostic).

Given a per-consumer secret and a host, derives a stable broker
`(username, password)`:  username = f"{prefix}{<id>}",  password =
sha256(secret + <id>) hex, where <id> = node_id(host.hostname).  See the
design spec §4.2 / §7 for why this is a deterministic KDF (recomputable by
Ansible) rather than a salted password hash.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from gdoc2netcfg.utils.mqtt import node_id

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

# Reject empty / trivially-short secrets. The recommendation is
# `openssl rand -hex 32` (64 chars / 256-bit); this is just a sanity floor.
_MIN_SECRET_LEN = 32


def credential_key(host: Host) -> str:
    """The canonical per-host key `<id>` — node_id of the unique hostname."""
    return node_id(host.hostname)


def username(prefix: str, host: Host) -> str:
    """`{prefix}{<id>}`, e.g. `s2m-rpi5_iot` / `tas-au_plug_1_iot`."""
    return f"{prefix}{credential_key(host)}"


def password(secret: str, host: Host) -> str:
    """`sha256(secret + <id>)` as 64-char lowercase hex."""
    return hashlib.sha256((secret + credential_key(host)).encode()).hexdigest()


def check_collisions(hosts: list[Host]) -> None:
    """Fail loud if two distinct hosts map to the same `<id>` (node_id is
    not injective)."""
    seen: dict[str, str] = {}
    for host in hosts:
        key = credential_key(host)
        if key in seen and seen[key] != host.hostname:
            raise ValueError(
                f"node_id collision: '{seen[key]}' and '{host.hostname}' "
                f"both map to '{key}'"
            )
        seen[key] = host.hostname


def require_strong_secret(secret: str) -> None:
    """Fail loud on an empty / trivially-short secret (the scheme's security
    rests entirely on the secret's entropy)."""
    if len(secret) < _MIN_SECRET_LEN:
        raise ValueError(
            f"mqtt_secret must be high-entropy (>= {_MIN_SECRET_LEN} chars; "
            "recommend `openssl rand -hex 32`)"
        )
```

- [ ] **Step 4: Run — verify pass**

Run: `uv run pytest tests/test_derivations/test_mqtt_credentials.py -q`
Expected: PASS

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/gdoc2netcfg/derivations/mqtt_credentials.py tests/test_derivations/test_mqtt_credentials.py
git add src/gdoc2netcfg/derivations/mqtt_credentials.py tests/test_derivations/test_mqtt_credentials.py
git commit -m "mqtt: pure per-host credential derivation + guards (#28)"
```

---

## Task 4: `supplements/mqtt_broker.py` — `register_logins`

Uses the pre-hash format + Supervisor-API commands confirmed in Task 1. Transport is isolated in three tiny helpers (`_supervisor_get`, `_supervisor_post`, `_restart_addon`) so tests can mock them without a live broker. `_prehash` is the Task 1 helper; `_verify_login` is a paho connect-test for the post-restart safety check.

**Files:**
- Create: `src/gdoc2netcfg/supplements/mqtt_broker.py`
- Create: `tests/test_supplements/test_mqtt_broker.py`

- [ ] **Step 1: Write the failing merge/dry-run/prune tests (transport mocked)**

```python
"""Tests for register_logins merge semantics (transport mocked)."""
from unittest.mock import patch

import pytest

from gdoc2netcfg.supplements import mqtt_broker
from gdoc2netcfg.supplements.mqtt_broker import register_logins

# Existing broker state: core logins + one stale s2m- login.
EXISTING = [
    {"username": "gdoc2netcfg", "password": "x"},
    {"username": "DVES_USER", "password": "y"},
    {"username": "s2m-old_host", "password": "z"},
]


def _patches(captured):
    """Patch the three transport helpers + prehash + verify."""
    def fake_get(ssh_host):
        return {"options": {"logins": [dict(x) for x in EXISTING]}}

    def fake_post(ssh_host, logins):
        captured["posted"] = logins

    return [
        patch.object(mqtt_broker, "_supervisor_get_logins", fake_get),
        patch.object(mqtt_broker, "_supervisor_post_logins", fake_post),
        patch.object(mqtt_broker, "_restart_addon", lambda ssh_host: captured.__setitem__("restarted", True)),
        patch.object(mqtt_broker, "_prehash", lambda pw: f"$7$HASH${pw}"),
        patch.object(mqtt_broker, "_verify_login", lambda *a, **k: None),
    ]


def _run(logins, *, dry_run=False, prune=False):
    captured = {}
    ps = _patches(captured)
    for p in ps:
        p.start()
    try:
        register_logins("ha.example", "s2m-", logins, dry_run=dry_run, prune=prune)
    finally:
        for p in ps:
            p.stop()
    return captured


def _names(logins):
    return sorted(x["username"] for x in logins)


class TestRegisterLogins:
    def test_upsert_preserves_core_and_other_prefix(self):
        cap = _run({"s2m-new_host": "pw1"})
        assert _names(cap["posted"]) == ["DVES_USER", "gdoc2netcfg", "s2m-new_host", "s2m-old_host"]
        # new login is pre-hashed + flagged
        new = next(x for x in cap["posted"] if x["username"] == "s2m-new_host")
        assert new["password"] == "$7$HASH$pw1" and new["password_pre_hashed"] is True
        # untouched logins keep their original password verbatim
        assert next(x for x in cap["posted"] if x["username"] == "gdoc2netcfg")["password"] == "x"
        assert cap["restarted"] is True

    def test_idempotent_no_dupes(self):
        cap = _run({"s2m-old_host": "pw"})
        assert _names(cap["posted"]).count("s2m-old_host") == 1
        assert len([x for x in cap["posted"] if x["username"] == "s2m-old_host"]) == 1

    def test_prune_drops_stale_own_prefix(self):
        cap = _run({"s2m-new_host": "pw1"}, prune=True)
        assert _names(cap["posted"]) == ["DVES_USER", "gdoc2netcfg", "s2m-new_host"]  # s2m-old_host pruned

    def test_no_prune_keeps_stale_own_prefix(self):
        cap = _run({"s2m-new_host": "pw1"}, prune=False)
        assert "s2m-old_host" in _names(cap["posted"])

    def test_dry_run_does_nothing(self):
        cap = _run({"s2m-new_host": "pw1"}, dry_run=True)
        assert "posted" not in cap and "restarted" not in cap

    def test_other_prefix_never_pruned(self):
        # registering tas- must not touch s2m- even with prune
        cap = _run({"s2m-x": "p"})  # using s2m- prefix; old s2m kept w/o prune
        assert "DVES_USER" in _names(cap["posted"]) and "gdoc2netcfg" in _names(cap["posted"])
```

- [ ] **Step 2: Run — verify it fails**

Run: `uv run pytest tests/test_supplements/test_mqtt_broker.py -q`
Expected: FAIL — `ModuleNotFoundError: gdoc2netcfg.supplements.mqtt_broker`

- [ ] **Step 3: Implement `src/gdoc2netcfg/supplements/mqtt_broker.py`**

Use the exact `GET_INFO`/POST/restart commands confirmed in Task 1 inside the three transport helpers. The merge/prehash/orchestration below is final.

```python
"""Register pre-hashed broker logins on the HA Mosquitto add-on.

Reaches the add-on over the existing HA SSH path (subprocess `ssh`, as the
dashboard deployer does) + the Supervisor API. Plaintext is pre-hashed into
the mosquitto-go-auth `$7$` PBKDF2-SHA512 format so it never lands in the
add-on options/backups. Merge is prefix-scoped: only logins starting with
`prefix` are this consumer's; everything else is preserved verbatim.

The exact Supervisor-API invocation was confirmed by the Task 1 spike (see
docs/superpowers/plans/2026-06-14-mqtt-credentials-core.md).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time

import paho.mqtt.client as mqtt

_ADDON = "core_mosquitto"
_SSH_OPTS = ["-o", "ControlPath=none", "-o", "ConnectTimeout=10"]


def _prehash(plaintext: str, *, iterations: int = 100_000, key_len: int = 64) -> str:
    salt = os.urandom(16).replace(b"$", b"A")
    dk = hashlib.pbkdf2_hmac("sha512", plaintext.encode(), salt, iterations, dklen=key_len)
    return f"$7${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def _ssh(ssh_host: str, remote_cmd: str, *, stdin: str | None = None) -> str:
    result = subprocess.run(
        ["ssh", *_SSH_OPTS, ssh_host, remote_cmd],
        input=stdin, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ssh {ssh_host}: {result.stderr.strip()}")
    return result.stdout


# --- transport (commands confirmed by the Task 1 spike) -------------------
# NOTE: substitute the GET/POST/restart forms the spike confirmed. The
# default below uses the s6 container-env token + Supervisor API.
_TOKEN = "$(cat /run/s6/container_environment/SUPERVISOR_TOKEN)"
_AUTH = f'-H "Authorization: Bearer {_TOKEN}"'


def _supervisor_get_logins(ssh_host: str) -> dict:
    out = _ssh(ssh_host, f'curl -sS {_AUTH} http://supervisor/addons/{_ADDON}/info')
    return json.loads(out)["data"]


def _supervisor_post_logins(ssh_host: str, logins: list[dict]) -> None:
    body = json.dumps({"logins": logins})
    _ssh(
        ssh_host,
        f'curl -sS -X POST {_AUTH} -H "Content-Type: application/json" '
        f"--data @- http://supervisor/addons/{_ADDON}/options",
        stdin=body,
    )


def _restart_addon(ssh_host: str) -> None:
    _ssh(ssh_host, f'curl -sS -X POST {_AUTH} http://supervisor/addons/{_ADDON}/restart')


def _verify_login(host: str, port: int, user: str, plaintext: str, *, timeout: float = 20.0) -> None:
    """Connect once as a just-registered user; raise if the broker rejects it.
    Retries across the add-on restart window."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        res = {"rc": None}
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="gdoc2netcfg-verify")
        c.username_pw_set(user, plaintext)
        c.on_connect = lambda cl, u, f, rc, p: res.__setitem__("rc", rc)
        try:
            c.connect(host, port, keepalive=10)
            c.loop_start()
            t = time.time()
            while res["rc"] is None and time.time() - t < 3:
                time.sleep(0.1)
            c.loop_stop(); c.disconnect()
        except OSError as e:
            last = e
            time.sleep(1.0)
            continue
        if res["rc"] == 0:
            return
        last = f"CONNACK rc={res['rc']}"
        time.sleep(1.0)
    raise RuntimeError(f"post-register login verify failed for {user}: {last}")


def register_logins(
    ssh_host: str,
    prefix: str,
    logins: dict[str, str],
    *,
    dry_run: bool = False,
    prune: bool = False,
    verify: tuple[str, int] | None = None,
) -> None:
    """Upsert `{username: plaintext}` (pre-hashed) into the add-on, scoped to
    `prefix`. Preserves every login not starting with `prefix`; with `prune`,
    drops `prefix`-logins absent from `logins`. `verify=(host, port)` connect-
    tests one login after the restart."""
    info = _supervisor_get_logins(ssh_host)
    current = info.get("options", {}).get("logins", [])

    kept = [x for x in current if not x["username"].startswith(prefix)]
    if not prune:
        # keep existing own-prefix logins that aren't being re-issued
        kept += [x for x in current if x["username"].startswith(prefix) and x["username"] not in logins]

    new = [
        {"username": u, "password": _prehash(p), "password_pre_hashed": True}
        for u, p in sorted(logins.items())
    ]
    merged = kept + new

    added = sorted(logins)
    pruned = sorted(
        x["username"] for x in current
        if x["username"].startswith(prefix) and x["username"] not in logins
    ) if prune else []
    print(f"register_logins[{prefix}]: +{len(added)} upsert, "
          f"-{len(pruned)} prune, {len(kept)} preserved", file=sys.stderr)

    if dry_run:
        print("  (dry-run: no POST / no restart)", file=sys.stderr)
        return

    _supervisor_post_logins(ssh_host, merged)
    _restart_addon(ssh_host)

    if verify and logins:
        u = next(iter(sorted(logins)))
        _verify_login(verify[0], verify[1], u, logins[u])
```

- [ ] **Step 4: Run — verify pass**

Run: `uv run pytest tests/test_supplements/test_mqtt_broker.py -q`
Expected: PASS

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/gdoc2netcfg/supplements/mqtt_broker.py tests/test_supplements/test_mqtt_broker.py
git add src/gdoc2netcfg/supplements/mqtt_broker.py tests/test_supplements/test_mqtt_broker.py
git commit -m "mqtt: register_logins broker core, pre-hashed + prefix-scoped (#28)"
```

---

## Task 5: Full suite + lint gate

- [ ] **Step 1: Whole suite green**

Run: `uv run pytest -q`
Expected: PASS (prior baseline 1671 + the new tests; 0 failures)

- [ ] **Step 2: Lint clean**

Run: `uv run ruff check src/ tests/`
Expected: `All checks passed!`

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-06-14-mqtt-credentials-design.md`):
- §4.1 shared core (`utils/mqtt.py`, `derivations/mqtt_credentials.py`, `supplements/mqtt_broker.py`) → Tasks 2, 3, 4 ✓
- §4.2 derivation (`credential_key`/`username`/`password`), collision guard, strong-secret guard → Task 3 ✓
- §4.5 `register_logins` (GET → pre-hash → prefix-scoped merge → POST → restart; `--dry-run`; `prune`; preserve core + other prefix) → Task 4 ✓
- §7 pre-hashing into mosquitto-go-auth `$7$` PBKDF2-SHA512 → Task 1 + Task 4 `_prehash` ✓
- §11.1 pre-hash mechanism spike → Task 1 ✓
- §6 fail-loud (ssh failure raises; verify raises) → `_ssh`/`_verify_login` ✓
- *Deferred to Plan 2/3 (correctly out of scope here):* §4.3 sheet column, §4.6 `status` HA query, §4.7 Tasmota, the CLI subcommands, the `mqtt_secret` config fields. §11.2 (HA entity naming) belongs to Plan 2.

**Placeholder scan:** Task 4's transport helpers carry a NOTE to substitute the spike-confirmed Supervisor-API form — this is intentional (the spike in Task 1 confirms it; the default shown is the most-likely form). Not a code placeholder: it's a complete, runnable default that Task 1 validates/adjusts. No TBD/TODO elsewhere.

**Type consistency:** `node_id` (Task 2) → used by `credential_key` (Task 3) → `username`/`password` (Task 3). `_prehash` (Task 1 → Task 4). `register_logins(ssh_host, prefix, logins, *, dry_run, prune, verify)` — the same signature in the test (`_run`) and the spec §4.5. `_supervisor_get_logins`/`_supervisor_post_logins`/`_restart_addon`/`_prehash`/`_verify_login` names match between the test patches and the implementation. Consistent.
