# sensors2mqtt MQTT credentials — design

**Date:** 2026-06-14
**Status:** Design (pre-implementation, pending user review)
**Task:** #28
**Requirements:** `docs/sensors2mqtt-mqtt-credentials-requirements.md`

## 1. Summary

Add a `gdoc2netcfg sensors2mqtt` subcommand that issues and manages per-host
MQTT credentials for the `sensors2mqtt` collector fleet:

1. **Derive** a deterministic `(username, password)` per in-scope host from a
   single shared secret.
2. **Register** those users on the Home Assistant Mosquitto broker (pre-hashed,
   merge-not-replace, restart).
3. **Emit** each host's `sensors2mqtt` systemd `EnvironmentFile`.
4. **Verify** (a new capability beyond the requirements) that every monitored
   host's sensors are present and fresh in Home Assistant.

gdoc2netcfg is the natural home: it already owns the host inventory (the Google
Sheets), already generates config, and already holds MQTT/HA credentials and an
HA SSH path.

## 2. Background / motivation

The HA Mosquitto add-on (v7.1.0, mosquitto 2.1.2 + mosquitto-go-auth 3.0.0) now
rejects anonymous connections. The ~30 welland RPi collectors (`sensors2mqtt-local`),
ten64's two collectors, and a few polled servers/switches connect with **empty
credentials** and are being locked out as their grandfathered TCP sessions drop
(≥11 RPis already offline). No `sensors2mqtt` code change is needed — its
`MqttConfig.from_env()` already reads `MQTT_USER`/`MQTT_PASSWORD`. The missing
piece is *issuing and delivering credentials* — this feature.

## 3. Decisions (from brainstorm)

1. **Automation scope:** gdoc2netcfg derives credentials, writes per-host env
   files locally, **and registers** the broker logins. Host-side env
   distribution to the RPis is handed off to the existing Ansible deployment,
   which **recomputes the identical password independently** from the shared
   secret in its vault.
2. **Password scheme** (overrides requirements R2's HMAC/base64url):
   `password = sha256(secret + <H>)` → 64-char lowercase hex, matching the
   Ansible convention `{{ (sensors2mqtt_mqtt_secret ~ inventory_hostname) | hash('sha256') }}`.
3. **Canonical host key `<H>` = `_node_id(host.hostname)`** for **both** username
   and password. Uses `host.hostname` (always unique) — never `machine_name`
   (shared between a BMC and its parent). `_node_id` makes it MQTT-safe
   (alphanumeric + `_`). One canonical form everywhere.
4. **Secret placement:** `[sensors2mqtt] mqtt_secret` in the `0600`
   `gdoc2netcfg.toml`, mirrored into the Ansible vault. Never logged, never
   written to target hosts.
5. **Host selection:** a new spreadsheet column `sensors2mqtt`, three states:
   `local` / `remote` / blank (see §4.3).
6. **SDR Pis (`rpi-sdr-*`):** excluded (blank) — left untouched on their own
   broker. (Drops requirements R7.)
7. **Broker pre-hashing:** logins stored `password_pre_hashed: true` (R5).
8. **HA verification:** sensor **presence + freshness** per non-blank host.

## 4. Architecture

### 4.1 Subcommand + module layout

A new top-level subcommand `gdoc2netcfg sensors2mqtt` with four sub-actions —
**not** a `generate` generator (the cron-driven `generate` writes a
world-readable tree every 15 minutes; per-host MQTT passwords must never land
there, and R11 requires generation to be independent of broker registration):

| Sub-action | Side effects | Purpose |
|---|---|---|
| `list` | none | Show in-scope hosts + treatment (no secrets). Review. |
| `env` | writes local `0600` files / stdout | Render per-host `EnvironmentFile` (R4). |
| `register [--dry-run]` | HA broker | Merge `s2m-*` logins, pre-hashed, restart (R5). |
| `status` | none (reads HA) | Per non-blank host: HA sensor presence + freshness. |

Modules:
- **`derivations/sensors2mqtt.py`** — pure, unit-tested: host selection, the
  `(username, password)` derivation, env-file rendering, collision detection.
- **`supplements/mqtt_broker.py`** — the side-effecting HA/Supervisor
  integration (SSH → Supervisor API, pre-hash, merge, restart) and the HA sensor
  query for `status`.
- **`utils/mqtt.py`** — `node_id(name)` promoted from `supplements/mqtt_ha.py`
  (currently the private `_node_id`) so `mqtt_ha.py` and `sensors2mqtt.py` share
  one transform that cannot drift. `mqtt_ha.py` imports it (keeping `_node_id`
  as a thin alias is unnecessary — update its call sites).
- **`cli/main.py`** — `cmd_sensors2mqtt` dispatch + argparse wiring.
- **`config.py`** — a new `Sensors2mqttConfig` dataclass (§4.7).

### 4.2 Credential derivation (pure)

```python
def node_id(name: str) -> str:                       # utils/mqtt.py (promoted)
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()

def s2m_key(host) -> str:                            # <H>
    return node_id(host.hostname)

def s2m_username(host) -> str:
    return f"s2m-{s2m_key(host)}"

def s2m_password(secret: str, host) -> str:
    return hashlib.sha256((secret + s2m_key(host)).encode()).hexdigest()
```

- `host.hostname` is the unique key, so `bmc.big-storage` (`bmc_big_storage`) and
  its parent `big-storage` (`big_storage`) get **distinct** credentials.
- **Collision guard:** `_node_id` is not injective. Before issuing or
  registering, build the `{<H>: host}` map and **fail loud** if two distinct
  in-scope hosts map to the same `<H>`.
- The secret is never logged; passwords are never printed except inside the
  `0600` env file content (and `env --stdout`, an explicit operator action).

### 4.3 Host selection — sheet column `sensors2mqtt`

| Value | Meaning | Credential? | HA check? |
|---|---|---|---|
| `local` | sensors2mqtt **runs on** this host | **Yes** — username/password + env file + broker login | Yes |
| `remote` | a collector **elsewhere** polls this host (SNMP/IPMI) | No | Yes |
| blank | not involved | No | No |

- Read from `host.extra["sensors2mqtt"]` (case-insensitive, stripped).
- An **unrecognized** non-blank value → hard error (never silently skipped).
- Credential issuance (`env`, `register`) acts on `local` hosts; `status` acts
  on all non-blank hosts.
- Initial population is a one-off operator step (assisted): compute the in-scope
  set from current inventory and write the column via the service-account sheet
  path (or hand the operator a paste-ready list).

### 4.4 `env` — per-host EnvironmentFile (R4)

For each `local` host render:

```ini
MQTT_HOST=ha.welland.mithis.com
MQTT_PORT=1883
MQTT_USER=s2m-<H>
MQTT_PASSWORD=<sha256(secret+<H>) hex>
POLL_INTERVAL=30
```

- `MQTT_HOST`/`MQTT_PORT`/`POLL_INTERVAL` come from `Sensors2mqttConfig`
  (defaults above).
- `--stdout` prints for review; otherwise files are written `0600` to a secure
  output dir (default `<cache.directory>/sensors2mqtt/` — **not** the
  world-readable generated tree). `--host <H>` renders a single host.
- The RPis' files are produced for verification/parity; Ansible recomputes the
  identical content from the vault secret and installs `/etc/sensors2mqtt/env`
  (`0600 root`). ten64's file (the gdoc2netcfg host itself) can be installed
  directly.

### 4.5 `register` — broker logins (R5)

Reaches the HA Mosquitto add-on over the **existing HA SSH path** (same as the
dashboard deployer, `ssh <ha_ssh_host> ...`). Inside the HA SSH add-on the
Supervisor API (`http://supervisor/...`) is reachable with `SUPERVISOR_TOKEN`.

Flow (executed by a small script piped to the HA host over SSH; plaintext
passwords arrive via **stdin**, never argv/logs):

1. `GET /addons/core_mosquitto/info` → current `options.logins`.
2. Pre-hash each `local` host's password (`password_pre_hashed: true`) using the
   add-on's password tool on the HA side (see §11 spike).
3. **Merge:** keep every existing non-`s2m-` login
   (`gdoc2netcfg`, `tweed-bridge`, `DVES_USER`); upsert each `s2m-<H>`.
   Idempotent — re-running converges, no duplicates, no drops.
4. `POST /addons/core_mosquitto/options` with the merged `logins`.
5. Restart the add-on (`POST /addons/core_mosquitto/restart`).

- `--dry-run` prints the merged **username** set and the add/remove/keep diff
  (no passwords) and performs **no** POST/restart — this is what makes the safe
  cutover ordering (§8) reviewable.
- The whole `logins` list is read-modify-written atomically; any SSH/Supervisor
  failure aborts before POST (no partial application).

### 4.6 `status` — HA sensor presence + freshness

For each **non-blank** host, query HA via the REST API (`GET /api/states`,
`[homeassistant] url` + `token` — the existing integration the `tasmota
ha-status` command already uses) and report one of: **fresh** (matching entities
exist and were updated within `freshness_seconds`), **stale** (exist but
last-updated beyond the window), or **missing** (no matching entities). Output is
a review table keyed by hostname; no secrets. This is the post-cutover acceptance
check (requirements §9) and the standing health view for the `remote`-polled
hosts.

**Host↔entity correlation:** match a host's entities by its `<H>` /
`host.hostname` appearing in the entity's `entity_id` or device identifiers.
The exact pattern depends on how sensors2mqtt names its HA discovery entities,
which is confirmed by an early implementation spike (§11) against the live HA
instance; classification (`last_updated` vs window) and the table are
independent of that pattern.

### 4.7 Configuration

```toml
[sensors2mqtt]
mqtt_secret = "..."                 # shared secret (0600 toml; mirrored to Ansible vault)
mqtt_host = "ha.welland.mithis.com" # default for env files
mqtt_port = 1883
poll_interval = 30
ha_ssh_host = "ha.welland.mithis.com"   # SSH target for broker registration
freshness_seconds = 900             # status: max age before "stale"
# env_output_dir defaults to <cache.directory>/sensors2mqtt/
```

`Sensors2mqttConfig` follows the existing dataclass pattern (`TasmotaConfig`,
`HomeAssistantConfig`): dataclass defaults are the single source of truth, only
present keys override. The broker add-on slug (`core_mosquitto`) and the
preserved-login prefixes are constants in `mqtt_broker.py`.

## 5. Data flow

```
derive (pure):
  config.mqtt_secret + host.hostname ──node_id──► <H> ──► (s2m-<H>, sha256 hex)

env:
  local hosts ──► EnvironmentFile text ──► 0600 files / stdout
                                           └─ Ansible recomputes + installs on RPis

register (HA SSH):
  {s2m-<H>: plaintext} ──stdin──► HA: pre-hash ──► merge with existing logins
                                  ──► POST options ──► restart add-on

status (HA API):
  non-blank hosts ──► query entities ──► fresh / stale / missing table
```

## 6. Error handling (fail loud)

- Missing/empty `mqtt_secret` → error (no silent blank-secret derivation).
- Unrecognized `sensors2mqtt` column value → error.
- `_node_id` collision among in-scope hosts → error.
- SSH/Supervisor/HA failure → error, no partial broker apply, no fabricated
  status; `register` verifies the POST succeeded before restart.
- Pre-hash step fails for any host → abort the whole `register` (don't register a
  subset).

## 7. Security

- `mqtt_secret` only in `0600 gdoc2netcfg.toml` (+ Ansible vault); never written
  to hosts (only the derived per-host password is); never logged/printed.
- Env files `0600`; written to a non-world-readable dir; absent from the cron
  `generate` tree.
- Broker stores **pre-hashed** passwords (not plaintext in add-on options/backups).
- Plaintext passwords cross the SSH channel via stdin only.
- No collateral breakage: merge preserves HA core MQTT, `gdoc2netcfg`,
  `tweed-bridge`, `DVES_USER`.

## 8. Cutover ordering (R11 / requirements §7)

`env` (generate/distribute) is independent of `register`. Safe operator
sequence: generate + distribute env to **all** local hosts (collectors not yet
restarted) → `register` (restarts the broker, dropping grandfathered sessions) →
restart collectors **ten64 + one canary Pi first**, confirm online via
`status` → restart the rest → reconcile with `status`.

## 9. Testing

- **Derivation (golden vectors):** known `secret` + `host.hostname` → exact
  expected hex; username format; BMC vs parent produce distinct values;
  `_node_id` collision raises.
- **Selection:** `local`/`remote`/blank → correct inclusion in
  derive/env/register/status; unrecognized value raises; case/whitespace
  normalization.
- **Env rendering:** exact bytes incl. config-driven host/port/poll; single-host
  `--host`; output dir mode `0600`.
- **Broker merge (mocked SSH/transport):** preserves the existing three logins;
  upserts `s2m-*`; idempotent (no dupes/drops); `--dry-run` performs zero side
  effects and prints no passwords; pre-hash failure aborts cleanly.
- **status (mocked HA responses):** fresh / stale / missing classification incl.
  the freshness boundary; no secrets in output.
- Full `uv run pytest` green; `uv run ruff check src/ tests/` clean.

## 10. Out of scope / non-goals

- Host-side env distribution to the RPis (Ansible owns it) and the
  sensors2mqtt-side systemd `EnvironmentFile` wiring (requirements R10).
- SDR Pis / their separate broker (excluded).
- Per-user broker ACLs (requirements §11.5, future).
- Secret rotation tooling (rotation = change `mqtt_secret` + Ansible vault, then
  re-run `env`/`register` + redeploy; documented, not automated).

## 11. Open implementation risks (early-task spikes)

Two HA-side unknowns are resolved by short spikes before the dependent code is
built; both have a fixed design contract regardless of the spike outcome.

1. **Pre-hash mechanism** (`register`). Confirm on HAOS how to produce a
   `password_pre_hashed: true` value: the Mosquitto add-on's password tool (e.g.
   `docker exec addon_core_mosquitto mosquitto_passwd` / the add-on `pw` helper)
   invoked from the HA SSH session. Contract: the stored value is pre-hashed and
   `register` verifies a test login before finalizing. Fallback if the add-on
   tool is unreachable from the SSH session: replicate the mosquitto-go-auth
   PBKDF2 hash format in Python. The spike decides which.

2. **HA entity naming** (`status`). Confirm how sensors2mqtt names its HA
   discovery entities so a host can be matched to its sensors (§4.6). Contract:
   `status` classifies presence/freshness from `/api/states` `last_updated`; only
   the host↔entity match pattern depends on the spike.

## 12. Ansible interop contract

For each `local` host the Ansible deployment must compute the **identical**
strings from the shared `sensors2mqtt_mqtt_secret`:

- `inventory_hostname` (the value hashed/embedded) **must equal `<H>` =
  `node_id(host.hostname)`** — i.e. the lowercased, non-alphanumeric→`_` form of
  gdoc2netcfg's `host.hostname` (e.g. `rpi5.iot` → `rpi5_iot`).
- `MQTT_USER = "s2m-" ~ inventory_hostname`
- `MQTT_PASSWORD = (sensors2mqtt_mqtt_secret ~ inventory_hostname) | hash('sha256')`

gdoc2netcfg's `host.hostname` is the single source of truth; Ansible aligns its
`inventory_hostname` to the `node_id` form.
