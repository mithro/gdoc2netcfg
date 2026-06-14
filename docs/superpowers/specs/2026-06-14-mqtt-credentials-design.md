# MQTT credential issuer (sensors2mqtt + Tasmota) — design

**Date:** 2026-06-14
**Status:** Design (pre-implementation, pending user review)
**Tasks:** #28 (issue per-host credentials); #29 (future: per-user IP restrictions)
**Requirements:** `docs/sensors2mqtt-mqtt-credentials-requirements.md` (sensors2mqtt consumer; the Tasmota consumer was added in the 2026-06-14 brainstorm)

## 1. Summary

A shared, consumer-agnostic **MQTT credential core** that issues a deterministic
per-host `(username, password)` from a per-consumer secret and registers those
logins — **pre-hashed** — on the Home Assistant Mosquitto broker. Two consumers
ride on the core:

- **sensors2mqtt** — the ~30 welland RPi collectors + ten64 + polled
  servers/switches. Delivery: per-host `0600` systemd `EnvironmentFile`s (and
  Ansible recomputes them independently).
- **Tasmota** — the IoT smart plugs. Delivery: per-device `MqttUser`/
  `MqttPassword` pushed over the existing HTTP `configure` path, replacing
  today's single shared credential.

gdoc2netcfg is the natural home: it owns the host inventory, already generates
config, already holds MQTT/HA credentials and an HA SSH path, and already
manages Tasmota devices.

## 2. Background / motivation

**sensors2mqtt (the original driver).** The HA Mosquitto add-on (v7.1.0,
mosquitto 2.1.2 + mosquitto-go-auth 3.0.0) now rejects anonymous connections.
The collectors connect with **empty credentials** and are being locked out as
grandfathered TCP sessions drop (≥11 RPis already offline). No sensors2mqtt code
change is needed — sensors2mqtt's own `MqttConfig.from_env()` (a class in the
sensors2mqtt repo, distinct from the gdoc2netcfg `MqttConfig` dataclass below)
already reads `MQTT_USER`/`MQTT_PASSWORD`; the missing piece is *issuing and
delivering credentials*.

**Tasmota (blast-radius).** Every Tasmota device currently shares one
`MqttUser`/`MqttPassword` (`tasmota_configure.compute_desired_config`). Tasmota's
own security guide is explicit: *"To minimize the impact EVERY and really EVERY
device must have a unique USER and a unique password."* A shared credential means
one compromised plug yields the credential for all of them — and Tasmota
passwords are recoverable from a device (config backup → `decode-config.py`).
Per-device credentials limit the blast radius to a single device.

The two needs share the entire credential mechanism (derive → register
pre-hashed) and differ only in delivery, so they are built as one core with two
thin adapters.

## 3. Decisions (from brainstorm)

1. **Generalize:** one shared credential core + per-consumer adapters (not two
   parallel implementations).
2. **Separate secrets:** `[sensors2mqtt] mqtt_secret` and `[tasmota] mqtt_secret`
   — fully partitions the low-trust IoT-device key domain (cleartext-HTTP
   delivery, flash-recoverable) from the collector domain. sha256
   preimage-resistance already blocks cross-derivation; separate secrets are
   defense-in-depth.
3. **Password scheme:** `password = sha256(secret + <id>)` → 64-char lowercase
   hex. Kept over HMAC to preserve the stock-Ansible one-liner; see §7 for the
   crypto rationale and why length-extension is non-exploitable here.
4. **Canonical host key `<id> = node_id(host.hostname)`** for both username and
   password. `host.hostname` is always unique (a BMC and its parent share
   `machine_name` but not `hostname`). `node_id` makes it MQTT-safe.
5. **Username prefixes:** `s2m-<id>` and `tas-<id>` — distinct broker accounts;
   the prefix also scopes each consumer's broker merge (§4.6).
6. **High-entropy secret is a hard requirement.** Both secrets MUST be
   high-entropy random (`openssl rand -hex 32` → 256-bit); `env`/`register`/
   `configure` fail loud on an empty or trivially-short secret. This is the
   actual linchpin of the scheme's security (§7).
7. **Broker pre-hashing:** logins stored `password_pre_hashed: true` —
   mosquitto-go-auth PBKDF2-SHA512 (16-byte salt, 100k iters). Plaintext never
   lands in the add-on options/backups.
8. **sensors2mqtt selection:** spreadsheet column `sensors2mqtt` =
   `local` / `remote` / blank (§4.3).
9. **Tasmota selection:** no new column — Tasmota-ness is derivable from
   last-known scan data, which persists for offline devices (§4.4).
10. **Shared-login retirement is manual:** the old Tasmota shared login is
    removed only after 100% of devices have migrated (offline devices block it)
    — never auto-pruned mid-migration.
11. **SDR Pis (`rpi-sdr-*`):** excluded (blank) — left on their own broker.
12. **Future (#29):** per-user source-IP restrictions on the broker; per-user
    topic ACLs (requirements §11.5). Out of scope here.

## 4. Architecture

### 4.1 Module layout

**Shared core (consumer-agnostic):**
- **`utils/mqtt.py`** — `node_id(name)` promoted from `supplements/mqtt_ha.py`'s
  private `_node_id` so both `mqtt_ha.py` and the new code share one transform
  that cannot drift (update `mqtt_ha.py`'s call sites; no alias).
- **`derivations/mqtt_credentials.py`** — pure, unit-tested: `credential_key`,
  `username`, `password`, `check_collisions`, `require_strong_secret`.
- **`supplements/mqtt_broker.py`** — the side-effecting HA/Supervisor
  integration: `register_logins(...)` (SSH → Supervisor API, pre-hash, merge,
  restart) shared by both consumers, plus the HA sensor query used by
  sensors2mqtt `status`.

**sensors2mqtt adapter:**
- **`derivations/sensors2mqtt.py`** — host selection (sheet column), env-file
  rendering, `build_logins(secret, hosts)`.
- **`cli/main.py`** — `cmd_sensors2mqtt` (`list`/`env`/`register`/`status`) +
  argparse.

**Tasmota adapter:**
- **`supplements/tasmota_configure.py`** — `compute_desired_config` derives
  per-device creds via the core (existing module, modified).
- **`cli/main.py`** — new `tasmota register-broker` sub-action; `tasmota
  configure` passes the secret.

**Config:**
- **`config.py`** — new shared `MqttConfig` (`[mqtt]`: host/port/ha_ssh_host) +
  `Sensors2mqttConfig`; `TasmotaConfig` reduces to `mqtt_secret` (host/port move
  to the shared `[mqtt]` section; user/password dropped).

### 4.2 Credential derivation (pure core)

```python
# utils/mqtt.py
def node_id(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()

# derivations/mqtt_credentials.py
def credential_key(host) -> str:                 # <id>
    return node_id(host.hostname)

def username(prefix: str, host) -> str:
    return f"{prefix}{credential_key(host)}"

def password(secret: str, host) -> str:
    return hashlib.sha256((secret + credential_key(host)).encode()).hexdigest()
```

- The password is prefix-independent (`sha256(secret + <id>)`); the username
  carries the prefix. With separate secrets the same `<id>` would still yield
  different passwords per consumer — but identities never overlap anyway
  (distinct hosts).
- **Collision guard** (`check_collisions`): `node_id` is not injective. Before
  issuing/registering, build the `{<id>: host}` map for the in-scope set and
  **fail loud** if two distinct hosts collide.
- **Strong-secret guard** (`require_strong_secret`): reject an empty or
  trivially-short secret (hard floor of 32 characters; recommend
  `openssl rand -hex 32` = 64 chars / 256-bit). Called by every command that
  derives a password.
- The secret is never logged; passwords are emitted only inside `0600` env-file
  content (and `env --stdout`, an explicit operator action) and the Tasmota push
  (masked in logs, as today).

### 4.3 sensors2mqtt selection — sheet column `sensors2mqtt`

| Value | Meaning | Credential? | HA check? |
|---|---|---|---|
| `local` | sensors2mqtt **runs on** this host | yes — username/password + env file + broker login | yes |
| `remote` | a collector **elsewhere** polls this host (SNMP/IPMI) | no | yes |
| blank | not involved | no | no |

- Read from `host.extra["sensors2mqtt"]` (case-insensitive, stripped). An
  unrecognized non-blank value → hard error (never silently skipped).
- Issuance (`env`, `register`) acts on `local` hosts; `status` on all non-blank
  hosts.
- Initial population is a one-off assisted operator step (compute the in-scope
  set from current inventory and write the column via the service-account sheet
  path, or hand the operator a paste-ready list).

### 4.4 Tasmota selection — last-known scan data (no column)

Tasmota credential targets = hosts with `host.tasmota_data` after enrichment
from `load_latest_tasmota()`. The discovery DB is a delta store, so the latest
reconstruction retains **last-known state for currently-offline devices** — a
plug that is unplugged still appears, so it still gets a registered login and
will authenticate when it returns. This mirrors the existing `configure`
selection (`host.tasmota_data is not None`); a brand-new never-scanned device is
picked up after the next `tasmota scan`.

### 4.5 sensors2mqtt `env` — per-host EnvironmentFile

For each `local` host:

```ini
MQTT_HOST=ha.welland.mithis.com
MQTT_PORT=1883
MQTT_USER=s2m-<id>
MQTT_PASSWORD=<sha256(secret+<id>) hex>
```

`MQTT_HOST`/`MQTT_PORT` come from the shared `[mqtt]` (`MqttConfig`).
`--stdout` prints for review; otherwise files are written `0600` to a secure dir
(default `<cache.directory>/sensors2mqtt/` — never the world-readable generated
tree). `--host <name>` renders one host. The RPis' files are produced for parity;
Ansible recomputes identical content from the vault secret and installs
`/etc/sensors2mqtt/env` (`0600 root`). ten64's own file can be installed
directly.

### 4.6 `register_logins` — shared broker core

Reaches the HA Mosquitto add-on over the **existing HA SSH path**
(`ssh <ha_ssh_host> …`, as the dashboard deployer does); inside, the Supervisor
API (`http://supervisor/…`) is reachable with `SUPERVISOR_TOKEN`.

`register_logins(ha_ssh_host, prefix, logins: dict[str, str], dry_run: bool, prune: bool = False)`:

1. `GET /addons/core_mosquitto/info` → current `options.logins`.
2. Pre-hash each supplied plaintext (`password_pre_hashed: true`) via the
   add-on's password tool on the HA side (§11 spike).
3. **Merge:** keep every existing login whose username does **not** start with
   `prefix` (so core logins — `gdoc2netcfg`, `tweed-bridge`, `DVES_USER` — and
   the *other* consumer's prefix are untouched); upsert each supplied login. With
   `prune=True`, also drop `prefix`-logins not in `logins` (cleanup for removed
   hosts); the default leaves them.
4. `POST /addons/core_mosquitto/options` with the merged `logins`.
5. Restart (`POST /addons/core_mosquitto/restart`).

- `--dry-run` prints the username add/keep/(prune) diff (no passwords) and
  performs no POST/restart — this makes the cutover (§8) reviewable.
- Read-modify-write is atomic; any SSH/Supervisor failure aborts before POST (no
  partial apply). Plaintext crosses via **stdin** only, never argv/logs.
- Both `sensors2mqtt register` (prefix `s2m-`) and `tasmota register-broker`
  (prefix `tas-`) call this; each only ever touches its own prefix.

### 4.7 sensors2mqtt `status` — HA sensor presence + freshness

For each non-blank host, query HA REST (`GET /api/states`, `[homeassistant]
url` + `token`, the same integration `tasmota ha-status` uses) and report
**fresh** (matching entities updated within `freshness_seconds`), **stale**
(older), or **missing**. Review table keyed by hostname; no secrets. This is the
post-cutover acceptance check and the standing health view for `remote`-polled
hosts. Host↔entity correlation matches a host's `<id>`/`hostname` in the entity's
`entity_id` or device identifiers; the exact pattern is confirmed by a spike
(§11), while classification (`last_updated` vs window) and the table are
independent of it. (Tasmota has its own `tasmota ha-status`; no new status path
is added for it.)

### 4.8 Tasmota `configure` + `register-broker`

- `compute_desired_config(host, mqtt_config, tasmota_config)` now sets
  `MqttHost`/`MqttPort` from the shared `MqttConfig`, and
  `MqttUser = username("tas-", host)` /
  `MqttPassword = password(tasmota_config.mqtt_secret, host)` instead of the
  removed shared credential keys. Everything else (drift detection, the
  write-only-`MqttPassword` handling, the `MqttCount==0` re-push) is unchanged —
  and because `MqttUser` *is* readable, the migration from the old shared user to
  `tas-<id>` is detected as drift and pushed automatically.
- New `tasmota register-broker [--dry-run] [--prune]` builds
  `{tas-<id>: password(...)}` for all known Tasmota devices and calls
  `register_logins(..., "tas-", …)`.

### 4.9 Configuration

Broker connection details (host, port, SSH target) are shared in one `[mqtt]`
section; the per-consumer sections hold only what is consumer-specific.

```toml
[mqtt]
host = "ha.welland.mithis.com"         # broker host for client connections (MQTT_HOST / MqttHost)
port = 1883                            # broker port (MQTT_PORT / MqttPort)
ha_ssh_host = "ha.welland.mithis.com"  # SSH target for pre-hashed login registration
# add-on slug (core_mosquitto) is a constant in mqtt_broker.py

[sensors2mqtt]
mqtt_secret = "..."                    # high-entropy (openssl rand -hex 32); 0600 toml + Ansible vault
freshness_seconds = 900

[tasmota]
mqtt_secret = "..."                    # high-entropy; host/port now come from [mqtt]
```

A shared `MqttConfig` (`[mqtt]`: `host` / `port` / `ha_ssh_host`) plus
`Sensors2mqttConfig` follow the existing dataclass pattern (`TasmotaConfig`,
`HomeAssistantConfig`): dataclass defaults are the single source of truth, only
present keys override. `TasmotaConfig` reduces to `mqtt_secret` — its former
`mqtt_host`/`mqtt_port` move to the shared `[mqtt]` section and
`mqtt_user`/`mqtt_password` are dropped (dead-code removal per project policy).
The shared *broker* login is retired separately (§8). Every command that
connects a client or registers a login reads the broker params from `MqttConfig`.

## 5. Data flow

```
derive (pure, per consumer):
  <secret> + host.hostname ──node_id──► <id> ──► (<prefix>-<id>, sha256(secret+<id>))

sensors2mqtt env:
  local hosts ──► EnvironmentFile ──► 0600 files / stdout
                                      └─ Ansible recomputes + installs on RPis

register (HA SSH, shared core, per prefix):
  {<prefix>-<id>: plaintext} ──stdin──► HA: pre-hash (PBKDF2) ──► merge (preserve others)
                                        ──► POST options ──► restart add-on

tasmota configure (HTTP, per device):
  per-device (tas-<id>, sha256) ──► http://<ip>/cm?cmnd=MqttUser/MqttPassword ──► device restart

sensors2mqtt status (HA REST):
  non-blank hosts ──► /api/states ──► fresh / stale / missing
```

## 6. Error handling (fail loud)

- Empty/short secret → error (strong-secret guard), per consumer.
- Unrecognized `sensors2mqtt` column value → error.
- `node_id` collision among in-scope hosts → error.
- SSH/Supervisor/HA failure → error; no partial broker apply; `register` verifies
  the POST succeeded before restart; pre-hash failure for any host aborts the
  whole register (never a subset).
- Tasmota: `configure` already fails loud per device; `register-broker` aborts
  atomically like `register`.

## 7. Security

**Two hashing layers, treated correctly:**

- **Storage (broker):** mosquitto-go-auth PBKDF2-SHA512, 16-byte random salt,
  100k iters, per login — the password-at-rest is salted + stretched. Plaintext
  never appears in add-on options/backups.
- **Derivation (`sha256(secret+<id>)`):** a deterministic KDF, not password
  storage. A *random* salt is deliberately **not** used — it would break the
  stateless recompute that Ansible and Tasmota re-derivation depend on. `<id>` is
  the deterministic per-host differentiator; `secret` carries the entropy. The
  output is effectively a 256-bit token (no guessable human password to
  rainbow-table) **provided `secret` is high-entropy** — enforced by the
  strong-secret guard (the real linchpin). `H(secret‖msg)` is length-extension-
  prone in general, but it is non-exploitable here: usernames are unhashed and
  identities are constrained to `node_id` form, so a length-extension forgery
  maps to no registered account. (HMAC was considered and declined to keep the
  stock-Ansible expression; see §12.)

**Other:**

- Secrets only in `0600 gdoc2netcfg.toml` (+ Ansible vault for sensors2mqtt);
  never written to hosts (only the derived per-host password is); never logged.
- Separate secrets partition the IoT-device domain from the collector domain.
- sensors2mqtt env files `0600`, outside the cron `generate` tree. The Tasmota
  plaintext push is cleartext HTTP on the segregated IoT VLAN (unchanged from
  today; per-device creds strictly improve on the shared credential) and is
  masked in logs.
- Broker merge preserves HA core MQTT, `gdoc2netcfg`, `tweed-bridge`,
  `DVES_USER`, and the other consumer's logins.
- **Future (#29):** restrict each login to its host's source IP so an extracted
  credential cannot be replayed from elsewhere.

## 8. Cutover ordering

**Both consumers: register-first** (the broker restart drops grandfathered
sessions, so the new logins must exist before consumers reconnect).

**sensors2mqtt:** generate + distribute env to **all** local hosts (collectors
not yet restarted) → `register` → restart **ten64 + one canary Pi**, confirm via
`status` → restart the rest → reconcile with `status`.

**Tasmota:** `register-broker` (old shared login left intact) → `configure --all`
(devices restart onto `tas-<id>`; `MqttUser` drift drives the migration) →
confirm all connected via `tasmota scan`/`show` (`MqttCount>0`) or `ha-status` →
**only once 100% migrated**, retire the old shared login from the broker (manual;
any device still offline is still on it). Precondition: the current shared
`MqttUser` must not start with `tas-` (else the prefix-merge would treat it as
managed).

## 9. Testing

- **Derivation (golden vectors):** known `secret` + `hostname` → exact hex;
  username format per prefix; BMC vs parent produce distinct values; collision
  raises; strong-secret guard rejects empty/short.
- **sensors2mqtt selection:** `local`/`remote`/blank → correct inclusion across
  env/register/status; unrecognized raises; case/whitespace normalization.
- **Tasmota selection:** hosts with last-known `tasmota_data` are included
  (including an offline/last-known fixture); non-Tasmota hosts excluded.
- **Env rendering:** exact bytes incl. config-driven host/port; single-host
  `--host`; output mode `0600`.
- **`register_logins` (mocked SSH/transport):** preserves core + other-prefix
  logins; upserts own prefix; idempotent (no dupes/drops); `--prune` drops only
  stale own-prefix logins; `--dry-run` performs zero side effects and prints no
  passwords; pre-hash failure aborts cleanly. Parametrised over `s2m-`/`tas-`.
- **Tasmota `compute_desired_config`:** derives per-device `MqttUser`/
  `MqttPassword`; an old-shared-user device shows `MqttUser` drift to `tas-<id>`.
- **status (mocked HA):** fresh/stale/missing classification incl. the freshness
  boundary; no secrets in output.
- Full `uv run pytest` green; `uv run ruff check src/ tests/` clean.

## 10. Out of scope / non-goals

- Host-side env distribution to the RPis (Ansible owns it) and sensors2mqtt's
  systemd `EnvironmentFile` wiring.
- The actual on-broker removal of the old Tasmota shared login (manual operator
  step, §8).
- SDR Pis / their separate broker.
- **Per-user source-IP restrictions (#29)** and per-user topic ACLs
  (requirements §11.5) — future.
- Secret rotation tooling (rotation = change the secret + (for sensors2mqtt) the
  Ansible vault, re-run `env`/`register` or `register-broker`+`configure`, then
  redeploy; documented, not automated).

## 11. Open implementation risks (early-task spikes)

1. **Pre-hash mechanism** (`register_logins`). Confirm on HAOS how to produce a
   `password_pre_hashed: true` value from the HA SSH session: the Mosquitto
   add-on's password tool (e.g. `docker exec addon_core_mosquitto …` / the add-on
   `pw` helper). Contract: the stored value is pre-hashed and `register` verifies
   a test login before finalizing. Fallback if the add-on tool is unreachable:
   replicate the mosquitto-go-auth PBKDF2-SHA512 format in Python. The spike
   decides which.
2. **HA entity naming** (sensors2mqtt `status`). Confirm how sensors2mqtt names
   its HA discovery entities so a host matches its sensors (§4.7). Contract:
   `status` classifies presence/freshness from `/api/states` `last_updated`; only
   the host↔entity match pattern depends on the spike.

## 12. Ansible interop contract (sensors2mqtt)

For each `local` host the Ansible deployment must compute the **identical**
strings from the shared `sensors2mqtt_mqtt_secret`:

- `inventory_hostname` (the value hashed/embedded) **must equal `<id>` =
  `node_id(host.hostname)`** — the lowercased, non-alphanumeric→`_` form of
  gdoc2netcfg's `host.hostname` (e.g. `rpi5.iot` → `rpi5_iot`).
- `MQTT_USER = "s2m-" ~ inventory_hostname`
- `MQTT_PASSWORD = (sensors2mqtt_mqtt_secret ~ inventory_hostname) | hash('sha256')`

gdoc2netcfg's `host.hostname` is the single source of truth; Ansible aligns its
`inventory_hostname` to the `node_id` form. (Tasmota needs no Ansible interop —
gdoc2netcfg pushes its credentials to the devices directly.)
