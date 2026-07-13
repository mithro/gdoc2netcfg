# Tasmota Remote Syslog Capture — Design

Date: 2026-07-12
Status: Approved (brainstorming session "tasmota syslog")

## Goal

Tasmota devices support sending their logs to a remote syslog server
(`LogHost` / `LogPort` / `SysLog <level>` commands). Capture those logs
on the site router (ten64) as per-device files, and teach
`gdoc2netcfg tasmota configure` to push the syslog settings to every
device — with drift detection, per-device level overrides, and
fail-loud resolution of the log target address.

## Non-goals

- Shipping logs anywhere beyond local files on the site router (no
  central aggregation, no HA integration).
- TCP or TLS syslog — Tasmota only speaks plain UDP syslog.
- Monarto rollout (design supports it; enabling is a later, separate
  deployment step).

## 1. Receiver on ten64 (rsyslog)

ten64 already runs Debian's rsyslog 8.x; remote reception is a config
drop-in, no new packages. Two new repo-tracked files under `etc/`:

### `etc/rsyslog-tasmota.conf` → `/etc/rsyslog.d/tasmota.conf`

- Loads `imudp`, listens on UDP 514 on all addresses (`0.0.0.0`).
  ten64 is itself the firewalled site router and every sender is on an
  RFC 1918 VLAN; binding a specific address would make this static
  file site-specific for no real gain.
- The input is bound to a dedicated ruleset, so remote messages are
  fully segregated from local logging — they never reach
  `/var/log/syslog` regardless of facility, and local messages never
  reach the tasmota files.
- The ruleset writes per-device files via a dynamic template:
  `/var/log/tasmota/<hostname>.log`, where `<hostname>` is the
  hostname field of the syslog message (Tasmota fills it with the
  device hostname, e.g. `au-plug-4`). The template uses rsyslog's
  `securepath="replace"` property option so a hostile hostname cannot
  path-escape the log directory (same injection-guard philosophy as
  `utils/dns.py`).
- Files are created `0640 root:adm` (the global settings in
  `rsyslog.conf` already establish this; the template sets dir/file
  create modes explicitly to be self-contained).

### `etc/logrotate-tasmota` → `/etc/logrotate.d/tasmota`

- Pattern `/var/log/tasmota/*.log`: rotated daily, `rotate 14`,
  `compress`, `delaycompress`, `missingok`, `notifempty`, with a
  `postrotate` block running `/usr/lib/rsyslog/rsyslog-rotate` to HUP
  rsyslogd — omfile holds dynafile handles open across renames, so
  without this signal rotated files keep growing and new ones aren't
  created.

### `make deploy-syslog`

New Makefile target following the `deploy-dnsmasq-*` shape:

1. `install -d /var/log/tasmota`
2. Copy both files into place.
3. `systemctl restart rsyslog`
4. Path-scoped etckeeper commits (one per `/etc` path touched), message
   `gdoc2netcfg deploy syslog: <git-describe>`.

`deploy-syslog` is NOT added to the aggregate `deploy` target: that
target regenerates sheet-derived configs, whereas the rsyslog files
are static and change only when this repo changes them. Keeping it
separate mirrors how `deploy` only covers generator outputs.

## 2. Configuration (toml + dataclass)

`[tasmota]` in `gdoc2netcfg.toml` gains three settings, mirrored into
`TasmotaConfig` (`config.py`):

```toml
[tasmota]
mqtt_secret = "..."
syslog_host = "ten64"    # inventory hostname; empty = syslog push disabled
syslog_port = 514
syslog_level = 2         # site default level (0-4); per-device override via sheet
```

- `syslog_host = ""` (the default) disables the feature entirely: no
  syslog fields enter the desired config, no drift is reported.
  Monarto stays off until its local toml opts in.
- `syslog_level` must be 0–4; anything else raises at config load.

## 3. Same-network LogHost resolution

The user-facing config names the log host by **hostname**; the value
pushed to each device is the **IP address on that device's network**.

Resolution is via the `NetworkInventory`, not live DNS:

1. Look up `syslog_host` among inventory hosts (same matching as other
   hostname lookups).
2. Determine the Tasmota device's VLAN from its IP using the existing
   `derivations/vlan.py` IP→VLAN logic.
3. Pick the syslog host's interface whose IP is on that same VLAN.
4. Push that interface's IPv4 address as `LogHost`.

Fail loud (raise) if: the host is not in the inventory, the device IP
maps to no VLAN, or the host has no interface on the device's VLAN.
Never fall back to another interface or to the name itself.

Rationale: deterministic, works offline, per-site and per-VLAN correct
by construction, and log delivery has no DNS dependency at runtime on
the devices.

## 4. Per-device level override

A spreadsheet column **`Syslog Level`**, surfaced through `Host.extra`:

- Blank / absent → site default from `[tasmota] syslog_level`.
- `0`–`4` → override for that device (0 silences one chatty plug while
  leaving the fleet logging).
- Any other value → raise (fail loud, never guess).

## 5. Scan, model, storage (discovery.db schema v8→v9)

The scanner already fetches `Status 0`, whose response includes a
`StatusLOG` section with `SysLog`, `LogHost` and `LogPort`. Changes:

- `supplements/tasmota.py::_parse_tasmota_status()` parses those three
  fields.
- `models/host.py::TasmotaData` gains:
  - `syslog_level: int`
  - `log_host: str`
  - `log_port: int`
- `storage/discovery_db.py`:
  - `_TASMOTA_FIELDS` gains `("syslog_level", int)`,
    `("log_host", str)`, `("log_port", int)`.
  - All three join `_TASMOTA_OPTIONAL_FIELDS` (absent-stays-absent for
    rows written before v9, exactly like `mqtt_count`).
  - `SCHEMA_VERSION` bumps to 9 with `ALTER TABLE tasmota ADD COLUMN`
    upgrade steps.

Deployment note: stop `gdoc2netcfg-reachability.service` before the
first post-pull DB write on prod (known SQLITE_IOERR crash-loop gotcha
during schema upgrades).

## 6. Drift detection and push

`supplements/tasmota_configure.py`:

- A small frozen dataclass `SyslogTarget(ip: str, port: int,
  level: int)` carries the per-device resolved values. A helper
  `resolve_syslog_target(host, inventory, tasmota_config) ->
  SyslogTarget | None` performs the section-3 resolution plus the
  section-4 level override, returning `None` only when the feature is
  disabled (`syslog_host` empty). `compute_desired_config()` gains a
  `syslog: SyslogTarget | None = None` parameter and adds `SysLog`,
  `LogHost`, `LogPort` when it is not None. This keeps
  `compute_desired_config()` pure and inventory-free.
- `_get_current_value()` field map gains
  `SysLog → syslog_level`, `LogHost → log_host`, `LogPort → log_port`.
- All three values are readable from the device, so they flow through
  the normal drift → push path with no special-casing (unlike
  `MqttPassword`).
- Devices scanned before the schema upgrade have no syslog fields in
  the cached scan; they show as drifted and converge on the next
  `tasmota configure` after a fresh scan.

## 7. Tests

- `StatusLOG` parsing (present, absent, partial).
- Desired config with syslog disabled (no syslog keys) and enabled.
- Per-device override: blank → default, valid override, invalid value
  raises.
- Resolution helper: same-VLAN match; unknown host raises; device IP
  with no VLAN raises; host with no interface on the VLAN raises.
- Drift: syslog fields drift/converge; pre-v9 scan data (fields
  absent) reports drift.
- Storage: round-trip with the new fields; v8→v9 migration preserves
  existing rows (new columns NULL → absent in reconstructed docs).

## 8. Docs

- CLAUDE.md: new make target, new toml keys, schema v9 note.
- `gdoc2netcfg.toml.example`: the three new `[tasmota]` keys with
  comments.

## 9. Rollout (welland now, monarto later)

1. Merge branch → main, `git pull` in `/opt/gdoc2netcfg` on welland.
2. `sudo make deploy-syslog` (rsyslog + logrotate live).
3. Add `syslog_host`/`syslog_port`/`syslog_level` to welland's toml.
4. Stop reachability daemon; `sudo .venv/bin/gdoc2netcfg tasmota scan
   --force` (performs v9 migration); restart daemon.
5. `tasmota configure --dry-run --all` — review drift.
6. `tasmota configure --all`; verify files appear under
   `/var/log/tasmota/`.
7. Monarto later: same steps after its toml opts in.
