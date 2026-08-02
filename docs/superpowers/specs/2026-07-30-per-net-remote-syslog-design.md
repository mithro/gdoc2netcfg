# Per-Net Remote Syslog Design

**Date:** 2026-07-30
**Status:** Approved (user-reviewed brainstorm; this document records the design)
**Repos:** `gdoc2netcfg` (receive side, generator + deploy + migration),
`gwifi-openwrt` (push side, OpenWISP base template)

## Problem

Remote syslog capture on the site routers (ten64s) grew ad hoc, one
device class at a time:

- Tasmota IoT devices → wildcard UDP 514 → `/var/log/tasmota/<hostname>.log`
  (`etc/rsyslog-tasmota.conf`, hand-written).
- Network switches + wisp's own syslog → UDP 10514 →
  `/var/log/network/<hostname>.log` (`z-network-switches.conf`, hand-written,
  welland-deployed).
- WiFi devices (gale pucks, tenwrt): OpenWrt `logd` is pointed at
  **wisp:6666** by a shell stanza in the `ansells-aps-base` OpenWISP
  template's post-reload-hook (delivered by wisp; defined in
  `openwisp/build-templates.py`) — the flashed image itself sets no
  syslog config. That port is `netconsole_rx`, the
  kernel-panic/printk receiver — so device *syslog* and raw kernel
  *netconsole* currently mix into per-source-IP files under
  `/var/log/gale-netconsole/` with no rotation and no hostname keying.
- OpenMesh APs and monarto: no syslog capture story at all.

Each new class so far meant a new port, a new hand-written rsyslog file,
and a new logrotate file — and the set of nets is site data the pipeline
already knows.

## Design

### Classification rule

**One well-known port (514/UDP) on every serving net; the class is the
net the message arrives on.** The router has a distinct leg address per
VLAN, and rsyslog's `imudp` supports one `input()` per local address on
a shared port, each bound to its own ruleset. Messages arriving on the
`<net>` leg are written to `/var/log/<netname>/<hostname>.log`.

Served nets: every leaf net **except `tmp` and `guest`** (untrusted).
Non-leaf nets (wg, transit VLANs, delegated nets) are never served.
Concretely today: welland = net, pwr, store, wifi, iot, roam, int, sm;
monarto = net, pwr, store, wifi, iot, roam, int. These lists are
illustrative — the derivation from the router's actual legs is
authoritative, and live verification checks the emitted set per site.

### Receive side: a new `rsyslog` generator (gdoc2netcfg)

`src/gdoc2netcfg/generators/rsyslog.py`, generator key `rsyslog`, enabled
on both sites. Output keys are deploy-relative paths mirroring `/etc`
(the DNS-stack convention):

- `etc/rsyslog.d/remote-logs.conf` — for each served net:

  ```
  template(name="RemoteLog-<net>" …
           string="/var/log/<net>/%hostname:::secpath-replace%.log")
  ruleset(name="remote-<net>") { action(omfile dynaFile …) stop }
  input(type="imudp" port="514" address="<leg-v4>" ruleset="remote-<net>")
  ```

  plus, at the top, the single `module(load="imudp")` (this file REPLACES
  `tasmota.conf` and `z-network-switches.conf`, which today share that
  load), and ONE transition input:
  `input(type="imudp" port="10514" ruleset="remote-net")` so existing
  switch/wisp senders keep logging (into `/var/log/net/`) until they are
  re-pointed at `<net-leg>:514`. Dropping 10514 is a documented follow-up,
  not part of this work.

  > **Status 2026-08-02 — the transition input has been REMOVED.** Every
  > sender it existed for was re-pointed: wisp to `10.1.4.1:514` on
  > 2026-08-01, and all five CLI-capable switches (welland's two m4300s
  > and two gsm7252ps, monarto's gs728tpp) to their net leg `:514` on
  > 2026-08-02. Two independent tcpdump captures totalling 300s saw zero
  > packets on 10514 before removal. The generator no longer emits it, and
  > a `net` leg is consequently no longer required.

- `etc/logrotate.d/remote-logs` — one stanza per `/var/log/<net>/*.log`
  with the existing 1-year-floor policy verbatim (daily, rotate 400,
  compress, delaycompress, missingok, notifempty, rsyslog-rotate
  postrotate).

Leg addresses are derived from the router's own interfaces in inventory
— the same rule `recursor_forward._leaf_gateways()` uses (ROUTER_HOSTNAME
interfaces → `ip_to_net`), filtered by the tmp/guest exclusion, **v4
only** (every current sender targets v4). A net where the router has no
leg gets no input, so both sites come out right from one code path. The
shared derivation is refactored into a helper both generators call
rather than duplicated.

File-safety properties carried over unchanged from the existing files:
remote messages only reach the per-device files (ruleset isolation +
`stop`), never `/var/log/syslog`; local messages never reach the remote
dirs; `secpath-replace` prevents hostile hostnames escaping the
directory; `omfile` `fileOwner root`/`fileGroup adm`/`0640`/dirs `0755`
(dynafile dir auto-creation — no `install -d` needed per net).

Binding to specific leg addresses is safe at boot: all leg addresses are
configured with `ConfigureWithoutCarrier=yes`, so they exist regardless
of link state when rsyslog starts.

### Effect on existing senders (no device changes except where noted)

| Sender | Today | After |
|---|---|---|
| Tasmota devices | `10.X.90.1:514` (already leg-targeted by `tasmota configure`) → `/var/log/tasmota/` | unchanged target → `/var/log/iot/` |
| Switches | `ten64:10514` → `/var/log/network/` | unchanged (transition input) → `/var/log/net/`; ops follow-up re-points them to `10.X.5.1:514` |
| wisp (`90-forward-ten64.conf`) | `10.1.4.1:10514` → `/var/log/network/wisp.log` | re-point to `10.1.4.1:514` → `/var/log/wifi/wisp.log` (wisp lives on the wifi net; one-line hand-config edit, part of rollout) |
| Pucks + tenwrt `logd` | wisp:6666 (mixed into netconsole) | site wifi leg `10.X.4.1:514` → `/var/log/wifi/` (via OpenWISP, below) |
| Kernel netconsole (pucks) | wisp:6666 (`netconsole_rx`) | **untouched** — crash forensics stays on wisp, now unpolluted by syslog |

### Push side: OpenWISP base template (gwifi-openwrt)

- The `uci set system.@system[0].log_ip/log_port/log_proto` stanza in
  the `ansells-aps-base` template's post-reload-hook
  (`openwisp/build-templates.py`) **stops hardcoding wisp:6666** — the
  image needs no syslog config; adoption by wisp is what configures
  logging (user decision).
- The `ansells-aps-base` template gains the equivalent as OpenWISP
  *configuration*: `log_ip = {{ syslog_ip }}` (template default context
  `syslog_ip = "10.1.4.1"`, overridable per device/group for any future
  monarto-managed device), `log_port = 514`, `log_proto = udp`. Respect
  the known netjsonconfig ordering gotcha: the default context must be
  defined on the template before devices render, or the literal
  `{{ syslog_ip }}` string ships to devices.
- Rollout: re-run `build-templates.py` against wisp (precondition: check
  the standing MT7915 single-phy / two-radio-attach caveat noted in the
  fleet docs before any re-run), push to the 12 pucks + tenwrt. OpenMesh
  units get nothing today; they inherit the base template whenever they
  are adopted.

### One-off migration of the old directories (per site)

A migration script in gdoc2netcfg (`scripts/migrate-remote-syslog.py`,
run once per site with sudo, idempotent, skip-if-absent with loud
per-step output — never silent):

1. Move contents (live + rotated archives) of `/var/log/tasmota/` →
   `/var/log/iot/` and `/var/log/network/` → `/var/log/net/`; remove the
   emptied old directories. Hostnames are unique across the fleet, so no
   filename collisions; the script still refuses (fail-loud) on any
   would-overwrite conflict.
2. Remove the superseded configs: `/etc/rsyslog.d/tasmota.conf`,
   `/etc/rsyslog.d/z-network-switches.conf`, `/etc/logrotate.d/tasmota`,
   plus any hand-deployed network-class logrotate file if one exists
   (the script checks `/etc/logrotate.d/` and reports what it found).
3. Leave restarting rsyslog and installing the new files to
   `make deploy-syslog` (below) — the documented sequence is
   migrate → deploy, and the script says so.

`make deploy-syslog` is rewritten to deploy the generated pair
(`generate rsyslog --output-dir out`, copy the two files, restart
rsyslog, path-scoped etckeeper commit covering the added AND removed
files). `etc/rsyslog-tasmota.conf` and `etc/logrotate-tasmota` are
deleted from the repo. CLAUDE.md's "Tasmota remote syslog" section is
rewritten around the per-net scheme (it also currently misstates the
retention as 14 days vs the actual rotate-400 policy — fixed as part of
the rewrite).

Ordering within the rollout window: migrate + deploy back-to-back on
each site. Between old-config removal and rsyslog restart there is a
sub-minute capture gap (UDP, fire-and-forget — same loss model the
system already accepts when rsyslog restarts today).

### Out of scope

- Re-pointing the switches to `10.X.5.1:514` and dropping the 10514
  transition input (ops follow-up).
- Any change to kernel netconsole / `netconsole_rx`.
- Log shipping/aggregation beyond per-device files.

## Testing

**gdoc2netcfg (TDD):** generator unit tests — per-net input/ruleset/
template emission from a two-site-style fixture; tmp/guest/wg/transit/
delegated exclusion; v4-only; single `module(load)` line; the 10514
transition input targets `remote-net`; secpath template string; logrotate
stanzas match the 1-year policy; a router with no leg on a net emits no
input. Migration script tests with a tmp-dir filesystem fixture (moves,
idempotency, conflict refusal). Full suite + ruff.

**gwifi-openwrt:** extend the template-builder tests for the base-template
syslog config (rendered values, context default present) and for the
bootstrap script no longer containing the `log_ip` stanza.

**Live verification (per site):** `logger` test message from a puck lands
in `/var/log/wifi/<puck>.log`; a Tasmota device's next message lands in
`/var/log/iot/`; switch messages continue into `/var/log/net/` via 10514;
`/var/log/syslog` gains no remote lines; nothing new appears under
`/var/log/gale-netconsole/` from `logd` (netconsole printk lines still
do); wisp's forward lands in `/var/log/wifi/wisp.log`.

## Alternatives considered

- **Per-class ports** (514 tasmota / 10514 network / 20514 wifi, wildcard
  binds): rejected — a new magic port per class, and classification by
  device type rather than by network doesn't match the per-net-leaf
  architecture the sites now run.
- **Devices → wisp relay → ten64**: rejected — extra hop, welland-only
  (no wisp at monarto), and keeps fleet syslog entangled with the
  netboot/crash-forensics box.
- **Static per-site rsyslog files in `etc/`**: rejected — the input set
  is pure site data (nets × router legs) that the pipeline already
  derives; hand-maintained per-site files would drift.
