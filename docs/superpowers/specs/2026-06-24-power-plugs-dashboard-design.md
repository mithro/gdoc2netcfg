# Power Plugs Dashboard — Design

**Status:** approved-pending-review
**Date:** 2026-06-24
**Scope:** Welland only (Home Assistant lives at welland; monarto has no `[homeassistant]`).

## Goal

A standalone Home Assistant dashboard ("Power Plugs") showing every Tasmota smart
plug (au-plug-* and us-plug-*) in one sortable table: identity, reachability,
relay state with a toggle, live load, windowed energy rate/total, and what each
plug powers.

## Background / why

The au-plug/us-plug fleet (~58 devices) already publishes everything we need to
Home Assistant:

- Tasmota MQTT integration → `switch.<topic>` (relay), `sensor.<topic>_energy_*`
  (power W, voltage, current, factor, today/total kWh).
- gdoc2netcfg reachability daemon → `binary_sensor.gdoc2netcfg_<nid>_connectivity`,
  `sensor.gdoc2netcfg_<nid>_default_ipv4`, `_rtt`, etc.

Today there is no single place to see plug state + power together. This dashboard
fills that gap, mirroring the existing reachability and switch-port dashboards.

## Architecture

Extend the existing generator `scripts/ha-create-reachability-dashboard.py` (which
already generates two dashboards) with a **third, standalone** dashboard. Same
proven pattern as the other two:

1. **Generation (Python):** load the pipeline (hosts + Tasmota enrichment), filter
   to plug hosts, bake per-plug *structural* data as JSON into an HTML template.
2. **Runtime (HTML + JS):** the page connects to HA's WebSocket API for **live**
   state (`get_states` + `subscribe_events`/`state_changed`) and periodically calls
   `recorder/statistics_during_period` for the **energy windows**.
3. **Deploy:** `ssh ha "sudo tee"` the HTML to `/config/www/network-power-plugs.html`;
   create/update a standalone Lovelace dashboard (`url_path: power-plugs`,
   title "Power Plugs", icon `mdi:power-plug`) with a single panel iframe view.

New artifacts:

- `scripts/ha-plug-dashboard.html` — new template (mirrors `ha-switch-dashboard.html`).
- New functions in the generator: `_load_plug_hosts()`, `_build_plug_data()`,
  `_generate_plug_html()`, `_ensure_plug_dashboard()`; wire into `main()`.
- New deploy/panel constants (`HA_PLUG_WWW_PATH`, `HA_PLUG_PANEL_URL`).

This is a **separate** dashboard from `network-reachability`; it does not touch the
existing two views.

## Scope / device filter

Plug = a tasmota-enriched host whose machine name matches `^(au|us)-plug-\d+$`.
Both families share an identical HA entity model (verified live: au-plug-10 @ 230 V,
us-plug-1 @ 120 V — same `switch.<topic>` + `sensor.<topic>_energy_*`). One code path
handles both. IR blasters / RF bridges (no relay/energy) are excluded.

## Entity model (per plug)

Two id prefixes are baked per plug:

- `topic` = `node_id(mqtt_topic)` (e.g. `au_plug_10`) — Tasmota entities.
- `nid` = `node_id(hostname)` (e.g. `au_plug_10_iot`) — reachability entities.

| Column data | Source entity |
|---|---|
| Online | `binary_sensor.gdoc2netcfg_{nid}_connectivity` |
| IP | `sensor.gdoc2netcfg_{nid}_default_ipv4` (baked ipv4 as fallback) |
| Relay / toggle | `switch.{topic}` (service `switch.toggle`) |
| Load (W) | `sensor.{topic}_energy_power` (+ `_voltage`/`_current`/`_factor` in tooltip) |
| Energy windows | `sensor.{topic}_energy_total` (kWh, `state_class: total`) via statistics |
| Today (bonus) | `sensor.{topic}_energy_today` |

## Energy rate / total over windows (the one non-trivial part)

Use HA **long-term statistics** — `recorder/statistics_during_period` on each plug's
`sensor.{topic}_energy_total`. Verified working live on au-plug-10.

- **Total over a window = Σ `change`** across that window's buckets (NOT
  `sum_last − sum_first`, which drops the first bucket — verified discrepancy:
  0.553 vs 0.577 kWh over 24 h on au-plug-10).
- **Rate (avg W) = total_kWh / window_hours × 1000.** Cross-checked against HA's
  independent power `mean` (24 W energy-derived vs 24.09 W mean) — consistent.
- HA's `sum` is reset-normalised, so a plug that rebooted mid-window (every cred
  migration reboots it) still reports correct consumption.

Two batched queries (all plugs at once), refreshed every ~60 s:

- `period: "5minute"`, last ~65 min → rolling **5 m** and **1 h** windows.
- `period: "hour"`, last ~25 h → **24 h** window.

Latency: short-term stats compile every 5 min, so windowed numbers lag up to ~5 min
— acceptable, and why "Load" stays on the live `_energy_power` subscription for the
true instantaneous value. 60 s refresh is ample.

## Table columns (sortable, natural-sort)

1. **Plug** — `machine_name`, link `http://ipv4.{fqdn}`
2. **IP** — live ipv4, link `http://ipv4.{fqdn}`
3. **Online** — 🟢/🔴
4. **Power** — 🟢 ON / ⚪ OFF, click to toggle (see safety below)
5. **Load (W)** — live; V/A/PF tooltip
6. **Rate 5m (W)**
7. **Rate 1h (W)**
8. **Rate 24h (W)**
9. **Energy 1h (kWh)**
10. **Energy 24h (kWh)**
11. **Today (kWh)** — bonus
12. **Controls** — `tasmota_data.controls` (what's behind the plug); blank if unrecorded

Optional footer: fleet aggregates (total live load W, total 24 h kWh).

## Controls / toggle safety

Several plugs feed critical infrastructure (au-plug-17 = NBN router, au-plug-47 =
UPS mains, switches). Clicking the Power cell shows a **confirm dialog naming the
plug and what it controls** before calling `switch.toggle`. Prevents an accidental
click taking down infra.

## Robustness (from the 2026-06-24 au-plug-21 entity-id fix)

A manual HA device rename (`name_by_user`) can pollute the expected entity_ids (e.g.
`sensor.au_plug_21_rpiz_dash_1_*`). The generator must NOT blindly assume
`switch.{topic}` / `sensor.{topic}_energy_power` exist:

- At generation, **verify** each plug's `switch.{topic}` and
  `sensor.{topic}_energy_power` appear in the fetched HA states.
- On a miss, **warn loudly** to stderr (and, where possible, resolve the real id via
  the device's MAC) — never silently bake a dead entity_id. (Fail-loud, per
  CLAUDE.md.)

## Error handling / edge cases

- Offline / `unavailable` → blank Load, "—" for windows; row de-emphasised.
- Plug with no energy sensors → energy columns blank (no fabricated values).
- Empty statistics (new plug) → blank windows.
- Counter reset / midnight rollover → handled by HA `sum`/`change`.
- WebSocket drop → auto-reconnect (as existing dashboards do).

## Testing

The generator currently has **no** unit tests. Add focused pytest coverage for the
new **pure** functions (plug filter, `_build_plug_data` structural JSON, entity-id
verification/warning), loading the dash-named script via `importlib`. HTML/JS is
verified manually on the deployed dashboard, consistent with the existing two
dashboards (which have no JS tests).

## Deployment

`uv run scripts/ha-create-reachability-dashboard.py` continues to generate all
dashboards. The new standalone Power Plugs dashboard appears as its own sidebar
entry. Regeneration is only needed when plug *structure* changes (plugs added /
removed / re-scoped); live state and energy update at runtime via WebSocket.

## Out of scope / future

- Monarto (no HA there).
- Per-plug history charts / graphs (the windows are point-in-time numbers).
- Editing the sheet's `Controls` column from the dashboard (relates to #21).
- Bulk on/off actions.

## Open questions

None blocking. The column grouping (separate rate/energy columns vs combined) and
the bonus "Today" column are easy to adjust during implementation.
