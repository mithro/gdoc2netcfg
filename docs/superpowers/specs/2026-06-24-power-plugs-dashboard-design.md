# Power Plugs Dashboard — Design

**Status:** design locked to mockup; ready for implementation plan
**Date:** 2026-06-24
**Scope:** Welland only (Home Assistant lives at welland; monarto has no `[homeassistant]`).

## Visual reference (source of truth)

The look, columns, icons, colours, and number formatting are pinned by a **mockup**
built from real fleet data (committed alongside this spec):

- `2026-06-24-power-plugs-dashboard-mockup.html` — the rendered mockup. Its markup
  and inline CSS are the **exact reference** the implementation's HTML template
  should mirror.
- `2026-06-24-power-plugs-dashboard-mockup.png` — screenshot of the above.
- `2026-06-24-power-plugs-dashboard-mockup.gen.py` — the **prototype generator**.
  Not the deliverable (it has hard-coded paths and reads live HA/sheet data
  directly), but it documents the exact data-derivation logic the real generator
  must reproduce: entity-id derivation, the `Σchange` energy windows, last-seen
  from recorder history, host-directory control resolution, the relay-aware icon
  matrix, the greyed-zero rule, and decimal alignment.

When this prose and the mockup disagree, **the mockup wins** — update the prose.

## Goal

A standalone Home Assistant dashboard ("Power Plugs") showing every Tasmota smart
plug (au-plug-\* and us-plug-\*) in one sortable table: identity, reachability,
relay state with a toggle, live load, windowed energy rate/total, and what each
plug powers (with each controlled device's live state).

## Background / why

The au-plug/us-plug fleet (~58 devices) already publishes everything we need to HA:

- Tasmota MQTT integration → `switch.<topic>` (relay), `sensor.<topic>_energy_*`
  (power W, voltage, current, factor, today/total kWh).
- gdoc2netcfg reachability daemon → `binary_sensor.gdoc2netcfg_<nid>_connectivity`,
  `sensor.gdoc2netcfg_<nid>_default_ipv4`, `_rtt`, and `sensor.gdoc2netcfg_host_directory`.

No single place shows plug state + power + what-it-powers together. This dashboard
fills that gap, mirroring the existing reachability and switch-port dashboards.

## Architecture

Extend the existing generator `scripts/ha-create-reachability-dashboard.py` (already
generates two dashboards) with a **third, standalone** dashboard. Same proven pattern:

1. **Generation (Python):** load the pipeline (hosts + Tasmota enrichment), filter to
   plug hosts, bake per-plug *structural* data as JSON into an HTML template.
2. **Runtime (HTML + JS):** connect to HA's WebSocket for **live** state
   (`get_states` + `subscribe_events`/`state_changed`); call
   `recorder/statistics_during_period` for the **energy windows**; call
   `history/history_during_period` for offline **last-seen**.
3. **Deploy:** `ssh ha "sudo tee"` the HTML to `/config/www/network-power-plugs.html`;
   create/update a standalone Lovelace dashboard (`url_path: power-plugs`, title
   "Power Plugs", icon `mdi:power-plug`) with a single panel iframe view.

New artifacts: `scripts/ha-plug-dashboard.html` (template, mirrors the mockup);
generator functions `_load_plug_hosts()` / `_build_plug_data()` /
`_generate_plug_html()` / `_ensure_plug_dashboard()` wired into `main()`; deploy/panel
constants. Separate from `network-reachability`; does not touch the existing views.

## Scope / device filter

Plug = a tasmota-enriched host whose machine name matches `^(au|us)-plug-\d+$`. Both
families share an identical HA entity model (verified live: au-plug-10 @ 230 V,
us-plug-1 @ 120 V). One code path. IR blasters / RF bridges (no relay/energy) excluded.

## Entity model (per plug)

Two id prefixes are baked per plug:

- `topic` = `node_id(mqtt_topic)` (e.g. `au_plug_10`) — Tasmota entities.
- `nid` = `node_id(hostname)` (e.g. `au_plug_10_iot`) — reachability entities.

| Data | Source entity |
|---|---|
| Online | `binary_sensor.gdoc2netcfg_{nid}_connectivity` |
| IP | `sensor.gdoc2netcfg_{nid}_default_ipv4` (baked ipv4 as fallback) |
| Relay / toggle | `switch.{topic}` (service `switch.toggle`) |
| Load (W) | `sensor.{topic}_energy_power` (+ `_voltage`/`_factor` in tooltip) |
| Energy windows | `sensor.{topic}_energy_total` (kWh, `state_class: total`) via statistics |
| Today | `sensor.{topic}_energy_today` |

## Table layout (final — see mockup)

Two-row grouped header; columns left→right:

1. **Plug** — `machine_name`, link `http://ipv4.{fqdn}`
2. **IP** — live ipv4, link `http://ipv4.{fqdn}`
3. **Online** — 🟢 online / 🔴 offline (+ relative last-seen, below)
4. **Power** — relay toggle (below)
5. **Controls** — linked list of controlled devices (below)
6. **Load** — live W
7. **Rate** *(shared header)* → `5m` · `1h` · `24h` (avg W)
8. **Energy** *(shared header)* → `1h` · `24h` · `today` (kWh)

Numeric columns (Load, Rate, Energy): **minimal padding**, right-aligned, tabular
numerals, **units on every value**, **fixed 3-decimal kWh** so decimal points line up,
integer W. **Zero values greyed.** Missing → `—`. Group-separator borders between
Load / Rate / Energy. All cells **vertically centred**. Sortable, natural-sort.
Footer: fleet totals (live load W, 24 h kWh).

A leading **"Examples — all states (illustrative)"** table renders one synthetic row
per state as an on-page legend, above the real fleet table.

## Online column / last-seen

Offline rows show a **relative** last-seen ("X seconds/minutes/hours/days ago"),
derived from **recorder history** — the last online→offline transition of
`binary_sensor.gdoc2netcfg_{nid}_connectivity` over a ~14-day window. Rationale:
current-state `last_changed` is unreliable (the daemon re-publishes "off" each cycle,
and an HA restart resets every offline entity's timestamp); the on→off transition in
history survives both. `>14 days ago` beyond the window; `unknown` if no connectivity
entity exists.

## Power toggle

`🟢 ON` / `⚪ OFF`, rendered as a **constant-width** button (min-width + centred, so ON
and OFF are the same size). Click → **confirm dialog naming the plug and what it
controls** → `switch.toggle`. Several plugs feed critical infra (au-plug-17 = NBN
router, au-plug-47 = UPS mains, switches) — the confirm prevents an accidental
outage. `—` when the relay state is unavailable.

## Controls column (list + relay-aware icons + flag)

Source: `tasmota_data.controls`, **already split on comma / newline** by
`supplements/tasmota.py` (the sheet's `Controls` cell uses in-cell newlines; no
sheet cell uses `/` or `;`, so the generator consumes the tuple as-is). Rendered as a vertical list; each device
resolved via `sensor.gdoc2netcfg_host_directory` (machine→hostname → `nid` →
connectivity + `http://ipv4.{host}.{domain}` link).

Per-device icon is **relay-aware** (plug relay `R`, device connectivity `D`):

| | R = on | R = off | R unavailable |
|---|---|---|---|
| **D online** | 🟢 (linked) | ⚠️ warning (powered despite plug off) | 🟢 |
| **D offline** | 🔴 alarm (should be powered) | ⚪ + greyed (expected off) | ⚪ + greyed |

- Resolved host but no connectivity entity → `•` bullet (linked).
- Unresolved free text (e.g. "Cisco Switch", which lives in *Notes* not *Controls*) →
  `•` bullet, plain text.
- **Empty Controls but plug is drawing power** (load/rate/energy > 0) → ❗
  "unlisted load" — an undocumented load worth recording (relates to **#21**; live
  examples: au-plug-7/8/10/47). Empty + idle → `—`.

## Energy rate / total over windows

HA **long-term statistics** — `recorder/statistics_during_period` on each plug's
`sensor.{topic}_energy_total` (kWh, `state_class: total`). Verified live on au-plug-10.

- **Total over a window = Σ `change`** across that window's buckets (NOT
  `sum_last − sum_first`, which drops the first bucket — verified 0.553 vs 0.577 kWh
  over 24 h).
- **Rate (avg W) = total_kWh / window_hours × 1000.** Cross-checked vs HA's `mean`
  power (24 W vs 24.09 W).
- `sum` is reset-normalised, so a plug that rebooted mid-window still reports correct
  consumption.

Two batched queries (all plugs), refreshed ~60 s: `period:"5minute"` last ~65 min
(rolling 5 m + 1 h); `period:"hour"` last ~25 h (24 h). Live **Load** stays on the
real-time `_energy_power` subscription (windows lag up to ~5 min by design).

## Robustness (from the 2026-06-24 au-plug-21 entity-id fix)

A manual HA device rename (`name_by_user`) can pollute the expected entity_ids. The
generator must NOT blindly assume `switch.{topic}` / `sensor.{topic}_energy_power`
exist: at generation, **verify** each plug's relay + power entity appear in the fetched
HA states; on a miss **warn loudly** to stderr (resolve the real id via the device MAC
where possible) — never silently bake a dead entity_id (fail-loud, per CLAUDE.md).

## Error handling / edge cases

- Offline / `unavailable` → blank Load, `—` windows; row de-emphasised.
- No energy sensors → energy columns blank (no fabricated values).
- Empty statistics (new plug) → blank windows.
- Counter reset / midnight rollover → handled by HA `sum`/`change`.
- WebSocket drop → auto-reconnect (as existing dashboards).

## Testing

The generator has **no** unit tests today. Add focused pytest coverage for the new
**pure** functions: plug filter, controls split + resolution + relay-aware icon
selection, last-seen-from-history transition logic, `Σchange` window math, entity-id
verification/warning, and `_build_plug_data` structural JSON. Load the dash-named
generator via `importlib`. HTML/JS verified manually on the deployed dashboard
(consistent with the existing two dashboards, which have no JS tests). The committed
mockup is the visual acceptance reference.

## Deployment

`uv run scripts/ha-create-reachability-dashboard.py` generates all dashboards. The new
Power Plugs dashboard appears as its own sidebar entry. Regeneration only needed when
plug *structure* changes; live state, energy, and last-seen update at runtime.

## Out of scope / future

- Monarto (no HA there).
- Per-plug history charts / graphs.
- Editing the sheet's `Controls` column from the dashboard (relates to #21).
- Bulk on/off actions.
