# Controlled By Sheet Updater — Design

Auto-populate the Network sheet's "Controlled By" column (F) from the control
relationships already tracked elsewhere: the IoT sheet's Controls column, a
(future) Controls column on the Zigbee Info sheet, and live PoE switch port
state from Home Assistant.

## Context and findings

Exploration of the live data (2026-06-11) established:

- The Network sheet's "Controlled By" column is **completely empty** today —
  the first run is pure additions, and full machine ownership of the column
  starts conflict-free.
- The **Zigbee Info sheet has no Controls column**. Its unnamed column G
  holds device serials (e.g. `a44001e4b2`) for SNZB-02D sensors and must
  continue to be preserved untouched.
- The DB-native PoE path is empty: `bridge_poe_status` has 0 rows (the SNMP
  `pethPsePortTable` poll gets no answers from the Netgear switches). HA's
  netgear integration is the only live PoE source (144 port entities across
  sw-netgear-gsm7252ps-s1/-s2 and sw-netgear-s3300-1).
- HA exposes per-port `poe_status` (`delivering`/`searching`) and `poe_power`,
  which distinguish truly PoE-powered hosts (rpi5-pmod, 3.2 W) from hosts
  whose ports merely default to PoE-admin-on (tweed, hifive-unmatched —
  toggling those controls nothing).
- ~10 delivering ports have **empty descriptions but valid LLDP names**
  (`rpia-ups`, `reterm2`, `rpi5-433mhz`, …). Port 17 on s1 has a stale
  description (`eth0.minnow-turbot`) contradicting LLDP (`eth0.rpi5-zigbee`).
- Controls cells use mixed name forms: machine names (`desktop`), subdomain
  hostnames (`rpi-sdr-kraken.iot`), FQDNs (`ten64.monarto.mithis.com`), and
  deliberate non-host appliances (`ac`, `monitors.desktop`,
  `speakers.rpiz-dash-2`). One stale value exists (`nvme` → machine is
  `nvmeof`).
- Real multi-controller cases exist: sw-netgear-gsm7252ps-s1 ← au-plug-14
  *and* au-plug-16.
- Welland's discovery.db has no monarto tasmota scans, but the shared
  spreadsheet has all sites' Controls cells — so reading the *sheet* (not
  scan caches) lets **one run from welland cover both sites**, eliminating
  cross-site clobbering. Welland also has the only HA and the creds.
- **No Google Sheets write credentials exist yet** (`credentials_file = ""`,
  no token cache anywhere). The `zigbee update-sheet` write path has never
  run. A one-time OAuth setup (client_secret.json + browser flow) is a
  prerequisite for real writes. Dry-run must therefore work creds-free.

## Decisions (user-confirmed)

1. **Zigbee source**: support a column literally named `Controls` found by
   header in the Zigbee Info sheet. The user adds the column and data when
   desired; an absent column contributes nothing, silently.
2. **PoE edge rule**: combine stability across power state with self-powered
   exclusion and LLDP coverage (see table below).
3. **Row targeting for machine-level controllers**: the machine's `bmc`
   interface row (if any) AND the first non-bmc row.
4. **Scheduling**: manual only initially; no cron entry.
5. **Common-area refactor first**: reusable pieces move into `utils/` before
   the new feature is built on them (user-directed).

## Phase 1 — common-area refactor

Pure moves, zero behaviour change, consumers updated in the same commit as
each extraction. Verified duplication sites:

| New module | Contents | Moved from |
|---|---|---|
| `utils/ha.py` | `fetch_ha_states(ha_config) -> list[dict]` (REST `/api/states` with bearer token); `node_id(name) -> str` | `supplements/tasmota_ha.py:41`, `scripts/ha-create-reachability-dashboard.py:504`; `supplements/mqtt_ha.py:52` + dashboard line 68 |
| `utils/gsheets.py` | `get_gspread_client(sheets_config)` (service-account or OAuth2 + token cache) | `supplements/zigbee_sheet.py` |
| `utils/controls.py` | `parse_controls_cell(value) -> tuple[str, ...]` (comma/newline split); interface-prefix regex + `strip_interface_prefix(desc) -> (iface, rest)`; `build_name_to_machine(hosts) -> dict[str, str]` | `supplements/tasmota.py` (enrich); dashboard `_build_controls_map` |

Config move with `utils/gsheets.py`: `credentials_file`, `token_cache`,
`service_account_file` relocate from `[zigbee]` to `[sheets]` (where
`[sheets.urls]` already lives). No backward-compat shim — no creds are
configured anywhere yet. Both site tomls and `gdoc2netcfg.toml.example` are
updated in the same commit. `ZigbeeConfig` loses the fields; a new
`SheetsConfig` dataclass in `config.py` gains them (alongside the existing
sheet URL handling).

The dashboard script's `_build_controls_map` is refactored to use the shared
helpers (same output as before).

## Phase 2 — the updater

### Command

`gdoc2netcfg update-sheet controlled-by [--dry-run] [--force] [--verbose]`

New module `supplements/controlled_by_sheet.py` (beside `zigbee_sheet.py`).
Runs from welland only.

### Inputs → control edges

Each edge is `(controller_label, controlled_name, site_scope, interface_hint)`.

1. **IoT plugs** — cached `iot.csv` (refreshed by `fetch`): columns Machine,
   Site, Controls. Controls split via `parse_controls_cell`. Controller
   label = plug machine name (`au-plug-4`). Site scope = the IoT row's Site
   column (case-normalised to the Sites-sheet shortnames).
2. **Zigbee plugs** — Zigbee Info tab, `Controls` column located by header
   name; absent → no edges. Controller label = Entity Name (`Z5`). Site
   scope = the row's Site column. Read via the published CSV export
   (gid 283200403) so dry-run stays creds-free.
3. **PoE ports** — HA `/api/states` via `fetch_ha_states`. Controller label
   = `{switch-machine-name} port {N}` with the port number unpadded
   (`sw-netgear-gsm7252ps-s1 port 1`); entity-id underscores are mapped back
   to hyphens. Site scope = welland. Interface hint = the interface prefix
   stripped from the description/LLDP value.

### PoE edge rule

| `switch.{pp}_poe` | `sensor.{pp}_poe_status` | edge? | name source |
|---|---|---|---|
| on | delivering | yes | description; LLDP if description empty; if both present and disagree → use LLDP and print a loud warning |
| on | searching | no — self-powered host or empty port | — |
| off | any | yes, if the description names a host (deliberately held off; stable across power state; LLDP is gone while the device is down) | description only |

Unknown `poe_status` or `poe` state values → raise (fail loud, no
fabrication). HA unreachable → abort before any read of the target sheet.

### Name resolution (controlled value → machine)

Try in order:

1. exact hostname/machine match in the welland pipeline inventory
   (`build_name_to_machine`),
2. the value minus any site domain suffix from the Sites sheet
   (`ten64.monarto.mithis.com` → `ten64`), re-tried against 1,
3. first DNS label, re-tried against 1,
4. raw `network.csv` Machine-cell match — catches site-filtered rows
   (`sw-netgear-gs728tpp`, monarto-only) and parser-dropped rows
   (`minnow-turbot-2`).

Unresolvable values are **warn-and-skip**: printed prominently with their
source (plug/port), never silently discarded, never failing the run — the
IoT sheet legitimately lists non-network appliances (`ac`,
`monitors.desktop`).

### Row targeting

- Machine-level edges (plugs, zigbee): the machine's `bmc` interface row (if
  any) and the first non-bmc row.
- Interface-level edges (PoE): the exact `(machine, interface)` row named in
  the description; fall back to the machine-level rule if that interface row
  doesn't exist.
- Site scoping: an edge targets machine rows whose Site cell is blank or
  equals the edge's site scope. `ten64.monarto.mithis.com` (site monarto)
  → only the `Site=monarto` ten64 rows.
- Duplicate `(Site, Machine, Interface)` rows exist in the sheet; "first"
  means first in sheet order — deterministic.

### Cell composition and ownership

- Multiple controllers in one cell: newline-separated (matches the existing
  Controls cell style), ordered plugs → zigbee → PoE, each group sorted
  lexically (PoE by switch then port number).
- Rows with no controller: computed value is blank.
- The column is machine-owned, but **fail loud on conflicts**: if any
  targeted cell holds a non-blank value different from the computed one, the
  run lists every conflict and aborts without writing anything. `--force`
  overwrites. Every applied change prints as
  `machine/interface: 'old' → 'new'`.

### Write mechanism

- gspread via `get_gspread_client` with the `[sheets]` creds.
- The Network worksheet is opened by gid parsed from the existing
  `[sheets.urls] network` URL — no new config knob. (Published-CSV gids
  match live worksheet gids; verified for the Zigbee Info tab.)
- Header row auto-detected: the first row containing `Machine`,
  `Interface`, and `Controlled By` (the Network tab has a stray first row).
  Missing header → raise.
- `batch_update` of changed Controlled-By cells only.
- `--dry-run`: creds-free. Computes edges identically, diffs against the
  cached `network.csv`, prints would-be changes and all warnings. A real run
  re-reads the live sheet through gspread for row addressing and the final
  diff (the cache may lag).

### Error handling summary

| Condition | Behaviour |
|---|---|
| HA unreachable / auth failure | abort, nothing written |
| Unknown `poe_status` value | raise |
| `Controlled By` header missing from Network tab | raise |
| Controls value resolves to no machine | warn loudly, skip the edge |
| description ↔ LLDP conflict on a delivering port | warn loudly, prefer LLDP |
| Cell conflict (non-blank, differs from computed) | list all, abort; `--force` overwrites |
| No creds configured (non-dry-run) | existing `get_gspread_client` RuntimeError |

## Testing

- Unit tests for each `utils/` extraction (move-equivalence: same behaviour
  as the code it replaced, via the existing tasmota/zigbee tests plus new
  direct tests).
- PoE state-table tests covering every row of the edge rule plus the
  unknown-value raise.
- Name resolution tests against the real cases found in exploration:
  `desktop` (machine), `rpi-sdr-kraken.iot` (subdomain hostname),
  `ten64.monarto.mithis.com` (FQDN, site-scoped), `sw-netgear-gs728tpp`
  (raw-sheet fallback), `minnow-turbot-2` (parser-dropped row), `nvme` /
  `ac` / `pi1.fpgas` (warn-and-skip).
- Row-targeting tests: bmc + first non-bmc (desktop, tweed), site-scoped
  ten64, interface-row PoE targeting with fallback.
- Cell composition ordering and idempotence (recomputing over an
  already-updated sheet yields zero changes).
- Conflict handling: abort lists all conflicts; `--force` writes.
- Zigbee column-by-header: absent column → zero edges, no warning.
- Fixtures mirror the real sheet quirks: two header rows, section rows
  (`desktop - 12`), duplicate machine rows, blank-site shared rows.

## Out of scope

- Cron scheduling (manual only for now).
- SNMP PoE polling fixes (`bridge_poe_status` stays empty; HA is the source).
- Provisioning the Google OAuth credentials (user action, one-time).
- Writing anything to the IoT or Zigbee sheets.
