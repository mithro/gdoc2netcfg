# Zigbee Per-Site Split — Design

Each site manages only its own Zigbee sheet rows and scans only its own
Zigbee2MQTT broker. Rows for devices present at both sites are duplicated —
one row per site — and cross-site projection (`best_device_view`) is
removed. This is task #26, the prerequisite for the Controlled By work
(#21, blocked on this).

## Context and findings

Exploration of the live system (2026-06-12) established:

- **Today welland does everything cross-site**: its `[[zigbee.sites]]`
  config lists both sites' brokers, the hourly cron (`zigbee scan` at :15,
  config-gated on having sites entries) runs only on welland, and it reaches
  monarto's broker over the WireGuard-routed hostname. Monarto's toml has no
  zigbee section.
- **`update_zigbee_sheet` keys rows by IEEE alone** — one row per device.
  For the ~6 devices present in BOTH Z2M registries (W1/Z4/Z11 online at
  monarto; Z10/W2/W3 offline in both), `best_device_view` picks a winning
  site view (online > newest last_seen) and the row's Site cell flips to
  whichever site won.
- **Storage is already site-split.** `discovery.db` keeps independent
  per-site zigbee documents with device AND site tombstones. `save_zigbee`'s
  contract already states: "a site absent from *data* entirely has been
  removed from the config: it is tombstoned along with all its devices."
  Dropping monarto from welland's config self-cleans welland's DB on the
  next scan, with history retained.
- **The sheet write path has never run.** No Google Sheets credentials are
  configured anywhere (`credentials_file = ""`, no token cache); only
  `--dry-run` has ever been used. Nothing can regress while per-site creds
  are being provisioned.
- The monarto broker credentials in welland's toml (`gdoc2netcfg` /
  z2m-scan password) live on monarto's broker — monarto's own config reuses
  them as-is.
- Zigbee Info sheet columns: A=Site, B=Type, C=Entity Name, D=Description,
  E=Friendly Name, F=State, G=unnamed (hand-maintained SNZB-02D serials,
  preserved untouched), H=Model, I=IEEE Address, J=Power Source,
  K=Connected Via.

## Decisions (user-confirmed)

1. **Scope: zigbee only.** The Network sheet keeps its shared
   `10.X.Y.Z`-placeholder rows; ownership rules for those stay in the
   Controlled By design (#21).
2. **Duplicated rows, one per site**: a device in both registries gets a
   welland row AND a monarto row, each reflecting that site's registry
   view. No cross-site tie-break; `best_device_view` is deleted.
3. **Approach A**: (Site, IEEE) row keying in the single shared worksheet —
   not per-site worksheets, not welland-writes-everything.
4. **Branch workflow**: implemented on `feature/zigbee-site-split` in
   `.worktrees/zigbee-site-split`, small logical commits.

## Design

### 1. Config split

- **Site tomls** (deployment step, not in git): welland removes the monarto
  `[[zigbee.sites]]` entry; monarto adds its own (same broker credentials).
- **Sheet credentials move `[zigbee]` → `[sheets]`**: `credentials_file`,
  `token_cache`, `service_account_file` relocate to the section that
  already holds `[sheets.urls]`. A new `SheetsConfig` dataclass in
  `config.py` carries them; `ZigbeeConfig` loses them. No backward-compat
  shim — no creds exist anywhere yet. `gdoc2netcfg.toml.example` is updated
  in the same commit. (This is the gsheets slice of #21's Phase 1 pulled
  forward; `utils/ha.py` and `utils/controls.py` stay in #21.)
- **`utils/gsheets.py`**: `get_gspread_client(sheets_config)` moves out of
  `supplements/zigbee_sheet.py` unchanged in behaviour; `zigbee_sheet`
  imports it.

### 2. Sheet updater — per-site row ownership

`update_zigbee_sheet` changes:

- **Row key = (Site, IEEE)** instead of IEEE. Site comparison is
  case-insensitive against the sheet cell, written back in config-name
  (lowercase) form.
- **Scope = the run's configured site names** (after the config split,
  exactly the local site). Rows whose Site cell is outside the scope are
  invisible: never read into the upsert map, never written, byte-for-byte
  untouched.
- Devices from each configured site's registry view upsert their
  (Site, IEEE) row; missing rows are appended with column A = the device's
  site. Appended rows start with a blank column G (the serial belongs to
  the physical device, but fabricating a copy from another site's row is
  out — the user fills it if wanted).
- **`best_device_view` is deleted** along with its call site in
  `cmd_zigbee_update_sheet`; each site projects its own registry view
  directly. Tombstoned devices are excluded as today.
- **No row deletions** (unchanged): a device removed from a registry keeps
  its last-written sheet row.

Warnings (loud, to stderr, never silent):

| Condition | Behaviour |
|---|---|
| Duplicate (Site, IEEE) within scope in the sheet | warn listing the rows; first in sheet order wins (deterministic) |
| In-scope device's IEEE also present in a **blank-Site** row | warn — legacy row needing a manual Site value |
| Same IEEE in an *other-site* row | silent — that's the intended duplication |

### 3. Scan, cron, storage — no code changes

- `scan_zigbee` already iterates configured sites only and fails loud on an
  empty/missing `[[zigbee.sites]]`.
- The cron entry is already config-gated; monarto gains the hourly scan by
  running `gdoc2netcfg cron` after its toml change.
- `save_zigbee` already tombstones config-removed sites. The existing
  scan/cron/storage tests passing unchanged is the proof of "no code
  changes here".

### 4. Rollout order

1. Merge to main, `sudo -E git pull` on both sites.
2. Edit both tomls (welland: remove monarto entry; monarto: add its own).
3. Welland's next hourly scan tombstones its monarto view automatically.
4. Monarto: run `gdoc2netcfg cron` to install the hourly entry; first scan
   builds its own DB view.
5. Sheet writes remain dry-run-only until the one-time per-site OAuth
   credential setup (user action) lands under `[sheets]`.

## Error handling summary

| Condition | Behaviour |
|---|---|
| No `[[zigbee.sites]]` configured | `scan_zigbee` raises (unchanged); `update-sheet` raises too — its row scope derives from the same config |
| No creds configured (non-dry-run update-sheet) | existing `get_gspread_client` RuntimeError (unchanged) |
| `IEEE Address` column missing from sheet | raise (unchanged) |
| Duplicate in-scope (Site, IEEE) rows | loud warning, first row wins |
| Blank-Site row sharing an in-scope IEEE | loud warning, row untouched |
| Other-site rows | untouched, silent |

## Testing

- (Site, IEEE) keying: upsert hits the right row when the same IEEE exists
  under two sites.
- Out-of-scope rows are untouched even when their IEEE matches an in-scope
  device (the duplication case end-to-end).
- Appends carry the device's site in column A and a blank column G.
- Both warning paths (duplicate in-scope key; blank-Site IEEE collision).
- Idempotence: re-running over an already-updated sheet yields zero writes.
- Move-equivalence: `get_gspread_client` behaves identically under
  `SheetsConfig` (existing zigbee_sheet creds tests, retargeted).
- Config: `SheetsConfig` parsing, `ZigbeeConfig` without cred fields,
  example toml round-trip.
- `best_device_view` tests removed with the function.
- Existing scan/cron/storage tests pass unchanged.

## Out of scope

- Network sheet shared-row ownership (stays in #21's design).
- Provisioning Google OAuth credentials (user action, one-time, per site).
- Row deletion / stale-row cleanup in the sheet (unchanged behaviour).
- The remaining #21 Phase 1 extractions (`utils/ha.py`, `utils/controls.py`).
- Cleaning the 6 stale dual-registry entries inside the Z2M UIs (user's
  call, cosmetic).
