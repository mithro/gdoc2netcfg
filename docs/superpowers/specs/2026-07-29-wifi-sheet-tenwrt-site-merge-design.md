# Design: wifi.welland border fix, tenwrt row, OpenMesh Site fill, per-host column merges

**Date:** 2026-07-29
**Status:** Approved by user 2026-07-29 (tenwrt single row; Site filled, Physical
Location untouched; code onto PR #18; monarto gains the wifi sheet)
**Branch:** `wifi-sheet-hosts` (PR #18)

## Motivation / user requests

1. The OpenMesh blocks on the `wifi.welland - WiFi Infrastructure` tab show
   incorrect borders.
2. Add the tenwrt host to the wifi sheet.
3. Fill in the Site column for the OpenMesh hardware.
4. Merge the Site, Hardware, Controlled By, Serial, and Notes/Comments cells
   per host block, the same way Physical Location is merged.

## Findings that drive the design

- **Border bug (root cause of request 1):** `scripts/wifi-sheet-format.py`'s
  clean-slate phase unmerges cells and deletes banding but never clears
  borders. When puck onboarding shifted the OpenMesh blocks, old block
  borders survived at their old row positions (verified live: stray solid
  borders mid-block at rows 27–28, 35–36, 41, 44, 48, 51, …).
- **Merged cells export anchor-only:** in the published CSV a merged cell's
  value appears only in its top-left (anchor) row; the covered rows read as
  empty. Host *extras* (Hardware, Controlled By, Serial, Notes, #, Type)
  already tolerate this — `derivations/host_builder.py` takes extras from the
  host's FIRST record (`group[0]`), which is the merge anchor. **Site does
  not**: it is a per-record field (`sources/parser.py`) and
  `derivations/ip_remap.py::is_record_for_site` treats blank as "all sites",
  so merging Site without a parser change would make every covered row exist
  at BOTH sites (phantom partial hosts at the other site — e.g. a lan-only
  `puck01` at monarto).
- **Live Site state:** all 24 puck rows say `welland`; OpenMesh rows are blank
  except a single `monarto` on openmesh-ab-30's first row — which is already
  broken today (at welland, ab-30 exists WITHOUT its lan interface; the other
  6 rows are unfiltered).
- **tenwrt:** one virtio NIC (`02:00:0A:01:00:02`, ten64 libvirt bridge),
  mgmt IP 10.1.4.163 on the wisp-DHCP VLAN. Not present anywhere in the
  current inventory (no name/MAC/IP hits in any cached sheet CSV).
- **OpenMesh IPs are site-templated (verified live 2026-07-29):** every
  OpenMesh row on the wifi tab carries `10.X.…` addresses, so a monarto
  fetch resolves them to `10.2.…` correctly — the precondition for the
  monarto consequence below.
- **Carry-forward must be WiFi-sheet-scoped:** a pre-flight audit of the
  cached Network/IoT sheets found exactly one same-machine block mixing a
  non-blank Site with blanks — `rpiz-usbdev` (IP Allocation rows 628–630,
  first row Site=`Special`, continuation rows blank and currently live at
  BOTH sites). Global carry-forward would silently drop those records, so
  the inheritance applies only to the wifi sheet (where the merge
  convention is being introduced).
- **Populate re-runs clobber hand edits:** `wifi-sheet-migrate.py populate`
  rewrites the tab from its sources, so tenwrt and the Site fill must live in
  the populate tooling, not as one-off cell edits.
- **Monarto consequence:** the wifi sheet is configured welland-only today.
  With Site=monarto filled, the 4 monarto APs leave welland's configs; after
  the (pending) `delete-old-rows` removes their old IP-Allocation rows they
  would exist in NO site's inventory unless monarto also fetches the wifi
  sheet. The Site fill is what makes a shared wifi sheet safe per-site.

## Changes

### 1. `scripts/wifi-sheet-format.py`

- Clean-slate now also clears ALL borders: one `updateBorders` request over
  the entire grid with all six positions (`top`, `bottom`, `left`, `right`,
  `innerHorizontal`, `innerVertical`) set to `{"style": "NONE"}`, issued
  immediately after `unmergeCells` and before any other formatting request
  (tests assert this position). The existing
  `test_borders_wrap_every_block` changes accordingly (its
  one-updateBorders-per-block count gains the clear request).
- `MERGE_COLUMNS_PER_BLOCK = ["Site", "Physical Location", "Hardware",
  "Controlled By", "Serial", "Notes / Comments"]` — each merged vertically
  (`MERGE_COLUMNS`) over every 2+-row machine block, replacing the current
  Physical-Location-only merge. (Sheets keeps the anchor value on merge;
  today's duplicate values on covered rows — e.g. puck Serial on the lan
  row, including its live cross-tab formula — are intentionally collapsed.
  Self-healing: populate unmerges and rewrites all rows, format re-merges —
  which is exactly why the standing "run the formatter after every populate"
  rule holds.) `#`, `Name`, `Type`, and `Upstream` deliberately stay
  per-row: they are either pipeline-consumed per-row conventions or per-row
  cross-tab formulas, and the user's merge list does not include them.

### 2. `src/gdoc2netcfg/sources/parser.py` — Site carry-forward (WiFi sheet ONLY)

On the **wifi sheet only** (normalized sheet name "wifi"), a data row whose
Site cell is blank inherits the Site of the immediately preceding row **when
that row has the same machine name** (contiguous block). First-row-blank
stays blank (all-sites semantics unchanged for genuinely site-less
machines). Other sheets keep today's strictly-per-row semantics — see the
`rpiz-usbdev` finding above for why global inheritance is unsafe. This is
the parser-side meaning of a merged Site cell and also fixes the
pre-existing ab-30 partial-filter bug. TDD.

### 3. `scripts/wifi-sheet-migrate.py` — populate additions

- `OPENMESH_SITE_BY_MACHINE`: ab-38, 96-00 → `welland`; ab-30, 94-98, 95-80,
  95-88 → `monarto`. Written into the Site column of **every row** of each
  OpenMesh block that populate emits (Physical Location text untouched).
  All-rows means a populate-without-format intermediate state is fully
  correct even for a parser without carry-forward; the formatter's merge
  then collapses the duplicates to the anchor.
- **Grid growth guard:** the formatter trims the grid to exactly the used
  range, and the Sheets values.update API rejects writes past the grid — so
  populate must expand the grid first (`appendDimension` ROWS) whenever its
  computed row count exceeds the tab's current `gridProperties.rowCount`.
  Without this, adding tenwrt fails on the first rollout step.
- tenwrt block appended AFTER the OpenMesh rows (keeps OpenMesh row positions
  stable for the rewrite-refs snapshot): single row
  `# = '', Name=tenwrt, Machine=tenwrt, Interface=lan,
  MAC=02:00:0A:01:00:02, IP=10.X.4.163, Type=DHCP:wisp, Site=welland,
  Physical Location="ten64 (VM)", Hardware="QEMU VM", Upstream='',
  Controlled By="ten64 libvirt", Serial='', Notes=''`.
  No `#`/`Serial` ⇒ no `wifi_data` ⇒ excluded from `pucks.json`; it gains a
  `tenwrt.wifi` hostname, welland DNS records (no dhcp-host — `DHCP:wisp`),
  and a `wifi-tenwrt_wifi` broker login on the next `wifi register-broker`.

### 4. Config guidance — monarto gains the wifi sheet

`gdoc2netcfg.toml.example`: drop the "welland only" caveat on `[sheets] wifi`
— both sites fetch it; per-record Site filtering (now complete) gives each
site exactly its own APs. PR #18 deploy notes gain: monarto's local toml must
add the wifi sheet URL, and the `wifi` generator stays welland-only (the
`[generators] enabled` list, which monarto already omits it from).

### 5. Tests / fixtures

- `tests/fixtures/wifi_sheet.csv` regenerated to the post-change published
  CSV shape: anchor-row-only values for all six merged columns, Site filled
  per the overlay, **the 42 OpenMesh rows added** (mirroring the live tab —
  today's fixture has only the 24 puck rows), tenwrt row appended. Golden
  `pucks.json` byte-identity must still pass UNMODIFIED (12 pucks; tenwrt
  and OpenMesh absent from it). Any test feeding this fixture into
  `wifi_credentials`/host-building must account for the ~7 extra hosts the
  broadened fixture now yields.
- New parser tests: carry-forward within a machine block; no inheritance
  across machine boundaries; blank-first-row block stays all-sites; existing
  per-row-Site sheets unaffected.
- Formatter tests: border-clear request emitted immediately after
  `unmergeCells`, before any other formatting request; merge requests cover
  all six columns per block.
- Populate tests: Site overlay applied to OpenMesh rows; tenwrt row appended
  last with the exact values above.
- Site-filter integration test: with the new fixture, welland selects pucks
  + 2 welland APs + tenwrt; monarto selects the 4 monarto APs.

## Live rollout — ORDER MATTERS

1. Code lands on PR #18; PR merges; **deploy to ten64 welland AND monarto**.
   The deploy must precede step 3: once the formatter merges the Site
   column, only a carry-forward-aware parser reads the covered rows
   correctly. Do NOT add the wifi sheet to monarto's toml yet — until
   step 2 fills the Site column, a monarto fetch would transiently claim
   all six APs (including welland's) at resolved 10.2 addresses.
2. `populate` re-run (expands grid, writes Site overlay on all rows +
   tenwrt, refreshes snapshot). Safe before the deploy — values are
   per-row-complete at this stage. **After this step**, add the wifi sheet
   URL to monarto's toml.
3. `wifi-sheet-format.py` run (clears stale borders, applies 6-column merges
   + correct block borders). Only after step 1's deploy.
4. Verify: fresh `fetch` at both sites; welland `generate wifi --stdout`
   byte-identical to the deployed pucks.json; `wifi-sheet-scan.py` clean;
   welland `validate` error delta explained (monarto APs leaving welland
   shrinks the transitional error set); monarto inventory gains exactly the
   4 monarto APs.

## Explicitly unchanged

- Physical Location text (prefixes kept, per user).
- `pucks.json` contract and golden fixture.
- OpenMesh row positions/order; puck rows; the flash tab.
- `rewrite-refs`/`delete-old-rows`/`verify` phases and their gating.
