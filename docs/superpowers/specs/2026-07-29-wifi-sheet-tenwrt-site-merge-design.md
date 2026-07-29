# Design: wifi.welland border fix, VLAN-4 infra rows (ten64/wisp/tenwrt), OpenMesh Site fill, per-host column merges

**Date:** 2026-07-29 (amended same day: request 5 superseded the original
single tenwrt row with the six-row both-sites VLAN-4 infra block)
**Status:** Approved by user 2026-07-29 (Site filled, Physical Location
untouched; code onto PR #18; monarto gains the wifi sheet; infra rows as
IP-Alloc formulas; permanent mirror carve-out)
**Branch:** `wifi-sheet-hosts` (PR #18)

## Motivation / user requests

1. The OpenMesh blocks on the `wifi.welland - WiFi Infrastructure` tab show
   incorrect borders.
2. Add the tenwrt host to the wifi sheet.
3. Fill in the Site column for the OpenMesh hardware.
4. Merge the Site, Hardware, Controlled By, Serial, and Notes/Comments cells
   per host block, the same way Physical Location is merged.
5. (Added 2026-07-29) Add wisp and ten64 entries too, so the wifi tab
   contains all 10.X.4.* (VLAN 4) addresses — both sites — **as spreadsheet
   formulas into 'Welland - IP Allocation'**, so the values are maintained
   in one place (same pattern as the puck rows' formulas into the flash
   tab). Scope constraint (user): only the wifi tab is written; all other
   tabs stay untouched (the user hand-added the IP-Alloc VLAN-4 rows
   themselves).

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
- **IP Allocation now owns VLAN 4 at both sites (user-added 2026-07-29):**
  per site, `ten64` interface `br-wifi` → `.1` (MAC `02:00:0a:0X:04:01`),
  `wisp` → `.2` (`…:04:02`), `tenwrt` → `.3` (`…:04:03`); live welland rows
  95/96/100, monarto rows 62/63/67 (row numbers move — formulas must MATCH,
  not point at fixed rows). These are the source cells for the wifi tab's
  infra rows.
- **tenwrt VM mismatch (ops follow-up, NOT this work):** the live VM's NIC
  is `02:00:0a:01:00:02` with DHCP 10.1.4.163; the sheet assigns
  `02:00:0a:01:04:03` / 10.1.4.3. The VM's libvirt MAC must be updated to
  match the sheet separately.
- **puck01 location hand-edit is populate-fragile:** the user replaced the
  Physical Location flash-tab formula with the literal "Not Deployed";
  the flash tab's Location cell for puck01 is empty, so a populate re-run
  reverts it. Fix (user-approved): write "Not Deployed" into the flash
  tab's Location cell for puck01 during rollout; populate then restores
  the formula which evaluates to the same text.
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
- **VLAN-4 infra block** appended AFTER the OpenMesh rows (keeps OpenMesh
  row positions stable for the rewrite-refs snapshot): SIX rows, ordered
  **site-then-machine** — welland ten64/wisp/tenwrt, then monarto
  ten64/wisp/tenwrt. The ordering is load-bearing: grouping by machine
  would make each machine a 2-row block whose Site cells the formatter
  would merge, silently discarding the second site's value; site-then-
  machine yields six 1-row blocks (nothing merges, borders per row).
- Infra row content: `#`/`Name`/`Serial`/`Notes` blank; `Machine`,
  `Interface` (ten64 rows: `br-wifi`; wisp/tenwrt rows: blank), `Site`
  (welland/monarto), `Type` (tenwrt rows: `DHCP:wisp`; **ten64/wisp rows:
  `static`** — see the dhcp-host note below), `Physical Location`
  ("ten64 (VM)" for the VMs, "ten64" for br-wifi — final text
  implementer's choice, keep it short), `Hardware` ("Ten64" / "QEMU VM"),
  `Controlled By` ("ten64 libvirt" for VMs) as literals.
- **`Type=static` (new sheet vocabulary + generator change):** the
  IP-Allocation-sourced `wisp`/`ten64` hosts already emit
  `dhcp-host=<MAC>,<IP>,…` bindings; a blank-Type mirror row would emit a
  SECOND binding for the same IP from another file, and dnsmasq treats a
  duplicate dhcp-host IP as a FATAL startup error at both sites.
  `_host_dhcp_config` (`generators/dnsmasq.py`) therefore learns a second
  suppressing value: `Type == "static"` skips the binding exactly like
  `DHCP:wisp`, honestly describing a statically-configured address; while
  touching that comparison, normalize BOTH values case-insensitively (the
  existing `== "DHCP:wisp"` check is case-sensitive — a hand-typed
  `dhcp:wisp` would silently emit a binding). DNS records still generate
  normally. TDD.
- **`MAC Address` and `IP` are FORMULAS into
  'Welland - IP Allocation'** (user requirement: single-source
  maintenance), matching by Site+Machine (+Interface=`br-wifi` for ten64,
  which has many rows) — e.g.
  `=INDEX(<IP-Alloc MAC col>, MATCH(1, (<Site col>="welland")*(<Machine col>="wisp")*(<VLAN col>=4), 0))`
  (exact idiom implementer's choice: INDEX/MATCH-array or FILTER). Two
  hard requirements: (i) row-shift-proof — match by content, never fixed
  row refs; (ii) column-shift-resistant — populate GENERATES these
  formulas, so it derives the column letters from the fetched IP-Alloc
  header (`find_header_row` + `header_index` → letter), never hardcoded
  A/B/I/J. The VLAN criterion uses the type-agnostic coercion idiom
  `(<VLAN col>&""="4")` — the IP-Alloc VLAN column is mixed-type (numbers
  and strings), so coercion beats probing the live cell type. The published CSV exports the EVALUATED values (site-literal
  IPs like 10.1.4.1 — fine, `resolve_site_ip` passes non-X IPs through).
- No `#`/`Serial` on any infra row ⇒ no `wifi_data` ⇒ excluded from
  `pucks.json`. Each site's pipeline gains hosts `ten64.wifi`, `wisp.wifi`,
  `tenwrt.wifi` (grouped by hostname; site filter keeps one row each) with
  DNS records; tenwrt rows are `DHCP:wisp` and ten64/wisp rows are
  `static` (no dhcp-host binding from any of them); all three get
  `wifi-<id>` broker logins on the next `wifi register-broker`.

### 3b. Cross-sheet mirror carve-out (validators) + wisp selector fix

The three VLAN-4 machines are now PERMANENTLY dual-recorded (IP Allocation
row + wifi-tab formula row → two hosts, e.g. `wisp` and `wisp.wifi`, same
MAC + same IP). User decision: keep both forever. Two code changes:

- **Validator carve-out (`ip_multiple_macs` ONLY, ADDITIVE):** the check
  gains an OR'd second exception: a duplicate is also accepted when every
  colliding record pairs the identical (MAC, IP) AND all owning hosts
  share one `machine_name` AND the owning hosts span MORE THAN ONE
  `sheet_type` (the genuine cross-sheet signal; added during review —
  without it, a BMC split's parent/child, which legitimately share a
  machine_name AND a sheet_type, could have a copy-paste MAC+IP typo
  silently accepted) — a deliberate cross-sheet mirror, not a data-entry
  error. The existing same-host multi-MAC exception (pucks:
  different MACs, ONE owning host) must keep working unchanged — this is
  an addition, not a rewrite; the implementation needs a parallel
  `mac → machine_names` map alongside the current `mac_to_hostnames`.
  (`mac_duplicate_ip` needs NO carve-out: it fires only when one MAC maps
  to multiple DISTINCT IPs, which an identical-pair mirror can never
  trigger — do not touch it.) TDD.
- **Accepted side effects of mirroring:** each mirrored IP gets two
  `ptr-record` lines under different names (dnsmasq accepts this; the
  auto-PTR winner is load-order-dependent — documented, accepted). The
  inventory's write-only `ip_to_hostname` index computes a meaningless
  common-suffix for mirrored IPs; nothing consumes it today, but any
  future consumer must be aware (noted here deliberately).
- **`wisp_credentials.select_wisp`** currently selects
  `machine_name == "wisp"` and fails loud on multiple matches — the mirror
  host `wisp.wifi` would break `wisp register-broker`. Change the selector
  to exact `hostname == "wisp"` (still fails loud on zero/multiple). TDD.

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
  today's fixture has only the 24 puck rows), plus the 6 infra rows with
  EVALUATED values (site-literal MACs/IPs — that's what the published CSV
  exports for formulas). Golden `pucks.json` byte-identity must still pass
  UNMODIFIED (12 pucks; infra and OpenMesh rows absent from it). Any test
  feeding this fixture into `wifi_credentials`/host-building must account
  for the extra hosts the broadened fixture now yields (per-site counts:
  welland 17, monarto 7 — the authoritative numbers below).
- Carve-out tests: mirrored (MAC, IP, machine_name) duplicate accepted;
  same MAC different IP still errors; same MAC+IP different machine still
  errors. `select_wisp` by-hostname tests (wisp + wisp.wifi coexist → picks
  `wisp`; zero/multiple exact-hostname matches fail loud).
- New parser tests: carry-forward within a machine block; no inheritance
  across machine boundaries; blank-first-row block stays all-sites; existing
  per-row-Site sheets unaffected.
- Formatter tests: border-clear request emitted immediately after
  `unmergeCells`, before any other formatting request; merge requests cover
  all six columns per block; the six infra rows form 1-row blocks (no
  merges over them).
- Populate tests: Site overlay applied to OpenMesh rows; the SIX-row infra
  block appended last in site-then-machine order with header-derived
  MAC/IP formulas and the literals above.
- Generator test: `Type=static` suppresses the dhcp-host binding (like
  `DHCP:wisp`); DNS records still emitted.
- Site-filter integration test (per-site expectations): welland selects
  the 12 pucks + 2 welland APs (ab-38, 96-00) + ten64.wifi + wisp.wifi +
  tenwrt.wifi = 17 WiFi-sheet hosts; monarto selects the 4 monarto APs +
  its 3 infra hosts = 7.

## Live rollout — ORDER MATTERS

1. Code lands on PR #18; PR merges; **deploy to ten64 welland AND monarto**.
   The deploy must precede step 3: once the formatter merges the Site
   column, only a carry-forward-aware parser reads the covered rows
   correctly. Do NOT add the wifi sheet to monarto's toml yet — until
   step 2 fills the Site column, a monarto fetch would transiently claim
   all six APs (including welland's) at resolved 10.2 addresses.
2. Write "Not Deployed" into the flash tab's Location cell for puck01
   (user-approved one-cell write; populate's formula then evaluates to it).
   `populate` re-run (expands grid, writes Site overlay on all rows + the
   6-row infra block with its MAC/IP formulas, refreshes snapshot). Safe
   before the deploy — values are per-row-complete at this stage. **After
   this step**, add the wifi sheet URL to monarto's toml.
3. `wifi-sheet-format.py` run (clears stale borders, applies 6-column merges
   + correct block borders). Only after step 1's deploy.
4. Verify: fresh `fetch` at both sites; welland `generate wifi --stdout`
   byte-identical to the deployed pucks.json; `wifi-sheet-scan.py` clean;
   welland `validate` error delta explained (monarto APs leaving welland
   shrinks the transitional error set); monarto inventory gains exactly 7
   WiFi-sheet hosts (its 4 APs + ten64.wifi/wisp.wifi/tenwrt.wifi).

## Explicitly unchanged

- Physical Location text on OpenMesh rows (prefixes kept, per user).
- `pucks.json` contract and golden fixture.
- OpenMesh row positions/order; the 24 puck rows (puck01's location text
  changes via the flash tab only); 'Welland - IP Allocation' (the user's
  hand-added VLAN-4 rows are READ by formulas, never written). The tab
  gains exactly the six infra rows — nothing else moves.
- `rewrite-refs`/`delete-old-rows`/`verify` phases and their gating.

## Follow-ups recorded (not this work)

- Update the tenwrt VM's libvirt NIC MAC to `02:00:0a:01:04:03` (and its
  address to 10.1.4.3 via wisp DHCP static lease or VM config) to match
  the sheet.
