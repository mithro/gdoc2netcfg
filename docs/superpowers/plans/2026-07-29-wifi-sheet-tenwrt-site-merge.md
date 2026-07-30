# WiFi-Sheet Borders / VLAN-4 Infra / Site / Merges Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the wifi-tab border bug, add the six VLAN-4 infra rows (formulas into IP Allocation), fill OpenMesh Site, and merge six columns per host block — with the pipeline changes that make all of it safe.

**Architecture:** Four small TDD'd pipeline changes (Type=static suppression, WiFi-scoped Site carry-forward, additive mirror carve-out, select_wisp hostname fix), then the two sheet tools (formatter border-clear + 6-column merges; populate Site overlay + infra block + grid growth), then fixture/docs, then acceptance+push. Live sheet operations are a separate final phase run by the controller, not subagents.

**Tech Stack:** Python 3.11+, `uv run pytest`, `uv run ruff check src/ tests/ scripts/`, Google Sheets API via the migrate tool's SheetsClient.

**Spec:** `docs/superpowers/specs/2026-07-29-wifi-sheet-tenwrt-site-merge-design.md` (the contract — every task below implements a numbered spec section; read the relevant section before starting).

**Working directory:** `/home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-sheet-hosts` (branch `wifi-sheet-hosts`, open PR #18). Conventions: `uv run` always; never `2>/dev/null`; no /tmp files; commit per task with the session trailer:

```
Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BSHiudkQxHncLaoZeKPMDt
```

---

### Task 1: `Type=static` dhcp-host suppression (TDD) — spec §3 "Type=static"

**Files:** Modify `src/gdoc2netcfg/generators/dnsmasq.py` (`_host_dhcp_config`, ~line 49–74); Test `tests/test_generators/test_dnsmasq.py`.

- [x] Write failing tests: (a) host with `extra={"Type": "static"}` emits NO `dhcp-host=` line but still gets DNS records via the shared sections; (b) `"Static"`/`"STATIC"` also suppress; (c) `"dhcp:wisp"` (lowercase) also suppresses — the existing check is case-sensitive, normalize BOTH; (d) blank/absent Type still emits the binding. Follow the file's existing test style for building hosts.
- [x] Run: `uv run pytest tests/test_generators/test_dnsmasq.py -v` — new tests FAIL.
- [x] Implement: the Type comparison becomes case-insensitive and suppresses on `{"dhcp:wisp", "static"}` (e.g. `host.extra.get("Type", "").strip().lower() in _NO_DHCP_TYPES`). Update the function docstring.
- [x] Run tests — pass. Full `uv run pytest && uv run ruff check src/ tests/ scripts/`.
- [x] Commit: `dnsmasq: Type=static suppresses dhcp-host (case-insensitive with DHCP:wisp)`.

### Task 2: WiFi-sheet Site carry-forward (TDD) — spec §2

**Files:** Modify `src/gdoc2netcfg/sources/parser.py`; Test `tests/test_sources/test_parser.py`.

- [x] Write failing tests (build CSV text with a Site column, parse with `sheet_name="wifi"`): (a) blank-Site row inherits the previous row's Site when machines match; (b) NO inheritance across a machine change; (c) first-row-blank block stays blank throughout; (d) the SAME csv parsed with `sheet_name="network"` does NOT inherit (per-row semantics preserved); (e) an explicit different Site on a later same-machine row is kept (only blanks inherit).
- [x] Run to verify failure.
- [x] Implement in the parsing loop: track `(prev_machine, prev_site)`; when `sheet_name.lower() == "wifi"` and the row's site is blank and machine equals prev_machine, use prev_site. Update prev-trackers on every data row. Keep `_validate_site_values` behavior unchanged (it runs downstream on the inherited values — that's desired).
- [x] Run tests — pass. Full suite + ruff.
- [x] Commit: `parser: WiFi-sheet rows inherit Site within a contiguous machine block`.

### Task 3: Additive mirror carve-out in `ip_multiple_macs` (TDD) — spec §3b

**Files:** Modify `src/gdoc2netcfg/constraints/validators.py` (~line 269–310); Test `tests/test_constraints/test_validators.py`.

- [x] Write failing tests: (a) two hosts (`wisp` from Network sheet, `wisp.wifi` from WiFi sheet, same `machine_name="wisp"`) recording the IDENTICAL (MAC, IP) pair → NO error; (b) same MAC+IP but DIFFERENT machine_names → still errors; (c) same machine_name but different MACs on the IP across the two hosts → still errors; (d) the existing puck exception (one host, wan+lan MACs, one IP) still passes — run the existing tests unmodified.
- [x] Run to verify failure (a fails today per the reviewer's trace: `mac_to_hostnames` yields 2 owners).
- [x] Implement ADDITIVELY: alongside `mac_to_hostnames`, build `mac→machine_names` (and the per-IP record pairs); accept when EITHER the existing same-host condition holds OR every colliding record for the IP has the identical MAC and all owning hosts share one machine_name. Do NOT touch `mac_duplicate_ip`.
- [x] Run tests — pass (including all pre-existing validator tests). Full suite + ruff.
- [x] Commit: `validators: accept identical-MAC+IP cross-sheet mirrors sharing a machine name`.

### Task 4: `select_wisp` by hostname (TDD) — spec §3b

**Files:** Modify `src/gdoc2netcfg/derivations/wisp_credentials.py`; Test `tests/test_derivations/test_wisp_credentials.py`.

- [x] Write failing test: hosts list containing `wisp` (hostname "wisp") AND `wisp.wifi` (hostname "wisp.wifi", same machine_name) → `select_wisp` returns the hostname-"wisp" host, no raise. **Rewrite the existing `test_select_wisp_duplicate_raises`** — it builds exactly this mirror pair and asserts a raise, which is the OLD semantics; its scenario becomes the new picks-"wisp" case, and the duplicate case becomes two hosts BOTH with hostname "wisp" (still raises). Zero matches still raises.
- [x] Run to verify failure (current machine_name match raises on the pair).
- [x] Implement: match `h.hostname == "wisp"` (update docstring + error messages accordingly).
- [x] Run tests — pass. Full suite + ruff.
- [x] Commit: `wisp_credentials: select by exact hostname, not machine_name`.

### Task 5: Formatter — border clear + six merged columns — spec §1

**Files:** Modify `scripts/wifi-sheet-format.py`; Test `tests/test_scripts/test_wifi_sheet_format.py`.

- [x] Write failing tests: (a) the SECOND request (immediately after `unmergeCells`, before banding-delete/anything else) is an `updateBorders` over the full grid with all six positions `{"style": "NONE"}`; (b) each 2+-row machine block gets `mergeCells` for ALL SIX columns (Site, Physical Location, Hardware, Controlled By, Serial, Notes / Comments); (c) 1-row blocks get NO merges; (d) adapt `test_borders_wrap_every_block` to the extra updateBorders request.
- [x] Run to verify failure.
- [x] Implement: `MERGE_COLUMNS_PER_BLOCK` list constant replacing the single `location_col`; the clear-borders request built from the sheet's full grid (rows/cols from properties). Keep per-block top/bottom border application unchanged.
- [x] Run tests — pass. Full suite + ruff. Also `uv run scripts/wifi-sheet-format.py --dry-run` against the live sheet: prints requests, verify by eye the clear request and 6-column merges appear, and NOTHING is applied.
- [x] Commit: `wifi-sheet-format: clear stale borders; merge six per-host columns`.

### Task 6: Populate — Site overlay, infra block, grid growth — spec §3

**Files:** Modify `scripts/wifi-sheet-migrate.py`; Test `tests/test_scripts/test_wifi_sheet_migrate.py`.

- [x] Write failing tests (pure-function style — this test file has no fake SheetsClient; keep it that way): (a) `OPENMESH_SITE_BY_MACHINE` = {ab-38: welland, 96-00: welland, ab-30: monarto, 94-98: monarto, 95-80: monarto, 95-88: monarto} and every row of every OpenMesh block emitted by `compute_new_tab_rows` (42 rows across 6 blocks in the full fixture) carries its machine's site in the Site column; (b) after the OpenMesh rows comes the six-row infra block in site-then-machine order (welland ten64/wisp/tenwrt, monarto ten64/wisp/tenwrt) with: Machine/Interface (`br-wifi` only on ten64 rows)/Site/Type (`static` for ten64+wisp, `DHCP:wisp` for tenwrt)/Location/Hardware/Controlled By literals per spec §3, and MAC+IP cells that are `=INDEX(...MATCH(...)...)` (or FILTER) formulas referencing 'Welland - IP Allocation' WITHOUT any fixed row number, with column letters derived from the `ip_alloc_values` header (index 0) already passed to `compute_new_tab_rows`, via the existing `header_index` + a new `col_letter` helper — tests just pass a fixture grid, no mocking; (c) grid growth via a NEW PURE HELPER `grid_growth_requests(sheet_id, current_row_count, needed_rows) -> list[dict]`: returns one `appendDimension` ROWS request when `needed_rows > current_row_count`, `[]` otherwise; `cmd_populate` calls it before `update_values`, reading `gridProperties.rowCount` from the sheets-properties response it already fetches (note: `sheet_id_by_title()` discards properties — read the raw properties dict instead; no extra API call).
- [x] Run to verify failure. NOTE: `TestComputeNewTabRows::test_openmesh_start_row_follows_all_puck_rows` asserts `len(rows) == 2 + 7` and WILL break — updating it to include the infra block is expected, not a regression.
- [x] Implement. VLAN criterion: use the type-agnostic coercion idiom `(<VLAN col>&""="4")` — no cell-type probing (the IP-Alloc VLAN column is mixed-type: numbers and strings like "Q"; a probe would also break every existing fixture). Add `"VLAN"` to `_IP_ALLOC_REQUIRED_COLUMNS` (needed for header_index). Fail loud at populate time if any of the six (site, machine) source rows is absent from the fetched IP-Alloc values — never emit a formula that would silently evaluate to #N/A.
- [x] Run tests — pass. Full suite + ruff.
- [x] Commit: `wifi-sheet-migrate: OpenMesh Site overlay + VLAN-4 infra formula block + grid growth`.

### Task 7: Fixture, integration tests, docs — spec §4/§5

**Files:** Modify `tests/fixtures/wifi_sheet.csv`; Test additions near the existing wifi-sheet parsing tests; Modify `gdoc2netcfg.toml.example` (~line 24: drop the "welland only" caveat), `CLAUDE.md` (*WiFi Sheet Hosts* + credentials sections gain the infra rows/Type=static/carry-forward facts).

- [x] Extend `tests/fixtures/wifi_sheet.csv` to the post-change published shape: existing 24 puck rows (now anchor-row-only for the six merged columns — blank the lan-row duplicates of Site/Hardware/Serial); + 42 OpenMesh rows mirroring the live tab (machines/MACs/IPs from the live values read in this session — anchor-row-only merged columns, Site on anchor only); + 6 infra rows with EVALUATED values (e.g. welland ten64 row: `br-wifi`, `02:00:0A:01:04:01`, `10.1.4.1`, `static`...). Keep exact column order.
- [x] New integration test: parse the fixture + site-filter for welland → exactly 17 hosts (named); for monarto → exactly 7. Assert `tenwrt.wifi` has no `wifi_data`; assert golden pucks.json STILL byte-identical (existing test must pass unmodified).
- [x] Update toml.example + CLAUDE.md per spec §4 (both sites fetch the wifi sheet; `wifi` GENERATOR stays welland-only; document `Type=static` and the six infra formula rows; carry-forward rule).
- [x] Full suite + ruff.
- [x] Commit(s): fixture+tests, then docs.

### Task 8: Acceptance + push + PR #18 update

- [x] Full `uv run pytest` + `uv run ruff check src/ tests/ scripts/`; `rg -in "gwifi" --glob '!docs/superpowers/**' .` still only external names.
- [x] `git push origin wifi-sheet-hosts` (plain push).
- [x] PR #18: add a comment describing this batch (border fix, six infra formula rows, Site fill + carry-forward, merges, Type=static, mirror carve-out, select_wisp fix; spec+plan paths); append to the body's Rollout state: the live-sheet steps below + monarto toml gains the wifi sheet URL **post-merge/post-deploy only** (Phase 2 runs format right after populate, so a pre-deploy monarto parser would misread the merged Site column — must match Phase 2's ordering, not the spec's earlier "after populate" wording).

---

## Phase 2 — LIVE SHEET OPERATIONS (controller runs these, NOT subagents)

Order per spec "Live rollout"; note prod ten64s do NOT fetch the wifi tab yet (their tomls predate PR #18), so populate/format may run before the PR merges — verify that assumption first.

- [ ] Verify prod welland toml has no wifi sheet: `ssh -A ten64.welland.mithis.com "grep -n wifi /opt/gdoc2netcfg/gdoc2netcfg.toml"` → expect no `[sheets] wifi` entry (grep exits 1 on no match — that's the PASS condition, not a broken command). If present, STOP until PR #18 is merged+deployed. Also confirm (already verified live 2026-07-29) the IP-Alloc VLAN-4 rows hold site-LITERAL MACs/IPs (`02:00:0a:01:04:01`/`10.1.4.1` etc.), not X-templated ones.
- [ ] Write "Not Deployed" into the flash tab's Location cell for puck01 (one-cell values.update on 'Google WiFi Pucks').
- [ ] `uv run scripts/wifi-sheet-migrate.py populate` (+ its snapshot); re-read the tab: 73 rows, Site filled on all OpenMesh rows, infra formulas evaluating to the IP-Alloc values, puck01 location "Not Deployed" via formula.
- [ ] `uv run scripts/wifi-sheet-format.py` (then re-read formatting: no stray borders mid-block, six columns merged per block, six infra rows unmerged 1-row blocks).
- [ ] Verify: fresh local `uv run gdoc2netcfg fetch` + `generate wifi --stdout` byte-identical to deployed pucks.json (md5 46fa63c82ed9667fba517afa2f84de78); `uv run scripts/wifi-sheet-scan.py` clean; local `validate` error delta explained and recorded.
- [ ] Post-merge (USER decides when): deploy both ten64s, add wifi sheet URL to monarto's toml, verify welland 17 / monarto 7 wifi hosts.
