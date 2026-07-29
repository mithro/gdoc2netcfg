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

- [ ] Write failing tests: (a) host with `extra={"Type": "static"}` emits NO `dhcp-host=` line but still gets DNS records via the shared sections; (b) `"Static"`/`"STATIC"` also suppress; (c) `"dhcp:wisp"` (lowercase) also suppresses — the existing check is case-sensitive, normalize BOTH; (d) blank/absent Type still emits the binding. Follow the file's existing test style for building hosts.
- [ ] Run: `uv run pytest tests/test_generators/test_dnsmasq.py -v` — new tests FAIL.
- [ ] Implement: the Type comparison becomes case-insensitive and suppresses on `{"dhcp:wisp", "static"}` (e.g. `host.extra.get("Type", "").strip().lower() in _NO_DHCP_TYPES`). Update the function docstring.
- [ ] Run tests — pass. Full `uv run pytest && uv run ruff check src/ tests/ scripts/`.
- [ ] Commit: `dnsmasq: Type=static suppresses dhcp-host (case-insensitive with DHCP:wisp)`.

### Task 2: WiFi-sheet Site carry-forward (TDD) — spec §2

**Files:** Modify `src/gdoc2netcfg/sources/parser.py`; Test `tests/test_sources/test_parser.py`.

- [ ] Write failing tests (build CSV text with a Site column, parse with `sheet_name="wifi"`): (a) blank-Site row inherits the previous row's Site when machines match; (b) NO inheritance across a machine change; (c) first-row-blank block stays blank throughout; (d) the SAME csv parsed with `sheet_name="network"` does NOT inherit (per-row semantics preserved); (e) an explicit different Site on a later same-machine row is kept (only blanks inherit).
- [ ] Run to verify failure.
- [ ] Implement in the parsing loop: track `(prev_machine, prev_site)`; when `sheet_name.lower() == "wifi"` and the row's site is blank and machine equals prev_machine, use prev_site. Update prev-trackers on every data row. Keep `_validate_site_values` behavior unchanged (it runs downstream on the inherited values — that's desired).
- [ ] Run tests — pass. Full suite + ruff.
- [ ] Commit: `parser: WiFi-sheet rows inherit Site within a contiguous machine block`.

### Task 3: Additive mirror carve-out in `ip_multiple_macs` (TDD) — spec §3b

**Files:** Modify `src/gdoc2netcfg/constraints/validators.py` (~line 269–310); Test `tests/test_constraints/test_validators.py`.

- [ ] Write failing tests: (a) two hosts (`wisp` from Network sheet, `wisp.wifi` from WiFi sheet, same `machine_name="wisp"`) recording the IDENTICAL (MAC, IP) pair → NO error; (b) same MAC+IP but DIFFERENT machine_names → still errors; (c) same machine_name but different MACs on the IP across the two hosts → still errors; (d) the existing puck exception (one host, wan+lan MACs, one IP) still passes — run the existing tests unmodified.
- [ ] Run to verify failure (a fails today per the reviewer's trace: `mac_to_hostnames` yields 2 owners).
- [ ] Implement ADDITIVELY: alongside `mac_to_hostnames`, build `mac→machine_names` (and the per-IP record pairs); accept when EITHER the existing same-host condition holds OR every colliding record for the IP has the identical MAC and all owning hosts share one machine_name. Do NOT touch `mac_duplicate_ip`.
- [ ] Run tests — pass (including all pre-existing validator tests). Full suite + ruff.
- [ ] Commit: `validators: accept identical-MAC+IP cross-sheet mirrors sharing a machine name`.

### Task 4: `select_wisp` by hostname (TDD) — spec §3b

**Files:** Modify `src/gdoc2netcfg/derivations/wisp_credentials.py`; Test `tests/test_derivations/test_wisp_credentials.py`.

- [ ] Write failing test: hosts list containing `wisp` (hostname "wisp") AND `wisp.wifi` (hostname "wisp.wifi", same machine_name) → `select_wisp` returns the hostname-"wisp" host, no raise. Keep/verify: zero matches raises; two hosts BOTH with hostname "wisp" raises.
- [ ] Run to verify failure (current machine_name match raises on the pair).
- [ ] Implement: match `h.hostname == "wisp"` (update docstring + error messages accordingly).
- [ ] Run tests — pass. Full suite + ruff.
- [ ] Commit: `wisp_credentials: select by exact hostname, not machine_name`.

### Task 5: Formatter — border clear + six merged columns — spec §1

**Files:** Modify `scripts/wifi-sheet-format.py`; Test `tests/test_scripts/test_wifi_sheet_format.py`.

- [ ] Write failing tests: (a) the SECOND request (immediately after `unmergeCells`, before banding-delete/anything else) is an `updateBorders` over the full grid with all six positions `{"style": "NONE"}`; (b) each 2+-row machine block gets `mergeCells` for ALL SIX columns (Site, Physical Location, Hardware, Controlled By, Serial, Notes / Comments); (c) 1-row blocks get NO merges; (d) adapt `test_borders_wrap_every_block` to the extra updateBorders request.
- [ ] Run to verify failure.
- [ ] Implement: `MERGE_COLUMNS_PER_BLOCK` list constant replacing the single `location_col`; the clear-borders request built from the sheet's full grid (rows/cols from properties). Keep per-block top/bottom border application unchanged.
- [ ] Run tests — pass. Full suite + ruff. Also `uv run scripts/wifi-sheet-format.py --dry-run` against the live sheet: prints requests, verify by eye the clear request and 6-column merges appear, and NOTHING is applied.
- [ ] Commit: `wifi-sheet-format: clear stale borders; merge six per-host columns`.

### Task 6: Populate — Site overlay, infra block, grid growth — spec §3

**Files:** Modify `scripts/wifi-sheet-migrate.py`; Test `tests/test_scripts/test_wifi_sheet_migrate.py`.

- [ ] Write failing tests: (a) `OPENMESH_SITE_BY_MACHINE` = {ab-38: welland, 96-00: welland, ab-30: monarto, 94-98: monarto, 95-80: monarto, 95-88: monarto} and every OpenMesh row emitted by `compute_new_tab_rows` carries its machine's site in the Site column (all 7 rows); (b) after the OpenMesh rows comes the six-row infra block in site-then-machine order (welland ten64/wisp/tenwrt, monarto ten64/wisp/tenwrt) with: Machine/Interface (`br-wifi` only on ten64 rows)/Site/Type (`static` for ten64+wisp, `DHCP:wisp` for tenwrt)/Location/Hardware/Controlled By literals per spec §3, and MAC+IP cells that are `=INDEX(...MATCH(...)...)` (or FILTER) formulas referencing 'Welland - IP Allocation' WITHOUT any fixed row number, with column letters derived from a (mocked) fetched IP-Alloc header via the existing `find_header_row`/`header_index` helpers; (c) grid growth: when the computed row count exceeds the (mocked) `gridProperties.rowCount`, an `appendDimension` ROWS request is issued BEFORE the values write; not issued otherwise.
- [ ] Run to verify failure.
- [ ] Implement. For the VLAN criterion's cell type: fetch one IP-Alloc VLAN cell with `UNFORMATTED_VALUE` at populate time and build the criterion to match its actual type (number vs string) — fail loud if neither 4 nor "4".
- [ ] Run tests — pass. Full suite + ruff.
- [ ] Commit: `wifi-sheet-migrate: OpenMesh Site overlay + VLAN-4 infra formula block + grid growth`.

### Task 7: Fixture, integration tests, docs — spec §4/§5

**Files:** Modify `tests/fixtures/wifi_sheet.csv`; Test additions near the existing wifi-sheet parsing tests; Modify `gdoc2netcfg.toml.example` (~line 24: drop the "welland only" caveat), `CLAUDE.md` (*WiFi Sheet Hosts* + credentials sections gain the infra rows/Type=static/carry-forward facts).

- [ ] Extend `tests/fixtures/wifi_sheet.csv` to the post-change published shape: existing 24 puck rows (now anchor-row-only for the six merged columns — blank the lan-row duplicates of Site/Hardware/Serial); + 42 OpenMesh rows mirroring the live tab (machines/MACs/IPs from the live values read in this session — anchor-row-only merged columns, Site on anchor only); + 6 infra rows with EVALUATED values (e.g. welland ten64 row: `br-wifi`, `02:00:0A:01:04:01`, `10.1.4.1`, `static`...). Keep exact column order.
- [ ] New integration test: parse the fixture + site-filter for welland → exactly 17 hosts (named); for monarto → exactly 7. Assert `tenwrt.wifi` has no `wifi_data`; assert golden pucks.json STILL byte-identical (existing test must pass unmodified).
- [ ] Update toml.example + CLAUDE.md per spec §4 (both sites fetch the wifi sheet; `wifi` GENERATOR stays welland-only; document `Type=static` and the six infra formula rows; carry-forward rule).
- [ ] Full suite + ruff.
- [ ] Commit(s): fixture+tests, then docs.

### Task 8: Acceptance + push + PR #18 update

- [ ] Full `uv run pytest` + `uv run ruff check src/ tests/ scripts/`; `rg -in "gwifi" --glob '!docs/superpowers/**' .` still only external names.
- [ ] `git push origin wifi-sheet-hosts` (plain push).
- [ ] PR #18: add a comment describing this batch (border fix, six infra formula rows, Site fill + carry-forward, merges, Type=static, mirror carve-out, select_wisp fix; spec+plan paths); append to the body's Rollout state: the live-sheet steps below + monarto toml gains the wifi sheet URL after populate.

---

## Phase 2 — LIVE SHEET OPERATIONS (controller runs these, NOT subagents)

Order per spec "Live rollout"; note prod ten64s do NOT fetch the wifi tab yet (their tomls predate PR #18), so populate/format may run before the PR merges — verify that assumption first.

- [ ] Verify prod welland toml has no wifi sheet: `ssh -A ten64.welland.mithis.com "grep -n wifi /opt/gdoc2netcfg/gdoc2netcfg.toml"` → expect no `[sheets] wifi` entry. If present, STOP until PR #18 is merged+deployed.
- [ ] Write "Not Deployed" into the flash tab's Location cell for puck01 (one-cell values.update on 'Google WiFi Pucks').
- [ ] `uv run scripts/wifi-sheet-migrate.py populate` (+ its snapshot); re-read the tab: 73 rows, Site filled on all OpenMesh rows, infra formulas evaluating to the IP-Alloc values, puck01 location "Not Deployed" via formula.
- [ ] `uv run scripts/wifi-sheet-format.py` (then re-read formatting: no stray borders mid-block, six columns merged per block, six infra rows unmerged 1-row blocks).
- [ ] Verify: fresh local `uv run gdoc2netcfg fetch` + `generate wifi --stdout` byte-identical to deployed pucks.json (md5 46fa63c82ed9667fba517afa2f84de78); `uv run scripts/wifi-sheet-scan.py` clean; local `validate` error delta explained and recorded.
- [ ] Post-merge (USER decides when): deploy both ten64s, add wifi sheet URL to monarto's toml, verify welland 17 / monarto 7 wifi hosts.
