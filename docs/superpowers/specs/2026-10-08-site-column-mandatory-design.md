# Mandatory `Site` column + `roam` value — Design

**Status:** draft, awaiting Tim's review
**Date:** 2026-10-08
**Author:** Claude (session on ten64.welland)

## Goal

Make the spreadsheet `Site` column **mandatory and meaningful** for every
device row: populate the ~587 currently-blank rows with the site where each
device actually lives (using live evidence from both sites), add a new
`roam` value for devices served at **both** welland and monarto (laptops and
genuinely-dual-site devices), and turn a missing or unrecognised `Site` into
a loud validation **ERROR** that gates `generate`/deploy the same way the
other sheet-contract validators do.

## Background — current state (verified 2026-10-08)

### Where `Site` is read and used
- `DeviceRecord.site: str = ""` — parsed case-insensitively by header name,
  `.strip()`-ed but **not** lowercased (`sources/parser.py:33,75,122,181-183`).
  WiFi-sheet continuation rows inherit the previous row's Site
  (`parser.py:138,185-186`); other sheets keep blanks as-is.
- `is_record_for_site(record, site)` (`derivations/ip_remap.py:47-49`) is the
  routing predicate:
  - `if not record.site: return True` → **blank = served at ALL sites**.
  - else `return record.site.lower() == site.name.lower()` → a non-blank Site
    is served **only** at the site whose `name` it equals.
- `resolve_site_ip` (`ip_remap.py:20-35`) substitutes the literal `X` in the
  **second octet** of a `10.X.Y.Z` address with `site.site_octet`. This runs
  **after** the site filter and is **independent of the Site value** — it
  triggers purely on the presence of literal `X`.
- `_validate_site_values` (`ip_remap.py:52-79`) **raises `ValueError`** (a hard
  mid-run crash, not a graceful report) if a record's non-empty Site is not in
  `site.all_sites`. Skipped entirely when `all_sites` is empty.
- Valid Site values = `all_sites`, populated at runtime from the **Sites sheet**
  (`cli/main.py:171`, `sources/sites_parser.py`): the single-lowercase-no-dot
  shortnames. Today: `welland`, `monarto`, `special`, `hetnzer`, `ps1`,
  `carlfk`, `k207`. **`roam` is NOT among them.**

### The `roam` VLAN is a different namespace (no code collision)
`roam` exists only as a VLAN/subdomain name (from the VLAN Allocations sheet;
e.g. `validators.py:339 ip_prefix_for_vlan("roam")`). Site values are compared
against `site.name`/`site.all_sites`; the VLAN is looked up via
`vlan_by_name`/`ip_prefix_for_vlan`. Adding a Site value named `roam` does not
shadow the VLAN. **But** with current logic a `roam` Site would be (a) rejected
by `_validate_site_values` unless added to the Sites sheet, and (b) if accepted,
dropped from **both** sites by `is_record_for_site` (it equals neither
`welland` nor `monarto`) — the opposite of the intended "both" meaning. New
routing logic is therefore required.

### Current `Site` distribution (prod cache, 2026-10-08)
| Sheet | Data rows | blank | welland | monarto | other |
|-------|-----------|-------|---------|---------|-------|
| network | 528 | 369 | 114 | 37 | 8 `special` |
| iot | 237 | 167 | 64 | 4 | 2 `Welland` (case) |
| wifi | 78 | 51 | 16 | 11 | — |

~587 blank rows total; ~505 of them carry a `10.X` placeholder IP (today's
implicit "both-site"). A few blanks carry non-`10.X` literals (tailscale
`100.110.251.x`, `192.168.2.10`, `192.168.42.1`). The 8 `special` rows and any
other off-site labels are **already populated** and out of scope.

## Decisions (Tim, 2026-10-08)

| # | Decision |
|---|----------|
| D1 | Placement policy: **propose → Tim approves → write.** Evidence from both sites yields a per-row proposal; sheet is written only after Tim approves; rows with no evidence are listed UNKNOWN, never guessed. |
| D2 | `roam` representation: **a Sites-sheet row** (blank domain/IP, like the existing `special` row) **+ both-routing** (`roam`, like blank, is served at every pipeline site). Sites sheet stays the single source of truth for valid values. |
| D3 | Validator scope: the new validator reports **both** a missing Site (`site_missing`) **and** an unrecognised Site value (`site_unknown`) as graceful ERRORs — loud like other sheet-data problems — superseding the hard `ValueError`. |
| D4 | **Keep the `10.X` form. No IP changes at all.** Placement is Site-column-only, so a device can migrate between sites by flipping `Site` alone and a site can re-allocate IPs freely. A single-site device keeps its `10.X` IP (only that site substitutes). |

## Design

### Valid values & semantics (after this work)
| Site value | Served at | Notes |
|------------|-----------|-------|
| `welland` | welland only | `10.X` → `10.1.Y.Z` at welland |
| `monarto` | monarto only | `10.X` → `10.2.Y.Z` at monarto |
| `roam` *(new)* | **both** welland + monarto | explicit replacement for today's `blank + 10.X`; laptops + dual-site devices |
| `special`, `ps1`, `carlfk`, `hetnzer`, `k207` | neither (inventory-only) | already populated; untouched |
| *(blank)* | — | **ERROR** after this work |

### Component 1 — `roam` routing (code)
- `is_record_for_site` (`ip_remap.py:47`): treat `roam` like blank — served
  wherever the pipeline runs. The predicate is only ever called with
  `site.name` ∈ {welland, monarto} (the pipeline sites), so returning `True`
  for `roam` yields exactly "both". New logic:
  `if not record.site or record.site.lower() == "roam": return True`.
- `10.X` substitution is unchanged and already correct for `roam` rows (each
  site substitutes its own octet).
- **Add a `roam` row to the Sites sheet** (Domain/IP columns blank, mirroring
  the existing `special` row) so `roam` enters `all_sites` and passes the
  validity guard. This is a one-off sheet edit, documented here.

### Component 2 — `validate_sites` validator (code)
- New `def validate_sites(records: list[DeviceRecord], site: Site) -> ValidationResult:`
  in `constraints/validators.py`, added to the `validate_all` list literal
  (`validators.py:585-608`), same shape as `validate_locations`/`validate_controls`.
- For each device record (one with a non-empty `machine` — the same skip rule
  the other record validators use, so blank spacer rows don't fire):
  - blank Site → `ConstraintViolation(severity=ERROR, code="site_missing",
    field="Site", record_id="<sheet>:<row>")`.
  - non-blank Site whose `.lower()` ∉ `site.all_sites` → `code="site_unknown"`.
- **Supersede the hard guard:** remove the `raise ValueError` in
  `_validate_site_values` (`ip_remap.py:52-79`) so an unknown value becomes a
  clean ERROR from `validate_sites` rather than a crash during host-building.
  (`validate_all`'s result gates the pipeline via `has_errors`; a bad value is
  reported, not fatal-crashed. The silent per-site drop a bad value would
  otherwise cause never reaches output because `generate` stops on the ERROR.)
- `roam` is in `all_sites` (via the Sites-sheet row), so `roam` rows pass.

### Component 3 — case normalisation (data)
The 2 `Welland` rows become `welland` during the data pass. Routing already
lowercases, so this is cleanup, not a bug fix; it also keeps the sheet tidy and
avoids `site_unknown` ever firing on a case variant (defensive, since
`all_sites` shortnames are lowercase).

### Component 4 — data migration (propose → approve → write)
A throwaway, **committed-then-removed** analysis script
(`scripts/site_populate.py`, removed in a later commit per the throwaway-script
convention) builds a per-row proposal by fusing evidence from **both sites**:

Evidence sources (read-only):
- **Reachability** — welland `discovery.db` (local), monarto `discovery.db`
  (read-only SSH): host up/down.
- **Bridge/FDB + LLDP** — which site's switches have learned the device's MAC
  (physical location).
- **DHCP leases + Tasmota/Zigbee scans** — which site actually serves it.
- **Sheet IP literal** — `10.1.*` → welland, `10.2.*` → monarto, `10.X` →
  ambiguous (both or either).
- **`roam`-VLAN membership** — a device on the roam VLAN is a strong `roam`
  signal.

Placement rule (produces a *suggestion*, never a silent write):
- Seen at exactly one site → that site.
- Seen at both sites, or on the roam VLAN → `roam`.
- No evidence anywhere → **UNKNOWN**, listed for Tim's decision. Never guessed.
- A device whose evidence says `roam` but which carries a **site-specific
  literal** IP (`10.1.*`/`10.2.*`) is **flagged** (that literal only works at
  one site) — Tim decides whether to make it `10.X`, place it single-site, or
  (for a non-site-specific address like tailscale `100.x` / global v6) accept
  `roam` as-is. Not auto-converted (D4).

Proposal format: a per-row table — sheet, row, machine, current Site, evidence
summary, **suggested Site**, confidence, and any flag. Tim reviews/edits; only
then are the `Site` cells written via **explicit A1 ranges**
(`ws.batch_update([{range, values}])`) — the gspread `append_row` column-offset
bug does not apply (all in-place edits). Writes run as root with the per-site
service account.

### Sequencing (critical — mirrors the controls/location playbook)
Deploy is all-or-nothing `git pull`, and the ERROR validator must not go live
until the data is clean, so the work lands in **two PRs** with the data
migration between them:

1. **PR #1 — enable `roam`:** Component 1 (routing) + the Sites-sheet `roam`
   row. Merge + deploy to both sites. Writing `roam` into a cell is now safe.
2. **Data migration:** evidence → proposal → Tim approves → write ~587 `Site`
   cells (Components 3+4). Verify `validate` on both sites reports **0**
   `site_missing`/`site_unknown`.
3. **PR #2 — enforce:** Component 2 (the `validate_sites` ERROR validator +
   removing the `ValueError` guard). Merge, then deploy **only after** step 2
   is verified clean, or the next cron `generate` at both sites exits 1 on 587
   blank rows.

## Error handling / fail-loud
- Unknown/missing Site → graceful ERROR (D3), gating `generate`/prod DNS, never
  a synthesised default.
- No-evidence device → surfaced as UNKNOWN for Tim, never auto-assigned.
- `roam` + site-literal IP contradiction → flagged for Tim, never auto-rewritten.
- Sheet writes only after explicit approval; in-place A1 ranges only.

## Testing
TDD for the code (PRs #1, #2):
- Routing: `roam` → served at both welland and monarto; `welland` → welland
  only, excluded at monarto; blank → both (pre-enforcement); an unknown value
  no longer crashes (`_validate_site_values` raise removed).
- `validate_sites`: blank → `site_missing` ERROR; unknown value →
  `site_unknown` ERROR; `welland`/`monarto`/`roam` → clean; off-site label
  (`special`) → clean; blank spacer row (no machine) → no violation.
- Sites parser: a `roam` Sites-sheet row appears in `all_sites`.
Data migration verified operationally: `validate` on both sites = 0 site
errors, and a spot-check of several proposed placements against reachability.

## Out of scope
- The 8 `special` rows and other off-site labels (already populated).
- Any IP change, including converting literals to `10.X` or vice-versa (D4).
- An IP-shape validator rule for `roam` (handled as a proposal-time flag, not code).
- Monarto-specific infrastructure changes.

## Open questions
None outstanding; the `roam` + literal-IP contradiction is handled as a
proposal-time flag (Tim decides per row), not a blanket rule.
