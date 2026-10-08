# Mandatory `Site` column + `roam` value — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the spreadsheet `Site` column mandatory on every device row, add a `roam` value served at both welland + monarto, and turn a missing/unknown `Site` into a graceful validation ERROR — while keeping the `10.X` IP form (no IP rewrites).

**Architecture:** Two code changes plus a human-gated data migration, in two PRs because of a hard two-deploy ordering (routing must deploy *before* any `roam` cell exists; the validator must deploy *after* the sheet is clean, or `generate` breaks at both sites). Phase 1 teaches the pipeline to route `roam` to both sites and ships a placement-proposal tool. Between the phases, a one-off operational migration populates the ~587 blank `Site` cells with Tim's approval. Phase 2 adds the ERROR validator and retires the old hard-crash guard.

**Tech Stack:** Python 3.11–3.13, `uv`, pytest, ruff; gspread for the sheet write; SQLite `discovery.db` (reachability/bridge) read read-only.

**Spec:** `docs/superpowers/specs/2026-10-08-site-column-mandatory-design.md`

## Global Constraints

- Always use `uv run` for Python; never bare `python`/`pip`.
- **Keep the `10.X` IP form. No IP changes at all** — placement is Site-column-only (spec D4).
- `roam` is a **Sites-sheet row** (single source of truth for valid values), not a code keyword (spec D2).
- Sheet writes happen only after Tim approves the proposal (spec D1), run as root with the per-site service account, via **explicit A1 ranges** (`ws.batch_update([{range, values}])`) — never `append_row` (column-offset bug).
- Deploy to prod only by merge→`git pull` (never copy files directly); `validate` must be 0 errors; never `--force`.
- No-evidence device → surfaced UNKNOWN, never guessed (spec fail-loud).
- Commit messages end with the attribution lines (`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` + `Claude-Session:`).

## Review Focus

- A `roam` record must survive into **both** welland and monarto inventories (not dropped like a single-site value) — pinned in Task 1.
- A capitalised valid value (`Welland`) must **not** be flagged `site_unknown` (the validator lowercases before the membership check) — pinned in Task 3.
- A blank spacer row (no machine name) must **not** trigger `site_missing` — pinned in Task 3.
- An off-site label already in the Sites sheet (`special`) must pass the validator, not be flagged — pinned in Task 3.
- A blank-Site device with a non-`10.X` literal IP (tailscale `100.x`) must still be flagged `site_missing` (the validator keys off a blank Site + a machine, never the IP shape) — pinned in Task 3.
- The placement classifier must return UNKNOWN (not a guessed site) when evidence is absent — pinned in Task 2.

---

## PHASE 1 — branch `site-column-mandatory` (this worktree): roam routing + placement tooling → PR #1

### Task 1: Route `roam` to both sites

**Files:**
- Modify: `src/gdoc2netcfg/derivations/ip_remap.py:38-49` (`is_record_for_site`)
- Test: `tests/test_derivations/test_ip_remap.py`

**Interfaces:**
- Consumes: `DeviceRecord` (has `.site: str`), `Site` (has `.name: str`, `.all_sites: tuple[str,...]`, `.site_octet: int`).
- Produces: `is_record_for_site(record, site) -> bool` — unchanged signature; now also returns `True` when `record.site.lower() == "roam"`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_derivations/test_ip_remap.py` (follow the existing `Site`/`DeviceRecord` construction in that file; `all_sites` is lowercase and must include `"roam"`):

```python
def test_roam_record_served_at_welland():
    rec = _record(site="roam", ip="10.X.20.5")
    welland = _site(name="welland", site_octet=1,
                    all_sites=("welland", "monarto", "roam"))
    assert is_record_for_site(rec, welland) is True


def test_roam_record_served_at_monarto():
    rec = _record(site="roam", ip="10.X.20.5")
    monarto = _site(name="monarto", site_octet=2,
                    all_sites=("welland", "monarto", "roam"))
    assert is_record_for_site(rec, monarto) is True


def test_roam_is_case_insensitive():
    rec = _record(site="Roam", ip="10.X.20.5")
    monarto = _site(name="monarto", site_octet=2,
                    all_sites=("welland", "monarto", "roam"))
    assert is_record_for_site(rec, monarto) is True


def test_single_site_value_still_excludes_other_site():
    rec = _record(site="welland", ip="10.X.20.5")
    monarto = _site(name="monarto", site_octet=2,
                    all_sites=("welland", "monarto", "roam"))
    assert is_record_for_site(rec, monarto) is False


def test_roam_record_resolves_octet_per_site():
    # roam survives the filter AND the 10.X octet substitutes per site
    rec = _record(site="roam", machine="laptop1", ip="10.X.20.5")
    monarto = _site(name="monarto", site_octet=2,
                    all_sites=("welland", "monarto", "roam"))
    [out] = filter_and_resolve_records([rec], monarto)
    assert out.ip == "10.2.20.5"
```

If the test file has no `_record`/`_site` helpers, construct `DeviceRecord` and `Site` inline exactly as the other tests in the file do, and import `is_record_for_site` / `filter_and_resolve_records` from `gdoc2netcfg.derivations.ip_remap`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_derivations/test_ip_remap.py -v -k "roam or single_site"`
Expected: the `roam*` tests FAIL (roam currently returns `False` from `is_record_for_site` / is dropped by `filter_and_resolve_records`); `single_site` passes.

- [ ] **Step 3: Implement the routing change**

In `ip_remap.py`, change `is_record_for_site` (lines 47-49) to:

```python
    if not record.site or record.site.lower() == "roam":
        return True
    return record.site.lower() == site.name.lower()
```

Update the docstring to add: `- If the record's site field is "roam", it applies to all sites (served at both welland and monarto).`

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_derivations/test_ip_remap.py -v`
Expected: PASS (all, including the existing ones).

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/derivations/ip_remap.py tests/test_derivations/test_ip_remap.py
git commit -m "feat(site): route a roam Site value to both sites"
```

### Task 2: Placement classifier + proposal script

**Files:**
- Create: `scripts/site_populate.py` (throwaway migration tool, removed in a later commit after the migration lands — per the throwaway-script convention)
- Test: `tests/test_scripts/test_site_populate.py` (create; add `tests/test_scripts/__init__.py` if the dir is new)

**Interfaces:**
- Produces: a pure classifier
  `classify_site(ev: SiteEvidence) -> SiteProposal`, where
  `SiteEvidence = dataclass(machine: str, current_site: str, ip: str, seen_welland: bool, seen_monarto: bool, on_roam_vlan: bool)` and
  `SiteProposal = dataclass(suggested: str | None, confidence: str, flags: list[str])`.
  `suggested` is one of `"welland"`, `"monarto"`, `"roam"`, or `None` (UNKNOWN). `confidence` ∈ `{"high", "low", "unknown"}`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scripts/test_site_populate.py`:

```python
from scripts.site_populate import SiteEvidence, classify_site


def ev(**kw):
    base = dict(machine="d", current_site="", ip="10.X.20.5",
                seen_welland=False, seen_monarto=False, on_roam_vlan=False)
    base.update(kw)
    return SiteEvidence(**base)


def test_seen_only_welland_is_welland():
    p = classify_site(ev(seen_welland=True))
    assert p.suggested == "welland" and p.confidence == "high"


def test_seen_only_monarto_is_monarto():
    p = classify_site(ev(seen_monarto=True))
    assert p.suggested == "monarto" and p.confidence == "high"


def test_seen_both_sites_is_roam():
    p = classify_site(ev(seen_welland=True, seen_monarto=True))
    assert p.suggested == "roam" and p.confidence == "high"


def test_on_roam_vlan_is_roam():
    p = classify_site(ev(on_roam_vlan=True))
    assert p.suggested == "roam"


def test_no_evidence_is_unknown_never_guessed():
    p = classify_site(ev())
    assert p.suggested is None and p.confidence == "unknown"


def test_roam_with_site_literal_ip_is_flagged():
    # seen at both (→roam) but carries a welland-only literal IP: contradiction
    p = classify_site(ev(seen_welland=True, seen_monarto=True, ip="10.1.20.5"))
    assert p.suggested == "roam"
    assert any("literal" in f.lower() for f in p.flags)


def test_existing_value_preserved_as_low_confidence_when_no_live_evidence():
    p = classify_site(ev(current_site="welland"))
    assert p.suggested == "welland" and p.confidence == "low"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_scripts/test_site_populate.py -v`
Expected: FAIL with `ModuleNotFoundError: scripts.site_populate` (or import error).

- [ ] **Step 3: Implement the classifier (pure core)**

Create `scripts/site_populate.py` with the dataclasses and `classify_site`:

```python
"""One-off: propose a Site value for every device row from live evidence.

THROWAWAY migration tool (committed for the record, removed after the
migration lands). Read-only until --apply; --apply writes Site cells via
explicit A1 ranges only after Tim approves the proposal. See
docs/superpowers/specs/2026-10-08-site-column-mandatory-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SiteEvidence:
    machine: str
    current_site: str
    ip: str
    seen_welland: bool
    seen_monarto: bool
    on_roam_vlan: bool


@dataclass
class SiteProposal:
    suggested: str | None
    confidence: str  # "high" | "low" | "unknown"
    flags: list[str] = field(default_factory=list)


def _is_site_literal(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and parts[0] == "10" and parts[1] in ("1", "2")


def classify_site(ev: SiteEvidence) -> SiteProposal:
    flags: list[str] = []
    if ev.on_roam_vlan or (ev.seen_welland and ev.seen_monarto):
        if _is_site_literal(ev.ip):
            flags.append("roam but carries a site-literal IP — make it 10.X "
                         "or place single-site")
        return SiteProposal("roam", "high", flags)
    if ev.seen_welland:
        return SiteProposal("welland", "high", flags)
    if ev.seen_monarto:
        return SiteProposal("monarto", "high", flags)
    if ev.current_site:
        # no live evidence: keep what the sheet already says, low confidence
        return SiteProposal(ev.current_site.lower(), "low", flags)
    return SiteProposal(None, "unknown", flags)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_scripts/test_site_populate.py -v`
Expected: PASS.

- [ ] **Step 5: Add the evidence-gathering + proposal I/O (not unit-tested; thin wrapper)**

Append to `scripts/site_populate.py` a `main()` that:
- parses the three device-sheet CSVs from the cache (reuse the header-detection
  approach: find the row containing a `site` cell; locate `machine`/`ip`/`site`
  columns case-insensitively),
- builds `SiteEvidence` per device row: `seen_welland` from welland
  `discovery.db` reachability (host up in the latest scan) + bridge FDB (its MAC
  learned by a welland switch); `seen_monarto` likewise from monarto's
  `discovery.db` (path passed via `--monarto-db`, copied over read-only SSH
  beforehand); `on_roam_vlan` from the IP being in the roam VLAN prefix,
- prints a per-row proposal table (sheet, row, machine, current Site,
  evidence summary, suggested Site, confidence, flags) and a summary count,
- `--apply` (guarded, root, service account) writes only the approved values
  via `ws.batch_update([{"range": a1, "values": [[value]]}])`.

For the wifi sheet, build evidence per host-**block** and target the anchor row
(the Site column is merged per block; see Rollout step 5). For network/iot, one
row = one target. Keep `main()` behind `if __name__ == "__main__":`. This step
has no unit test (it reads live DBs/sheet); it is exercised operationally in the
rollout. Verify it imports and `--help`/dry-run runs:

Run: `uv run python scripts/site_populate.py --help`
Expected: usage printed, exit 0.

- [ ] **Step 6: Commit**

```bash
git add scripts/site_populate.py tests/test_scripts/
git commit -m "feat(site): placement classifier + proposal tool (throwaway migration)"
```

### Task 3 lives in PHASE 2 (below) — do not start it until the rollout gate completes.

At the end of Phase 1, run the full suite and open PR #1:

```bash
uv run pytest && uv run ruff check src/ tests/ scripts/
git push -u origin site-column-mandatory
# gh pr create --base main --title "feat(site): roam routing + placement tooling" --body-file <(...)
```

---

## OPERATIONAL ROLLOUT (human-gated — between Phase 1 and Phase 2)

These are **not** TDD tasks; each is an irreversible/outward step requiring Tim.
Do them in order; do not proceed past a failing check.

1. **Merge PR #1** (sub-agent review clean + CI green) and **deploy routing to both sites**: `sudo -E git pull` on welland (local) and monarto (SSH), then `deploy-check`/`validate` sanity. Routing now knows `roam`; nothing else changes (no generator affected).
2. **Add the `roam` row to the Sites sheet** (live edit, root + service account, explicit A1): a shortname `roam` with blank Domain/IP, mirroring the existing `special` row. After this, `roam` ∈ `all_sites` so the validity guard accepts it. Re-`fetch` so the cached `sites.csv` includes it.
3. **Copy monarto's `discovery.db`** to a local read-only path (SSH scp) for cross-site evidence.
4. **Run the proposal**: `uv run python scripts/site_populate.py --monarto-db <path>` → review the per-row table. Resolve every UNKNOWN and every flagged roam-with-literal-IP **with Tim**. Nothing is written yet.
5. **Write the approved values** (`--apply`, root, service account): populate the blank cells + normalise the 2 `Welland`→`welland`. Explicit A1 ranges only.
   - **network + iot:** per-row Site (no inheritance) — write each blank device row.
   - **wifi:** the Site column is **merged per host-block** (CLAUDE.md "WiFi-sheet-only Site carry-forward"), so continuation rows read blank in the CSV but inherit the anchor's Site at parse time. Write only the **anchor** (first) row of each block; the parser fills the rest, and the formatter keeps the merge. The raw-CSV blank count (51 on wifi) therefore overcounts the rows that actually need a write.
6. **Verify clean**: `fetch` then, using the Phase-2 validator code in a local checkout (or a manual blank/unknown scan), confirm **0** `site_missing`/`site_unknown` across network/iot/wifi on both sites. Do not start Phase 2 deploy until this is 0.

---

## PHASE 2 — branch `site-mandatory-validator` (new worktree off updated main): enforce → PR #2

### Task 3: `validate_sites` ERROR validator + retire the hard guard

**Files:**
- Modify: `src/gdoc2netcfg/constraints/validators.py` (add `validate_sites`; add it to the `validate_all` list)
- Modify: `src/gdoc2netcfg/derivations/ip_remap.py:52-95` (remove `_validate_site_values` and its call in `filter_and_resolve_records`)
- Test: `tests/test_constraints/test_site_validator.py` (create)
- Modify: `tests/test_derivations/test_ip_remap.py` (remove/replace any test asserting `_validate_site_values` raises `ValueError`)

**Interfaces:**
- Consumes: `DeviceRecord` (`.site`, `.machine`, `.sheet_name`, `.row_number`), `Site.all_sites`, `ValidationResult`, `ConstraintViolation`, `Severity.ERROR` (same imports `validate_locations` uses).
- Produces: `validate_sites(records: list[DeviceRecord], site: Site) -> ValidationResult` with codes `site_missing` and `site_unknown`, `field="Site"`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_constraints/test_site_validator.py` (mirror `test_location_validator.py`'s construction of `DeviceRecord`/`Site`):

```python
from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.constraints.validators import validate_sites
# construct DeviceRecord / Site as test_location_validator.py does

ALL = ("welland", "monarto", "roam", "special")


def test_blank_site_on_device_row_is_error():
    r = _rec(machine="d1", site="", ip="10.X.20.5")
    res = validate_sites([r], _site(all_sites=ALL))
    assert [v.code for v in res.violations] == ["site_missing"]
    assert res.violations[0].severity is Severity.ERROR


def test_unknown_value_is_error():
    r = _rec(machine="d1", site="back shed", ip="10.X.20.5")
    res = validate_sites([r], _site(all_sites=ALL))
    assert [v.code for v in res.violations] == ["site_unknown"]


def test_valid_values_are_clean():
    recs = [_rec(machine="a", site="welland"), _rec(machine="b", site="monarto"),
            _rec(machine="c", site="roam"), _rec(machine="d", site="special")]
    assert validate_sites(recs, _site(all_sites=ALL)).violations == []


def test_capitalised_valid_value_is_not_unknown():
    r = _rec(machine="d1", site="Welland")
    assert validate_sites([r], _site(all_sites=ALL)).violations == []


def test_blank_spacer_row_without_machine_is_ignored():
    r = _rec(machine="", site="")
    assert validate_sites([r], _site(all_sites=ALL)).violations == []


def test_blank_site_with_nonstandard_ip_still_errors():
    r = _rec(machine="laptop", site="", ip="100.110.251.12")
    assert [v.code for v in validate_sites([r], _site(all_sites=ALL)).violations] \
        == ["site_missing"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_constraints/test_site_validator.py -v`
Expected: FAIL — `validate_sites` not defined.

- [ ] **Step 3: Implement `validate_sites` and wire it in**

Add to `validators.py` (next to `validate_locations`):

```python
def validate_sites(records: list[DeviceRecord], site: Site) -> ValidationResult:
    """Every device row must carry a Site value known to the Sites sheet.

    A blank Site (site_missing) or a value not in the Sites sheet
    (site_unknown) is an ERROR, the same as other sheet-contract problems —
    superseding the former hard ValueError in ip_remap. Rows without a
    machine name (spacers/section headers) are skipped.
    """
    result = ValidationResult()
    for r in records:
        if not getattr(r, "machine", ""):
            continue
        if not r.site:
            result.add(ConstraintViolation(
                severity=Severity.ERROR, code="site_missing",
                message="device row has no Site value",
                record_id=f"{r.sheet_name}:{r.row_number}", field="Site"))
        elif site.all_sites and r.site.lower() not in site.all_sites:
            result.add(ConstraintViolation(
                severity=Severity.ERROR, code="site_unknown",
                message=(f"Site {r.site!r} is not a known site; valid: "
                         + ", ".join(site.all_sites)),
                record_id=f"{r.sheet_name}:{r.row_number}", field="Site"))
    return result
```

Add `validate_sites(records, inventory.site),` to the list literal in `validate_all`.

- [ ] **Step 4: Remove the superseded hard guard**

In `ip_remap.py`, delete `_validate_site_values` (lines 52-79) and its call on
line 95 (`_validate_site_values(records, site)`), and trim the now-stale
"Three-step process"/"Raises ValueError" wording in `filter_and_resolve_records`'s
docstring to the two remaining steps.

- [ ] **Step 5: Update the ip_remap tests that asserted the raise**

In `tests/test_derivations/test_ip_remap.py`, remove or rewrite any test that
asserts `filter_and_resolve_records`/`_validate_site_values` raises `ValueError`
on an unknown Site value (that behaviour is now `validate_sites` → `site_unknown`,
covered in `test_site_validator.py`). Grep first:

Run: `grep -n "ValueError\|_validate_site_values\|invalid site" tests/test_derivations/test_ip_remap.py`

- [ ] **Step 6: Run the validator + ip_remap tests, then the full suite**

Run: `uv run pytest tests/test_constraints/test_site_validator.py tests/test_derivations/test_ip_remap.py -v`
Expected: PASS.
Run: `uv run pytest && uv run ruff check src/ tests/`
Expected: full suite green, lint clean.

- [ ] **Step 7: Commit**

```bash
git add src/gdoc2netcfg/constraints/validators.py src/gdoc2netcfg/derivations/ip_remap.py tests/test_constraints/test_site_validator.py tests/test_derivations/test_ip_remap.py
git commit -m "feat(site): site_missing/site_unknown ERROR validator, retire ValueError guard"
```

Then open PR #2 and **deploy only after** the rollout step 6 confirms 0 site errors on both sites.

---

## Notes on decomposition
- The `roam` Sites-sheet row and the ~587-cell populate are **data/operational** steps (rollout 2, 4-5), not code tasks — they need Tim's approval and live sheet writes, which no TDD cycle covers.
- Phase 1 and Phase 2 are separate PRs solely because of the two-deploy ordering; each is independently reviewable and testable.
- `scripts/site_populate.py` is removed in a follow-up commit once the migration has landed (throwaway-script convention); its classifier tests go with it.
