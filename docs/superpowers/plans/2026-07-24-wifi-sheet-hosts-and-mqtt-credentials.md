# WiFi Sheet Hosts + MQTT Credentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make gwifi pucks first-class `Host`s sourced from a new `wifi.welland` sheet tab (standard parser, IoT-sheet pattern), then derive per-device MQTT broker credentials for pucks and the wisp service using the existing credential machinery.

**Spec:** `docs/superpowers/specs/2026-07-24-wifi-sheet-hosts-and-mqtt-credentials-design.md` — read it first; it holds the user-confirmed decisions and rollout constraints.

**Architecture:** Sheet migration adds a `wifi.welland - WiFi Infrastructure` tab (puck rows formula-linked to the `Google WiFi Pucks` flash tab; OpenMesh blocks moved from `Welland - IP Allocation`). gdoc2netcfg consumes it as a normal `[sheets]` source; sheet-type suffix maps give `.wifi` hostnames; a typed `PuckData` enrichment replaces the bespoke puck pipeline; two new credential consumers (`gwifi-`, `wisp-`) mirror the Tasmota pattern.

**Tech Stack:** Python 3.12, uv, pytest, Google Sheets API (service account), existing `supplements/mqtt_broker.py`.

**Working directory:** `/home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-sheet-hosts` (branch `wifi-sheet-hosts`). All commands run there. Always `uv run`, never bare python. Small discrete commits after each task (and after meaningful sub-steps).

---

### Task 1: Merge the `gwifi-pucks-generator` baseline

The puck code this plan refactors lives ONLY on `origin/gwifi-pucks-generator` (5 commits, `58e8e9a..3096eec`). Merge it first.

- [ ] **Step 1.1:** `git merge origin/gwifi-pucks-generator`
  - Expected conflict candidates: `src/gdoc2netcfg/cli/main.py` (pipeline wiring), `gdoc2netcfg.toml.example`, `src/gdoc2netcfg/config.py`. Resolve keeping BOTH mainline changes (PR #17 cleanup work) and the gwifi additions.
- [ ] **Step 1.2:** `uv run pytest -q` — expect ALL tests pass (>1825; the branch brings its own tests).
- [ ] **Step 1.3:** `uv run ruff check src/ tests/` — clean.
- [ ] **Step 1.4:** Commit the merge.

### Task 2: Sheet-type suffix maps in `dns_names.py`

**Files:** Modify `src/gdoc2netcfg/derivations/dns_names.py`; Test `tests/test_derivations/test_dns_names.py` (extend existing).

- [ ] **Step 2.1:** Write failing tests:

```python
def test_compute_hostname_wifi_suffix():
    assert compute_hostname("puck04", "WiFi") == "puck04.wifi"

def test_compute_dhcp_name_wifi_suffix():
    assert compute_dhcp_name("puck04", "wan", "WiFi") == "wan-puck04.wifi"

def test_compute_dhcp_name_test_sheet_has_no_suffix():
    # preserved asymmetry: Test suffixes hostname but NOT dhcp name
    assert compute_dhcp_name("box", "", "Test") == "box"
```

- [ ] **Step 2.2:** `uv run pytest tests/test_derivations/test_dns_names.py -q` — new tests FAIL.
- [ ] **Step 2.3:** Replace the hardcoded branches with module-level maps, preserving current behaviour exactly:

```python
# Sheet types whose hostnames get a subdomain suffix. compute_dhcp_name has
# a narrower map: Test-sheet hosts historically get NO dhcp suffix.
_HOSTNAME_SUFFIXES = {"IoT": ".iot", "Test": ".test", "WiFi": ".wifi"}
_DHCP_NAME_SUFFIXES = {"IoT": ".iot", "WiFi": ".wifi"}
```

In `compute_hostname`: `hostname += _HOSTNAME_SUFFIXES.get(sheet_type, "")` replacing the if/elif. Same shape in `compute_dhcp_name` with `_DHCP_NAME_SUFFIXES`.

- [ ] **Step 2.4:** `uv run pytest tests/test_derivations/test_dns_names.py -q` — PASS; full suite still green.
- [ ] **Step 2.5:** Commit.

### Task 3: `host_builder` sheet-type normalization for WiFi

**Files:** Modify `src/gdoc2netcfg/derivations/host_builder.py` (both normalization sites, ~lines 33–38 and 93–98); Test `tests/test_derivations/test_host_builder.py`.

- [ ] **Step 3.1:** Failing test: records with `sheet_name="wifi"` produce a host with `sheet_type == "WiFi"` and hostname `puck04.wifi`.
- [ ] **Step 3.2:** Add `elif sheet_type.lower() == "wifi": sheet_type = "WiFi"` to both normalization blocks.
- [ ] **Step 3.3:** Tests pass; commit.

### Task 4: `PuckData` model + enrichment derivation

**Files:** Modify `src/gdoc2netcfg/models/host.py` (dataclass + `Host.puck_data` field); Create `src/gdoc2netcfg/derivations/puck_data.py`; Test `tests/test_derivations/test_puck_data.py`.

- [ ] **Step 4.1:** Failing tests covering: happy path (host with `#`/`Serial` extras → `PuckData(number, serial)`); machine-name mismatch (`puck5` with `#`=4) raises; number outside 1..99 raises; non-integer `#` raises; duplicate numbers or serials across hosts raise; WiFi host WITHOUT `#`/`Serial` (OpenMesh) → `puck_data is None`; a host with only one of `#`/`Serial` raises (partial data = sheet error, fail loud).
- [ ] **Step 4.2:** Model:

```python
@dataclass(frozen=True)
class PuckData:
    """Typed gwifi puck identity lifted from the WiFi sheet's extra columns."""
    number: int
    serial: str
```

`Host` gains `puck_data: PuckData | None = None` next to `tasmota_data`.

- [ ] **Step 4.3:** Derivation (pure, fail-loud — mirrors repo doctrine):

```python
def enrich_hosts_with_puck_data(hosts: list[Host]) -> None:
    """Attach PuckData to WiFi-sheet hosts carrying '#' + 'Serial' extras.

    Both interface rows of a puck carry the same values (sheet formulas), so
    equal duplicates within one host are fine. Raises ValueError on partial
    data, malformed numbers, name mismatch, or cross-host duplicates.
    """
    seen_numbers: dict[int, str] = {}
    seen_serials: dict[str, str] = {}
    for host in hosts:
        if host.sheet_type != "WiFi":
            continue
        raw_num = host.extra.get("#", "").strip()
        serial = host.extra.get("Serial", "").strip()
        if not raw_num and not serial:
            continue  # OpenMesh etc. — not a puck row
        if not raw_num or not serial:
            raise ValueError(f"{host.hostname}: partial puck data (need both # and Serial)")
        number = int(raw_num)  # ValueError propagates with context added
        if not 1 <= number <= 99:
            raise ValueError(f"{host.hostname}: puck number {number} outside 1..99")
        expected = f"puck{number:02d}"
        if host.machine_name != expected:
            raise ValueError(f"{host.hostname}: machine {host.machine_name!r} != {expected!r} from #")
        if number in seen_numbers or serial in seen_serials:
            raise ValueError(f"{host.hostname}: duplicate puck number/serial")
        seen_numbers[number] = host.hostname
        seen_serials[serial] = host.hostname
        host.puck_data = PuckData(number=number, serial=serial)
```

Wrap the bare `int()` with a try/except raising a message that names the host (fail loud with context). Wire the call into `_build_pipeline` next to `enrich_hosts_with_tasmota`.

- [ ] **Step 4.4:** Tests pass; full suite green; commit.

### Task 5: Relax `ip_multiple_macs` for same-host endpoints

**Files:** Modify `src/gdoc2netcfg/constraints/validators.py` (~lines 280–293); Test `tests/test_constraints/test_validators.py`.

- [ ] **Step 5.1:** Failing tests: (a) two MACs on one non-roam IP, both interfaces of ONE host → no violation; (b) two MACs on one non-roam IP from TWO hosts → still ERROR; (c) roam-range behaviour unchanged.
- [ ] **Step 5.2:** Implementation: build `mac_to_hostname` from `inventory.hosts` (NOT `ip_to_macs`, whose tuples carry dhcp_name); in the loop, skip the violation when `{mac_to_hostname.get(str(mac).lower()) for mac, _ in macs}` is a single non-None hostname.
- [ ] **Step 5.3:** Tests pass; commit.

### Task 6: DHCP suppression via `Type = DHCP:wisp`

**Files:** Modify `src/gdoc2netcfg/generators/dnsmasq.py` (dhcp-host block, ~lines 50–67); Test `tests/test_generators/test_dnsmasq.py`.

- [ ] **Step 6.1:** Failing test: a host with `extra={"Type": "DHCP:wisp"}` produces host-records but **zero** `dhcp-host=` lines; a host with any other `Type` value is unchanged.
- [ ] **Step 6.2:** Implementation in the dhcp-host generation function:

```python
# DHCP for this host is served elsewhere (e.g. wisp on the pucks' VLAN,
# netboot design D7) — emit no bindings so ten64 never competes.
if host.extra.get("Type", "").strip() == "DHCP:wisp":
    return []
```

- [ ] **Step 6.3:** Tests pass; commit.

### Task 7: Rework `pucks.json` generator; delete the bespoke puck pipeline

**Files:** Modify `src/gdoc2netcfg/generators/gwifi_pucks.py` (rework `generate_gwifi_pucks`, DELETE `generate_gwifi_pucks_dns`); Delete `src/gdoc2netcfg/sources/gwifi_pucks_parser.py`, `src/gdoc2netcfg/constraints/gwifi_pucks_validation.py`, their tests; Modify `src/gdoc2netcfg/models/host.py` (drop `NetworkInventory.gwifi_pucks`), `src/gdoc2netcfg/cli/main.py` (drop special parse/validate wiring; drop `gwifi_pucks` from sources handling — the sheet is no longer fetched), `gdoc2netcfg.toml.example` (drop `gwifi_pucks` source + `gwifi_pucks_dns` generator; add `wifi` source); Test `tests/test_generators/test_gwifi_pucks.py` (rewrite).

- [ ] **Step 7.1:** Capture the golden: run the CURRENT (branch) generator against the live sheet once and commit its output as `tests/fixtures/pucks.json.golden` (this is the wisp contract). No `gdoc2netcfg.toml` exists in the worktree (gitignored) — create one from the merged `toml.example` (it has the pucks-tab URL), or equivalently take the golden from the file deployed on wisp (`/etc/gwifi-netboot/pucks.json`).
- [ ] **Step 7.2:** Failing test: build an inventory from a WiFi-sheet fixture CSV (2 rows per puck for all 9 OpenWRT pucks with real MACs/serials, wan+lan) via the REAL pipeline path (`parse_csv` → `build_hosts` → `enrich_hosts_with_puck_data`), then `generate_gwifi_pucks(inventory)` output `== pucks.json.golden` byte-for-byte. Also: fail-loud test for a puck host missing its `lan` interface.
- [ ] **Step 7.3:** Rework `generate_gwifi_pucks`: iterate `sorted((h for h in inventory.hosts if h.puck_data), key=lambda h: h.puck_data.number)`; fields `name=h.machine_name`, `number`, `serial` from `puck_data`, `eth0`=MAC of interface named `wan`, `eth1`=MAC of interface named `lan` (KeyError → raise with hostname), `ip`=the shared IPv4. Preserve exact JSON shape (`version`, `generated_by`, indent=2, trailing newline). GOTCHA: `MACAddress` canonical string form is **lowercase** — uppercase explicitly (`str(mac).upper()`) or the golden byte-compare fails.
- [ ] **Step 7.4:** Delete `generate_gwifi_pucks_dns` + parser + constraint + `inventory.gwifi_pucks` + all wiring; `grep -rn "gwifi_pucks" src/ tests/` afterwards must show only the reworked generator + its test + the `wifi` source has replaced the old sheet entry.
- [ ] **Step 7.5:** Full suite green (deleted tests removed, new ones pass); commit.

### Task 8: Config + credential derivations for `gwifi` and `wisp`

**Files:** Modify `src/gdoc2netcfg/config.py` (two dataclasses + loaders, mirror `TasmotaConfig` at ~62/250); Create `src/gdoc2netcfg/derivations/gwifi_credentials.py`, `src/gdoc2netcfg/derivations/wisp_credentials.py`; Tests `tests/test_derivations/test_gwifi_credentials.py`, `test_wisp_credentials.py` (mirror the tasmota credential tests).

- [ ] **Step 8.1:** Failing tests: selection (only `puck_data` hosts / only machine `wisp`); username shapes `gwifi-puck04_wifi`, `wisp-wisp`; deterministic passwords; weak-secret rejection; wisp absent → ValueError; two wisp hosts → ValueError.
- [ ] **Step 8.2:** `gwifi_credentials.py`:

```python
PREFIX = "gwifi-"

def select_pucks(hosts: list[Host]) -> list[Host]:
    return [h for h in hosts if h.puck_data is not None]

def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    require_strong_secret(secret)
    pucks = select_pucks(hosts)
    check_collisions(pucks)
    return {username(PREFIX, h): password(secret, h) for h in pucks}
```

`wisp_credentials.py` identical shape: `PREFIX = "wisp-"`, `select_wisp` returns the single host with `machine_name == "wisp"` (raise if zero or >1), `build_logins` over `[wisp_host]`.

- [ ] **Step 8.3:** Config: `GwifiConfig`/`WispConfig` dataclasses with `mqtt_secret: str = ""`, `[gwifi]`/`[wisp]` loaders, fields on `PipelineConfig`. Document in `gdoc2netcfg.toml.example` (commented, with `openssl rand -hex 32` note).
- [ ] **Step 8.4:** Tests pass; commit.

### Task 9: CLI `gwifi register-broker` and `wisp register-broker`

**Files:** Modify `src/gdoc2netcfg/cli/main.py`; Test `tests/test_cli/` (mirror existing register-broker tests if present, else dry-run smoke test via fixture config).

- [ ] **Step 9.1:** Two commands mirroring `cmd_tasmota_register_broker` (line ~2095) in flow (note: tasmota gets hosts via a `_tasmota_hosts(config)` helper; gwifi/wisp should use `_build_pipeline` hosts directly since the puck enrichment runs there — same flow, not a line-for-line copy): `_load_config` → `_build_pipeline` hosts → `build_logins` → `register_logins(config.homeassistant.ssh_host, PREFIX, logins, dry_run, prune, verify=(mqtt.host, mqtt.port) unless dry-run)`. Same `--dry-run`/`--prune` flags, same error messages for missing `ssh_host`/weak secret. Subparsers: top-level `gwifi` group with `register-broker`, top-level `wisp` group with `register-broker` (parallel to `tasmota`/`sensors2mqtt` groups at ~2949/3011).
- [ ] **Step 9.2:** `uv run gdoc2netcfg gwifi register-broker --dry-run` against a fixture toml prints the upsert summary and does not POST.
- [ ] **Step 9.3:** Update `CLAUDE.md` command list; commit.

### Task 10: Sheet migration + verification scripts

**Files:** Create `scripts/wifi-sheet-scan.py` (promote `/home/tim/local/gwifi/tmp/scan_formulas.py` into the repo, cleaned up); Create `scripts/wifi-sheet-migrate.py`; Test `tests/test_scripts/test_wifi_sheet_migrate.py` for the pure row-building helpers.

- [ ] **Step 10.1:** `wifi-sheet-migrate.py` structure — phased subcommands so the rollout can hold between code deploy and old-row deletion; service-account auth (`~/.config/gale-fleet/sheets-sa.json`); every phase idempotent and preceded by a printed diff of what it will change:
  - `create` — add tab `wifi.welland - WiFi Infrastructure` with the spec's 14 columns; error if it exists with different headers.
  - `populate` — write puck rows (2/puck, `=`-formulas referencing `'Google WiFi Pucks'` by `#` lookup: Machine←Name, MAC←wan/lan, Serial, Location, Upstream, Controlled By; literal `Type=DHCP:wisp`, `Site=welland`, `IP` formula `="10.X.4."&(100+<#>)`) and OpenMesh rows (values copied from `Welland - IP Allocation`, Site preserved blank, `Hardware` from family). Pure helpers `build_puck_rows(pucks_tab_values) -> list[list[str]]` and `build_openmesh_rows(ip_alloc_values) -> list[list[str]]` are unit-tested against fixture CSVs. `build_puck_rows` MUST filter to `Firmware == "OpenWRT"` rows (the spec's "exclusion lives in the sheet" means the WiFi tab only lists OpenWRT pucks — this filter is what enforces it at populate time; unit-test that a `Google Original` row produces no output).
  - `rewrite-refs` — repoint the 6 `iot.welland` formulas (R24–29 C8) at the new tab's Physical Location cells; print before/after.
  - `delete-old-rows` — remove the OpenMesh blocks from `Welland - IP Allocation` (only after the code deploy; refuses to run unless `rewrite-refs` verifies clean).
  - `verify` — full-spreadsheet formula scan: zero `#REF!`, zero references into the deleted range; fetch published CSVs and assert `iot.welland` evaluated values unchanged vs a pre-migration snapshot and the new tab parses via `parse_csv`.
- [ ] **Step 10.2:** Unit tests for the row builders (golden rows for puck04 + openmesh-ab-30) pass.
- [ ] **Step 10.3:** Commit. (RUNNING the phases against the live sheet is the rollout, not this task.)

### Task 11: Docs, example config, final green run

- [ ] **Step 11.1:** `gdoc2netcfg.toml.example`: `wifi` source URL (published-CSV gid of the new tab — filled during rollout `create`), `[gwifi]`/`[wisp]` sections, removed `gwifi_pucks` entries.
- [ ] **Step 11.2:** `CLAUDE.md`: new commands, WiFi-sheet description in the pipeline section, remove pucks-tab special-case notes.
- [ ] **Step 11.3:** `uv run pytest -q` and `uv run ruff check src/ tests/` — fully green.
- [ ] **Step 11.4:** Commit; then use superpowers:requesting-code-review before the finishing skill.

---

## Rollout runbook (operational — after code review, gated on user go-ahead)

Order per spec Part 4; prod reads old rows until step 3.

1. `scripts/wifi-sheet-migrate.py create` + `populate`; publish tab to CSV; put its URL in both sites' `gdoc2netcfg.toml` (`wifi` source) — prod still ignores it (old code).
2. Merge PR; deploy to ten64 welland (`sudo -E git pull`); `fetch`; `generate --force`; **diff review** of `internal/generated/`, `external/generated/`, and `pucks.json` (expect: puck host-records identical, OpenMesh `.wifi` renames, no puck dhcp-host lines, `pucks.json` byte-identical); `make deploy-*`; same for monarto (expect only OpenMesh `.wifi` renames).
3. `rewrite-refs` → `delete-old-rows` → `verify`; re-`fetch` both sites; re-`generate`; confirm no diff beyond intended.
4. Set `[gwifi]`/`[wisp] mqtt_secret` on welland ten64; `gwifi register-broker --dry-run` then real; `wisp register-broker`; verify logins connect.
5. Deploy `pucks.json` to wisp; confirm gwifi-netboot still resolves identities (byte-identical file ⇒ no-op).
