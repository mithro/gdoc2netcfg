# gwifi/puck → wifi Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename every `gwifi`/puck-named identifier introduced by PR #18 to `wifi`, and broaden MQTT credential selection from puck-only to all WiFi-sheet hosts.

**Architecture:** Six mostly-mechanical rename tasks ordered so every commit compiles and passes the full suite, plus one TDD task for the single behavior change (credential selection). The `wisp/pucks.json` output contract is untouched — the golden byte-identity test must pass unmodified throughout.

**Tech Stack:** Python 3.11+, `uv run pytest`, `uv run ruff check src/ tests/ scripts/`.

**Spec:** `docs/superpowers/specs/2026-07-28-wifi-rename-design.md`

**Working directory:** `/home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-sheet-hosts` (branch `wifi-sheet-hosts`, open PR #18). All commands run from there. Commit after every task; end each commit message with the session's Co-Authored-By/Claude-Session trailer.

**Conventions that apply to every task:**
- Where prose genuinely means the gale-puck *hardware* or the wisp netboot contract ("puck number", "pucks.json", the `gwifi-netboot` service on wisp, `gwifi-openwrt` repo docs), the words stay. Only *identifiers owned by this repo* (classes, functions, modules, config keys, CLI names) become `wifi`.
- After each task: `uv run pytest` → all pass (currently 1937+), `uv run ruff check src/ tests/ scripts/` → clean.

---

### Task 1: Model + enrichment rename (`PuckData` → `WifiData`, `puck_data` → `wifi_data`)

**Files:**
- Modify: `src/gdoc2netcfg/models/host.py` (class at ~line 334, field at ~387)
- Rename: `src/gdoc2netcfg/derivations/puck_data.py` → `src/gdoc2netcfg/derivations/wifi_data.py`
- Modify: `src/gdoc2netcfg/generators/gwifi_pucks.py` (attribute refs only — file renamed in Task 2)
- Modify: `src/gdoc2netcfg/derivations/gwifi_credentials.py` (attribute refs only — module renamed in Task 5)
- Modify: `src/gdoc2netcfg/cli/main.py` (~line 477: import + call)
- Rename: `tests/test_derivations/test_puck_data.py` → `tests/test_derivations/test_wifi_data.py`
- Modify: any other test referencing `PuckData`/`puck_data` (`rg -l "PuckData|puck_data" tests/`)

- [ ] **Step 1: Rename the model.** In `models/host.py`: `class PuckData` → `class WifiData`; field `puck_data: PuckData | None = None` → `wifi_data: WifiData | None = None`. Rewrite the class docstring to say: typed wifi-device identity lifted from the WiFi sheet's `#` (device number) + `Serial` extra columns; present only on netboot-managed devices (today: the gale-puck fleet); `None` for OpenMesh/stock rows which carry neither column.
- [ ] **Step 2: Rename the derivation module.** `git mv src/gdoc2netcfg/derivations/puck_data.py src/gdoc2netcfg/derivations/wifi_data.py`; inside it rename `enrich_hosts_with_puck_data` → `enrich_hosts_with_wifi_data`, import `WifiData`, assign `host.wifi_data = WifiData(...)`, and update the module/function docstrings. Keep all validation (its messages may keep saying "puck number" — that's the hardware). Keep the `expected = f"puck{number:02d}"` machine-name check verbatim: fleet pucks ARE named puckNN.
- [ ] **Step 3: Update every consumer.** `rg -n "PuckData|puck_data|enrich_hosts_with_puck_data" src/ tests/` and fix all hits: `generators/gwifi_pucks.py` (selection + `_puck_entry` field access + docstring), `derivations/gwifi_credentials.py` (`select_pucks` body/docstring — body only; the module renames in Task 5), `cli/main.py` ~477 (`from gdoc2netcfg.derivations.wifi_data import enrich_hosts_with_wifi_data`), and tests (`git mv` the test file; update imports/attribute names inside it and in any other test touching `puck_data`).
- [ ] **Step 4: Verify.** Run: `uv run pytest && uv run ruff check src/ tests/ scripts/` — all pass. Then `rg -n "PuckData|puck_data" src/ tests/` — zero hits.
- [ ] **Step 5: Commit.** `git add -A && git commit -m "rename: PuckData/puck_data -> WifiData/wifi_data"`

### Task 2: Generator rename (`gwifi_pucks` → `wifi`)

**Files:**
- Rename: `src/gdoc2netcfg/generators/gwifi_pucks.py` → `src/gdoc2netcfg/generators/wifi.py`
- Modify: `src/gdoc2netcfg/cli/main.py` (~line 600 registry)
- Modify: `gdoc2netcfg.toml.example` (lines ~24–28, ~61–66, ~96–100)
- Rename: `tests/test_generators/test_gwifi_pucks.py` → `tests/test_generators/test_wifi.py`
- Do NOT touch: `tests/fixtures/pucks.json.golden`, `wisp/pucks.json` (contract + committed output)

- [ ] **Step 1: Rename module + function.** `git mv`; `generate_gwifi_pucks` → `generate_wifi`. Docstring keeps saying it emits `pucks.json` for wisp's `gwifi-netboot` service (external names). `_puck_entry` may keep its name (private, describes a pucks.json entry).
- [ ] **Step 2: Registry.** In `cli/main.py` ~600: `"gwifi_pucks": ("gdoc2netcfg.generators.gwifi_pucks", "generate_gwifi_pucks")` → `"wifi": ("gdoc2netcfg.generators.wifi", "generate_wifi")`.
- [ ] **Step 3: toml.example.** `[generators.gwifi_pucks]` → `[generators.wifi]` (keep `output = "wisp/pucks.json"`); `"gwifi_pucks"` in the `enabled` list → `"wifi"`; update the comment blocks at ~24–28 ("feed the `gwifi_pucks` generator" → "feed the `wifi` generator") and ~61–62 ("no gwifi_pucks" → "no wifi generator"); the ~96–98 deploy comment keeps `gwifi-netboot`/`wisp/pucks.json` verbatim.
- [ ] **Step 4: Tests.** `git mv` the test file; update its imports and any `"gwifi_pucks"` generator-key strings to `"wifi"`. The golden byte-identity test (`test_matches_golden_byte_for_byte`) must remain logically unchanged and passing.
- [ ] **Step 5: Verify + commit.** `uv run pytest && uv run ruff check src/ tests/ scripts/`; `rg -n "gwifi_pucks" .` → only historical docs under `docs/superpowers/` plus CLAUDE.md/README.md (those two are Task 6's job — src/, tests/, toml.example must be clean). `git add -A && git commit -m "rename: gwifi_pucks generator -> wifi"`

### Task 3: Config rename (`[gwifi]`/`GwifiConfig` → `[wifi]`/`WifiConfig`)

**Files:**
- Modify: `src/gdoc2netcfg/config.py` (~80–91, ~190, ~305–310, ~391)
- Modify: `src/gdoc2netcfg/cli/main.py` (~line 2331: `config.gwifi.mqtt_secret`)
- Modify: `gdoc2netcfg.toml.example` (~135–141)
- Modify: `tests/test_config.py`, `tests/test_sources/test_config.py`, `tests/test_cli/test_gwifi_register_broker.py` (any `[gwifi]`/`gwifi=` fixture strings)

- [ ] **Step 1:** `GwifiConfig` → `WifiConfig` (docstring: "wifi-device per-device MQTT credential derivation ([wifi]). `mqtt_secret` derives each WiFi-sheet host's MqttUser (`wifi-<id>`)…"); field `gwifi: GwifiConfig` → `wifi: WifiConfig`; `_build_gwifi` → `_build_wifi` reading `data.get("wifi", {})`; call site `gwifi=_build_gwifi(data)` → `wifi=_build_wifi(data)`.
- [ ] **Step 2:** `cli/main.py` ~2331: `config.gwifi.mqtt_secret` → `config.wifi.mqtt_secret` (function still named `cmd_gwifi_register_broker` until Task 5 — fine).
- [ ] **Step 3:** toml.example ~135–141: section `[gwifi]` → `[wifi]`; comment becomes "Optional: wifi-device per-device MQTT credentials … derives each device's MqttUser (wifi-<id>) …`gdoc2netcfg wifi register-broker`".
- [ ] **Step 4:** Update test fixtures/assertions (`rg -n "GwifiConfig|_build_gwifi|\.gwifi|\[gwifi\]" src/ tests/` → fix all, re-check zero hits).
- [ ] **Step 5: Verify + commit.** `uv run pytest && uv run ruff check src/ tests/ scripts/`. `git add -A && git commit -m "rename: [gwifi]/GwifiConfig -> [wifi]/WifiConfig"`

### Task 4: Credential broadening (TDD) + module rename (`gwifi_credentials` → `wifi_credentials`, prefix `wifi-`)

**Files:**
- Rename: `src/gdoc2netcfg/derivations/gwifi_credentials.py` → `src/gdoc2netcfg/derivations/wifi_credentials.py`
- Rename: `tests/test_derivations/test_gwifi_credentials.py` → `tests/test_derivations/test_wifi_credentials.py`
- Modify: `src/gdoc2netcfg/cli/main.py` (~2319: import)
- Modify: `tests/test_cli/test_gwifi_register_broker.py` — it asserts `prefix == "gwifi-"` and `set(logins) == {"gwifi-puck07_wifi"}` (lines ~63–64), so it breaks in THIS task; update those expectations here (the file itself is renamed in Task 5)

- [ ] **Step 1: Rename first (mechanical).** `git mv` both files; inside: module docstring → "wifi-device per-device MQTT credential derivation… selects ALL WiFi-sheet hosts (`sheet_type == 'WiFi'`)"; `PREFIX = "gwifi-"` → `PREFIX = "wifi-"`; update test imports + expected `wifi-` usernames; `cli/main.py` import → `from gdoc2netcfg.derivations.wifi_credentials import PREFIX, build_logins`.
- [ ] **Step 2: Write the failing tests** in `tests/test_derivations/test_wifi_credentials.py` (follow the existing test style/fixtures in that file — hosts are built the same way the current tests build puck hosts):

```python
def test_selects_all_wifi_sheet_hosts():
    """OpenMesh-style rows (no wifi_data) and stock pucks get logins too."""
    puck = make_host("puck04.wifi", sheet_type="WiFi", wifi_data=WifiData(4, "SER04"))
    openmesh = make_host("om2p-kitchen.wifi", sheet_type="WiFi")   # wifi_data=None
    stock = make_host("puck01.wifi", sheet_type="WiFi")            # wifi_data=None
    network = make_host("ten64", sheet_type="Network")
    logins = build_logins(SECRET, [puck, openmesh, stock, network])
    assert set(logins) == {"wifi-puck04_wifi", "wifi-om2p_kitchen_wifi", "wifi-puck01_wifi"}

def test_empty_selection_fails_loud():
    """Zero WiFi-sheet hosts means the wifi sheet didn't parse — never
    silently register nothing."""
    network_only = [make_host("ten64", sheet_type="Network")]
    with pytest.raises(ValueError, match="no WiFi-sheet hosts"):
        build_logins(SECRET, network_only)
```

  (Adjust `make_host`/`SECRET`/expected node_ids to the file's real helpers — verify expected usernames against `node_id()` behavior, e.g. dots/dashes → underscores.)
- [ ] **Step 3: Run to verify failure.** `uv run pytest tests/test_derivations/test_wifi_credentials.py -v` — the two new tests FAIL (openmesh/stock missing from logins; no ValueError raised).
- [ ] **Step 4: Implement.** Replace `select_pucks` with:

```python
def select_wifi_hosts(hosts: list[Host]) -> list[Host]:
    """All WiFi-sheet hosts (pucks, OpenMesh APs, future wifi infrastructure)."""
    return [h for h in hosts if h.sheet_type == "WiFi"]
```

  and in `build_logins`, after selection: `if not selected: raise ValueError("no WiFi-sheet hosts found — check the [sheets] wifi source is configured and fetched")`. Keep `require_strong_secret` + `check_collisions(selected)`.
- [ ] **Step 5: Run to verify pass.** `uv run pytest tests/test_derivations/test_wifi_credentials.py -v` — all pass. Any pre-existing test asserting puck-only selection must be updated to the broadened semantics (that's the approved behavior change, not a regression). **Gotcha:** in both `test_gwifi_register_broker.py` and the renamed credentials test, the existing `_host()` helper hardcodes `sheet_type="WiFi"` even for *negative* hosts (`desktop.network`, `desktop`) — under broadened selection those would now get logins. Give the negative hosts `sheet_type="Network"` so they remain a meaningful exclusion case; do NOT just widen the assertion.
- [ ] **Step 6: Full verify + commit.** `uv run pytest && uv run ruff check src/ tests/ scripts/`. `git add -A && git commit -m "wifi_credentials: rename from gwifi + broaden to all WiFi-sheet hosts"`

### Task 5: CLI rename (`gwifi register-broker` → `wifi register-broker`)

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (~2313–2351 cmd, ~3117–3129 subparsers, ~3310–3311 dispatch)
- Rename: `tests/test_cli/test_gwifi_register_broker.py` → `tests/test_cli/test_wifi_register_broker.py`
- Modify: `CLAUDE.md` command list (one line)

- [ ] **Step 1:** Rename `cmd_gwifi_register_broker` → `cmd_wifi_register_broker` (docstring: "Register wifi-device broker logins…"); subparser `"gwifi"` → `"wifi"` with help `"wifi infrastructure MQTT credentials"`; `gwifi_parser/gwifi_subparsers/gwifi_rb/dest="gwifi_command"` → `wifi_parser/wifi_subparsers/wifi_rb/dest="wifi_command"`; dispatch `args.gwifi_command` → `args.wifi_command`.
- [ ] **Step 2:** `git mv` the test file; update argv strings (`["gwifi", "register-broker", ...]` → `["wifi", ...]`), function/patch targets, and expected output text.
- [ ] **Step 3:** CLAUDE.md command list: `uv run gdoc2netcfg gwifi register-broker --dry-run    # Preview gwifi puck broker login changes` → `uv run gdoc2netcfg wifi register-broker --dry-run     # Preview wifi-device broker login changes` (full docs pass is Task 6).
- [ ] **Step 4: Verify + commit.** `uv run pytest && uv run ruff check src/ tests/ scripts/`; sanity: `uv run gdoc2netcfg wifi register-broker --help` prints usage. `git add -A && git commit -m "cli: rename gwifi subcommand -> wifi"`

### Task 6: Docs pass (CLAUDE.md + README.md)

**Files:**
- Modify: `CLAUDE.md` — sections *WiFi Sheet Hosts*, *Models* (`PuckData` bullet), *Per-device MQTT broker credentials (tasmota / gwifi / wisp)*
- Modify: `README.md` line ~74 (`gwifi_pucks` generator mention → `wifi`)

- [ ] **Step 1:** CLAUDE.md: retitle the credentials section "(tasmota / wifi / wisp)"; `[gwifi]`→`[wifi]`, `gwifi_credentials.py`→`wifi_credentials.py`, prefix `gwifi-`→`wifi-`, "one login per gale puck (hosts with `puck_data`…)" → "one login per WiFi-sheet host (pucks, OpenMesh APs, tenwrt once it has a wifi-tab row)"; *WiFi Sheet Hosts* section: `puck_data.py::enrich_hosts_with_puck_data()`/`PuckData`/`host.puck_data` → new names, `generators/gwifi_pucks.py`/`[generators.gwifi_pucks]` → `generators/wifi.py`/`[generators.wifi]`; fix the stock-puck sentence ("filling them in would make `wifi_data` claim the host…"); *Models* bullet: `WifiData` … attached to `host.wifi_data` by `derivations/wifi_data.py`. Keep `gwifi-netboot`, `gwifi-openwrt`, and `wisp/pucks.json` references verbatim.
- [ ] **Step 2:** README.md ~74: "The `wifi` generator (welland only) reads gale puck hosts…" — keep the deploy command (`/etc/gwifi-netboot/pucks.json`, `systemctl restart gwifi-netboot`) verbatim.
- [ ] **Step 3: Verify + commit.** `uv run pytest` (docs-only, still run). `git add -A && git commit -m "docs: gwifi/puck -> wifi naming in CLAUDE.md + README"`

### Task 7: Acceptance sweep + push + PR update

- [ ] **Step 1: Acceptance grep.** Run: `rg -in "gwifi" --glob '!docs/superpowers/**' .` — every remaining hit must be an *external* gwifi-named thing this repo doesn't own: the `gwifi-netboot` service on wisp, the `gwifi-openwrt` repo/docs references, and prose/paths in `scripts/wifi-sheet-migrate.py` / `wifi-sheet-scan.py` ("gwifi puck" sheet-surgery prose, the `/home/tim/local/gwifi/` seed-script path) — all expected to remain. Anything else = missed rename, fix it. Also `rg -n "PuckData|puck_data|select_pucks|GwifiConfig" src/ tests/` → zero hits.
- [ ] **Step 2: Full suite.** `uv run pytest` (expect ≥1937 passing, plus the 2 new credential tests) and `uv run ruff check src/ tests/ scripts/` — clean.
- [ ] **Step 3: Push.** `git push origin wifi-sheet-hosts` (never force-push).
- [ ] **Step 4: Update PR #18.** `gh pr edit 18 --title "WiFi sheet hosts: wifi.welland tab as host source + per-device MQTT credentials"`; edit the body: "per-puck" → "per-device", `[gwifi]`→`[wifi]`, `gdoc2netcfg gwifi register-broker`→`gdoc2netcfg wifi register-broker`, generator key `gwifi_pucks`→`wifi`, and add a Rollout-state bullet noting credential selection now covers all WiFi-sheet hosts (pucks + OpenMesh + future tenwrt row). Add a PR comment summarizing the rename (spec: `docs/superpowers/specs/2026-07-28-wifi-rename-design.md`).

---

## Follow-up work (out of scope for this plan)

- **Fail-soft unknown generator key** (Task 2 quality review, 2026-07-29):
  `cmd_generate` warn-and-`continue`s on an unknown `enabled` key and still
  exits 0 (`cli/main.py` ~673) — a stale/typo'd key silently stops output,
  contrary to the repo's fail-loud rule. Pre-existing; deserves its own fix +
  test. Mitigation landed in Task 7: a parametrized test asserting every
  `enabled` key in `gdoc2netcfg.toml.example` resolves via `_get_generator`.
- **Local/live `gdoc2netcfg.toml` key migration** (Task 2 spec review): the
  gitignored dev-worktree toml (and any site toml created before merge) may
  still say `gwifi_pucks`/`[gwifi]` — Task 7 updates the dev worktree's copy
  and the PR body must note the rename for deploy time.

- **WiFi-device remote syslog** (user request, 2026-07-29): replicate the
  tasmota/network-device remote-syslog functionality for the wifi devices
  (pucks, OpenMesh APs, tenwrt) — per-device log files on the site router à la
  `/var/log/tasmota/<hostname>.log` (rsyslog drop-in + logrotate +
  `make deploy-syslog`), with device-side `log_ip`-style configuration. Needs
  its own brainstorm/spec: the receive side mirrors the existing rsyslog
  pattern, but the push side differs per device class (pucks/tenwrt are
  OpenWISP-templated in `gwifi-openwrt`, not pushed by gdoc2netcfg the way
  `tasmota configure` is; OpenMesh APs differ again).
