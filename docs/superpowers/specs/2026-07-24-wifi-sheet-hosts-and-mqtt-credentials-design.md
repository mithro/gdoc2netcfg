# WiFi Sheet Hosts + MQTT Credentials — Design

Date: 2026-07-24
Status: draft (pending user approval)

## Goal

Make the gwifi pucks first-class `Host`s in the gdoc2netcfg inventory —
sourced from a new `wifi.welland` spreadsheet tab parsed by the *standard*
parser, exactly like the IoT sheet — and then derive per-device MQTT broker
credentials for the pucks and the OpenWISP service, reusing the existing
Tasmota/sensors2mqtt credential machinery unchanged.

## Background / current state

- **Baseline pin**: all existing gwifi puck code lives on the pushed but
  unmerged branch `gwifi-pucks-generator` (5 commits, `58e8e9a..3096eec`) —
  it is NOT on `origin/main`. Step zero of the plan is merging that branch
  into this feature branch (`wifi-sheet-hosts`) so the refactor operates on
  real code. The `pucks.json` byte-compare target is that branch's generator
  output against the current sheet (equivalently, the file currently
  deployed to wisp).
- Pucks exist only as `PuckRecord`s (bespoke parser over the
  `Google WiFi Pucks` flash tab) in `inventory.gwifi_pucks`, consumed by two
  special generators (`gwifi_pucks` → `pucks.json` for wisp's netboot;
  `gwifi_pucks_dns` → a dnsmasq host-record fragment). They are invisible to
  every standard subsystem (reachability, HA dashboard, known_hosts,
  constraints, credentials).
- The bespoke parser reads `eth0`/`eth1` columns that were renamed to
  `wan`/`lan` on 2026-07-22; it silently falls back to the `MAC` column +
  MAC+1 derivation. Output is coincidentally still correct — a live instance
  of the silent-degradation anti-pattern this repo forbids.
- The OpenMesh APs (6 units) are 7-row interface blocks in
  `Welland - IP Allocation` (the "network" source tab). The `iot.welland`
  tab additionally holds their iot-VLAN (10.X.90.4x) allocation ledger rows
  (Machine-less; never become hosts).
- `wisp` is already a proper Host (Network sheet, welland `10.1.4.2`,
  monarto `10.2.5.2`).
- MQTT credential machinery: `derivations/mqtt_credentials.py` (deterministic
  KDF: username `{prefix}{node_id(hostname)}`, password
  `sha256(secret + node_id)`), per-consumer selection modules
  (`tasmota_credentials.py`, `sensors2mqtt.py`), and
  `supplements/mqtt_broker.py::register_logins()` (prefix-scoped, PBKDF2
  pre-hashed upsert into the HA Mosquitto add-on via SSH + Supervisor API,
  `--dry-run`/`--prune`, post-restart connect-verify).
- Each site runs its own dedicated HA/Mosquitto and its own wisp. There are
  no multi-site pucks.

## Design decisions (user-confirmed)

1. Pucks become hosts via a **new `wifi.welland` tab** parsed by the
   standard parser (IoT-sheet pattern) — no bespoke parser, no firmware
   special-casing in code.
2. OpenMesh hardware **moves** from `Welland - IP Allocation` into the new
   tab. Its `iot.welland` allocation rows **stay** (that sheet is the
   10.X.90.0/24 ledger).
3. Formulas referencing moved rows are **rewritten**, not left to break.
4. WiFi-sheet hosts get a **`.wifi` hostname suffix** (like IoT's `.iot`).
   Puck DNS is unchanged by construction; OpenMesh canonical names change
   (accepted, clean cut, no transition aliases).
5. **Two independent MQTT credential consumers** with separate secrets and
   prefixes: gwifi pucks and wisp. Per-device deterministic passwords, same
   KDF as Tasmota.
6. Credential scope is **broker registration only** — delivering credentials
   to pucks/OpenWISP configs is a later, separate task.
7. All development on a dedicated branch + worktree.

## Part 1 — Spreadsheet migration (`wifi.welland` tab)

New tab `wifi.welland - WiFi Infrastructure` in the same spreadsheet,
following the established `<subdomain>.welland` tab convention. It is the
device inventory + IP-allocation ledger for the wifi infrastructure.

**Columns** (IoT-sheet layout plus what multi-interface hardware needs):

```
Name, Machine, Interface, MAC Address, IP, Type, Site, Physical Location,
Hardware, Upstream, Controlled By, Serial, #, Notes / Comments
```

**Puck rows** — two rows per OpenWRT puck (interfaces `wan`, `lan`), both
carrying the puck's fixed IP `10.X.4.(100+#)` so the existing same-IP
interface grouping models one endpoint with two MACs:

- Values are **cross-tab formulas** referencing `Google WiFi Pucks` (lookup
  by `#`): MAC Address (from `wan`/`lan` columns), Serial, Physical Location
  (from `Location`), Upstream, Controlled By. Single source of truth stays in
  the flash tab; the WiFi tab cannot drift from it. Machine/Name are instead
  derived in-tab as `="puck"&TEXT(#,"00")` — the flash tab's `Name` column is
  unreliably filled (blank for several current OpenWRT rows), so it is not a
  usable machine-name source; this stays consistent with the `PuckData`
  identity rule (`machine_name == f"puck{number:02d}"`).
- `IP` = `="10.X.4." & (100 + <#ref>)` (placeholder-X convention; the
  parser's site-octet resolution handles it).
- `Type` = `DHCP:wisp` (see Part 2 — suppresses ten64 dhcp-host bindings).
- Stock Google-firmware pucks get **no rows** — exclusion lives in the sheet
  (only OpenWRT pucks are listed), not in code.
- `Site` = `welland` (pucks are welland-only).

**OpenMesh rows** — the six 7-row interface blocks move verbatim from
`Welland - IP Allocation` (Machine, Interface, MAC, IP, VLAN-implied
subnets, Site value preserved — currently blank = all sites). `Hardware`
column records the family (`OM2P` / `OM2P-LC`).

**Reference rewrite** — full-spreadsheet formula scan (seed:
`tmp/scan_formulas.py`) found exactly 6 formulas referencing the moved
block: `iot.welland - IoT Devices` R24–R29 C8 (Physical Location, pulling
`'Welland - IP Allocation'!F337/F344/F351/F358/F365/F372`). Migration order:

1. Create the new tab, insert puck + OpenMesh rows.
2. Rewrite the 6 `iot.welland` formulas to the new tab's cells.
3. Delete the old `Welland - IP Allocation` OpenMesh rows.
4. Verify: re-scan shows zero `#REF!` anywhere and zero remaining references
   into the deleted range; the *evaluated* published-CSV values of
   `iot.welland` are unchanged; the new tab's published CSV parses.

The migration is driven by a script using the service-account credentials
(`~/.config/gale-fleet/sheets-sa.json`) so it is reviewable and re-runnable,
not hand-edited. The formula-scan seed lives outside the repo at
`/home/tim/local/gwifi/tmp/scan_formulas.py`; the plan copies it into this
repo (e.g. `scripts/`) as the basis of the migration + verification tool.

**Optional ledger row**: a Machine-less allocation row documenting wisp's
`10.X.4.2` (parallel to IoT's section rows). Documentation only; creates no
host.

## Part 2 — gdoc2netcfg refactor

### Removed

- `sources/gwifi_pucks_parser.py` (and its tests) — the stale-column bug
  dies with it.
- `constraints/gwifi_pucks_validation.py` — pucks are now inside the
  inventory, so the standard MAC/IP-uniqueness validators cover them; the
  "absent from inventory" premise is inverted.
- `generators/gwifi_pucks_dns` — superseded by standard host-records from
  the wifi sheet (`puck04.wifi.welland.mithis.com` etc.). Note: both puck
  generators live in `generators/gwifi_pucks.py` on the branch — that file
  is *edited* (dns generator function deleted, identity generator reworked),
  not removed wholesale.
- `NetworkInventory.gwifi_pucks` and the `[sheets] gwifi_pucks` source.

### Added / changed

- **`[sheets] wifi` source** (published-CSV URL of the new tab), fetched and
  cached like `network`/`iot`, parsed by the standard `parse_csv` with
  `sheet_name="WiFi"`. Zero parser changes.
- **Hostname suffix**: generalize the hardcoded sheet-type special-cases in
  `derivations/dns_names.py` into suffix mappings that preserve today's
  exact behaviour and add WiFi: `compute_hostname` maps
  `{"IoT": ".iot", "Test": ".test", "WiFi": ".wifi"}`; `compute_dhcp_name`
  maps `{"IoT": ".iot", "WiFi": ".wifi"}` (its existing IoT-only asymmetry —
  no `.test` — is preserved, not "fixed"). `host_builder`'s sheet-type
  normalization gains `"wifi" → "WiFi"`.
- **Constraint amendment** (`constraints/validators.py`): `ip_multiple_macs`
  currently ERRORs on any IP with >1 MAC outside the roam range
  (`10.X.20.0/24`) — every 2-MAC puck endpoint on `10.X.4.x` would fail.
  Relax it: multiple MACs on one IP are allowed when **all MACs belong to
  the same host** (single machine, multi-port endpoint — the existing
  `VirtualInterface` model); MACs from different hosts on one non-roam IP
  remain an ERROR. Additive relaxation: no currently-passing configuration
  changes validity. (Implementation note: `inventory.ip_to_macs` holds
  `(mac, dhcp_name)` tuples without a host backreference — the validator
  needs a MAC→host map built during validation.)
- **`PuckData`** (typed, frozen, `models/host.py`): `number: int`,
  `serial: str`. A pure derivation lifts it from `host.extra` (`#`,
  `Serial`) for WiFi-sheet hosts whose rows carry them; fail-loud on
  malformed values (non-integer `#`, number outside 1..99, duplicate
  numbers/serials across hosts). OpenMesh hosts have no Serial/# → no
  `puck_data`, by construction.
- **`pucks.json` generator** (`generate_gwifi_pucks`) now iterates hosts
  with `puck_data`: `name` = machine name, `number`/`serial` from
  `puck_data`, `eth0` = the `wan` interface MAC, `eth1` = the `lan`
  interface MAC, `ip` = the shared fixed IP. Output must remain
  **byte-identical** to today's file (wisp's gwifi-netboot contract);
  fail loud if a puck host is missing either interface. Two equivalences
  this rests on, both enforced: the `PuckData` enrichment asserts
  machine name == `puck{number:02d}` (the old parser synthesized the name
  from `#`; the new path takes the sheet's Machine value), and MAC string
  form must match the old uppercase-colon normalization — NOTE the
  `MACAddress` model's canonical form is *lowercase*, so the generator must
  uppercase explicitly (pinned by the golden test).
- **DHCP suppression**: the internal dnsmasq generator skips `dhcp-host`
  bindings for hosts whose `Type` extra equals `DHCP:wisp` (wisp is the
  DHCP authority for the pucks' VLAN — netboot design D7). The value is
  visible policy in the sheet; other `Type` values keep current behaviour.
  (Exact interaction with existing `Type` handling to be pinned during
  planning; today `Type` is a free-form extra column.)
- **Free wins** (no code): pucks join reachability scans, the HA
  dashboards, `known_hosts` generation, and MAC-collision validation.

### Behaviour changes accepted

- OpenMesh hostnames gain `.wifi`
  (`openmesh-ab-30.wifi.welland.mithis.com`); old canonical names drop out
  of DNS. No transition aliases.
- Pucks gain bare-hostname DNS variants (`puck04.welland.mithis.com`)
  alongside the existing `.wifi` names, per standard derivations.
- Monarto also gains the `.wifi` OpenMesh hosts: their rows keep the
  current blank `Site` (= all sites) and X-placeholder IPs, so monarto's
  generated DNS renames the same way welland's does — expected in the
  monarto diff review, not a surprise.

## Part 3 — MQTT credentials (two consumers)

Mirrors the Tasmota shape exactly; the `Host`-based KDF core is untouched.

- **Config**: `[gwifi] mqtt_secret` and `[wisp] mqtt_secret` in
  `gdoc2netcfg.toml` (independent, ≥32 chars, `require_strong_secret`).
- **`derivations/gwifi_credentials.py`**: prefix `gwifi-`; selects hosts
  with `puck_data`; `build_logins()` → `{gwifi-puck04_wifi: sha256(...)}`
  (usernames include the `.wifi` suffix via `node_id`, consistent with
  Tasmota's `tas-*_iot`). `check_collisions` retained.
- **`derivations/wisp_credentials.py`**: prefix `wisp-`; selects the host
  whose machine name is `wisp` (fail loud if absent or ambiguous); single
  login `wisp-wisp`.
- **CLI**: `gwifi register-broker` and `wisp register-broker`, both
  mirroring `tasmota register-broker`: `--dry-run`, `--prune`,
  post-registration connect-verify, same HA SSH target configuration.
  Each site registers against its own HA broker.
- Passwords are recomputable by any future consumer holding the secret
  (that's the KDF's purpose); no credential files are emitted (scope
  decision 6).

## Part 4 — Verification & rollout

1. **Unit/golden tests**: new-sheet fixture; drift-guard asserting a
   WiFi-sheet host's derived DNS names match the standard path (they *are*
   the standard path — the golden pins it); `pucks.json` byte-compare
   against the current production file's content; dnsmasq golden diff shows
   only the intended deltas (OpenMesh renames, retired fragment replaced by
   identical records, no puck dhcp-host lines).
2. **Sheet migration verification** as in Part 1 step 4.
3. **Staged rollout** (order matters — prod reads the old rows until
   deployed):
   0. Merge `gwifi-pucks-generator` into `wifi-sheet-hosts` (baseline pin,
      see Background); tests green on the merged base.
   1. Land the sheet migration (new tab populated; old rows still present;
      both welland and monarto prod unaffected — they don't read the new tab
      yet).
   2. Merge + deploy the gdoc2netcfg refactor to ten64 (welland): add
      `[sheets] wifi` + generators config, `fetch`, `generate`, diff review
      of `internal/generated/` + `pucks.json` before `make deploy-*`;
      monarto config gains the wifi source with its own site filtering.
   3. Delete the old `Welland - IP Allocation` OpenMesh rows + rewrite the 6
      formulas (sheet-side completion), re-fetch, verify no diff beyond the
      intended renames.
   4. Credentials: set secrets, `--dry-run` both consumers, register on the
      welland broker, verify logins.
4. No test regressions versus the merged base (1825 pass on `origin/main`
   today; the count grows when the branch's own tests merge in at step 0).

## Out of scope

- Deploying wifi-presence (or any MQTT publisher) onto the pucks; the
  wisp→HA presence pipeline (session task #1) builds on these credentials
  later.
- OpenWISP template changes.
- Monarto broker registration (no pucks; wisp consumer can be registered
  there when its HA integration is wanted).
- Any change to the `Google WiFi Pucks` flash tab or the flash tooling.
