# Design: rename gwifi/puck surfaces to `wifi` + broaden MQTT credential scope

**Date:** 2026-07-28
**Status:** Approved by user (branch A / generator key `wifi` / full rename chosen 2026-07-28)
**Branch:** `wifi-sheet-hosts` (updates open PR #18 — nothing renamed here has merged,
deployed, or been registered on the broker yet, so every rename below is free of
production migration work)
**Supersedes naming in:** `2026-07-24-wifi-sheet-hosts-and-mqtt-credentials-design.md`
(that spec and its plan remain as historical record; this spec documents only the delta)

## Motivation

The `gwifi`/puck naming baked into PR #18 is too narrow. The WiFi-sheet host
machinery applies to **tenwrt, the gale ("gwifi") pucks, the OpenMesh APs, and any
future wifi infrastructure device** — not just Google WiFi pucks. Rename every
`gwifi`/puck-named surface to `wifi`, and broaden the MQTT credential selection to
match the name.

## Renames (mechanical, no behavior change)

| Area | Old | New |
|---|---|---|
| Config section | `[gwifi]` | `[wifi]` |
| Config class | `GwifiConfig` / `config.gwifi` / `_build_gwifi` | `WifiConfig` / `config.wifi` / `_build_wifi` |
| Credential module | `derivations/gwifi_credentials.py` | `derivations/wifi_credentials.py` |
| Username prefix | `PREFIX = "gwifi-"` | `PREFIX = "wifi-"` |
| Credential selector | `select_pucks()` | `select_wifi_hosts()` (semantics change — see below) |
| CLI | `gdoc2netcfg gwifi register-broker` (`cmd_gwifi_register_broker`, `gwifi_parser`, `gwifi_subparsers`, `gwifi_rb`, `args.gwifi_command`) | `gdoc2netcfg wifi register-broker` (`cmd_wifi_register_broker`, `wifi_parser`, `wifi_subparsers`, `wifi_rb`, `args.wifi_command`) |
| Model | `PuckData` / `Host.puck_data` | `WifiData` / `Host.wifi_data` |
| Enrichment | `derivations/puck_data.py::enrich_hosts_with_puck_data()` | `derivations/wifi_data.py::enrich_hosts_with_wifi_data()` |
| Generator | `generators/gwifi_pucks.py::generate_gwifi_pucks`, registry/toml key `gwifi_pucks` | `generators/wifi.py::generate_wifi`, registry/toml key `wifi` (`[generators.wifi]`) |
| Tests | `test_gwifi_credentials.py`, `test_gwifi_register_broker.py`, `test_gwifi_pucks.py`, puck_data tests | renamed to match the new module names |
| Docs/example | CLAUDE.md sections, `gdoc2netcfg.toml.example` | updated to the new names |

Internal renames track the surface renames throughout (variables like `pucks`,
`puck_entry`, docstrings). Where prose genuinely means the gale-puck hardware or
the wisp netboot contract (e.g. the generator's docstring, `WifiData` field docs),
it keeps saying "puck" — the *identifiers* say `wifi`.

## Behavior change: credential selection broadens

`build_logins()` currently issues logins only for hosts with `puck_data` set
(fleet pucks). New selection rule:

```python
def select_wifi_hosts(hosts: list[Host]) -> list[Host]:
    return [h for h in hosts if h.sheet_type == "WiFi"]
```

- Every WiFi-sheet host gets a `wifi-<node_id(hostname)>` login: fleet pucks
  (04–12), stock pucks (01–03), OpenMesh APs — and tenwrt automatically, once it
  is given a row on the `wifi.welland` tab (adding that row is out of scope here).
- Stock pucks cannot consume the login on Google firmware; registering it is
  harmless and makes it ready the moment they need it (same "spare login"
  precedent as the SDR Pis in the sensors2mqtt scheme).
- Passwords are `sha256(secret + node_id)` — prefix-independent — and the broker
  has **zero** registered `gwifi-*` logins (registration is a pending rollout
  step), so changing the username prefix costs nothing.
- **New fail-loud:** `build_logins()` raises `ValueError` when `select_wifi_hosts()`
  returns an empty list. A configured `[wifi] mqtt_secret` with zero WiFi-sheet
  hosts in inventory means the wifi sheet didn't parse (or the site has no wifi
  sheet); silently registering nothing would hide that.
- `check_collisions()` now runs across the full broadened selection.

## Explicitly unchanged

- **`wisp/pucks.json`** — filename, shape, and gating are a deployed wisp-netboot
  contract. The generator still emits entries only for hosts with `wifi_data` set
  (i.e. non-blank `#`/`Serial` sheet columns), still fails loud on an empty
  result and on missing `wan`/`lan` interfaces. The golden-fixture byte-identity
  test must still pass unmodified.
- **`WifiData` semantics** — fields stay `number` + `serial`; attached only when
  the sheet columns are non-blank. Stock pucks keep them deliberately blank →
  excluded from pucks.json (but now included in MQTT credentials via
  `sheet_type`).
- **`[wisp]` / `wisp_credentials.py` / `wisp register-broker`** — the OpenWISP
  service login is a different consumer; untouched.
- **`scripts/wifi-sheet-*.py`**, **`[sheets] wifi`**, the `.wifi` hostname
  suffix, `DHCP:wisp` handling — already correctly named / out of scope.

## Tests

- Renamed test modules keep their existing coverage (golden pucks.json,
  register-broker CLI dry-run/apply, credential derivation).
- New: OpenMesh-row host (no `wifi_data`) receives a `wifi-` login;
  stock-puck host receives a login; empty selection raises;
  no `gwifi` identifier remains (`rg -i gwifi src/ tests/` clean except
  deliberate prose references to gale-puck hardware and historical docs).

## Rollout

- Commits land on `wifi-sheet-hosts`; PR #18 title/body updated
  ("per-puck" → "per-device", note the `wifi` naming).
- No prod steps change: the pending rollout sequence (merge → deploy ten64 →
  `rewrite-refs`/`delete-old-rows`/`verify` → broker registration) is identical,
  except the final registration command is now
  `gdoc2netcfg wifi register-broker` and the toml section is `[wifi]`.
