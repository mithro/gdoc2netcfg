# IPMI/BMC Credentials from the BMC Host's `Password` (#39) — Design

**Date:** 2026-06-17
**Status:** Approved (brainstorm), ready for implementation plan
**Issue:** #39 — Resolve IPMI password from the associated BMC host's Password field
**Builds on:** #40 (exact-first host lookup) — BMC resolution relies on exact hostname matching.

## Goal

Resolve IPMI/BMC credentials from the **single `Password` column** on the BMC host
(format `username:password`), for both consumers:
- `password --type ipmi <server>` — currently returns nothing.
- the `bmc-firmware` scan — currently authenticates only with `ADMIN`/`ADMIN`.

## Background / current state

The spreadsheet has exactly one credential column: **`Password`** (stripped into the
root-only `credentials.db` at fetch). The `SNMP Community` / `IPMI Username` /
`IPMI Password` names in `CREDENTIAL_TYPES` are speculative — they have never existed in
the sheet, so:
- `password --type ipmi` reads non-existent columns → always *"no ipmi credential found."*
- `bmc_firmware._try_ipmi_credentials` reads the same non-existent columns (and from a
  credential-stripped cache) → always falls through to `ADMIN`/`ADMIN`.

A BMC host (`bmc.<machine>`, `is_bmc == True`) carries its login in its `Password` column
as `username:password`.

## Design

### Shared parser — `split_login(value: str) -> tuple[str | None, str]`
New in `utils/lookup.py`. Splits on the **first** `:`:
- `"ADMIN:s3cr3t"` → `("ADMIN", "s3cr3t")`
- `"s3cr3t"` (no colon) → `(None, "s3cr3t")`
- `"ADMIN:a:b"` → `("ADMIN", "a:b")` (password may contain colons)

Pure function, no I/O.

### Part A — `password --type ipmi <server>` (`cli/main.py::cmd_password`)
Special-case `--type ipmi` ahead of the generic `get_credential_fields` path:
1. Resolve the query → host `X` (exact, via #40's `lookup_host`).
2. Determine the BMC host:
   - `X.is_bmc` → the BMC is `X` itself.
   - else → the inventory host whose hostname equals `"bmc." + X.hostname` (exact).
     **None found → fail loud:** `Error: no BMC host (bmc.<X.hostname>) found for '<X>'`.
3. Load `credentials.db` (read-only) and read the BMC host's `Password`
   (`stored[bmc.hostname]["Password"]`). Reuse `cmd_password`'s existing store-open error
   handling (missing store → "run fetch"; unreadable → "re-run with sudo").
   **BMC has no `Password` → fail loud:** `Error: BMC <bmc.hostname> has no Password`.
4. `split_login(password)` → `(username, password)`.
5. Output `{"IPMI Username": username, "IPMI Password": password}`, **omitting**
   `IPMI Username` when `username is None`. This flows through the existing print /
   `--quiet` code unchanged (quiet prints values only → password-only when no username).
   The non-quiet `Matched by:` block notes the BMC source.

`CREDENTIAL_TYPES` loses its `ipmi` entry (the path is special-cased); `get_credential_fields`
is only called for `password` / `snmp` / `--field`.

### Part B — `bmc-firmware` scan (`cli/main.py::cmd_bmc_firmware`, `supplements/bmc_firmware.py`)
- `cmd_bmc_firmware` (runs as root) loads `credentials.db` and merges each scanned host's
  stored fields onto `host.extra` (so `host.extra["Password"]` is available). If the store
  is missing/unreadable → print a **warning** and continue (the scan still works for factory
  `ADMIN`/`ADMIN` BMCs). *A scan has a legitimate fallback, so this is graceful, not a hard
  failure — unlike Part A's direct credential request.*
- `_try_ipmi_credentials(ip, host)`:
  - `user, pw = split_login(host.extra.get("Password", "").strip())`; an empty value means
    no configured creds.
  - Attempts, first success wins:
    1. **Configured BMC creds** (only if a password was found): `(user or "ADMIN", pw)`.
       No-colon → username `ADMIN` (ipmitool requires `-U`; `ADMIN` is the factory username).
    2. **Factory default**: `ADMIN`/`ADMIN`.
  - Delete the dead `IPMI Username`/`IPMI Password` branch.

### Cleanup
- Delete `IPMI Username` / `IPMI Password` from `CREDENTIAL_TYPES` (`utils/lookup.py`).
  `credential_field_names()` becomes `["Password", "SNMP Community"]`; column stripping is
  unaffected (neither extra column exists). `--type snmp` is unchanged and out of scope.

## Intentional divergence (state explicitly)
The no-colon `Password` is handled differently by the two consumers, **by design**:
- **Part A (display):** no username — honest about what is stored.
- **Part B (authenticate):** username defaults to `ADMIN` — ipmitool needs a concrete `-U`.

Do not "unify" these into one policy.

## Error handling / edge cases
- `password --type ipmi <X>` where X has no BMC → fail loud (no fabrication).
- BMC found but no `Password` → fail loud.
- `password --type ipmi bmc.<X>` (BMC queried directly) → uses its own `Password`.
- `bmc-firmware` with no `credentials.db` → warn + `ADMIN`/`ADMIN` only.
- `Password` with multiple colons → username = before the first colon, password = remainder.

## Testing
- `split_login` (`tests/test_utils/test_lookup.py`): colon, no colon, multiple colons, empty.
- `password --type ipmi` (`tests/test_cli/test_password.py`): resolves the BMC's `Password`
  from a server query; BMC-direct query; no-BMC → exit 1 + clear error; BMC-without-Password
  → exit 1; no-colon → password only (no username line); `--quiet` output; multi-colon password.
- `bmc_firmware` (`tests/test_supplements/test_bmc_firmware.py`, create if absent): with
  `_run_ipmitool_mc_info` monkeypatched to record attempts, assert order = configured BMC
  creds first, then `ADMIN`/`ADMIN`; no-colon → `ADMIN` username; empty `Password` → only
  `ADMIN`/`ADMIN` tried.
- Cleanup: assert `CREDENTIAL_TYPES` has no `ipmi` key.

## Out of scope
- `--type snmp` and the `SNMP Community` column (separate concern — SNMP community lives elsewhere).
- How BMC hosts are derived (`bmc.<machine>`) — unchanged.
