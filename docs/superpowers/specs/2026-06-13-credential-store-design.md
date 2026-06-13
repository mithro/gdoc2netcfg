# Root-only credential store — design

**Date:** 2026-06-13
**Status:** Design (approved, pre-implementation)
**Task:** #27

## 1. Summary

Make device credentials (the spreadsheet's `Password` and the other
`CREDENTIAL_TYPES` columns) readable **only by root**, while keeping every other
gdoc2netcfg read command (`generate`, `db`, `validate`, the `show` commands)
runnable sudo-free as a normal user.

The credential columns are currently co-mingled with non-secret device data in
the **world-readable** cache, so file permissions alone cannot isolate them. The
fix physically separates credentials into a new root-only store at fetch time,
leaving the cache credential-free.

## 2. Background / motivation

- The network sheet has a `Password` column (27 populated rows today).
  `CREDENTIAL_TYPES` (`utils/lookup.py`) defines the full protected set:
  `Password`, `SNMP Community`, `IPMI Username`, `IPMI Password`. Only
  `Password` is populated currently.
- These values live in `.cache/network.csv` (`664 root:root`) and inside
  `config.db` → `csv_snapshots.csv_text` (**485 historical rows**, never
  pruned). Both are world-readable so that `password` / `generate` / `db` /
  `validate` / the `show` commands can run sudo-free as `tim` (the documented
  "root writes, anyone reads" model).
- The `password` command reads credentials from `host.extra`; the `--field`
  flag can also pull any column by name. So the design must protect the **data**,
  not just one command path.
- The site `gdoc2netcfg.toml` (HA token, MQTT passwords) was already tightened
  to `600` separately; this spec covers the device credentials in the cache.

## 3. Decisions (from brainstorm)

1. **Separate credential store** (not "lock the whole cache to root"): only the
   `password` command needs root; everything else stays sudo-free.
2. **Delta history** in a new root-only SQLite DB (consistent with the other
   DBs), not a latest-only flat file.
3. **Existing exposure is scrubbed manually**, one-off, at deploy time — NOT a
   shipped migration tool.
4. **Generic `(hostname, field, value)` EAV table** for the credentials (not a
   typed 4-column table) — flexible to new credential column names without a
   schema change; still no JSON blobs.
5. `password` requiring `sudo` on prod (store is `600 root`) is the intended UX.

## 4. Architecture

### 4.1 `credentials.db` (new, root-only)

- Location: `.cache/credentials.db`. Mode **`0600 root:root`**, enforced on
  create/open (`BaseDatabase` otherwise creates `0644`; chmod after connect and
  verify). Sits in the world-readable `.cache/` dir, but the file itself is
  unreadable to non-root.
- Inherits `BaseDatabase`: DELETE journal, schema versioning, shared `scans`
  audit table. New `storage/credentials_db.py` with a `CredentialsDB` class.
- Written **only by `fetch`** (which already runs as root on prod). The
  reachability daemon and other scans never touch it.
- Schema — EAV, delta-stored:

  ```
  credentials(
      scan_id   INTEGER NOT NULL REFERENCES scans(id),
      hostname  TEXT    NOT NULL,
      field     TEXT    NOT NULL,   -- e.g. "Password", "SNMP Community"
      value     TEXT               -- NULL = tombstone (cleared/removed)
  )
  ```

- **Delta key = `(hostname, field)`.** `save_credentials(scan_id, map)` inserts a
  row for a `(hostname, field)` only when its value differs from the latest
  stored value (new value, changed value, or cleared → NULL tombstone). A field
  present in the latest state but absent from the new map is tombstoned
  (NULL) — so removing a `Password` in the sheet, or removing the host, is
  reflected. Never prunes.
- `load_latest_credentials()` reconstructs the latest non-tombstoned value per
  `(hostname, field)` and returns `{hostname: {field: value}}`.

### 4.2 `fetch` changes (`cli/main.py::cmd_fetch`)

For each fetched sheet, detect credential columns by header name — the protected
column names are the **flattened values** of `CREDENTIAL_TYPES`
(`Password`, `SNMP Community`, `IPMI Username`, `IPMI Password`). If a sheet
contains any:

1. Build a `hostname → {field: value}` map by parsing the **full** CSV and
   running the host-building pipeline. **Hostname parity is critical:** the
   `hostname` keys written here must be byte-identical to those the `password`
   command computes at lookup, so both sides MUST use the same
   parse → `_enrich_site_from_sheets` → `build_hosts` sequence. This is factored
   into one shared helper (e.g. `build_hosts_from_csvs(config, csv_data)`) called
   by both `fetch` and `password`, so the keying (unique `hostname`, BMC vs
   parent distinct) cannot drift.
2. `save_credentials(...)` to `credentials.db` (delta).
3. **Strip** the credential column(s) from the CSV (by column index, applied to
   every row including any banner/header rows) and write the **credential-free**
   CSV to the flat cache (`network.csv`) and to `config.db` `csv_snapshots`.

Sheets with no credential columns (e.g. `iot.csv`) are written unchanged. A
sheet whose credential columns are all empty still results in an empty/tombstone
delta — no special-casing that hides data.

### 4.3 `password` command changes (`cli/main.py::cmd_password`)

1. Load the (credential-free) cache and build hosts via the shared
   `build_hosts_from_csvs` helper (§4.2), then match the query — unchanged and
   sudo-free for the matching half.
2. Open `credentials.db` (root-only) and merge the matched host's stored
   credentials into `host.extra` (keyed by `host.hostname`).
3. `get_credential_fields(...)` / `available_credential_fields(...)` run exactly
   as today (covers both `--type` and `--field`).

### 4.4 Permissions / deployment / scrub

- `credentials.db` `0600 root`; `network.csv` and `config.db` remain
  world-readable (credential-free), preserving sudo-free `generate`/`db`/
  `validate`/`show`.
- Deploy: merge → `git pull` both sites → run `fetch` (as root) once per site to
  populate `credentials.db` and rewrite the cache credential-free.
- **Manual one-off scrub** at deploy (operator, not shipped code): rewrite the
  existing `config.db` `csv_snapshots` (485 rows) and `network.csv` on both
  sites to drop the credential columns, closing the historical exposure.

## 5. Data flow

```
fetch (root):
  raw CSV ──► detect credential cols
            ├─ build_hosts ──► {hostname:{field:value}} ──► credentials.db (0600 root, delta)
            └─ strip cols ──► credential-free CSV ──► network.csv (664) + config.db csv_snapshots (644)

password (root):
  credential-free cache ──► build_hosts ──► match query ──► host
  credentials.db ──► load host's {field:value} ──► merge into host.extra ──► get_credential_fields
```

## 6. Error handling (fail loud)

- `password` when `credentials.db` is unreadable (running as non-root): fail loud
  with "credentials are stored root-only — run with sudo". Do not return an empty
  credential silently.
- `password` when `credentials.db` is missing: fail loud with "no credential
  store — run `fetch`".
- `CredentialsDB` enforces `0600` on open; if it cannot (e.g. wrong owner),
  raise rather than proceed with a world-readable store.
- `save_credentials` validates the input map shape and fails loud on drift,
  matching the other `save_*` methods.

## 7. Testing

- `CredentialsDB`: save → delta (no row when unchanged), tombstone on
  clear/removal, `load_latest_credentials` reconstruction, `0600` enforcement.
- `fetch` stripping: credential column removed from the cached CSV; values land
  in the store; hostname keying including a BMC case; credential-free sheets
  untouched.
- `password`: merges from the store; fails loud when the store is
  unreadable/missing; `--type` and `--field` both resolve via the store.
- Full `uv run pytest` green; `uv run ruff check src/ tests/` clean.

## 8. Out of scope / non-goals

- Tightening the world-readable cache further (the non-credential data stays
  world-readable by design).
- An automated historical-scrub tool (done manually, §4.4).
- Changing the `password` command's matching/UX beyond the new root requirement.
- The HA token / MQTT passwords in `gdoc2netcfg.toml` (already tightened to
  `600`).
