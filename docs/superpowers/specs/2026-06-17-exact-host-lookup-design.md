# Exact-First Host Lookup (#40) — Design

**Date:** 2026-06-17
**Status:** Approved (brainstorm), ready for implementation plan
**Issue:** #40 — Fix host lookup to prefer exact matches over substring matches

## Goal

Make `gdoc2netcfg password <query>` host resolution **exact-first** so a query
resolves to the one host the operator means — eliminating the
substring/`machine_name` collisions that currently return multiple hosts (e.g.
`password big-storage` also matching `bmc.big-storage`).

## Problem

`utils/lookup.py::lookup_host` dispatches by query type (MAC / IP / hostname) to
three matchers. Two of them return **mixed tiers** of match quality in one list:

- `_match_by_hostname` returns `exact + prefix + substring`, matching on **both**
  `hostname` and `machine_name`. Because a BMC host (`hostname="bmc.big-storage"`,
  `machine_name="big-storage"`) shares its parent's `machine_name`, and
  `"big-storage"` is a substring of `"bmc.big-storage"`, the query `big-storage`
  returns **two** hosts. `cmd_password` then prints
  "Note: 2 matches found, using best match." — noisy, and fragile if the exact
  host is ever absent.
- `_match_by_ip` returns `exact + wildcard` combined, so an exact IP hit can be
  accompanied by spurious second-octet-wildcard hits.

## Design

**Core principle:** each matcher returns a **single best tier** — never a mix.
A higher tier shadows lower ones; a lower tier is consulted only when the higher
tier is empty.

### Hostname (`_match_by_hostname`)
- **Exact `hostname` match only** (case-insensitive). Production hostnames are the
  *short* `compute_hostname` form — `desktop`, `bmc.big-storage`, `au-plug-1.iot`
  — never FQDNs.
- **Removed:** `machine_name` matching, the `query + "."` prefix match, and
  substring matching.
- Result: `password big-storage` → only `big-storage`. A BMC is reached by its
  full hostname, `password bmc.big-storage`.

### IP (`_match_by_ip`)
- **Tier 1 — exact:** any interface IPv4 equals the query.
- **Tier 2 — second-octet wildcard (fallback only):** octets 1, 3, 4 equal and
  octet 2 differs (the cross-site `10.X.Y.Z` placeholder pattern).
- Return Tier 1 if non-empty; otherwise Tier 2. Never both.

### MAC (`_match_by_mac`)
- Unchanged — exact normalized-MAC match.

### Suggestions (`suggest_matches`)
- Still `difflib`-based, but **drop the `machine_name` candidate** so every
  suggestion is a *resolvable* identifier (hostname, MAC, IP). With hostname-only
  matching, suggesting a bare `machine_name` like `au-plug-1` (which no longer
  resolves) would loop the user; the resolvable `au-plug-1.iot` is what they need.

### Types
- `LookupResult.match_type` ∈ `{"exact", "wildcard"}`. The `"prefix"` and
  `"substring"` values and their code branches are deleted (dead code).

## Behaviour changes (intended)
1. **BMC by parent name no longer resolves.** `password big-storage` returns only
   the primary host; use `password bmc.big-storage` for the BMC. This unambiguous
   resolution is the foundation for **#39** (resolve the IPMI password from the
   associated BMC host).
2. **IoT/Test devices must be queried by full hostname.** `password au-plug-1` no
   longer resolves `au-plug-1.iot` (hostnames carry the `.iot`/`.test` suffix);
   query `au-plug-1.iot`. `suggest_matches` points the short form at the full
   hostname. Operator-confirmed trade-off for an unambiguous exact rule.
3. **No more multi-match noise** for the common substring/wildcard collisions;
   `cmd_password`'s "N matches" path now fires only on genuine duplicates (which
   indicate a data problem worth surfacing).

## Error handling / edge cases
- No match → empty list → `cmd_password` prints `no device found` +
  `suggest_matches` suggestions (unchanged).
- Exact IP and wildcard IP both possible → only exact returned.
- Case-insensitivity preserved for hostnames.

## Testing (`tests/test_utils/test_lookup.py`, `tests/test_cli/test_password.py`)
- **Fix the fixtures first:** the current `test_lookup.py` hosts use unrealistic
  FQDN hostnames (`big-storage.int.welland.mithis.com`). Rebuild them with the
  production-shaped short hostnames (`big-storage`, `bmc.big-storage`,
  `au-plug-1.iot`) so the exact-match assertions are meaningful.
- Hostname: exact hit; `big-storage` does **not** match `bmc.big-storage`; a
  `machine_name`-only query no longer matches; former prefix/substring queries now
  return empty.
- IP: exact hit; wildcard hit **only** when no exact exists; exact preferred when
  both could match.
- MAC: unchanged (regression guard).
- Command: `password big-storage` resolves to one host with no "N matches" note.

## Out of scope
- **#39** (IPMI password from the BMC host's `Password`) — a separate spec on the
  same `credential-lookup-fixes` branch, built on this exact-match foundation.
