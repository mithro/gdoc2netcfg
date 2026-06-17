# Exact-First Host Lookup (#40) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `gdoc2netcfg password <query>` resolve a host by *exact* identity — exact hostname (no machine_name/prefix/substring), and exact IP with a second-octet-wildcard *fallback* — eliminating substring collisions like `password big-storage` also matching `bmc.big-storage`.

**Architecture:** Three matchers in `src/gdoc2netcfg/utils/lookup.py` (`_match_by_hostname`, `_match_by_ip`, `_match_by_mac`), dispatched by `lookup_host`. Each matcher returns a *single best tier*, never a mix. `suggest_matches` (the "did you mean?" helper) suggests only resolvable identifiers.

**Tech Stack:** Python 3.13, pytest, ruff, `uv run`.

**Spec:** `docs/superpowers/specs/2026-06-17-exact-host-lookup-design.md`

**Production fact (verified):** `compute_hostname` returns the *short* name — `desktop`, `bmc.big-storage`, `au-plug-1.iot` — never an FQDN. The existing `test_lookup.py` fixtures use unrealistic FQDN hostnames and must be rebuilt.

---

## File Structure

- Modify: `src/gdoc2netcfg/utils/lookup.py`
  - `_match_by_hostname` → exact hostname only
  - `_match_by_ip` → exact, falling back to wildcard only when no exact
  - `suggest_matches` → drop the `machine_name` candidate
  - `LookupResult` docstring → `match_type` ∈ `{exact, wildcard}`
- Modify: `tests/test_utils/test_lookup.py` (rebuild fixtures + matcher tests)
- Modify: `tests/test_cli/test_password.py` (fix the mislabeled substring test)

No new files. No call-site changes (`cmd_password` already takes `results[0]`).

---

## Task 1: Exact-only hostname matching

**Files:**
- Modify: `src/gdoc2netcfg/utils/lookup.py` (`_match_by_hostname`, `LookupResult` docstring)
- Test: `tests/test_utils/test_lookup.py` (`TestMatchByHostname` class + its fixture)

- [ ] **Step 1: Rewrite the `TestMatchByHostname` fixture and tests**

Replace the entire `TestMatchByHostname` class (and only that class) in
`tests/test_utils/test_lookup.py` with production-shaped short hostnames and
exact-only assertions:

```python
class TestMatchByHostname:
    @pytest.fixture
    def hosts(self):
        return [
            # Network devices: hostname == machine_name (short)
            _make_host("switch1", "switch1",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("switch10", "switch10",
                        ip="10.1.30.10", mac="aa:bb:cc:dd:ee:04"),
            _make_host("big-storage", "big-storage",
                        ip="10.1.10.3", mac="aa:bb:cc:dd:ee:03"),
            # BMC: hostname "bmc.big-storage", machine_name shared with parent
            _make_host("big-storage", "bmc.big-storage",
                        ip="10.1.10.4", mac="aa:bb:cc:dd:ee:05"),
            # IoT: hostname carries the ".iot" suffix, machine_name is short
            _make_host("au-plug-1", "au-plug-1.iot",
                        ip="10.1.90.71", mac="aa:bb:cc:dd:ee:06"),
        ]

    def test_exact_hostname_match(self, hosts):
        results = lookup_host("switch1", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "switch1"
        assert results[0].match_type == "exact"

    def test_case_insensitive(self, hosts):
        results = lookup_host("SWITCH1", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "switch1"

    def test_bmc_collision_resolved(self, hosts):
        """'big-storage' must resolve ONLY the primary, never bmc.big-storage."""
        results = lookup_host("big-storage", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "big-storage"
        assert results[0].match_type == "exact"

    def test_bmc_reached_by_full_hostname(self, hosts):
        results = lookup_host("bmc.big-storage", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "bmc.big-storage"

    def test_machine_name_not_matched(self, hosts):
        """machine_name no longer matches: 'au-plug-1' != hostname 'au-plug-1.iot'."""
        assert lookup_host("au-plug-1", hosts) == []

    def test_iot_full_hostname_matches(self, hosts):
        results = lookup_host("au-plug-1.iot", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "au-plug-1.iot"

    def test_substring_no_longer_matches(self, hosts):
        """'storage' was a substring of 'big-storage'; now no match."""
        assert lookup_host("storage", hosts) == []

    def test_prefix_no_longer_matches(self, hosts):
        """'switch1' must NOT prefix-match 'switch10'."""
        results = lookup_host("switch1", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "switch1"

    def test_no_match(self, hosts):
        assert lookup_host("nonexistent", hosts) == []
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_utils/test_lookup.py::TestMatchByHostname -v`
Expected: FAIL — e.g. `test_bmc_collision_resolved` returns 2 results,
`test_substring_no_longer_matches` returns 1, `test_machine_name_not_matched`
returns 1 (current code matches machine_name/substring).

- [ ] **Step 3: Rewrite `_match_by_hostname` to exact-only**

In `src/gdoc2netcfg/utils/lookup.py`, replace the whole `_match_by_hostname`
function body with:

```python
def _match_by_hostname(
    query: str, hosts: list[Host],
) -> list[LookupResult]:
    """Match hosts by exact hostname (case-insensitive).

    Only an exact hostname match counts — no machine_name, prefix, or
    substring matching. Production hostnames are the short compute_hostname
    form (e.g. 'desktop', 'bmc.big-storage', 'au-plug-1.iot'), so a BMC is
    reached by its full 'bmc.<machine>' hostname and an IoT device by its
    '.iot' hostname.
    """
    q = query.lower()
    return [
        LookupResult(
            host=host, match_type="exact",
            match_detail=f"hostname '{host.hostname}'",
        )
        for host in hosts
        if host.hostname.lower() == q
    ]
```

- [ ] **Step 4: Update the `LookupResult` docstring**

In the `LookupResult` dataclass docstring, change the `match_type` line from
`('exact', 'prefix', 'substring', 'wildcard')` to `('exact', 'wildcard')`.

- [ ] **Step 5: Run the hostname tests to verify they pass**

Run: `uv run pytest tests/test_utils/test_lookup.py::TestMatchByHostname -v`
Expected: PASS (all).

- [ ] **Step 6: Commit**

```bash
git add src/gdoc2netcfg/utils/lookup.py tests/test_utils/test_lookup.py
git commit -m "feat: exact-only hostname lookup (#40)"
```

---

## Task 2: Tiered IP fallback (exact, then second-octet wildcard)

**Files:**
- Modify: `src/gdoc2netcfg/utils/lookup.py` (`_match_by_ip`)
- Test: `tests/test_utils/test_lookup.py` (`TestMatchByIP`)

- [ ] **Step 1: Add the failing "exact shadows wildcard" test**

In `tests/test_utils/test_lookup.py`, replace `TestMatchByIP` with (the new
`test_exact_shadows_wildcard` is the one that fails on current code):

```python
class TestMatchByIP:
    @pytest.fixture
    def hosts(self):
        return [
            _make_host("switch1", "switch1",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("server1", "server1",
                        ip="10.1.10.5", mac="aa:bb:cc:dd:ee:02"),
            # Same octets 1/3/4 as switch1 but a different second octet:
            _make_host("switch1-m", "switch1-m",
                        ip="10.2.30.1", mac="aa:bb:cc:dd:ee:03"),
        ]

    def test_exact_ip_match(self, hosts):
        results = lookup_host("10.1.30.1", hosts)
        assert results[0].host.hostname == "switch1"
        assert results[0].match_type == "exact"

    def test_exact_shadows_wildcard(self, hosts):
        """An exact hit suppresses the wildcard tier entirely."""
        results = lookup_host("10.1.30.1", hosts)
        assert len(results) == 1
        assert all(r.match_type == "exact" for r in results)
        assert results[0].host.hostname == "switch1"

    def test_wildcard_only_when_no_exact(self, hosts):
        """No host has 10.3.30.1, so the wildcard tier is returned."""
        results = lookup_host("10.3.30.1", hosts)
        hostnames = {r.host.hostname for r in results}
        assert hostnames == {"switch1", "switch1-m"}
        assert all(r.match_type == "wildcard" for r in results)

    def test_no_match(self, hosts):
        assert lookup_host("10.1.99.99", hosts) == []
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_utils/test_lookup.py::TestMatchByIP -v`
Expected: FAIL — `test_exact_shadows_wildcard` gets 2 results (current returns
`exact + wildcard` combined: switch1 exact + switch1-m wildcard).

- [ ] **Step 3: Rewrite `_match_by_ip` to be tiered**

Replace the whole `_match_by_ip` function body in `lookup.py`:

```python
def _match_by_ip(query: str, hosts: list[Host]) -> list[LookupResult]:
    """Match hosts by IPv4 address, exact-first.

    Tier 1 — exact match on any interface IPv4.
    Tier 2 — second-octet wildcard (octets 1, 3, 4 equal, octet 2 differs),
             the cross-site 10.X.Y.Z placeholder pattern.

    Returns Tier 1 if non-empty; otherwise Tier 2. Never both. One result
    per host (exact preferred over a wildcard on another interface).
    """
    q_parts = query.split(".")
    exact: list[LookupResult] = []
    wildcard: list[LookupResult] = []

    for host in hosts:
        host_exact: LookupResult | None = None
        host_wildcard: LookupResult | None = None
        for iface in host.interfaces:
            ip_str = str(iface.ipv4)
            if query == ip_str:
                host_exact = LookupResult(
                    host=host, match_type="exact",
                    match_detail=f"IP {ip_str} on interface "
                                 f"{iface.name or 'default'}",
                )
                break  # exact is best for this host
            ip_parts = ip_str.split(".")
            if (host_wildcard is None and len(q_parts) == 4
                    and len(ip_parts) == 4
                    and q_parts[0] == ip_parts[0]
                    and q_parts[2] == ip_parts[2]
                    and q_parts[3] == ip_parts[3]
                    and q_parts[1] != ip_parts[1]):
                host_wildcard = LookupResult(
                    host=host, match_type="wildcard",
                    match_detail=f"IP {ip_str} (second-octet wildcard "
                                 f"match for {query})",
                )
                # keep scanning — a later interface may be an exact hit
        if host_exact is not None:
            exact.append(host_exact)
        elif host_wildcard is not None:
            wildcard.append(host_wildcard)

    return exact if exact else wildcard
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_utils/test_lookup.py::TestMatchByIP -v`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/utils/lookup.py tests/test_utils/test_lookup.py
git commit -m "feat: tiered IP lookup — exact before second-octet wildcard (#40)"
```

---

## Task 3: Resolvable-only suggestions + command tests + full verification

**Files:**
- Modify: `src/gdoc2netcfg/utils/lookup.py` (`suggest_matches`)
- Test: `tests/test_utils/test_lookup.py` (`TestSuggestMatches`)
- Test: `tests/test_cli/test_password.py` (fix mislabeled substring test)

- [ ] **Step 1: Add the failing suggestion test**

Append to `TestSuggestMatches` in `tests/test_utils/test_lookup.py`:

```python
    def test_suggests_full_hostname_not_machine_name(self):
        """A short IoT name should suggest the resolvable '.iot' hostname,
        not the bare machine_name (which no longer resolves)."""
        hosts = [
            _make_host("au-plug-1", "au-plug-1.iot",
                        ip="10.1.90.71", mac="aa:bb:cc:dd:ee:06"),
        ]
        suggestions = suggest_matches("au-plug-1", hosts)
        assert "au-plug-1.iot" in suggestions
        assert "au-plug-1" not in suggestions
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_utils/test_lookup.py::TestSuggestMatches::test_suggests_full_hostname_not_machine_name -v`
Expected: FAIL — current `suggest_matches` adds the bare `machine_name`
`au-plug-1` as a candidate, so it appears in (and tops) the suggestions.

- [ ] **Step 3: Drop the machine_name candidate in `suggest_matches`**

In `lookup.py::suggest_matches`, remove the two lines that append
`host.machine_name`:

```python
        if host.machine_name != host.hostname:
            candidates.append(host.machine_name)
```

Update its docstring to: "Compares against all hostnames, MACs, and IPs — the
identifiers exact lookup can resolve (machine_name is intentionally excluded)."

- [ ] **Step 4: Fix the mislabeled command-level substring test**

In `tests/test_cli/test_password.py`, replace `test_lookup_by_substring`
(in `TestPasswordByHostname`) — it claims to test a substring but actually
queries the full name `server1`. Replace it with a test that a genuine
substring now fails:

```python
    def test_substring_no_longer_matches(self, password_config, capsys):
        """A partial name ('serv') must NOT resolve under exact matching."""
        result = main([
            "-c", str(password_config), "password", "serv",
        ])
        assert result == 1
        assert "no device found" in capsys.readouterr().err
```

(Leave `test_lookup_by_machine_name` as-is: in this fixture `hostname ==
machine_name`, so `password switch1` is a valid *exact hostname* hit.)

- [ ] **Step 5: Run the targeted tests to verify they pass**

Run: `uv run pytest tests/test_utils/test_lookup.py tests/test_cli/test_password.py -v`
Expected: PASS (all).

- [ ] **Step 6: Full lint + test sweep**

Run: `uv run ruff check src/ tests/`
Expected: All checks passed.

Run: `uv run pytest -q`
Expected: all pass (no regressions elsewhere).

Also confirm no stale tier strings remain:
Run: `grep -rn "substring\|\"prefix\"\|'prefix'" src/gdoc2netcfg/utils/lookup.py`
Expected: no matches.

- [ ] **Step 7: Commit**

```bash
git add src/gdoc2netcfg/utils/lookup.py tests/test_utils/test_lookup.py tests/test_cli/test_password.py
git commit -m "feat: suggest only resolvable identifiers; exact-match command tests (#40)"
```

---

## Self-Review notes (for the executor)

- **Spec coverage:** hostname exact-only (Task 1), IP tiered fallback (Task 2),
  suggest_matches resolvable-only + match_type cleanup (Tasks 1+3),
  fixture realism (Task 1), command-level substring removal (Task 3). All spec
  points covered.
- **No call-site churn:** `cmd_password` consumes `results[0]` and prints
  "N matches" only when `len(results) > 1`; tiered single-tier results make
  that fire only on genuine duplicates. No change needed there.
- **Out of scope:** #39 (IPMI-from-BMC) is a separate spec/plan on this branch.
