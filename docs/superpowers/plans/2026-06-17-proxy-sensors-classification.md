# Proxy Sensors Classification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Network sheet's `Sensors` column accept a 4th value `proxy` (a host that runs sensors2mqtt but publishes to a different broker proxied onto HA): no HA broker login, but included in the HA state check.

**Architecture:** A one-value change to `classify()` in `derivations/sensors2mqtt.py`. The selectors (`select_local`, `select_non_blank`) already produce the right behaviour once `classify` accepts the value — `proxy` ≠ `local` (no login) and `proxy` ≠ `blank` (state-checked) — so they are unchanged.

**Tech Stack:** Python, pytest, uv.

**Out of scope:** The status check's entity-name mismatch for subdomain hosts (`sensor.pi1_fpgas_*` vs the live `sensor.pi1_*`) is tracked as task #42 and is NOT addressed here. See `docs/superpowers/specs/2026-06-17-proxy-sensors-classification-design.md`.

---

### Task 1: Accept `proxy` in `classify()`

**Files:**
- Modify: `src/gdoc2netcfg/derivations/sensors2mqtt.py` (the `_VALID` set + `classify()` docstring/error, ~lines 23-38)
- Test: `tests/test_derivations/test_sensors2mqtt.py`

The current code (for reference):

```python
_VALID = {"local", "remote", ""}


def classify(host: Host) -> str:
    """Return 'local' / 'remote' / 'blank' for a host's `Sensors` column value.

    Fails loud on an unrecognized non-blank value (never silently skipped)."""
    value = host.extra.get(_COLUMN, "").strip().lower()
    if value not in _VALID:
        raise ValueError(
            f"host {host.hostname}: unrecognized Sensors value "
            f"{value!r} (expected 'local', 'remote', or blank)"
        )
    return "blank" if value == "" else value
```

The existing test fixture (already in the file) — do NOT redefine it, just use it:

```python
def _host(hostname, s2m=None):
    extra = {} if s2m is None else {"Sensors": s2m}
    return Host(machine_name=hostname.split(".")[0], hostname=hostname,
                sheet_type="Network", interfaces=[NetworkInterface(
                    name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.5.10"),), dhcp_name=hostname)],
                extra=extra)
```

- [ ] **Step 1: Write the failing tests**

Add these three methods to the existing test classes in
`tests/test_derivations/test_sensors2mqtt.py` (into `TestClassify`, `TestSelect`,
and `TestBuildLogins` respectively):

```python
    # add to class TestClassify:
    def test_proxy(self):
        assert classify(_host("pi1.fpgas", "proxy")) == "proxy"
```

```python
    # add to class TestSelect:
    def test_proxy_no_login_but_checked(self):
        hosts = [_host("a", "local"), _host("b", "proxy"), _host("c")]
        # proxy excluded from the broker-login set...
        assert [h.hostname for h in select_local(hosts)] == ["a"]
        # ...but included in the state-check set
        assert sorted(h.hostname for h in select_non_blank(hosts)) == ["a", "b"]
```

```python
    # add to class TestBuildLogins:
    def test_proxy_excluded(self):
        secret = "0123456789abcdef0123456789abcdef"
        logins = build_logins(secret, [_host("a", "proxy"), _host("b", "local")])
        assert set(logins) == {"s2m-b"}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_derivations/test_sensors2mqtt.py -k "proxy" -v`
Expected: FAIL — `test_proxy` and `test_proxy_no_login_but_checked` raise
`ValueError: ... unrecognized Sensors value 'proxy' ...` (because `classify`
rejects `proxy`); `test_proxy_excluded` fails the same way inside `build_logins`.

- [ ] **Step 3: Implement — add `proxy` to `_VALID` and update the docstring/error**

In `src/gdoc2netcfg/derivations/sensors2mqtt.py`, change the `_VALID` line to:

```python
_VALID = {"local", "remote", "proxy", ""}
```

and replace the `classify()` docstring + the `ValueError` message so they read:

```python
def classify(host: Host) -> str:
    """Return 'local' / 'remote' / 'proxy' / 'blank' for a host's `Sensors` value.

    'local' runs a collector locally and gets an HA broker login; 'remote' is polled
    by a collector elsewhere; 'proxy' runs a collector that publishes to a different
    broker which proxies the data onto HA (so it gets NO HA login but is still
    state-checked); blank means not involved. Fails loud on an unrecognized non-blank
    value (never silently skipped)."""
    value = host.extra.get(_COLUMN, "").strip().lower()
    if value not in _VALID:
        raise ValueError(
            f"host {host.hostname}: unrecognized Sensors value "
            f"{value!r} (expected 'local', 'remote', 'proxy', or blank)"
        )
    return "blank" if value == "" else value
```

(The `return` line is unchanged — for `value == "proxy"` it returns `"proxy"`.)

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `uv run pytest tests/test_derivations/test_sensors2mqtt.py -k "proxy" -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Run the full sensors2mqtt test module + lint**

Run: `uv run pytest tests/test_derivations/test_sensors2mqtt.py -v`
Expected: PASS (all, including the pre-existing `test_unrecognized_raises` which
still rejects a genuinely unknown value like `"maybe"`).
Run: `uv run ruff check src/gdoc2netcfg/derivations/sensors2mqtt.py tests/test_derivations/test_sensors2mqtt.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/gdoc2netcfg/derivations/sensors2mqtt.py tests/test_derivations/test_sensors2mqtt.py
git commit -m "feat: accept 'proxy' Sensors classification (no HA login, state-checked)"
```
