# IPMI/BMC Credentials from the BMC Host's `Password` (#39) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve IPMI/BMC credentials from the BMC host's single `Password` column (`username:password`) for both `password --type ipmi <server>` and the `bmc-firmware` scan.

**Architecture:** One shared parser (`split_login`) in `utils/lookup.py`; `cmd_password` special-cases `--type ipmi` to resolve the BMC host and parse its `Password`; `bmc_firmware` authenticates with the parsed BMC `Password` (falling back to `ADMIN`/`ADMIN`). The never-existent `IPMI Username`/`IPMI Password` columns are removed from `CREDENTIAL_TYPES`.

**Tech Stack:** Python 3.13, pytest, ruff, `uv run`.

**Spec:** `docs/superpowers/specs/2026-06-17-ipmi-from-bmc-design.md`. Builds on #40 (exact lookup, already merged).

**Verified facts:** the sheet has one credential column (`Password`); a BMC host is `is_bmc` with hostname `bmc.<machine>`; `credentials.db` is read via `CredentialsDB(path, read_only=True).load_latest_credentials()` → `{hostname: {field: value}}`; `cmd_bmc_firmware` builds hosts from the credential-free cache; `sqlite3` is already imported in `cli/main.py`.

---

## File Structure
- Modify `src/gdoc2netcfg/utils/lookup.py` — add `split_login`; remove `ipmi` from `CREDENTIAL_TYPES`.
- Modify `src/gdoc2netcfg/cli/main.py` — `cmd_password` ipmi special-case; `cmd_bmc_firmware` credential merge.
- Modify `src/gdoc2netcfg/supplements/bmc_firmware.py` — rewrite `_try_ipmi_credentials`.
- Modify tests: `tests/test_utils/test_lookup.py`, `tests/test_cli/test_password.py`, `tests/test_supplements/test_bmc_firmware.py`.

---

## Task 1: `split_login` parser

**Files:** `src/gdoc2netcfg/utils/lookup.py`, `tests/test_utils/test_lookup.py`.

- [ ] **Step 1: Write the failing tests** — add a new class to `tests/test_utils/test_lookup.py` and import `split_login` (add it to the existing `from gdoc2netcfg.utils.lookup import (...)` block):

```python
class TestSplitLogin:
    def test_username_and_password(self):
        assert split_login("ADMIN:s3cr3t") == ("ADMIN", "s3cr3t")

    def test_no_colon_is_password_only(self):
        assert split_login("s3cr3t") == (None, "s3cr3t")

    def test_password_may_contain_colons(self):
        assert split_login("ADMIN:a:b:c") == ("ADMIN", "a:b:c")

    def test_empty(self):
        assert split_login("") == (None, "")
```

- [ ] **Step 2: Run, expect failure** — `uv run pytest tests/test_utils/test_lookup.py::TestSplitLogin -v` → `ImportError`/`AttributeError` (`split_login` undefined).

- [ ] **Step 3: Implement** — add to `src/gdoc2netcfg/utils/lookup.py` (after `detect_query_type`, before the `LookupResult` section):

```python
def split_login(value: str) -> tuple[str | None, str]:
    """Split a ``username:password`` credential value on the first colon.

    Returns ``(username, password)``; when there is no colon, the username is
    ``None`` and the whole value is the password. The password itself may
    contain colons (only the first is the separator).

    >>> split_login("ADMIN:s3cr3t")
    ('ADMIN', 's3cr3t')
    >>> split_login("s3cr3t")
    (None, 's3cr3t')
    """
    username, sep, password = value.partition(":")
    if not sep:
        return None, value
    return username, password
```

- [ ] **Step 4: Run, expect pass** — `uv run pytest tests/test_utils/test_lookup.py::TestSplitLogin -v`.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: split_login helper for username:password parsing (#39)"`

---

## Task 2: `password --type ipmi` resolves the BMC's `Password` (Part A)

**Files:** `src/gdoc2netcfg/utils/lookup.py` (CREDENTIAL_TYPES), `src/gdoc2netcfg/cli/main.py` (`cmd_password`), `tests/test_cli/test_password.py`, `tests/test_utils/test_lookup.py`.

- [ ] **Step 1: Update the credential-lookup unit tests** in `tests/test_utils/test_lookup.py`:
  - **Delete** `TestGetCredentialFields::test_ipmi_type` and `test_ipmi_partial` (they assert the removed `CREDENTIAL_TYPES["ipmi"]` behaviour).
  - **Add** to `TestGetCredentialFields`:
    ```python
    def test_ipmi_not_in_credential_types(self):
        """--type ipmi is special-cased in cmd_password, not via CREDENTIAL_TYPES."""
        from gdoc2netcfg.utils.lookup import CREDENTIAL_TYPES
        assert "ipmi" not in CREDENTIAL_TYPES
        with pytest.raises(ValueError, match="Unknown credential type"):
            get_credential_fields(_make_host("s", "s"), credential_type="ipmi")
    ```

- [ ] **Step 2: Rewrite the command-level IPMI tests** in `tests/test_cli/test_password.py`. First extend the `password_config` fixture's CSV and credentials so there is a server **with a BMC**:
  - In the CSV string, add two rows (a primary and its `bmc` interface):
    ```
    "big-storage,aa:bb:cc:dd:ee:04,10.1.10.7,\n"
    "big-storage,aa:bb:cc:dd:ee:05,10.1.10.8,bmc\n"
    ```
  - In the `db.save_credentials(...)` dict, add the BMC's Password:
    ```python
    "bmc.big-storage": {"Password": "ADMIN:bmcsecret"},
    ```
    and bump `finish_scan(s, host_count=4, changed_count=6)` accordingly.
  - **Replace** `TestPasswordTypes::test_ipmi_type` and `TestPasswordQuietMode::test_quiet_ipmi_outputs_both_values` with:
    ```python
    def test_ipmi_resolves_bmc_password(self, password_config, capsys):
        result = main(["-c", str(password_config), "password",
                       "--type", "ipmi", "big-storage"])
        assert result == 0
        out = capsys.readouterr().out
        assert "ADMIN" in out and "bmcsecret" in out

    def test_ipmi_direct_bmc_query(self, password_config, capsys):
        result = main(["-c", str(password_config), "password",
                       "--type", "ipmi", "bmc.big-storage"])
        assert result == 0
        assert "bmcsecret" in capsys.readouterr().out

    def test_ipmi_quiet_outputs_user_and_pass(self, password_config, capsys):
        result = main(["-c", str(password_config), "password",
                       "--quiet", "--type", "ipmi", "big-storage"])
        assert result == 0
        lines = capsys.readouterr().out.strip().split("\n")
        assert "ADMIN" in lines and "bmcsecret" in lines

    def test_ipmi_no_bmc_fails_loud(self, password_config, capsys):
        # 'switch1' has no bmc.switch1 host
        result = main(["-c", str(password_config), "password",
                       "--type", "ipmi", "switch1"])
        assert result == 1
        assert "no BMC host" in capsys.readouterr().err
    ```

- [ ] **Step 3: Run, expect failure** — `uv run pytest tests/test_cli/test_password.py -k ipmi -v` (current code reads non-existent IPMI columns → wrong behaviour / errors).

- [ ] **Step 4: Remove `ipmi` from `CREDENTIAL_TYPES`** in `src/gdoc2netcfg/utils/lookup.py`:
```python
CREDENTIAL_TYPES: dict[str, list[str]] = {
    "password": ["Password"],
    "snmp": ["SNMP Community"],
}
```
(Leave `get_credential_fields` as-is — it already raises `ValueError` for unknown types, including `ipmi` now.)

- [ ] **Step 5: Special-case `--type ipmi` in `cmd_password`** (`src/gdoc2netcfg/cli/main.py`). Replace the block from `best = results[0]` through the `cred = get_credential_fields(...)` call with:

```python
    best = results[0]
    host = best.host

    from gdoc2netcfg.sources.credentials import credential_field_names
    from gdoc2netcfg.storage.credentials_db import CredentialsDB
    from gdoc2netcfg.utils.lookup import CREDENTIAL_TYPES, split_login

    # --type ipmi: credentials come from the associated BMC host's single
    # Password column (username:password), not the queried host itself.
    ipmi_source: Host | None = None
    if args.credential_type == "ipmi":
        if host.is_bmc:
            ipmi_source = host
        else:
            bmc_hostname = f"bmc.{host.hostname}"
            ipmi_source = next(
                (h for h in hosts if h.hostname == bmc_hostname), None,
            )
            if ipmi_source is None:
                print(
                    f"Error: no BMC host ({bmc_hostname}) found for "
                    f"'{host.hostname}'",
                    file=sys.stderr,
                )
                return 1
        cred_host = ipmi_source
        requested = {"Password"}
    else:
        cred_host = host
        if args.field_name is not None:
            requested = {args.field_name}
        elif args.credential_type is not None:
            requested = set(CREDENTIAL_TYPES.get(args.credential_type, []))
        else:
            requested = set(CREDENTIAL_TYPES["password"])

    credential_names = set(credential_field_names())
    if requested & credential_names:
        cred_path = config.cache.credentials_db_path
        try:
            with CredentialsDB(cred_path, read_only=True) as cred_db:
                stored = cred_db.load_latest_credentials() or {}
        except FileNotFoundError:
            print(
                "Error: no credential store at "
                f"{cred_path}. Run 'gdoc2netcfg fetch' (as root) first.",
                file=sys.stderr,
            )
            return 1
        except sqlite3.OperationalError:
            print(
                "Error: cannot read the credential store "
                f"{cred_path} — credentials are root-only. Re-run with sudo.",
                file=sys.stderr,
            )
            return 1
        cred_host.extra.update(stored.get(cred_host.hostname, {}))

    if args.credential_type == "ipmi":
        raw = cred_host.extra.get("Password", "").strip()
        if not raw:
            print(
                f"Error: BMC {cred_host.hostname} has no Password",
                file=sys.stderr,
            )
            return 1
        user, pw = split_login(raw)
        cred = {}
        if user is not None:
            cred["IPMI Username"] = user
        cred["IPMI Password"] = pw
    else:
        cred = get_credential_fields(host, args.credential_type, args.field_name)
```

  Add `Host` to the `TYPE_CHECKING`/imports if not already importable in this scope (it is used only as an annotation; if a runtime name is unavailable, drop the `: Host | None` annotation and write `ipmi_source = None`).

- [ ] **Step 6: Note the BMC source in non-quiet output.** In the output block, after the `Matched by:` line, add (only when ipmi):
```python
        if args.credential_type == "ipmi" and cred_host is not host:
            print(f"IPMI source: {cred_host.hostname}")
```

- [ ] **Step 7: Run, expect pass** — `uv run pytest tests/test_cli/test_password.py tests/test_utils/test_lookup.py -v`.

- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat: password --type ipmi resolves the BMC host's Password (#39)"`

---

## Task 3: `bmc-firmware` authenticates with the BMC `Password` (Part B)

**Files:** `src/gdoc2netcfg/supplements/bmc_firmware.py`, `src/gdoc2netcfg/cli/main.py` (`cmd_bmc_firmware`), `tests/test_supplements/test_bmc_firmware.py`.

- [ ] **Step 1: Rewrite `TestTryIPMICredentials`** in `tests/test_supplements/test_bmc_firmware.py` to the BMC-`Password` model (the cascade now reads `host.extra["Password"]`, configured creds first then `ADMIN`/`ADMIN`):

```python
class TestTryIPMICredentials:
    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_no_password_tries_admin_only(self, mock_run):
        mock_run.return_value = {"Product Name": "X11SPM-T(P)F",
                                 "Firmware Revision": "1.74", "IPMI Version": "2.0"}
        result = _try_ipmi_credentials("10.1.5.10", _make_host())
        assert result is not None
        mock_run.assert_called_once_with("10.1.5.10", "ADMIN", "ADMIN")

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_configured_creds_tried_first(self, mock_run):
        mock_run.return_value = {"Product Name": "X11SPM-T(P)F",
                                 "Firmware Revision": "1.74", "IPMI Version": "2.0"}
        host = _make_host(extra={"Password": "root:secret"})
        result = _try_ipmi_credentials("10.1.5.10", host)
        assert result is not None
        mock_run.assert_called_once_with("10.1.5.10", "root", "secret")

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_falls_back_to_admin(self, mock_run):
        mock_run.side_effect = [None, {"Product Name": "X11SPM-T(P)F",
                                       "Firmware Revision": "1.74", "IPMI Version": "2.0"}]
        host = _make_host(extra={"Password": "root:secret"})
        result = _try_ipmi_credentials("10.1.5.10", host)
        assert result is not None
        assert mock_run.call_args_list[0][0] == ("10.1.5.10", "root", "secret")
        assert mock_run.call_args_list[1][0] == ("10.1.5.10", "ADMIN", "ADMIN")

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_no_colon_defaults_username_admin(self, mock_run):
        mock_run.side_effect = [None, None]
        host = _make_host(extra={"Password": "justpass"})
        _try_ipmi_credentials("10.1.5.10", host)
        assert mock_run.call_args_list[0][0] == ("10.1.5.10", "ADMIN", "justpass")

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_admin_password_not_tried_twice(self, mock_run):
        mock_run.return_value = None
        host = _make_host(extra={"Password": "ADMIN:ADMIN"})
        result = _try_ipmi_credentials("10.1.5.10", host)
        assert result is None
        assert mock_run.call_count == 1

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_all_fail(self, mock_run):
        mock_run.return_value = None
        assert _try_ipmi_credentials("10.1.5.10", _make_host()) is None
```

- [ ] **Step 2: Run, expect failure** — `uv run pytest tests/test_supplements/test_bmc_firmware.py::TestTryIPMICredentials -v`.

- [ ] **Step 3: Rewrite `_try_ipmi_credentials`** in `src/gdoc2netcfg/supplements/bmc_firmware.py` (and add `from gdoc2netcfg.utils.lookup import split_login` to the top-level imports):

```python
def _try_ipmi_credentials(
    ip: str,
    host: Host,
) -> dict[str, str] | None:
    """Try the IPMI credential cascade for a BMC.

    Order (first success wins):
    1. The BMC host's own ``Password`` column (``username:password``); a value
       with no colon uses username ``ADMIN`` (ipmitool requires ``-U``).
    2. Factory default ``ADMIN``/``ADMIN``.

    Returns parsed mc info dict, or None if all attempts fail.
    """
    attempts: list[tuple[str, str]] = []
    raw = host.extra.get("Password", "").strip()
    if raw:
        user, pw = split_login(raw)
        attempts.append((user or "ADMIN", pw))
    if ("ADMIN", "ADMIN") not in attempts:
        attempts.append(("ADMIN", "ADMIN"))

    for user, pw in attempts:
        result = _run_ipmitool_mc_info(ip, user, pw)
        if result is not None:
            return result
    return None
```

- [ ] **Step 4: Run, expect pass** — `uv run pytest tests/test_supplements/test_bmc_firmware.py -v`.

- [ ] **Step 5: Wire credentials into the scan command.** In `cmd_bmc_firmware` (`src/gdoc2netcfg/cli/main.py`), after `hosts = build_hosts(all_records, config.site)` and before the reachability call, add:

```python
    # BMC IPMI creds come from each BMC host's Password column (username:password),
    # stored root-only in credentials.db. Best-effort: the scan still works on
    # factory ADMIN/ADMIN BMCs if the store is unavailable.
    from gdoc2netcfg.storage.credentials_db import CredentialsDB
    cred_path = config.cache.credentials_db_path
    try:
        with CredentialsDB(cred_path, read_only=True) as cred_db:
            stored = cred_db.load_latest_credentials() or {}
        for h in hosts:
            h.extra.update(stored.get(h.hostname, {}))
    except FileNotFoundError:
        print(
            "Warning: no credential store; trying ADMIN/ADMIN only. "
            "Run 'gdoc2netcfg fetch' (as root) for custom-credential BMCs.",
            file=sys.stderr,
        )
    except sqlite3.OperationalError:
        print(
            "Warning: credential store unreadable (root-only); trying "
            "ADMIN/ADMIN only. Re-run with sudo for custom-credential BMCs.",
            file=sys.stderr,
        )
```

- [ ] **Step 6: Full sweep.**
  - `uv run ruff check src/ tests/` → All checks passed.
  - `uv run pytest -q` → all pass.
  - `grep -rnE "IPMI Username|IPMI Password" src/gdoc2netcfg/` → no matches (the dead column references are gone).

- [ ] **Step 7: Commit** — `git add -A && git commit -m "feat: bmc-firmware authenticates with the BMC Password (#39)"`

---

## Self-Review notes (for the executor)
- **Spec coverage:** `split_login` (T1); Part A BMC resolution + parse + fail-loud + CREDENTIAL_TYPES cleanup (T2); Part B cascade + credential wiring + dead-branch removal (T3). All covered.
- **Intentional divergence:** Part A omits the username when there's no colon; Part B defaults it to `ADMIN`. Both are tested. Do not unify.
- **Root:** `--type ipmi` opens `credentials.db` (already a root-only path); `cmd_bmc_firmware` runs as root for scans. Both degrade with a clear message when the store is unavailable (Part B) / fail loud (Part A).
- **Out of scope:** `--type snmp` / `SNMP Community` unchanged.
