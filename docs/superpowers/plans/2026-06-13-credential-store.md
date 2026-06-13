# Root-only Credential Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move device credentials (the `CREDENTIAL_TYPES` columns) out of the world-readable cache into a new root-only `credentials.db`, so only the `password` command needs root while `generate`/`db`/`validate`/`show` stay sudo-free.

**Architecture:** `fetch` strips credential columns from each sheet at source and saves their values (keyed by `hostname`) to a delta-stored, `0600` SQLite `credentials.db`; the credential-free CSV is what lands in `network.csv` and `config.db`. The `password` command loads credentials from `credentials.db` only when a credential field is requested, merges them into the matched host, and fails loud when the store is unreadable or missing.

**Tech Stack:** Python 3.11+, SQLite via the project's `BaseDatabase`, `csv` module, `uv`/`pytest`/`ruff`.

**Spec:** `docs/superpowers/specs/2026-06-13-credential-store-design.md`

---

## File structure

- **Create** `src/gdoc2netcfg/storage/credentials_db.py` — `CredentialsDB` (EAV `(hostname, field, value)`, delta + tombstone, `0600` enforcement).
- **Create** `src/gdoc2netcfg/sources/credentials.py` — `credential_field_names()`, `strip_credential_columns()`, `extract_credentials()`.
- **Modify** `src/gdoc2netcfg/config.py` — add `CacheConfig.credentials_db_path`.
- **Modify** `src/gdoc2netcfg/cli/main.py` — add `_build_hosts_from_csvs()`; rework `cmd_fetch` (strip + creds save); rework `cmd_password` (load from store, fail loud).
- **Modify** `CLAUDE.md` — document the credential store + `password` needing sudo.
- **Tests**: `tests/test_storage/test_credentials_db.py`, `tests/test_sources/test_credentials.py`, `tests/test_cli/test_fetch_credentials.py`, and updates to `tests/test_cli/test_password.py`.

Note for the implementer: protected credential columns are the **flattened values** of `CREDENTIAL_TYPES` in `src/gdoc2netcfg/utils/lookup.py`: `Password`, `SNMP Community`, `IPMI Username`, `IPMI Password`. Only `Password` is populated in production today.

---

## Task 1: `CacheConfig.credentials_db_path`

**Files:**
- Modify: `src/gdoc2netcfg/config.py` (the `CacheConfig` dataclass, ~lines 20-34)
- Test: `tests/test_sources/test_config.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_sources/test_config.py`:

```python
def test_credentials_db_path():
    from pathlib import Path
    from gdoc2netcfg.config import CacheConfig

    cfg = CacheConfig(directory=Path("/x/.cache"))
    assert cfg.credentials_db_path == Path("/x/.cache/credentials.db")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_sources/test_config.py::test_credentials_db_path -v`
Expected: FAIL with `AttributeError: 'CacheConfig' object has no attribute 'credentials_db_path'`

- [ ] **Step 3: Add the property**

In `src/gdoc2netcfg/config.py`, in `CacheConfig`, after `discovery_db_path`:

```python
    @property
    def credentials_db_path(self) -> Path:
        """Path to the root-only credential SQLite database."""
        return self.directory / "credentials.db"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_sources/test_config.py::test_credentials_db_path -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/config.py tests/test_sources/test_config.py
git commit -m "feat: add CacheConfig.credentials_db_path"
```

---

## Task 2: `CredentialsDB` storage class

**Files:**
- Create: `src/gdoc2netcfg/storage/credentials_db.py`
- Test: `tests/test_storage/test_credentials_db.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_storage/test_credentials_db.py`:

```python
"""Tests for the root-only CredentialsDB storage layer."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from gdoc2netcfg.storage.credentials_db import CredentialsDB


@pytest.fixture()
def db(tmp_path: Path) -> CredentialsDB:
    d = CredentialsDB(tmp_path / "credentials.db")
    yield d
    d.close()


def test_save_and_load(db: CredentialsDB):
    s = db.begin_scan("csv_credentials")
    changed = db.save_credentials(s, {"switch1": {"Password": "p1"}})
    db.finish_scan(s, host_count=1, changed_count=changed)
    assert changed == 1
    assert db.load_latest_credentials() == {"switch1": {"Password": "p1"}}


def test_load_returns_none_with_no_scans(db: CredentialsDB):
    assert db.load_latest_credentials() is None


def test_delta_no_change(db: CredentialsDB):
    s1 = db.begin_scan("csv_credentials")
    db.save_credentials(s1, {"switch1": {"Password": "p1"}})
    db.finish_scan(s1, host_count=1, changed_count=1)
    s2 = db.begin_scan("csv_credentials")
    changed = db.save_credentials(s2, {"switch1": {"Password": "p1"}})
    db.finish_scan(s2, host_count=1, changed_count=changed)
    assert changed == 0
    assert db.load_latest_credentials() == {"switch1": {"Password": "p1"}}


def test_delta_value_change(db: CredentialsDB):
    s1 = db.begin_scan("csv_credentials")
    db.save_credentials(s1, {"switch1": {"Password": "p1"}})
    db.finish_scan(s1, host_count=1, changed_count=1)
    s2 = db.begin_scan("csv_credentials")
    changed = db.save_credentials(s2, {"switch1": {"Password": "p2"}})
    db.finish_scan(s2, host_count=1, changed_count=changed)
    assert changed == 1
    assert db.load_latest_credentials() == {"switch1": {"Password": "p2"}}


def test_tombstone_on_removal(db: CredentialsDB):
    s1 = db.begin_scan("csv_credentials")
    db.save_credentials(s1, {"switch1": {"Password": "p1"}})
    db.finish_scan(s1, host_count=1, changed_count=1)
    # switch1 no longer has a Password -> tombstoned, dropped from latest.
    s2 = db.begin_scan("csv_credentials")
    changed = db.save_credentials(s2, {})
    db.finish_scan(s2, host_count=1, changed_count=changed)
    assert changed == 1
    assert db.load_latest_credentials() == {}


def test_multiple_fields(db: CredentialsDB):
    s = db.begin_scan("csv_credentials")
    db.save_credentials(s, {
        "bmc.server1": {"IPMI Username": "admin", "IPMI Password": "pw"},
    })
    db.finish_scan(s, host_count=1, changed_count=2)
    assert db.load_latest_credentials() == {
        "bmc.server1": {"IPMI Username": "admin", "IPMI Password": "pw"},
    }


def test_file_mode_is_0600(tmp_path: Path):
    path = tmp_path / "credentials.db"
    db = CredentialsDB(path)
    db.close()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert oct(mode) == oct(0o600)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_storage/test_credentials_db.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'gdoc2netcfg.storage.credentials_db'`

- [ ] **Step 3: Implement `CredentialsDB`**

Create `src/gdoc2netcfg/storage/credentials_db.py`:

```python
"""Root-only credential store (delta-based, 0600).

Holds the spreadsheet's credential columns (the CREDENTIAL_TYPES fields)
separated out of the world-readable cache.  Written only by ``fetch``
(which runs as root on prod) and read only by the ``password`` command.
The file is forced to mode 0600 on every read-write open so the
credentials are unreadable to non-root users, even though the enclosing
.cache directory is world-readable for the other databases.

EAV schema ``credentials(scan_id, hostname, field, value)``; a NULL value
is a tombstone (the credential was cleared or its host disappeared).
Delta key is ``(hostname, field)`` — a new row only when that field's
value changes.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from gdoc2netcfg.storage.base import BaseDatabase


class CredentialsDB(BaseDatabase):
    """Delta-stored, root-only store of per-host credential fields."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Path, *, read_only: bool = False) -> None:
        super().__init__(db_path, read_only=read_only)
        # Enforce 0600 on every read-write open (BaseDatabase otherwise
        # creates 0644).  Read-only opens never reach here with write
        # access, so don't chmod there.
        if not read_only:
            os.chmod(db_path, 0o600)

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS credentials ("
            "scan_id INTEGER NOT NULL REFERENCES scans(id), "
            "hostname TEXT NOT NULL, "
            "field TEXT NOT NULL, "
            "value TEXT)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_credentials_host_field "
            "ON credentials(hostname, field)"
        )

    def save_credentials(
        self, scan_id: int, data: dict[str, dict[str, str]],
    ) -> int:
        """Store credentials delta-based per (hostname, field).

        *data* maps hostname -> {field: value}.  Inserts a row only when a
        field's value differs from the latest stored value; tombstones
        (NULL) fields that previously had a value but are now absent.
        Returns changed_count.
        """
        latest = self._latest_credentials()
        new: dict[tuple[str, str], str] = {}
        for hostname, fields in data.items():
            for field_name, value in fields.items():
                new[(hostname, field_name)] = value

        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for (hostname, field_name), value in new.items():
                if latest.get((hostname, field_name)) != value:
                    cur.execute(
                        "INSERT INTO credentials "
                        "(scan_id, hostname, field, value) VALUES (?, ?, ?, ?)",
                        (scan_id, hostname, field_name, value),
                    )
                    changed += 1
            for (hostname, field_name), value in latest.items():
                if value is not None and (hostname, field_name) not in new:
                    cur.execute(
                        "INSERT INTO credentials "
                        "(scan_id, hostname, field, value) VALUES (?, ?, ?, NULL)",
                        (scan_id, hostname, field_name),
                    )
                    changed += 1
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_credentials(self) -> dict[str, dict[str, str]] | None:
        """Latest non-tombstoned credentials as {hostname: {field: value}}.

        Returns None if no completed csv_credentials scan exists.
        """
        if self.latest_scan_id("csv_credentials") is None:
            return None
        result: dict[str, dict[str, str]] = {}
        for (hostname, field_name), value in self._latest_credentials().items():
            if value is None:
                continue
            result.setdefault(hostname, {})[field_name] = value
        return result

    def _latest_credentials(self) -> dict[tuple[str, str], str | None]:
        """Latest value (incl. NULL tombstones) per (hostname, field)."""
        cur = self._conn.execute(
            "SELECT c.hostname, c.field, c.value "
            "FROM credentials c "
            "WHERE c.scan_id = ("
            "  SELECT c2.scan_id FROM credentials c2 "
            "  JOIN scans s ON c2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND c2.hostname = c.hostname AND c2.field = c.field "
            "  ORDER BY s.id DESC LIMIT 1"
            ")"
        )
        return {(h, f): v for h, f, v in cur.fetchall()}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_storage/test_credentials_db.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/storage/credentials_db.py tests/test_storage/test_credentials_db.py
git commit -m "feat: add root-only CredentialsDB (EAV, delta, 0600)"
```

---

## Task 3: credential strip/extract helpers

**Files:**
- Create: `src/gdoc2netcfg/sources/credentials.py`
- Test: `tests/test_sources/test_credentials.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_sources/test_credentials.py`:

```python
"""Tests for credential column stripping and extraction."""

from __future__ import annotations

import csv
import io

from gdoc2netcfg.sources.credentials import (
    credential_field_names,
    extract_credentials,
    strip_credential_columns,
)


def test_field_names_are_flattened_credential_types():
    names = credential_field_names()
    assert names == ["Password", "SNMP Community", "IPMI Username", "IPMI Password"]


def test_strip_removes_credential_columns():
    csv_text = (
        "Machine,MAC Address,IP,Password,Notes\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,secret,hi\n"
    )
    stripped, present = strip_credential_columns(csv_text)
    assert present == ["Password"]
    rows = list(csv.reader(io.StringIO(stripped)))
    assert rows[0] == ["Machine", "MAC Address", "IP", "Notes"]
    assert rows[1] == ["switch1", "aa:bb:cc:dd:ee:01", "10.1.30.1", "hi"]
    assert "secret" not in stripped


def test_strip_handles_banner_row_before_header():
    # Row 0 is a banner (IPv6 prefix); header is row 1 (find_header_row).
    csv_text = (
        ",,,,2001:db8::,,\n"
        "Machine,MAC Address,IP,Password,Notes\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,secret,hi\n"
    )
    stripped, present = strip_credential_columns(csv_text)
    assert present == ["Password"]
    assert "secret" not in stripped
    rows = list(csv.reader(io.StringIO(stripped)))
    assert rows[1] == ["Machine", "MAC Address", "IP", "Notes"]


def test_strip_noop_when_no_credential_columns():
    csv_text = "Machine,MAC Address,IP,Notes\nx,aa:bb:cc:dd:ee:01,10.1.1.1,hi\n"
    stripped, present = strip_credential_columns(csv_text)
    assert present == []
    assert stripped == csv_text


def test_extract_credentials_keyed_by_hostname():
    from gdoc2netcfg.models.host import Host

    class _FakeHost:
        def __init__(self, hostname, extra):
            self.hostname = hostname
            self.extra = extra

    hosts = [
        _FakeHost("switch1", {"Password": "p1", "Notes": "x"}),
        _FakeHost("desktop", {"Notes": "y"}),  # no credentials
        _FakeHost("bmc.server1", {"IPMI Username": "admin", "IPMI Password": "pw"}),
    ]
    assert extract_credentials(hosts) == {
        "switch1": {"Password": "p1"},
        "bmc.server1": {"IPMI Username": "admin", "IPMI Password": "pw"},
    }
```

(Remove the unused `from gdoc2netcfg.models.host import Host` import if ruff flags it — the test uses a fake host. Keep the test self-contained.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_sources/test_credentials.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'gdoc2netcfg.sources.credentials'`

- [ ] **Step 3: Implement the helpers**

Create `src/gdoc2netcfg/sources/credentials.py`:

```python
"""Separate credential columns out of fetched CSV data.

The spreadsheet's credential columns (the flattened CREDENTIAL_TYPES
names) are stripped from the world-readable cache and stored in the
root-only credentials.db.  These helpers do the column-level work.
"""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

from gdoc2netcfg.sources.parser import find_header_row
from gdoc2netcfg.utils.lookup import CREDENTIAL_TYPES

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host


def credential_field_names() -> list[str]:
    """The credential column names — flattened CREDENTIAL_TYPES values, deduped."""
    names: list[str] = []
    for columns in CREDENTIAL_TYPES.values():
        for column in columns:
            if column not in names:
                names.append(column)
    return names


def strip_credential_columns(csv_text: str) -> tuple[str, list[str]]:
    """Remove credential columns from CSV text.

    Returns (stripped_csv_text, present_field_names).  Columns are
    identified by header name in the detected header row and removed by
    index from every row (banner rows included).  When no credential
    columns are present, returns the input unchanged with an empty list.
    """
    rows = list(csv.reader(io.StringIO(csv_text)))
    if not rows:
        return csv_text, []

    header_idx = find_header_row(rows)
    header = rows[header_idx]
    credential_names = set(credential_field_names())
    drop = [i for i, h in enumerate(header) if h.strip() in credential_names]
    if not drop:
        return csv_text, []

    present = [header[i].strip() for i in drop]
    for row in rows:
        for i in sorted(drop, reverse=True):
            if i < len(row):
                del row[i]

    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(rows)
    return out.getvalue(), present


def extract_credentials(hosts: list[Host]) -> dict[str, dict[str, str]]:
    """Map hostname -> {credential field: value} for hosts that have any.

    Reads credential fields from ``host.extra`` (populated from the raw,
    un-stripped CSV).  Hosts with no credential fields are omitted.
    """
    names = credential_field_names()
    result: dict[str, dict[str, str]] = {}
    for host in hosts:
        fields = {n: host.extra[n] for n in names if host.extra.get(n)}
        if fields:
            result[host.hostname] = fields
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_sources/test_credentials.py -v`
Expected: PASS (5 tests). If ruff flags the unused `Host` import in the test, delete that import line.

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/sources/credentials.py tests/test_sources/test_credentials.py
git commit -m "feat: add credential strip/extract helpers"
```

---

## Task 4: shared `_build_hosts_from_csvs` helper

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (add helper near `_fetch_or_load_csvs` ~line 50; refactor `cmd_password` ~lines 2219-2237)
- Test: `tests/test_cli/test_password.py` (existing tests must still pass — pure refactor)

- [ ] **Step 1: Add the helper**

In `src/gdoc2netcfg/cli/main.py`, after `_enrich_site_from_sheets` (~line 150), add:

```python
def _build_hosts_from_csvs(config, csv_data: list[tuple[str, str]]):
    """Parse cached CSVs and build hosts — the shared fetch/password path.

    Both ``cmd_fetch`` (to key credentials by hostname) and ``cmd_password``
    (to match a query) MUST build hosts identically, so the credential
    store's keys line up with lookups.  Skips the vlan_allocations sheet
    (not device records).  Callers must run ``_enrich_site_from_sheets``
    first so hostname derivation has VLAN/site data.
    """
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv

    records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records.extend(parse_csv(csv_text, name))
    return build_hosts(records, config.site)
```

- [ ] **Step 2: Refactor `cmd_password` to use it**

In `cmd_password`, replace the parse+build block (currently ~lines 2230-2237):

```python
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)
```

with:

```python
    hosts = _build_hosts_from_csvs(config, csv_data)
```

Remove the now-unused `build_hosts` / `parse_csv` imports from `cmd_password`'s local import block if they are no longer referenced there.

- [ ] **Step 3: Run the existing password tests (pure refactor — still green)**

Run: `uv run pytest tests/test_cli/test_password.py -v`
Expected: PASS (all existing tests — behaviour unchanged).

- [ ] **Step 4: Commit**

```bash
git add src/gdoc2netcfg/cli/main.py
git commit -m "refactor: extract _build_hosts_from_csvs shared helper"
```

---

## Task 5: `cmd_fetch` strips credentials into the store

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (`cmd_fetch`, ~lines 376-422)
- Test: `tests/test_cli/test_fetch_credentials.py`

**Behaviour:** fetch all sheets into memory; strip credential columns from each; if any fetched sheet actually contained credential columns, enrich + build hosts from the **raw** data, extract credentials, and save them to `credentials.db` **before** writing anything else (so a failure leaves old state intact); then write the **stripped** CSVs to the flat cache and `config.db`. If the credential-bearing sheet failed to fetch (no credential columns seen this run), skip the credential save entirely — never tombstone on a transient fetch failure.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli/test_fetch_credentials.py`:

```python
"""Tests for credential stripping during fetch."""

from __future__ import annotations

import textwrap

import pytest

import gdoc2netcfg.cli.main as cli
from gdoc2netcfg.sources.sheets import SheetData
from gdoc2netcfg.storage.credentials_db import CredentialsDB


@pytest.fixture()
def fetch_config(tmp_path):
    cache_dir = tmp_path / ".cache"
    config = tmp_path / "gdoc2netcfg.toml"
    config.write_text(textwrap.dedent(f"""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]
        network = "https://example.com/network"

        [cache]
        directory = "{cache_dir}"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [generators]
        enabled = []
    """))
    return config, cache_dir


def _fake_network_csv() -> str:
    return (
        "Machine,MAC Address,IP,Interface,Password,Notes\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,,secret1,hi\n"
    )


def test_fetch_strips_password_from_cache_and_stores_it(
    fetch_config, monkeypatch,
):
    config, cache_dir = fetch_config

    def fake_fetch(name, url):
        return SheetData(name=name, csv_text=_fake_network_csv())

    monkeypatch.setattr(cli, "fetch_sheet", fake_fetch, raising=False)
    monkeypatch.setattr(
        "gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=False,
    )

    rc = cli.main(["-c", str(config), "fetch"])
    assert rc == 0

    # Cache CSV is credential-free.
    cached = (cache_dir / "network.csv").read_text()
    assert "secret1" not in cached
    assert "Password" not in cached

    # Credential is in the root-only store, keyed by hostname.
    with CredentialsDB(cache_dir / "credentials.db", read_only=True) as db:
        creds = db.load_latest_credentials()
    assert creds is not None
    assert any(v == {"Password": "secret1"} for v in creds.values())


def test_fetch_creates_credentials_db_0600(fetch_config, monkeypatch):
    import os
    import stat

    config, cache_dir = fetch_config

    def fake_fetch(name, url):
        return SheetData(name=name, csv_text=_fake_network_csv())

    monkeypatch.setattr(
        "gdoc2netcfg.sources.sheets.fetch_sheet", fake_fetch, raising=False,
    )
    cli.main(["-c", str(config), "fetch"])

    mode = stat.S_IMODE(os.stat(cache_dir / "credentials.db").st_mode)
    assert oct(mode) == oct(0o600)
```

(The implementer should confirm how `cmd_fetch` references `fetch_sheet` — it currently does `from gdoc2netcfg.sources.sheets import fetch_sheet` inside the function. Patch the name the function actually resolves; the test patches the source module, which the local import picks up. Adjust the monkeypatch target to match the final code.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli/test_fetch_credentials.py -v`
Expected: FAIL — currently `network.csv` still contains `secret1` and no `credentials.db` is created.

- [ ] **Step 3: Rework `cmd_fetch`**

Replace `cmd_fetch` in `src/gdoc2netcfg/cli/main.py` with:

```python
def cmd_fetch(args: argparse.Namespace) -> int:
    """Download CSVs from Google Sheets to local cache.

    Credential columns (CREDENTIAL_TYPES) are stripped out of the
    world-readable cache and stored in the root-only credentials.db.
    """
    config = _load_config(args)

    from gdoc2netcfg.sources.cache import CSVCache
    from gdoc2netcfg.sources.credentials import (
        extract_credentials,
        strip_credential_columns,
    )
    from gdoc2netcfg.sources.sheets import fetch_sheet
    from gdoc2netcfg.storage.config_db import ConfigDB
    from gdoc2netcfg.storage.credentials_db import CredentialsDB

    # 1. Fetch every sheet into memory (raw, with credentials).
    raw_csvs: list[tuple[str, str]] = []
    ok = 0
    fail = 0
    for sheet in config.sheets:
        try:
            data = fetch_sheet(sheet.name, sheet.url)
            raw_csvs.append((sheet.name, data.csv_text))
            print(f"  {sheet.name}: fetched ({len(data.csv_text)} bytes)")
            ok += 1
        except Exception as e:
            print(f"  {sheet.name}: FAILED ({e})", file=sys.stderr)
            fail += 1

    # 2. Strip credential columns from each fetched sheet.
    stripped: list[tuple[str, str, list[str]]] = []
    for name, text in raw_csvs:
        clean, present = strip_credential_columns(text)
        stripped.append((name, clean, present))

    has_credential_columns = any(present for _, _, present in stripped)

    # 3. If a credential-bearing sheet was fetched, store credentials FIRST
    #    (before touching the cache) so a failure leaves old state intact.
    #    Skip entirely when no credential columns were seen this run — never
    #    tombstone credentials on a transient fetch failure of that sheet.
    if has_credential_columns:
        _enrich_site_from_sheets(config, raw_csvs)
        hosts = _build_hosts_from_csvs(config, raw_csvs)
        creds = extract_credentials(hosts)
        with CredentialsDB(config.cache.credentials_db_path) as cred_db:
            scan_id = cred_db.begin_scan("csv_credentials")
            try:
                changed = cred_db.save_credentials(scan_id, creds)
                cred_db.finish_scan(
                    scan_id, host_count=len(hosts), changed_count=changed,
                )
            except Exception:
                cred_db.connection.execute(
                    "DELETE FROM scans WHERE id = ?", (scan_id,),
                )
                raise

    # 4. Write the credential-free CSVs to the flat cache.
    cache = CSVCache(config.cache.directory)
    fetched_csvs: list[tuple[str, str]] = []
    for name, clean, _present in stripped:
        cache.write(name, clean)
        fetched_csvs.append((name, clean))

    # 5. Save the credential-free CSVs to ConfigDB.
    if fetched_csvs:
        with ConfigDB(config.cache.config_db_path) as config_db:
            scan_id = config_db.begin_scan("csv_fetch")
            try:
                for sheet_name, csv_text in fetched_csvs:
                    config_db.save_csv(scan_id, sheet_name, csv_text)
                config_db.finish_scan(
                    scan_id,
                    host_count=len(fetched_csvs),
                    changed_count=len(fetched_csvs),
                )
            except Exception:
                config_db.connection.execute(
                    "DELETE FROM scans WHERE id = ?", (scan_id,),
                )
                raise

    print(f"\nFetched {ok} sheets, {fail} failures.")
    return 1 if fail > 0 else 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli/test_fetch_credentials.py -v`
Expected: PASS (2 tests). If the monkeypatch target is wrong, fix it to patch the symbol `cmd_fetch` resolves (`gdoc2netcfg.sources.sheets.fetch_sheet`).

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/cli/main.py tests/test_cli/test_fetch_credentials.py
git commit -m "feat: fetch strips credentials into root-only store"
```

---

## Task 6: `cmd_password` reads from the store and fails loud

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (`cmd_password`, ~lines 2215-2291)
- Test: `tests/test_cli/test_password.py` (rewrite fixture to put credentials in the store)

**Behaviour:** after matching the host, determine the requested credential fields. If any requested field is a credential field (`credential_field_names()`), open `credentials.db` read-only and merge the matched host's stored fields into `host.extra`; fail loud if the store is missing (`FileNotFoundError`) or unreadable (`sqlite3.OperationalError`, i.e. not root). A `--field` request for a non-credential column does not touch the store (stays sudo-free).

- [ ] **Step 1: Rewrite the password test fixture + add fail-loud tests**

Replace the `password_config` fixture in `tests/test_cli/test_password.py` so credentials live in `credentials.db` and the CSV is credential-free:

```python
import os
import stat
import textwrap

import pytest

from gdoc2netcfg.cli.main import main
from gdoc2netcfg.storage.credentials_db import CredentialsDB


@pytest.fixture
def password_config(tmp_path):
    """Config with a credential-free CSV cache + a populated credentials.db."""
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()

    # Credential-free CSV (Password/SNMP/IPMI columns stripped at fetch).
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
        "desktop,aa:bb:cc:dd:ee:02,10.1.10.2,\n"
        "server1,aa:bb:cc:dd:ee:03,10.1.10.5,\n"
    )

    # Credentials in the root-only store, keyed by hostname. The hostname
    # here must match what build_hosts derives for these machines; for this
    # minimal site (no subdomains) the hostname equals the machine name.
    with CredentialsDB(cache_dir / "credentials.db") as db:
        s = db.begin_scan("csv_credentials")
        db.save_credentials(s, {
            "switch1": {"Password": "sw1pass", "SNMP Community": "public"},
            "desktop": {"IPMI Username": "admin", "IPMI Password": "hunter2"},
            "server1": {"Password": "srv1pass", "SNMP Community": "community1"},
        })
        db.finish_scan(s, host_count=3, changed_count=5)

    config = tmp_path / "gdoc2netcfg.toml"
    config.write_text(textwrap.dedent(f"""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]
        network = "https://example.com/not-used"

        [cache]
        directory = "{cache_dir}"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [generators]
        enabled = []
    """))
    return config
```

The implementer MUST verify the hostname assumption: run the existing matching and confirm `build_hosts` yields `hostname == machine` for this minimal site. If it derives a different hostname (e.g. with a domain suffix), update the keys in `save_credentials(...)` to the derived hostnames so lookups resolve. (This is exactly the parity the shared helper guarantees — the test just needs the right keys.)

All existing `TestPassword*` cases stay as-is (they assert the same outputs); they now exercise the store path.

Add fail-loud tests at the end of the file:

```python
class TestPasswordStoreErrors:
    def test_missing_store_fails_loud(self, tmp_path, capsys):
        # Credential-free cache but NO credentials.db.
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
        )
        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"
            [sheets]
            network = "https://example.com/not-used"
            [cache]
            directory = "{cache_dir}"
            [ipv6]
            prefixes = ["2001:db8:1:"]
            [generators]
            enabled = []
        """))
        result = main(["-c", str(config), "password", "switch1"])
        assert result == 1
        assert "fetch" in capsys.readouterr().err.lower()

    def test_field_for_noncredential_column_does_not_need_store(
        self, tmp_path, capsys,
    ):
        # No credentials.db; a non-credential --field still works sudo-free.
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface,Serial Number\n"
            "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,,SN123\n"
        )
        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"
            [sheets]
            network = "https://example.com/not-used"
            [cache]
            directory = "{cache_dir}"
            [ipv6]
            prefixes = ["2001:db8:1:"]
            [generators]
            enabled = []
        """))
        result = main([
            "-c", str(config), "password", "--field", "Serial Number", "switch1",
        ])
        assert result == 0
        assert "SN123" in capsys.readouterr().out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli/test_password.py -v`
Expected: most existing tests FAIL (credentials no longer in the CSV, store not consulted) and the new fail-loud test FAILS (no store-error handling yet).

- [ ] **Step 3: Implement the store lookup in `cmd_password`**

In `src/gdoc2netcfg/cli/main.py`, in `cmd_password`, extend the imports block to include the credential helpers and add the store merge. After `hosts = _build_hosts_from_csvs(config, csv_data)` and after the match resolves `host = best.host`, insert before the `cred = get_credential_fields(...)` call:

```python
    # Credentials live in the root-only credentials.db, not the cache.
    # Only consult it when a credential field is actually requested, so a
    # --field for a non-credential column stays sudo-free.
    from gdoc2netcfg.sources.credentials import credential_field_names
    from gdoc2netcfg.storage.credentials_db import CredentialsDB

    credential_names = set(credential_field_names())
    if args.field_name is not None:
        requested = {args.field_name}
    elif args.credential_type is not None:
        requested = set(CREDENTIAL_TYPES.get(args.credential_type, []))
    else:
        requested = set(CREDENTIAL_TYPES["password"])

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
        host.extra.update(stored.get(host.hostname, {}))
```

Add the required imports at the top of the function's import block: `CREDENTIAL_TYPES` (from `gdoc2netcfg.utils.lookup`) and ensure `sqlite3` is imported at module top (add `import sqlite3` to the file header if not already present).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli/test_password.py -v`
Expected: PASS (all existing cases + the two new store-error cases). If a host-key mismatch surfaces, fix the fixture keys per the note in Step 1.

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/cli/main.py tests/test_cli/test_password.py
git commit -m "feat: password reads credentials from root-only store, fails loud"
```

---

## Task 7: Documentation

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md**

In `CLAUDE.md`:

1. Under **SQLite Storage**, add `credentials.db` to the database list:

   ```markdown
   - `.cache/credentials.db` (`CredentialsDB`) — root-only (`0600`) store of
     device credential columns (`Password`, `SNMP Community`, `IPMI Username`,
     `IPMI Password`), stripped out of the world-readable cache at fetch time.
     Written only by `fetch`; read only by the `password` command. EAV
     `(hostname, field, value)`, delta-stored with NULL tombstones.
   ```

2. Under the credential-lookup section, note that `password` now needs root:

   ```markdown
   Credentials are stored root-only in `.cache/credentials.db`, so the
   `password` command must run as root on prod (`sudo .venv/bin/gdoc2netcfg
   password <query>`). `generate`, `db`, `validate`, and the show commands
   stay sudo-free (the rest of the cache is credential-free).
   ```

3. In the `password` command list near the top, leave the commands as-is but
   ensure the note above is discoverable.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document root-only credentials.db and sudo for password"
```

---

## Task 8: Full verification

- [ ] **Step 1: Run the whole suite**

Run: `uv run pytest`
Expected: all green (including the new tests).

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/ tests/`
Expected: clean (fix any unused imports surfaced in the new modules/tests).

- [ ] **Step 3: Manual smoke (local dev cache, no prod)**

In a scratch dir, confirm the `password` command prints the right error when `credentials.db` is absent, and resolves a credential when the store is populated (covered by tests; optional manual check).

- [ ] **Step 4: Commit any lint fixes**

```bash
git add -A
git commit -m "chore: lint fixes for credential store"
```

---

## Deployment (after merge — operator steps, not code)

1. Merge to `main`, `git pull` on welland + monarto.
2. Run `fetch` as root on each site: `cd /opt/gdoc2netcfg && sudo .venv/bin/gdoc2netcfg fetch`. This populates `credentials.db` (`0600 root`) and rewrites `network.csv` credential-free.
3. **Manual one-off scrub** (close historical exposure): rewrite the existing `config.db` `csv_snapshots` (485 rows) and any pre-existing `network.csv` backups on both sites to drop the credential columns. (Operator script, run once; not shipped.)
4. Verify: `sudo .venv/bin/gdoc2netcfg password <host>` resolves; a non-root `password` fails loud; `grep -l Password .cache/network.csv` finds nothing; `generate`/`db info` still work sudo-free.
```
