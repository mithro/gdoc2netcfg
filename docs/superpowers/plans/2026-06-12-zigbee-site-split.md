# Zigbee Per-Site Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each site scans only its own Zigbee2MQTT broker and manages only its own Zigbee sheet rows, keyed by (Site, IEEE); dual-registry devices get one row per site.

**Architecture:** Sheet credentials move from `[zigbee]` to a new `SheetsConfig` under `[sheets]`, with `get_gspread_client` extracted to `utils/gsheets.py`. `update_zigbee_sheet` re-keys rows by (Site, IEEE) scoped to the run's configured sites. `cmd_zigbee_update_sheet` projects every configured site's registry view directly and `best_device_view` is deleted. Scan/cron/storage are untouched (already per-site with config-removal tombstones).

**Tech Stack:** Python 3.13, uv, pytest, gspread (mocked in tests), SQLite (existing DiscoveryDB).

**Spec:** `docs/superpowers/specs/2026-06-12-zigbee-site-split-design.md`

**Worktree:** `.worktrees/zigbee-site-split`, branch `feature/zigbee-site-split`. All commands run from the worktree root. Commit messages end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

## File structure

| File | Change |
|---|---|
| `src/gdoc2netcfg/config.py` | + `SheetsConfig` dataclass, `_RESERVED_SHEET_KEYS`, `_build_sheets_config()`; `PipelineConfig.sheets_config`; later − `ZigbeeConfig` cred fields |
| `src/gdoc2netcfg/utils/gsheets.py` | **new** — `get_gspread_client(sheets_config)` moved from `zigbee_sheet.py` |
| `src/gdoc2netcfg/supplements/zigbee_sheet.py` | (Site, IEEE) keying, scope, warnings, skip-unchanged; client import from utils |
| `src/gdoc2netcfg/cli/main.py` | `cmd_zigbee_update_sheet`: per-site projection, no-sites error, `sheets_config` creds gate |
| `src/gdoc2netcfg/supplements/zigbee.py` | − `best_device_view`; docstring updates |
| `gdoc2netcfg.toml.example` | creds keys move `[zigbee]` → `[sheets]` |
| `tests/test_sources/test_config.py` | `SheetsConfig` parsing + reserved-keys tests |
| `tests/test_utils/test_gsheets.py` | **new** — client-construction error paths |
| `tests/test_supplements/test_zigbee_sheet.py` | **new** — direct `update_zigbee_sheet` tests with fake gspread |
| `tests/test_cli/test_zigbee_db.py` | one-row-per-site, unconfigured-site filter, no-sites error |
| `tests/test_supplements/test_zigbee.py` | − `best_device_view` tests |

---

### Task 1: `SheetsConfig` dataclass and `[sheets]` parsing

**Files:**
- Modify: `src/gdoc2netcfg/config.py`
- Test: `tests/test_sources/test_config.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_sources/test_config.py` (module already imports `Path` and `load_config`):

```python
class TestSheetsConfig:
    def _write(self, tmp_path: Path, body: str) -> Path:
        p = tmp_path / "gdoc2netcfg.toml"
        p.write_text(body)
        return p

    def test_sheets_config_parsed_from_sheets_section(self, tmp_path: Path):
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"

[sheets]
network = "https://example.com/network.csv"
spreadsheet_url = "https://docs.google.com/spreadsheets/d/x/edit"
credentials_file = "client_secret.json"
token_cache = ".cache/tok.json"
service_account_file = "sa.json"
"""))
        assert config.sheets_config.credentials_file == "client_secret.json"
        assert config.sheets_config.token_cache == ".cache/tok.json"
        assert config.sheets_config.service_account_file == "sa.json"

    def test_reserved_keys_are_not_sheet_urls(self, tmp_path: Path):
        """Cred keys in [sheets] must not become SheetConfig entries."""
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"

[sheets]
network = "https://example.com/network.csv"
spreadsheet_url = "https://docs.google.com/spreadsheets/d/x/edit"
credentials_file = "client_secret.json"
token_cache = ".cache/tok.json"
service_account_file = "sa.json"
"""))
        assert [s.name for s in config.sheets] == ["network"]

    def test_sheets_config_defaults(self, tmp_path: Path):
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"
"""))
        assert config.sheets_config.credentials_file == ""
        assert config.sheets_config.token_cache == ".cache/google_oauth_token.json"
        assert config.sheets_config.service_account_file == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_sources/test_config.py::TestSheetsConfig -v`
Expected: 3 FAILED with `AttributeError: 'PipelineConfig' object has no attribute 'sheets_config'`

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/config.py`, after the `ZigbeeConfig` dataclass (line ~92), add:

```python
@dataclass
class SheetsConfig:
    """Google Sheets write-access credentials, from the [sheets] section.

    OAuth2 (credentials_file + token_cache) or a service account
    (service_account_file). Used by sheet-writing commands.
    """

    credentials_file: str = ""      # OAuth2 client_secret.json path
    token_cache: str = ".cache/google_oauth_token.json"
    service_account_file: str = ""  # Alternative: service account JSON key path
```

Add the field to `PipelineConfig` (after `spreadsheet_url`):

```python
    sheets_config: SheetsConfig = field(default_factory=SheetsConfig)
```

Above `_build_sheets` add the reserved-key set and replace `_build_sheets`'s skip clause:

```python
# [sheets] keys that are settings, not sheet-name→URL pairs.
_RESERVED_SHEET_KEYS = frozenset({
    "spreadsheet_url", "credentials_file", "token_cache",
    "service_account_file",
})


def _build_sheets(data: dict) -> list[SheetConfig]:
    """Build sheet configs from parsed TOML data.

    Skips reserved settings keys (_RESERVED_SHEET_KEYS).
    """
    sheets = []
    for name, url in data.get("sheets", {}).items():
        if name in _RESERVED_SHEET_KEYS:
            continue
        sheets.append(SheetConfig(name=name, url=url))
    return sheets


def _build_sheets_config(data: dict) -> SheetsConfig:
    """Build sheet write-access credentials from the [sheets] section."""
    section = data.get("sheets", {})
    return SheetsConfig(
        credentials_file=section.get("credentials_file", ""),
        token_cache=section.get(
            "token_cache", ".cache/google_oauth_token.json",
        ),
        service_account_file=section.get("service_account_file", ""),
    )
```

Wire it in `load_config`'s `PipelineConfig(...)` call (after the `spreadsheet_url=` line):

```python
        sheets_config=_build_sheets_config(data),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_sources/test_config.py -v`
Expected: all PASS (including the pre-existing `TestLoadConfig` tests)

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/config.py tests/test_sources/test_config.py
git commit -m "config: add SheetsConfig parsed from the [sheets] section"
```

---

### Task 2: extract `utils/gsheets.py`, switch consumers to `sheets_config`

**Files:**
- Create: `src/gdoc2netcfg/utils/gsheets.py`
- Create: `tests/test_utils/test_gsheets.py`
- Modify: `src/gdoc2netcfg/supplements/zigbee_sheet.py` (remove `get_gspread_client` + `_SCOPES`, import from utils, call with `config.sheets_config`)
- Modify: `src/gdoc2netcfg/cli/main.py:2132-2138` (creds gate)
- Modify: `tests/test_cli/test_zigbee_db.py` (`_config` fixture gains `sheets_config`)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_utils/test_gsheets.py`:

```python
"""Tests for the shared Google Sheets client helper."""

import pytest

from gdoc2netcfg.config import SheetsConfig
from gdoc2netcfg.utils.gsheets import get_gspread_client


class TestGetGspreadClient:
    def test_no_credentials_configured_raises(self):
        with pytest.raises(RuntimeError, match=r"\[sheets\] section"):
            get_gspread_client(SheetsConfig())

    def test_missing_service_account_file_raises(self, tmp_path):
        cfg = SheetsConfig(
            service_account_file=str(tmp_path / "nope.json"),
        )
        with pytest.raises(RuntimeError, match="Service account file not found"):
            get_gspread_client(cfg)

    def test_missing_oauth_credentials_file_raises(self, tmp_path):
        cfg = SheetsConfig(credentials_file=str(tmp_path / "nope.json"))
        with pytest.raises(RuntimeError, match="credentials file not found"):
            get_gspread_client(cfg)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_utils/test_gsheets.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'gdoc2netcfg.utils.gsheets'`

- [ ] **Step 3: Create `src/gdoc2netcfg/utils/gsheets.py`**

Move `_SCOPES` and `get_gspread_client` from `supplements/zigbee_sheet.py` verbatim except: the parameter becomes `sheets_config: SheetsConfig`, every `zigbee_config.` becomes `sheets_config.`, and the no-creds error names the new section.

```python
"""Shared Google Sheets client construction.

OAuth2: provide credentials_file (client_secret.json from Google Cloud
        Console).  Token is cached to token_cache and auto-refreshed on
        expiry.
Service account: provide service_account_file instead.

Credentials live in the [sheets] section of gdoc2netcfg.toml
(SheetsConfig).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import SheetsConfig


_SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def get_gspread_client(sheets_config: SheetsConfig) -> object:
    """Return an authenticated gspread Client.

    Tries service_account_file first (non-interactive), then OAuth2
    (opens a browser on first use; token is cached for subsequent runs).
    """
    try:
        import gspread
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
    except ImportError as exc:
        raise RuntimeError(
            "Google Sheets dependencies not installed. "
            "Install with: uv sync  (gspread and google-auth-oauthlib are in pyproject.toml)"
        ) from exc

    if sheets_config.service_account_file:
        sa_path = Path(sheets_config.service_account_file).expanduser()
        if not sa_path.exists():
            raise RuntimeError(
                f"Service account file not found: {sa_path}"
            )
        from google.oauth2.service_account import Credentials as SACredentials
        creds = SACredentials.from_service_account_file(str(sa_path), scopes=_SCOPES)
        return gspread.Client(auth=creds)

    credentials_file = sheets_config.credentials_file
    if not credentials_file:
        raise RuntimeError(
            "No credentials_file or service_account_file configured in "
            "[sheets] section of gdoc2netcfg.toml"
        )

    creds_path = Path(credentials_file).expanduser()
    if not creds_path.exists():
        raise RuntimeError(
            f"OAuth2 credentials file not found: {creds_path}\n"
            "Download it from Google Cloud Console → APIs & Services → Credentials"
        )

    token_path = Path(sheets_config.token_cache).expanduser()

    creds: Credentials | None = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), _SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            from google_auth_oauthlib.flow import InstalledAppFlow
            flow = InstalledAppFlow.from_client_secrets_file(str(creds_path), _SCOPES)
            creds = flow.run_local_server(port=0)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json())

    return gspread.Client(auth=creds)
```

- [ ] **Step 4: Update `supplements/zigbee_sheet.py`**

Delete `_SCOPES` (line 36) and the whole `get_gspread_client` function (lines 102–159). Add the import and change the call in `update_zigbee_sheet`:

```python
from gdoc2netcfg.utils.gsheets import get_gspread_client
```

(plain import near the top, NOT under `TYPE_CHECKING` — it is called at runtime), and at line ~181:

```python
    client = get_gspread_client(config.sheets_config)
```

Also drop `ZigbeeConfig` from the `TYPE_CHECKING` import and the now-stale OAuth2 paragraph (lines 20–22) from the module docstring.

- [ ] **Step 5: Update the CLI creds gate**

In `src/gdoc2netcfg/cli/main.py` `cmd_zigbee_update_sheet` (lines 2132–2138), replace:

```python
    if not config.zigbee.credentials_file and not config.zigbee.service_account_file:
        print(
            "Error: [zigbee] credentials_file or service_account_file must be "
            "configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1
```

with:

```python
    if (
        not config.sheets_config.credentials_file
        and not config.sheets_config.service_account_file
    ):
        print(
            "Error: [sheets] credentials_file or service_account_file must be "
            "configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1
```

- [ ] **Step 6: Update the CLI test fixture**

In `tests/test_cli/test_zigbee_db.py`, add `SheetsConfig` to the `from gdoc2netcfg.config import (...)` block and give `_config` a `sheets_config` (keep the `[zigbee]` `credentials_file` kwarg for now — it dies in Task 3):

```python
        sheets_config=SheetsConfig(credentials_file="client_secret.json"),
```

(insert into the `PipelineConfig(...)` call, after `cache=...`).

- [ ] **Step 7: Run the affected suites**

Run: `uv run pytest tests/test_utils/test_gsheets.py tests/test_cli/test_zigbee_db.py tests/test_supplements/test_zigbee.py -v`
Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add src/gdoc2netcfg/utils/gsheets.py tests/test_utils/test_gsheets.py \
    src/gdoc2netcfg/supplements/zigbee_sheet.py src/gdoc2netcfg/cli/main.py \
    tests/test_cli/test_zigbee_db.py
git commit -m "utils: extract get_gspread_client, creds come from [sheets]"
```

---

### Task 3: remove cred fields from `ZigbeeConfig`; move them in the example toml

**Files:**
- Modify: `src/gdoc2netcfg/config.py` (`ZigbeeConfig`, `_build_zigbee`)
- Modify: `gdoc2netcfg.toml.example`
- Modify: `tests/test_cli/test_zigbee_db.py` (drop the dead kwarg)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sources/test_config.py` inside `TestSheetsConfig`:

```python
    def test_zigbee_config_has_no_credential_fields(self):
        from gdoc2netcfg.config import ZigbeeConfig
        import dataclasses
        names = {f.name for f in dataclasses.fields(ZigbeeConfig)}
        assert "credentials_file" not in names
        assert "token_cache" not in names
        assert "service_account_file" not in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_sources/test_config.py::TestSheetsConfig::test_zigbee_config_has_no_credential_fields -v`
Expected: FAIL — the fields still exist

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/config.py`:

- Delete the three cred fields from `ZigbeeConfig` (lines 89–91) and trim its docstring's credentials sentence, leaving:

```python
@dataclass
class ZigbeeConfig:
    """Configuration for Zigbee2MQTT device scanning and sheet updates.

    Supports multiple sites (each with its own MQTT broker).  Sheet
    credentials live in SheetsConfig ([sheets] section).
    """

    sites: list[ZigbeeSiteConfig] = field(default_factory=list)
    sheet_name: str = "Zigbee Info"
```

- In `_build_zigbee`, delete the three cred kwargs, leaving:

```python
    return ZigbeeConfig(
        sites=sites,
        sheet_name=section.get("sheet_name", "Zigbee Info"),
    )
```

In `gdoc2netcfg.toml.example`: delete the three cred lines and the two-line "Sheet credentials" comment from `[zigbee]` (the section keeps `sheet_name` and the `[[zigbee.sites]]` entries), and extend `[sheets]` after the `spreadsheet_url` comment block:

```toml
# Sheet write credentials: set credentials_file for OAuth2 (browser-based,
# recommended) or service_account_file for a service account key.
# Real values belong in gdoc2netcfg.toml only (this file is a template).
credentials_file = ""  # Path to OAuth2 client_secret.json (Google Cloud Console)
token_cache = ".cache/google_oauth_token.json"
# service_account_file = ""  # Alternative: path to service account JSON key
```

In `tests/test_cli/test_zigbee_db.py` `_config`, delete the now-invalid `credentials_file="client_secret.json",` kwarg from the `ZigbeeConfig(...)` call (the `sheets_config` from Task 2 carries it).

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -q`
Expected: all PASS (any other `ZigbeeConfig(credentials_file=...)` user would explode here — there are none)

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/config.py gdoc2netcfg.toml.example \
    tests/test_sources/test_config.py tests/test_cli/test_zigbee_db.py
git commit -m "config: zigbee loses sheet credentials; [sheets] owns them"
```

---

### Task 4: `update_zigbee_sheet` — (Site, IEEE) keying, scope, warnings, skip-unchanged

**Files:**
- Modify: `src/gdoc2netcfg/supplements/zigbee_sheet.py`
- Create: `tests/test_supplements/test_zigbee_sheet.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_supplements/test_zigbee_sheet.py`:

```python
"""Direct tests for update_zigbee_sheet's per-site row ownership."""

from unittest.mock import patch

import pytest

from gdoc2netcfg.config import (
    CacheConfig,
    PipelineConfig,
    SheetsConfig,
    ZigbeeConfig,
    ZigbeeSiteConfig,
)
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.supplements.zigbee import ZigbeeDevice
from gdoc2netcfg.supplements.zigbee_sheet import update_zigbee_sheet

HEADER = [
    "Site", "Type", "Entity Name", "Description", "Friendly Name",
    "State", "", "Model", "IEEE Address", "Power Source", "Connected Via",
]


class FakeWorksheet:
    def __init__(self, rows):
        self.rows = rows
        self.batch_updates: list = []
        self.appended: list = []

    def get_all_values(self):
        return self.rows

    def batch_update(self, updates):
        self.batch_updates.extend(updates)

    def append_rows(self, rows):
        self.appended.extend(rows)


class FakeClient:
    def __init__(self, ws):
        self._ws = ws

    def open_by_url(self, url):
        return self

    def worksheet(self, name):
        return self._ws


def _config(*site_names: str) -> PipelineConfig:
    return PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        spreadsheet_url="https://docs.google.com/spreadsheets/d/x/edit",
        cache=CacheConfig(),
        sheets_config=SheetsConfig(credentials_file="client_secret.json"),
        zigbee=ZigbeeConfig(
            sites=[
                ZigbeeSiteConfig(name=n, mqtt_host=f"mqtt.{n}.example")
                for n in site_names
            ],
        ),
    )


def _device(site: str, ieee: str, **overrides) -> ZigbeeDevice:
    fields = {
        "site": site,
        "ieee_address": ieee,
        "friendly_name": "kitchen_temp",
        "object_id": "kitchen_temp",
        "device_type": "EndDevice",
        "model_id": "WSDCGQ12LM",
        "manufacturer": "Xiaomi",
        "model": "Aqara temperature sensor",
        "power_source": "Battery",
        "software_build_id": "100",
        "date_code": "",
        "last_seen": None,
        "link_quality": 80,
        "availability": "online",
        "network_address": 1234,
    }
    fields.update(overrides)
    return ZigbeeDevice(**fields)


def _run(config, devices, rows, dry_run=False):
    ws = FakeWorksheet(rows)
    with patch(
        "gdoc2netcfg.supplements.zigbee_sheet.get_gspread_client",
        return_value=FakeClient(ws),
    ):
        written = update_zigbee_sheet(
            config, devices, {s.name: None for s in config.zigbee.sites},
            dry_run=dry_run, verbose=True,
        )
    return written, ws


def _row(site, ieee, **cells):
    row = [site, "Temp Sensor", "kitchen_temp", "", "kitchen_temp",
           "Online", "", "WSDCGQ12LM", ieee, "Battery", ""]
    for idx, val in cells.items():
        row[idx] = val
    return row


class TestPerSiteKeying:
    def test_same_ieee_two_sites_hits_the_right_row(self):
        """(Site, IEEE) keying: the welland run updates the welland row
        even though a monarto row shares the IEEE."""
        monarto_row = _row("monarto", "0x01")
        rows = [HEADER, monarto_row, _row("welland", "0x01", **{5: "Offline"})]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 1
        assert len(ws.batch_updates) == 1
        # Row 3 of the sheet (header + monarto row above it)
        assert ws.batch_updates[0]["range"].startswith("A3:")
        assert ws.batch_updates[0]["values"][0][0] == "welland"
        assert ws.appended == []

    def test_other_site_rows_untouched(self):
        """A run never writes rows owned by another site — the same
        IEEE under another site appends a NEW row (the duplication)."""
        monarto_row = _row("monarto", "0x01")
        rows = [HEADER, monarto_row]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 1
        assert ws.batch_updates == []
        assert len(ws.appended) == 1
        assert ws.appended[0][0] == "welland"
        assert ws.rows[1] == monarto_row  # byte-for-byte untouched

    def test_site_match_is_case_insensitive(self):
        rows = [HEADER, _row("Welland", "0x01", **{5: "Offline"})]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 1
        assert len(ws.batch_updates) == 1
        assert ws.appended == []

    def test_append_carries_site_and_blank_col_g(self):
        rows = [HEADER]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert ws.appended == [[
            "welland", "Temp Sensor", "kitchen_temp", "", "kitchen_temp",
            "Online", "", "WSDCGQ12LM", "0x01", "Battery", "",
        ]]

    def test_unchanged_row_is_not_rewritten(self):
        """Idempotence: a second run over current data writes nothing."""
        rows = [HEADER, _row("welland", "0x01")]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 0
        assert ws.batch_updates == []
        assert ws.appended == []


class TestWarnings:
    def test_duplicate_in_scope_rows_warns_first_wins(self, capsys):
        rows = [
            HEADER,
            _row("welland", "0x01", **{5: "Offline"}),
            _row("welland", "0x01", **{5: "Offline"}),
        ]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert "duplicate rows for site=welland ieee=0x01" in capsys.readouterr().err
        assert written == 1
        assert ws.batch_updates[0]["range"].startswith("A2:")  # first row won

    def test_blank_site_row_with_matching_ieee_warns(self, capsys):
        rows = [HEADER, _row("", "0x01")]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        err = capsys.readouterr().err
        assert "blank" in err and "0x01" in err
        assert ws.rows[1][0] == ""  # legacy row untouched
        assert len(ws.appended) == 1  # device still got its own row


class TestErrors:
    def test_no_sites_configured_raises(self):
        with pytest.raises(RuntimeError, match="No zigbee sites configured"):
            _run(_config(), [], [HEADER])

    def test_device_outside_scope_raises(self):
        with pytest.raises(RuntimeError, match="not in this run's configured"):
            _run(_config("welland"), [_device("monarto", "0x01")], [HEADER])

    def test_missing_site_column_raises(self):
        header = [c for c in HEADER if c != "Site"]
        with pytest.raises(RuntimeError, match="'Site' not found"):
            _run(_config("welland"), [_device("welland", "0x01")], [header])

    def test_dry_run_writes_nothing(self):
        rows = [HEADER]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
            dry_run=True,
        )
        assert written == 1
        assert ws.appended == [] and ws.batch_updates == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_zigbee_sheet.py -v`
Expected: most FAIL (old code keys by IEEE alone, no scope, no warnings, rewrites unchanged rows, no Site-column check)

- [ ] **Step 3: Rewrite `update_zigbee_sheet`**

In `src/gdoc2netcfg/supplements/zigbee_sheet.py`, add below `_IEEE_COL`:

```python
# Expected column header for the row-owning site.  Must exist in the sheet.
_SITE_COL = "Site"
```

Replace the body of `update_zigbee_sheet` (keep the signature):

```python
def update_zigbee_sheet(
    config: PipelineConfig,
    devices: list[ZigbeeDevice],
    bridge_infos: dict[str, ZigbeeBridgeInfo | None],
    dry_run: bool = False,
    verbose: bool = False,
) -> int:
    """Update the Zigbee Info sheet with fresh device data.

    Upserts rows matched by (Site, IEEE address) — each site manages
    only its own rows.  Rows whose Site cell is outside this run's
    configured sites are never read or written, so a device present at
    two sites keeps one row per site.  New devices are appended;
    rows already showing the current values are left alone.
    Returns the number of rows written (or that would be in dry-run).
    """
    if not config.zigbee.sites:
        raise RuntimeError("No zigbee sites configured in gdoc2netcfg.toml")
    site_scope = {s.name.strip().lower() for s in config.zigbee.sites}

    if not config.spreadsheet_url:
        raise RuntimeError(
            "spreadsheet_url not configured. Add it to the [sheets] section of "
            "gdoc2netcfg.toml:\n"
            "  spreadsheet_url = \"https://docs.google.com/spreadsheets/d/{ID}/edit\""
        )
    client = get_gspread_client(config.sheets_config)
    sh = client.open_by_url(config.spreadsheet_url)
    ws = sh.worksheet(config.zigbee.sheet_name)

    all_values = ws.get_all_values()
    if not all_values:
        raise RuntimeError(f"Sheet '{config.zigbee.sheet_name}' is empty")

    header = all_values[0]
    data_rows = all_values[1:]

    for col in (_SITE_COL, _IEEE_COL):
        if col not in header:
            raise RuntimeError(
                f"Column '{col}' not found in sheet header: {header}"
            )
    site_col_idx = header.index(_SITE_COL)
    ieee_col_idx = header.index(_IEEE_COL)
    type_col_idx = header.index("Type") if "Type" in header else 1

    def _cell(row: list[str], idx: int) -> str:
        return row[idx].strip() if idx < len(row) else ""

    # (site, ieee) -> row index (0-based in data_rows), for rows owned
    # by this run's sites.  Blank-Site rows are collected separately so
    # an IEEE collision with them can be flagged for manual fixing.
    key_to_row_idx: dict[tuple[str, str], int] = {}
    blank_site_ieees: set[str] = set()
    for i, row in enumerate(data_rows):
        ieee = _cell(row, ieee_col_idx)
        if not ieee:
            continue
        row_site = _cell(row, site_col_idx).lower()
        if not row_site:
            blank_site_ieees.add(ieee)
            continue
        if row_site not in site_scope:
            continue  # another site's row — not ours to touch
        key = (row_site, ieee)
        if key in key_to_row_idx:
            print(
                f"Warning: duplicate rows for site={row_site} ieee={ieee} "
                f"(sheet rows {key_to_row_idx[key] + 2} and {i + 2}); "
                "using the first",
                file=sys.stderr,
            )
            continue
        key_to_row_idx[key] = i

    updates: list[dict] = []
    appends: list[list[str]] = []

    for device in sorted(devices, key=lambda d: (d.site, d.object_id)):
        device_site = device.site.strip().lower()
        if device_site not in site_scope:
            raise RuntimeError(
                f"Device {device.ieee_address} belongs to site "
                f"'{device.site}', not in this run's configured sites "
                f"{sorted(site_scope)}"
            )
        bridge = bridge_infos.get(device.site)
        ieee = device.ieee_address

        if ieee in blank_site_ieees:
            print(
                f"Warning: IEEE {ieee} also appears in a row with a blank "
                "Site cell — that row was left untouched; fill in its Site "
                "column manually",
                file=sys.stderr,
            )

        key = (device_site, ieee)
        if key in key_to_row_idx:
            row_idx = key_to_row_idx[key]
            existing_row = data_rows[row_idx]
            col_g_val = (
                existing_row[_UNNAMED_COL_IDX]
                if _UNNAMED_COL_IDX < len(existing_row)
                else ""
            )
            existing_type = (
                existing_row[type_col_idx]
                if type_col_idx < len(existing_row)
                else ""
            )
            new_row = _device_to_row(device, bridge, col_g_val, existing_type)

            padded_existing = [
                existing_row[i] if i < len(existing_row) else ""
                for i in range(len(new_row))
            ]
            if padded_existing == new_row:
                continue  # row already current — idempotent re-run

            # Sheet rows are 1-indexed; +1 for header row, +1 for 1-indexing
            sheet_row = row_idx + 2
            end_col = chr(ord("A") + len(new_row) - 1)
            updates.append({
                "range": f"A{sheet_row}:{end_col}{sheet_row}",
                "values": [new_row],
            })
            if verbose:
                print(
                    f"  UPDATE row {sheet_row}: "
                    f"{device.site}/{device.object_id} ({ieee})",
                    file=sys.stderr,
                )
        else:
            new_row = _device_to_row(device, bridge, "", "")
            appends.append(new_row)
            if verbose:
                print(
                    f"  APPEND: {device.site}/{device.object_id} ({ieee})",
                    file=sys.stderr,
                )

    if not dry_run:
        if updates:
            ws.batch_update(updates)
        if appends:
            ws.append_rows(appends)

    written = len(updates) + len(appends)
    return written
```

Also update the module docstring lines 3–5 and the column-layout comment line 16: rows are matched by `(Site, IEEE address)` and column I's annotation becomes `<- key together with Site (column A)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_supplements/test_zigbee_sheet.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/zigbee_sheet.py \
    tests/test_supplements/test_zigbee_sheet.py
git commit -m "zigbee sheet: per-site row ownership keyed by (Site, IEEE)"
```

---

### Task 5: `cmd_zigbee_update_sheet` — project every configured site's view

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py:2118-2194`
- Test: `tests/test_cli/test_zigbee_db.py`

- [ ] **Step 1: Update/replace the CLI tests**

In `tests/test_cli/test_zigbee_db.py`, replace `test_update_sheet_projects_one_view_per_device` with:

```python
    def test_update_sheet_one_row_per_site(self, tmp_path):
        """A device in both configured sites' registries becomes one
        sheet row PER SITE — no cross-site projection."""
        config = _config(tmp_path, "welland", "monarto")
        _seed_db(config, {
            "welland": _site_doc(
                "welland",
                _device("welland", "0x01", availability="offline"),
            ),
            "monarto": _site_doc(
                "monarto",
                _device("monarto", "0x01", availability="online"),
            ),
        })
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee_sheet.update_zigbee_sheet",
                 return_value=2,
             ) as mock_update:
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 0
        _, devices, _bridge_infos = mock_update.call_args.args[:3]
        assert sorted((d.site, d.ieee_address) for d in devices) == [
            ("monarto", "0x01"), ("welland", "0x01"),
        ]

    def test_update_sheet_skips_unconfigured_site(self, tmp_path, capsys):
        """DB data for a site no longer in config (stale, pre-tombstone)
        contributes no rows."""
        config = _config(tmp_path, "welland")
        _seed_db(config, {
            "welland": _site_doc("welland", _device("welland", "0x01")),
            "monarto": _site_doc("monarto", _device("monarto", "0x02")),
        })
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
             patch(
                 "gdoc2netcfg.supplements.zigbee_sheet.update_zigbee_sheet",
                 return_value=1,
             ) as mock_update:
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 0
        _, devices, _ = mock_update.call_args.args[:3]
        assert [d.ieee_address for d in devices] == ["0x01"]
        assert "monarto" in capsys.readouterr().err

    def test_update_sheet_no_sites_configured_errors(self, tmp_path, capsys):
        config = _config(tmp_path)
        config.zigbee.sites = []
        args = argparse.Namespace(config=None, dry_run=True)

        with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
            rc = cmd_zigbee_update_sheet(args)

        assert rc == 1
        assert "No zigbee sites configured" in capsys.readouterr().err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli/test_zigbee_db.py::TestZigbeeUpdateSheet -v`
Expected: the three new/changed tests FAIL (old code projects one view per IEEE, doesn't filter or check sites)

- [ ] **Step 3: Rewrite the command's projection block**

In `cmd_zigbee_update_sheet`, insert the sites check right after `config = _load_config(args)`:

```python
    if not config.zigbee.sites:
        print(
            "Error: No zigbee sites configured in gdoc2netcfg.toml "
            "([[zigbee.sites]])",
            file=sys.stderr,
        )
        return 1
```

Then replace the import + projection block (the `from gdoc2netcfg.supplements.zigbee import ...` through the `all_devices` list comprehension, lines ~2140–2163) with:

```python
    from gdoc2netcfg.supplements.zigbee import ZigbeeBridgeInfo, ZigbeeDevice
    from gdoc2netcfg.supplements.zigbee_sheet import update_zigbee_sheet

    zigbee_data = _load_latest_from_db(config, "load_latest_zigbee") or {}

    # Each site manages only its own rows: project every configured
    # site's registry view directly (one row per site per device).
    # DB data for a site no longer configured (stale until the next
    # scan tombstones it) is skipped loudly.
    configured = {site_cfg.name for site_cfg in config.zigbee.sites}
    bridge_infos: dict[str, ZigbeeBridgeInfo | None] = {}
    all_devices: list[ZigbeeDevice] = []
    for site_name, doc in sorted(zigbee_data.items()):
        if site_name not in configured:
            print(
                f"Skipping site '{site_name}': in the database but not in "
                "this run's configured [[zigbee.sites]]",
                file=sys.stderr,
            )
            continue
        bridge_infos[site_name] = (
            ZigbeeBridgeInfo(**doc["bridge"]) if doc["bridge"] else None
        )
        all_devices.extend(
            ZigbeeDevice(**device)
            for _ieee, device in sorted(doc["devices"].items())
        )
```

(The following `for site_cfg in config.zigbee.sites:` no-data warning loop and everything after it stay as they are.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli/test_zigbee_db.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/cli/main.py tests/test_cli/test_zigbee_db.py
git commit -m "zigbee update-sheet: one row per configured site, no projection"
```

---

### Task 6: delete `best_device_view`

**Files:**
- Modify: `src/gdoc2netcfg/supplements/zigbee.py` (delete the function; fix the two docstrings that reference it)
- Modify: `tests/test_supplements/test_zigbee.py` (delete its tests + import)

- [ ] **Step 1: Delete the function and its references**

- Delete `best_device_view` (zigbee.py lines ~334–353).
- In the `scan_zigbee` docstring, replace the sentence ending "consumers needing one view per device pick via best_device_view." with "a device listed by two sites (moved between sites without removing the old registry entry) keeps both sites' views — each site's sheet run projects its own view."
- In `tests/test_supplements/test_zigbee.py`: remove `best_device_view` from the import and delete the whole `TestBestDeviceView` class (the tests at lines ~190–211).

- [ ] **Step 2: Verify nothing references it**

Run: `grep -rn "best_device_view" src/ tests/`
Expected: no output

- [ ] **Step 3: Run the full suite and lint**

Run: `uv run pytest -q && uv run ruff check src/ tests/`
Expected: all PASS, no lint errors

- [ ] **Step 4: Commit**

```bash
git add src/gdoc2netcfg/supplements/zigbee.py tests/test_supplements/test_zigbee.py
git commit -m "zigbee: delete best_device_view — sites project their own rows"
```

---

### Task 7: final verification and push

- [ ] **Step 1: Full suite + lint from a clean state**

Run: `uv run pytest -q && uv run ruff check src/ tests/`
Expected: ~1650 tests PASS, lint clean

- [ ] **Step 2: Sanity-check the spec's no-code-change claims**

Run: `git diff main --stat`
Expected: NO changes under `src/gdoc2netcfg/storage/`, `src/gdoc2netcfg/cli/cron.py`, or `scan_zigbee` — only the files listed in this plan's file-structure table.

- [ ] **Step 3: Push the branch**

```bash
git push -u origin feature/zigbee-site-split
```

Merging, deployment (toml edits on both sites, monarto cron install), and the post-merge memory/CLAUDE.md touch-ups are handled after review via the finishing-a-development-branch flow — see the spec's "Rollout order".
