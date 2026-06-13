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
