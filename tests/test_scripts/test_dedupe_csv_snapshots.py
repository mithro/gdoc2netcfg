"""Tests for scripts/dedupe_csv_snapshots.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from gdoc2netcfg.storage.config_db import ConfigDB

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "dedupe_csv_snapshots.py"
_spec = importlib.util.spec_from_file_location("dedupe_csv_snapshots", _SCRIPT)
dedupe_csv_snapshots = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dedupe_csv_snapshots)


@pytest.fixture
def bloated_db(tmp_path):
    """A config.db written the pre-delta way: every fetch stores the text.
    network: A A B B A (two consecutive-duplicate rows); iot: X X X X X."""
    path = tmp_path / "config.db"
    db = ConfigDB(path)
    conn = db.connection
    for net_text, iot_text in zip("AABBA", "XXXXX"):
        s = db.begin_scan("csv_fetch")
        conn.execute(
            "INSERT INTO csv_snapshots (scan_id, sheet_name, csv_text) VALUES (?, 'network', ?)",
            (s, net_text),
        )
        conn.execute(
            "INSERT INTO csv_snapshots (scan_id, sheet_name, csv_text) VALUES (?, 'iot', ?)",
            (s, iot_text),
        )
        conn.commit()
        db.finish_scan(s, host_count=2, changed_count=2)
    db.close()
    return path


def _history(path, sheet):
    with ConfigDB(path, read_only=True) as db:
        return [text for _, text in reversed(db.csv_history(sheet))]


def test_dry_run_deletes_nothing(bloated_db, capsys):
    rc = dedupe_csv_snapshots.main([str(bloated_db)])
    assert rc == 0
    assert "would delete 6 rows" in capsys.readouterr().out
    assert _history(bloated_db, "network") == list("AABBA")


def test_execute_collapses_only_consecutive_duplicates(bloated_db):
    rc = dedupe_csv_snapshots.main([str(bloated_db), "--execute", "--no-vacuum"])
    assert rc == 0
    assert _history(bloated_db, "network") == ["A", "B", "A"]   # the revert to A survives
    assert _history(bloated_db, "iot") == ["X"]
    with ConfigDB(bloated_db, read_only=True) as db:
        assert db.load_latest_csv("network") == "A"
        assert db.load_latest_csv("iot") == "X"
        assert db.connection.execute("SELECT count(*) FROM scans").fetchone()[0] == 5


def test_execute_with_vacuum_shrinks_file(bloated_db):
    before = bloated_db.stat().st_size
    rc = dedupe_csv_snapshots.main([str(bloated_db), "--execute"])
    assert rc == 0
    assert bloated_db.stat().st_size <= before


def test_missing_db_is_an_error(tmp_path):
    assert dedupe_csv_snapshots.main([str(tmp_path / "nope.db")]) == 2
