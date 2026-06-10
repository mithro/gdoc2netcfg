"""Tests for the BaseDatabase storage foundation."""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gdoc2netcfg.storage.base import (
    BaseDatabase,
    SchemaVersionError,
    _utcnow_iso,
)

# -- Helpers ---------------------------------------------------------------

class ConcreteDB(BaseDatabase):
    """Minimal subclass for testing (BaseDatabase is abstract-ish)."""

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS test_data ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  scan_id INTEGER NOT NULL REFERENCES scans(id),"
            "  value TEXT NOT NULL"
            ")"
        )


@pytest.fixture()
def db(tmp_path: Path) -> ConcreteDB:
    """Create a fresh database for each test."""
    d = ConcreteDB(tmp_path / "test.db")
    yield d
    d.close()


# -- Connection & journal mode --------------------------------------------

class TestConnection:
    def test_creates_database_file(self, tmp_path: Path):
        db_path = tmp_path / "new.db"
        assert not db_path.exists()
        d = ConcreteDB(db_path)
        assert db_path.exists()
        d.close()

    def test_creates_parent_directories(self, tmp_path: Path):
        db_path = tmp_path / "nested" / "dir" / "test.db"
        d = ConcreteDB(db_path)
        assert db_path.exists()
        d.close()

    def test_delete_journal_mode(self, db: ConcreteDB):
        # DELETE (rollback) journal, NOT WAL: a WAL reader must write the -shm
        # wal-index, which a non-owner of a root-owned DB cannot do.  DELETE has
        # no -shm, so a read-only open needs zero write access.
        cur = db.connection.execute("PRAGMA journal_mode")
        assert cur.fetchone()[0] == "delete"

    def test_busy_timeout_set(self, db: ConcreteDB):
        # A non-zero busy_timeout lets readers/writers wait out the brief lock
        # contention DELETE mode introduces (it serializes writes vs reads).
        cur = db.connection.execute("PRAGMA busy_timeout")
        assert cur.fetchone()[0] >= 1000

    def test_reopen_converts_wal_to_delete(self, tmp_path: Path):
        # Existing production DBs are WAL; re-opening them RW with this code must
        # convert them to DELETE.  The deploy relies on this to migrate live DBs.
        path = tmp_path / "conv.db"
        d = ConcreteDB(path)
        d.connection.execute("PRAGMA journal_mode=WAL")  # simulate an old WAL db
        d.close()
        d2 = ConcreteDB(path)
        assert d2.connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        d2.close()

    def test_foreign_keys_enabled(self, db: ConcreteDB):
        cur = db.connection.execute("PRAGMA foreign_keys")
        assert cur.fetchone()[0] == 1

    def test_context_manager(self, tmp_path: Path):
        db_path = tmp_path / "ctx.db"
        with ConcreteDB(db_path) as d:
            assert db_path.exists()
            d.begin_scan("test")
        # Connection should be closed after with-block
        with pytest.raises(Exception):
            d.connection.execute("SELECT 1")

    def test_reopen_existing_database(self, tmp_path: Path):
        db_path = tmp_path / "reopen.db"
        with ConcreteDB(db_path) as d:
            scan_id = d.begin_scan("test")
            d.finish_scan(scan_id, host_count=1, changed_count=0)
        # Re-open should succeed and see the scan
        with ConcreteDB(db_path) as d2:
            assert d2.latest_scan_id("test") == scan_id


# -- Schema versioning -----------------------------------------------------

class TestSchemaVersion:
    def test_new_database_has_correct_version(self, db: ConcreteDB):
        cur = db.connection.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        )
        assert int(cur.fetchone()[0]) == ConcreteDB.SCHEMA_VERSION

    def test_wrong_version_raises(self, tmp_path: Path):
        db_path = tmp_path / "wrong_version.db"
        # Create a DB then manually change the version
        d = ConcreteDB(db_path)
        d.connection.execute(
            "UPDATE _meta SET value = '999' WHERE key = 'schema_version'"
        )
        d.connection.commit()
        d.close()

        with pytest.raises(SchemaVersionError, match="999"):
            ConcreteDB(db_path)

    def test_missing_meta_table_raises(self, tmp_path: Path):
        db_path = tmp_path / "no_meta.db"
        # Create a bare DB with no _meta table
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY, scan_type TEXT, "
            "started_at TEXT, finished_at TEXT, host_count INTEGER, "
            "changed_count INTEGER, metadata TEXT)"
        )
        conn.execute(
            "CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        # No version row inserted
        conn.commit()
        conn.close()

        with pytest.raises(SchemaVersionError, match="no schema_version"):
            ConcreteDB(db_path)


# -- Subclass table creation -----------------------------------------------

class TestSubclassTables:
    def test_subclass_tables_created(self, db: ConcreteDB):
        cur = db.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='test_data'"
        )
        assert cur.fetchone() is not None


# -- Scan lifecycle --------------------------------------------------------

class TestScanLifecycle:
    def test_begin_scan_returns_incrementing_ids(self, db: ConcreteDB):
        id1 = db.begin_scan("type_a")
        id2 = db.begin_scan("type_b")
        assert id2 > id1

    def test_begin_scan_records_type_and_time(self, db: ConcreteDB):
        before = _utcnow_iso()
        scan_id = db.begin_scan("reachability")
        after = _utcnow_iso()

        cur = db.connection.execute(
            "SELECT scan_type, started_at, finished_at FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        assert row[0] == "reachability"
        assert before <= row[1] <= after
        assert row[2] is None  # not finished yet

    def test_finish_scan_sets_fields(self, db: ConcreteDB):
        scan_id = db.begin_scan("test")
        db.finish_scan(scan_id, host_count=50, changed_count=3)

        cur = db.connection.execute(
            "SELECT finished_at, host_count, changed_count FROM scans "
            "WHERE id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        assert row[0] is not None  # finished_at set
        assert row[1] == 50
        assert row[2] == 3

    def test_finish_scan_raises_on_zero_host_count(self, db: ConcreteDB):
        scan_id = db.begin_scan("test")
        with pytest.raises(ValueError, match="host_count=0"):
            db.finish_scan(scan_id, host_count=0, changed_count=0)

    def test_finish_scan_allows_zero_changed_count(self, db: ConcreteDB):
        scan_id = db.begin_scan("test")
        db.finish_scan(scan_id, host_count=10, changed_count=0)
        cur = db.connection.execute(
            "SELECT changed_count FROM scans WHERE id = ?", (scan_id,)
        )
        assert cur.fetchone()[0] == 0


# -- latest_scan_id --------------------------------------------------------

class TestLatestScanId:
    def test_no_scans_returns_none(self, db: ConcreteDB):
        assert db.latest_scan_id("test") is None

    def test_unfinished_scan_not_returned(self, db: ConcreteDB):
        db.begin_scan("test")  # not finished
        assert db.latest_scan_id("test") is None

    def test_returns_most_recent_completed(self, db: ConcreteDB):
        id1 = db.begin_scan("test")
        db.finish_scan(id1, host_count=5, changed_count=1)
        id2 = db.begin_scan("test")
        db.finish_scan(id2, host_count=5, changed_count=0)
        assert db.latest_scan_id("test") == id2

    def test_filters_by_scan_type(self, db: ConcreteDB):
        id_a = db.begin_scan("type_a")
        db.finish_scan(id_a, host_count=1, changed_count=0)
        id_b = db.begin_scan("type_b")
        db.finish_scan(id_b, host_count=1, changed_count=0)

        assert db.latest_scan_id("type_a") == id_a
        assert db.latest_scan_id("type_b") == id_b
        assert db.latest_scan_id("type_c") is None


# -- latest_scan_age -------------------------------------------------------

class TestLatestScanAge:
    def test_no_scans_returns_none(self, db: ConcreteDB):
        assert db.latest_scan_age("test") is None

    def test_returns_approximate_age(self, db: ConcreteDB):
        scan_id = db.begin_scan("test")
        db.finish_scan(scan_id, host_count=1, changed_count=0)
        age = db.latest_scan_age("test")
        assert age is not None
        # Should be very recent (less than 2 seconds)
        assert 0 <= age < 2.0

    def test_age_increases_over_time(self, db: ConcreteDB):
        scan_id = db.begin_scan("test")
        db.finish_scan(scan_id, host_count=1, changed_count=0)
        age1 = db.latest_scan_age("test")
        time.sleep(0.1)
        age2 = db.latest_scan_age("test")
        assert age2 > age1


# -- cleanup_incomplete_scans ----------------------------------------------

class TestCleanupIncompleteScans:
    def test_removes_old_incomplete_scans(self, db: ConcreteDB):
        # Insert an incomplete scan with a timestamp 2 hours ago
        two_hours_ago = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).isoformat()
        db.connection.execute(
            "INSERT INTO scans (scan_type, started_at) VALUES (?, ?)",
            ("test", two_hours_ago),
        )
        db.connection.commit()

        deleted = db.cleanup_incomplete_scans(max_age_hours=1)
        assert deleted == 1

    def test_preserves_recent_incomplete_scans(self, db: ConcreteDB):
        # A scan started just now should not be cleaned up
        scan_id = db.begin_scan("test")
        deleted = db.cleanup_incomplete_scans(max_age_hours=1)
        assert deleted == 0
        # Scan should still exist
        cur = db.connection.execute(
            "SELECT id FROM scans WHERE id = ?", (scan_id,)
        )
        assert cur.fetchone() is not None

    def test_preserves_completed_scans(self, db: ConcreteDB):
        # Insert a completed scan with old timestamp
        two_hours_ago = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).isoformat()
        db.connection.execute(
            "INSERT INTO scans (scan_type, started_at, finished_at, "
            "host_count, changed_count) VALUES (?, ?, ?, ?, ?)",
            ("test", two_hours_ago, two_hours_ago, 5, 0),
        )
        db.connection.commit()

        deleted = db.cleanup_incomplete_scans(max_age_hours=1)
        assert deleted == 0

    def test_runs_on_init(self, tmp_path: Path):
        db_path = tmp_path / "auto_cleanup.db"
        # Create DB with an old incomplete scan
        d = ConcreteDB(db_path)
        two_hours_ago = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).isoformat()
        d.connection.execute(
            "INSERT INTO scans (scan_type, started_at) VALUES (?, ?)",
            ("test", two_hours_ago),
        )
        d.connection.commit()
        d.close()

        # Re-opening should clean up the orphan
        d2 = ConcreteDB(db_path)
        cur = d2.connection.execute(
            "SELECT COUNT(*) FROM scans WHERE finished_at IS NULL"
        )
        assert cur.fetchone()[0] == 0
        d2.close()


# -- scan_history ----------------------------------------------------------

class TestScanHistory:
    def test_empty_returns_empty_list(self, db: ConcreteDB):
        assert db.scan_history() == []

    def test_returns_completed_scans(self, db: ConcreteDB):
        id1 = db.begin_scan("type_a")
        db.finish_scan(id1, host_count=10, changed_count=2)
        db.begin_scan("type_b")  # not finished — should be excluded

        history = db.scan_history()
        assert len(history) == 1
        assert history[0]["id"] == id1
        assert history[0]["scan_type"] == "type_a"
        assert history[0]["host_count"] == 10
        assert history[0]["changed_count"] == 2

    def test_filters_by_scan_type(self, db: ConcreteDB):
        id_a = db.begin_scan("type_a")
        db.finish_scan(id_a, host_count=1, changed_count=0)
        id_b = db.begin_scan("type_b")
        db.finish_scan(id_b, host_count=1, changed_count=0)

        history_a = db.scan_history(scan_type="type_a")
        assert len(history_a) == 1
        assert history_a[0]["scan_type"] == "type_a"

    def test_filters_by_since(self, db: ConcreteDB):
        # Create a scan, then filter with a future timestamp
        id1 = db.begin_scan("test")
        db.finish_scan(id1, host_count=1, changed_count=0)

        future = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()
        assert db.scan_history(since=future) == []

    def test_respects_limit(self, db: ConcreteDB):
        for _ in range(5):
            sid = db.begin_scan("test")
            db.finish_scan(sid, host_count=1, changed_count=0)

        history = db.scan_history(limit=2)
        assert len(history) == 2

    def test_most_recent_first(self, db: ConcreteDB):
        id1 = db.begin_scan("test")
        db.finish_scan(id1, host_count=1, changed_count=0)
        id2 = db.begin_scan("test")
        db.finish_scan(id2, host_count=1, changed_count=0)

        history = db.scan_history()
        assert history[0]["id"] == id2  # most recent first
        assert history[1]["id"] == id1


# -- Read-only access ------------------------------------------------------

class TestReadOnly:
    """A read-only open must work without ANY write access to the DB file, so a
    non-owner can read a root-owned database (the WAL->DELETE switch enables this).
    """

    def test_read_only_reads_data(self, tmp_path: Path):
        path = tmp_path / "ro.db"
        d = ConcreteDB(path)
        sid = d.begin_scan("test")
        d.finish_scan(sid, host_count=1, changed_count=0)
        d.close()

        ro = ConcreteDB(path, read_only=True)
        assert len(ro.scan_history()) == 1
        ro.close()

    def test_read_only_open_on_unwritable_file(self, tmp_path: Path):
        # Acceptance case: a DB the opening process cannot write at all.
        path = tmp_path / "ro.db"
        d = ConcreteDB(path)
        sid = d.begin_scan("test")
        d.finish_scan(sid, host_count=1, changed_count=0)
        d.close()
        path.chmod(0o444)
        try:
            # A read-write open must fail — writers genuinely need write access.
            with pytest.raises(sqlite3.OperationalError):
                ConcreteDB(path)
            # A read-only open must succeed and read the data.
            ro = ConcreteDB(path, read_only=True)
            assert len(ro.scan_history()) == 1
            ro.close()
        finally:
            path.chmod(0o644)

    def test_read_only_rejects_writes(self, tmp_path: Path):
        path = tmp_path / "ro.db"
        ConcreteDB(path).close()
        ro = ConcreteDB(path, read_only=True)
        with pytest.raises(sqlite3.OperationalError):
            ro.begin_scan("nope")
        ro.close()

    def test_read_only_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            ConcreteDB(tmp_path / "does-not-exist.db", read_only=True)
