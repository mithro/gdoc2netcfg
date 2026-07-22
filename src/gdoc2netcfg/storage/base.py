"""Base database class for SQLite storage with historical data retention.

Provides connection management, DELETE-journal mode, schema versioning, and
the shared ``scans`` table that tracks every scan/fetch operation. Both
ConfigDB and DiscoveryDB inherit from this class.  DELETE (rollback) journal
is used rather than WAL so a read-only open needs no write access — letting a
non-owner read a root-owned database (see ``read_only`` in ``__init__``).

The scans table is an audit trail: every scan creates a row (even if
nothing changed). Data tables reference scans via scan_id and only
INSERT rows when values actually change (delta-based storage).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

# SQL for tables shared by both databases.
_SCANS_SQL = """\
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type     TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    host_count    INTEGER,
    changed_count INTEGER,
    metadata      TEXT
);
"""

_SCANS_INDEX_SQL = """\
CREATE INDEX IF NOT EXISTS idx_scans_type_finished
    ON scans(scan_type, finished_at);
"""

_META_SQL = """\
CREATE TABLE IF NOT EXISTS _meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class SchemaVersionError(Exception):
    """Raised when the database schema version does not match the code."""


class BaseDatabase:
    """Manages a single SQLite database with DELETE-journal mode and scan tracking.

    Subclasses must override ``_create_tables()`` to define their
    data-specific tables (called once when the database is first created),
    and bump ``SCHEMA_VERSION`` + add a ``SCHEMA_UPGRADES`` entry whenever
    their tables change.

    Pass ``read_only=True`` to open an existing database without any write
    access (used by read-only commands against a root-owned DB).
    """

    # Per-database schema version — subclasses bump this when their
    # tables change.
    SCHEMA_VERSION = 1

    # target_version -> upgrade steps from target_version - 1, applied
    # in order by a read-write open of an older database.  Each step is
    # either a DDL string or a callable(conn) for data migrations that
    # need more than SQL.
    SCHEMA_UPGRADES: dict[int, list[str | Callable[[sqlite3.Connection], None]]] = {}

    def __init__(self, db_path: Path, *, read_only: bool = False) -> None:
        self._db_path = db_path
        self._read_only = read_only

        if read_only:
            self._connect_read_only(db_path)
            return

        db_path.parent.mkdir(parents=True, exist_ok=True)

        is_new = not db_path.exists()
        # isolation_level=None disables Python's implicit transaction
        # management.  All transactions are managed explicitly via
        # BEGIN/COMMIT/ROLLBACK in save methods.
        self._conn = sqlite3.connect(str(db_path), isolation_level=None)
        # DELETE (rollback) journal, NOT WAL.  WAL forces every reader to write
        # the -shm wal-index, which a non-owner of a root-owned DB cannot do;
        # DELETE has no -shm, so a read-only open (see _connect_read_only) needs
        # no write access at all.  busy_timeout absorbs the brief writer/reader
        # lock contention DELETE introduces (it serializes writes against reads).
        self._conn.execute("PRAGMA journal_mode=DELETE")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")

        if is_new:
            self._init_schema()
        else:
            self._check_schema_version()

        # NB: incomplete-scan cleanup is deliberately NOT run here.  A
        # crashed scan can leave a committed orphan row, and deleting it
        # trips the child tables' foreign keys — running that on every
        # open once crash-looped the reachability daemon.  Reads already
        # ignore unfinished scans (every reconstruction filters
        # finished_at IS NOT NULL), so the cleanup is housekeeping only
        # and is exposed as the manual ``db cleanup-incomplete-scans``
        # admin command instead.
        self._verify_writable()

    def _connect_read_only(self, db_path: Path) -> None:
        """Open an existing DELETE-mode database read-only — no write access needed.

        Uses a ``mode=ro`` URI so SQLite never writes the database file, and
        relies on DELETE journal mode (no -shm sidecar to create).  This lets a
        non-owner read a root-owned database.  None of the write-path setup
        (parent-dir creation, schema creation, incomplete-scan cleanup) runs.
        """
        if not db_path.exists():
            raise FileNotFoundError(
                f"Cannot open {db_path} read-only: file does not exist."
            )
        self._conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, isolation_level=None,
        )
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._check_schema_version()

    def _verify_writable(self) -> None:
        """Fail fast if this read-write open cannot actually write.

        Performs a harmless write inside a transaction that is always
        rolled back, so no data changes — but the write forces SQLite to
        open its journal, which fails immediately on a database the
        process cannot write (a bare ``BEGIN IMMEDIATE`` does not, as it
        never dirties a page).  A writer that lacks write access should
        learn at open time, not mid-scan.  (This guarantee previously
        rode on the automatic incomplete-scan cleanup, now a manual
        admin command.)
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE _meta SET value = value WHERE key = 'schema_version'"
            )
        finally:
            self._conn.execute("ROLLBACK")

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create all tables in a new database.

        Uses an explicit transaction so that a crash during init
        leaves no half-created database file.
        """
        self._conn.execute("BEGIN")
        try:
            # Run each DDL statement individually (not executescript,
            # which auto-commits and would break our transaction).
            for stmt in (
                _SCANS_SQL + _SCANS_INDEX_SQL + _META_SQL
            ).split(";"):
                stmt = stmt.strip()
                if stmt:
                    self._conn.execute(stmt)
            self._conn.execute(
                "INSERT INTO _meta (key, value) VALUES ('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )
            self._create_tables(self._conn)
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        """Create data-specific tables.  Override in subclasses.

        Called inside a transaction — use ``conn.execute()`` for each
        DDL statement, not ``executescript()`` (which auto-commits).
        """

    def _check_schema_version(self) -> None:
        """Verify the on-disk schema version, upgrading older databases.

        A read-write open of an older database applies the registered
        ``SCHEMA_UPGRADES`` steps.  A read-only open cannot upgrade and
        fails loud; a database NEWER than the code always fails loud.
        """
        cur = self._conn.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        )
        row = cur.fetchone()
        if row is None:
            raise SchemaVersionError(
                f"Database {self._db_path} has no schema_version in _meta. "
                "The file is not a gdoc2netcfg database — investigate "
                "before deleting it."
            )
        on_disk = int(row[0])
        if on_disk == self.SCHEMA_VERSION:
            return
        if on_disk > self.SCHEMA_VERSION:
            raise SchemaVersionError(
                f"Database {self._db_path} has schema version {on_disk}, "
                f"newer than the code's version {self.SCHEMA_VERSION} — "
                "the code is out of date for this database."
            )
        if self._read_only:
            raise SchemaVersionError(
                f"Database {self._db_path} has schema version {on_disk}, "
                f"but the code expects version {self.SCHEMA_VERSION}. "
                "A read-only open cannot upgrade it — any write command "
                "(the daemon, a scan, fetch) will upgrade it in place."
            )
        self._upgrade_schema(on_disk)

    def _upgrade_schema(self, on_disk: int) -> None:
        """Apply SCHEMA_UPGRADES steps from *on_disk* up to SCHEMA_VERSION."""
        self._conn.execute("BEGIN")
        try:
            for version in range(on_disk + 1, self.SCHEMA_VERSION + 1):
                steps = self.SCHEMA_UPGRADES.get(version)
                if steps is None:
                    raise SchemaVersionError(
                        f"Database {self._db_path} is at schema version "
                        f"{on_disk} but no upgrade step to version "
                        f"{version} is registered."
                    )
                for step in steps:
                    if callable(step):
                        step(self._conn)
                    else:
                        self._conn.execute(step)
            self._conn.execute(
                "UPDATE _meta SET value = ? WHERE key = 'schema_version'",
                (str(self.SCHEMA_VERSION),),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> BaseDatabase:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying sqlite3 connection (for subclass use)."""
        return self._conn

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def begin_scan(self, scan_type: str) -> int:
        """Record the start of a scan.  Returns the new scan ID."""
        cur = self._conn.execute(
            "INSERT INTO scans (scan_type, started_at) VALUES (?, ?)",
            (scan_type, _utcnow_iso()),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def finish_scan(
        self,
        scan_id: int,
        host_count: int,
        changed_count: int,
    ) -> None:
        """Record the completion of a scan.

        Raises ``ValueError`` if *host_count* is zero — an empty scan
        result almost always indicates a problem (network outage, empty
        spreadsheet, misconfigured site filter).  Callers that genuinely
        expect zero hosts should handle this before calling finish_scan.
        """
        if host_count == 0:
            raise ValueError(
                f"Scan {scan_id} finished with host_count=0. "
                "This usually indicates a problem (network outage, "
                "empty spreadsheet, or misconfigured site filter)."
            )
        now = _utcnow_iso()
        self._conn.execute(
            "UPDATE scans SET finished_at = ?, host_count = ?, "
            "changed_count = ? WHERE id = ?",
            (now, host_count, changed_count, scan_id),
        )
        self._conn.commit()

    def latest_scan_id(self, scan_type: str) -> int | None:
        """Return the ID of the most recent *completed* scan, or None."""
        cur = self._conn.execute(
            "SELECT id FROM scans "
            "WHERE scan_type = ? AND finished_at IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (scan_type,),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def latest_scan_age(self, scan_type: str) -> float | None:
        """Seconds since the most recent completed scan, or None."""
        cur = self._conn.execute(
            "SELECT finished_at FROM scans "
            "WHERE scan_type = ? AND finished_at IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (scan_type,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        finished = datetime.fromisoformat(row[0])
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - finished).total_seconds()

    def _scan_child_tables(self) -> list[str]:
        """Tables holding a foreign key that references ``scans``.

        Discovered from the live schema (``PRAGMA foreign_key_list``) so
        every current or future child table is covered automatically and
        the set cannot drift from the DDL.
        """
        tables: list[str] = []
        for (name,) in self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall():
            if name == "scans":
                continue
            for fk in self._conn.execute(
                f'PRAGMA foreign_key_list("{name}")'
            ).fetchall():
                if fk[2] == "scans":  # fk[2] = referenced table
                    tables.append(name)
                    break
        return tables

    def cleanup_incomplete_scans(self, max_age_hours: int = 1) -> int:
        """Delete scans that were never finished (process crash).

        Housekeeping, run manually via the ``db cleanup-incomplete-scans``
        admin command — NOT automatically on open (see ``__init__``).
        Reads already ignore unfinished scans (every reconstruction
        filters ``finished_at IS NOT NULL``), so this only reclaims
        rows orphaned by a crash.

        Only deletes scans older than *max_age_hours*, sparing any scan
        currently in progress.  A crashed scan may already have committed
        child rows (``begin_scan`` and the row-saving commit run in
        separate transactions), so rows referencing the orphaned scans
        are deleted first — otherwise the ``scans`` DELETE trips the
        child tables' no-cascade foreign keys (foreign_keys=ON) with
        ``FOREIGN KEY constraint failed``.  All deletes run in one
        explicit transaction (the connection is autocommit,
        ``isolation_level=None``).  Returns the number of scan rows
        deleted.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        cutoff_iso = cutoff.isoformat()
        where = "finished_at IS NULL AND started_at < ?"
        orphans = f"SELECT id FROM scans WHERE {where}"  # noqa: S608
        self._conn.execute("BEGIN")
        try:
            for table in self._scan_child_tables():
                self._conn.execute(
                    f'DELETE FROM "{table}" WHERE scan_id IN ({orphans})',  # noqa: S608
                    (cutoff_iso,),
                )
            cur = self._conn.execute(
                f"DELETE FROM scans WHERE {where}",  # noqa: S608
                (cutoff_iso,),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        return cur.rowcount

    # ------------------------------------------------------------------
    # Scan history queries
    # ------------------------------------------------------------------

    def scan_history(
        self,
        scan_type: str | None = None,
        *,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return recent completed scans as a list of dicts.

        Filters by *scan_type* and/or *since* (ISO 8601 timestamp).
        """
        clauses = ["finished_at IS NOT NULL"]
        params: list[str | int] = []
        if scan_type is not None:
            clauses.append("scan_type = ?")
            params.append(scan_type)
        if since is not None:
            clauses.append("started_at >= ?")
            params.append(since)
        where = " AND ".join(clauses)
        params.append(limit)
        cur = self._conn.execute(
            f"SELECT id, scan_type, started_at, finished_at, "  # noqa: S608
            f"host_count, changed_count, metadata "
            f"FROM scans WHERE {where} "
            f"ORDER BY id DESC LIMIT ?",
            params,
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()
