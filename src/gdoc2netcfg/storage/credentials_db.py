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
