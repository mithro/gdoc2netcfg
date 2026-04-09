"""Configuration database for spreadsheet data with historical retention.

Stores CSV text snapshots, parsed DeviceRecords, and VLAN definitions.
CSV snapshots are always stored (not delta-based). DeviceRecords and
VLANDefinitions are delta-based: a new row is inserted only when the
data for that key differs from the latest stored row.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from gdoc2netcfg.storage.base import BaseDatabase

_CSV_SNAPSHOTS_SQL = """\
CREATE TABLE IF NOT EXISTS csv_snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id),
    sheet_name TEXT NOT NULL,
    csv_text   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_csv_scan ON csv_snapshots(scan_id);
"""

_DEVICE_RECORDS_SQL = """\
CREATE TABLE IF NOT EXISTS device_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    sheet_name  TEXT NOT NULL,
    row_number  INTEGER NOT NULL,
    machine     TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    ip          TEXT NOT NULL,
    interface   TEXT NOT NULL DEFAULT '',
    site        TEXT NOT NULL DEFAULT '',
    extra_json  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_device_scan ON device_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_device_key ON device_records(machine, interface);
"""

_VLAN_DEFINITIONS_SQL = """\
CREATE TABLE IF NOT EXISTS vlan_definitions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    vlan_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    ip_range    TEXT NOT NULL,
    netmask     TEXT NOT NULL,
    cidr        TEXT NOT NULL,
    color       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_vlan_scan ON vlan_definitions(scan_id);
CREATE INDEX IF NOT EXISTS idx_vlan_key ON vlan_definitions(vlan_id);
"""


class ConfigDB(BaseDatabase):
    """SQLite storage for spreadsheet configuration data."""

    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)

    def _create_tables(self, cur: sqlite3.Cursor) -> None:
        cur.executescript(
            _CSV_SNAPSHOTS_SQL + _DEVICE_RECORDS_SQL + _VLAN_DEFINITIONS_SQL
        )

    # ------------------------------------------------------------------
    # CSV snapshots (always stored, NOT delta-based)
    # ------------------------------------------------------------------

    def save_csv(self, scan_id: int, sheet_name: str, csv_text: str) -> None:
        """Store a CSV text snapshot for a sheet."""
        self._conn.execute(
            "INSERT INTO csv_snapshots (scan_id, sheet_name, csv_text) "
            "VALUES (?, ?, ?)",
            (scan_id, sheet_name, csv_text),
        )
        self._conn.commit()

    def load_latest_csv(self, sheet_name: str) -> str | None:
        """Load the most recent CSV text for a sheet, or None."""
        cur = self._conn.execute(
            "SELECT cs.csv_text FROM csv_snapshots cs "
            "JOIN scans s ON cs.scan_id = s.id "
            "WHERE cs.sheet_name = ? AND s.finished_at IS NOT NULL "
            "ORDER BY s.id DESC LIMIT 1",
            (sheet_name,),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def has_csv(self, sheet_name: str) -> bool:
        """Check if any CSV snapshot exists for this sheet."""
        return self.load_latest_csv(sheet_name) is not None

    def csv_history(
        self,
        sheet_name: str,
        *,
        since: str | None = None,
    ) -> list[tuple[str, str]]:
        """Return (timestamp, csv_text) pairs for a sheet, newest first."""
        clauses = [
            "cs.sheet_name = ?",
            "s.finished_at IS NOT NULL",
        ]
        params: list[str] = [sheet_name]
        if since is not None:
            clauses.append("s.started_at >= ?")
            params.append(since)
        where = " AND ".join(clauses)
        cur = self._conn.execute(
            f"SELECT s.started_at, cs.csv_text "  # noqa: S608
            f"FROM csv_snapshots cs "
            f"JOIN scans s ON cs.scan_id = s.id "
            f"WHERE {where} ORDER BY s.id DESC",
            params,
        )
        return cur.fetchall()

    # ------------------------------------------------------------------
    # Device records (delta-based per machine+interface key)
    # ------------------------------------------------------------------

    def save_device_records(
        self,
        scan_id: int,
        records: list[dict],
    ) -> int:
        """Store device records, inserting only changed ones.

        Each record dict must have keys: sheet_name, row_number, machine,
        mac_address, ip, interface, site, extra (dict).

        Returns the number of records that actually changed.
        """
        # Load the latest state for comparison
        latest = self._latest_device_records_by_key()

        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for rec in records:
                key = (rec["machine"], rec.get("interface", ""))
                extra_json = json.dumps(
                    rec.get("extra", {}), sort_keys=True,
                )
                new_tuple = (
                    rec["sheet_name"],
                    rec["row_number"],
                    rec["machine"],
                    rec.get("mac_address", ""),
                    rec.get("ip", ""),
                    rec.get("interface", ""),
                    rec.get("site", ""),
                    extra_json,
                )
                if key in latest and latest[key] == new_tuple:
                    continue  # unchanged
                cur.execute(
                    "INSERT INTO device_records "
                    "(scan_id, sheet_name, row_number, machine, mac_address, "
                    "ip, interface, site, extra_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, *new_tuple),
                )
                changed += 1
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_device_records(self) -> list[dict] | None:
        """Load the latest device record for each (machine, interface) key.

        Returns None if no completed scan exists.
        """
        if self.latest_scan_id("csv_fetch") is None:
            return None

        cur = self._conn.execute(
            "SELECT dr.sheet_name, dr.row_number, dr.machine, "
            "dr.mac_address, dr.ip, dr.interface, dr.site, dr.extra_json "
            "FROM device_records dr "
            "JOIN scans s ON dr.scan_id = s.id "
            "WHERE s.finished_at IS NOT NULL "
            "AND dr.id = ("
            "  SELECT dr2.id FROM device_records dr2 "
            "  JOIN scans s2 ON dr2.scan_id = s2.id "
            "  WHERE s2.finished_at IS NOT NULL "
            "  AND dr2.machine = dr.machine "
            "  AND dr2.interface = dr.interface "
            "  ORDER BY s2.id DESC LIMIT 1"
            ") "
            "ORDER BY dr.machine, dr.interface"
        )
        results = []
        for row in cur.fetchall():
            results.append({
                "sheet_name": row[0],
                "row_number": row[1],
                "machine": row[2],
                "mac_address": row[3],
                "ip": row[4],
                "interface": row[5],
                "site": row[6],
                "extra": json.loads(row[7]),
            })
        return results

    def device_history(
        self,
        machine: str,
    ) -> list[tuple[str, dict]]:
        """Return (timestamp, record_dict) pairs for a machine.

        Every row is a change — returns all historical records, newest first.
        """
        cur = self._conn.execute(
            "SELECT s.started_at, dr.sheet_name, dr.row_number, "
            "dr.machine, dr.mac_address, dr.ip, dr.interface, "
            "dr.site, dr.extra_json "
            "FROM device_records dr "
            "JOIN scans s ON dr.scan_id = s.id "
            "WHERE dr.machine = ? AND s.finished_at IS NOT NULL "
            "ORDER BY s.id DESC",
            (machine,),
        )
        results = []
        for row in cur.fetchall():
            results.append((
                row[0],
                {
                    "sheet_name": row[1],
                    "row_number": row[2],
                    "machine": row[3],
                    "mac_address": row[4],
                    "ip": row[5],
                    "interface": row[6],
                    "site": row[7],
                    "extra": json.loads(row[8]),
                },
            ))
        return results

    def _latest_device_records_by_key(
        self,
    ) -> dict[tuple[str, str], tuple]:
        """Build a lookup of (machine, interface) -> comparable tuple."""
        cur = self._conn.execute(
            "SELECT dr.sheet_name, dr.row_number, dr.machine, "
            "dr.mac_address, dr.ip, dr.interface, dr.site, dr.extra_json "
            "FROM device_records dr "
            "JOIN scans s ON dr.scan_id = s.id "
            "WHERE s.finished_at IS NOT NULL "
            "AND dr.id = ("
            "  SELECT dr2.id FROM device_records dr2 "
            "  JOIN scans s2 ON dr2.scan_id = s2.id "
            "  WHERE s2.finished_at IS NOT NULL "
            "  AND dr2.machine = dr.machine "
            "  AND dr2.interface = dr.interface "
            "  ORDER BY s2.id DESC LIMIT 1"
            ")"
        )
        result: dict[tuple[str, str], tuple] = {}
        for row in cur.fetchall():
            key = (row[2], row[5])  # (machine, interface)
            result[key] = row
        return result

    # ------------------------------------------------------------------
    # VLAN definitions (delta-based per vlan_id)
    # ------------------------------------------------------------------

    def save_vlan_definitions(
        self,
        scan_id: int,
        definitions: list[dict],
    ) -> int:
        """Store VLAN definitions, inserting only changed ones.

        Each dict must have keys: id (int), name, ip_range, netmask,
        cidr, color, description.

        Returns the number of definitions that actually changed.
        """
        latest = self._latest_vlan_definitions_by_id()

        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for vdef in definitions:
                vlan_id = vdef["id"]
                new_tuple = (
                    vlan_id,
                    vdef["name"],
                    vdef["ip_range"],
                    vdef["netmask"],
                    vdef["cidr"],
                    vdef.get("color", ""),
                    vdef.get("description", ""),
                )
                if vlan_id in latest and latest[vlan_id] == new_tuple:
                    continue
                cur.execute(
                    "INSERT INTO vlan_definitions "
                    "(scan_id, vlan_id, name, ip_range, netmask, cidr, "
                    "color, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, *new_tuple),
                )
                changed += 1
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_vlan_definitions(self) -> list[dict] | None:
        """Load the latest VLAN definition for each vlan_id.

        Returns None if no completed scan exists.
        """
        if self.latest_scan_id("csv_fetch") is None:
            return None

        cur = self._conn.execute(
            "SELECT vd.vlan_id, vd.name, vd.ip_range, vd.netmask, "
            "vd.cidr, vd.color, vd.description "
            "FROM vlan_definitions vd "
            "JOIN scans s ON vd.scan_id = s.id "
            "WHERE s.finished_at IS NOT NULL "
            "AND vd.id = ("
            "  SELECT vd2.id FROM vlan_definitions vd2 "
            "  JOIN scans s2 ON vd2.scan_id = s2.id "
            "  WHERE s2.finished_at IS NOT NULL "
            "  AND vd2.vlan_id = vd.vlan_id "
            "  ORDER BY s2.id DESC LIMIT 1"
            ") "
            "ORDER BY vd.vlan_id"
        )
        results = []
        for row in cur.fetchall():
            results.append({
                "id": row[0],
                "name": row[1],
                "ip_range": row[2],
                "netmask": row[3],
                "cidr": row[4],
                "color": row[5],
                "description": row[6],
            })
        return results

    def _latest_vlan_definitions_by_id(self) -> dict[int, tuple]:
        """Build a lookup of vlan_id -> comparable tuple."""
        cur = self._conn.execute(
            "SELECT vd.vlan_id, vd.name, vd.ip_range, vd.netmask, "
            "vd.cidr, vd.color, vd.description "
            "FROM vlan_definitions vd "
            "JOIN scans s ON vd.scan_id = s.id "
            "WHERE s.finished_at IS NOT NULL "
            "AND vd.id = ("
            "  SELECT vd2.id FROM vlan_definitions vd2 "
            "  JOIN scans s2 ON vd2.scan_id = s2.id "
            "  WHERE s2.finished_at IS NOT NULL "
            "  AND vd2.vlan_id = vd.vlan_id "
            "  ORDER BY s2.id DESC LIMIT 1"
            ")"
        )
        result: dict[int, tuple] = {}
        for row in cur.fetchall():
            result[row[0]] = row
        return result
