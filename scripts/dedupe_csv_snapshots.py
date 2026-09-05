#!/usr/bin/env python3
"""Collapse consecutive duplicate CSV snapshots in config.db, then VACUUM.

Until 2026-09 ConfigDB.save_csv stored a full copy of every sheet on every
15-minute fetch regardless of change: 8 608 snapshots per sheet with only
1–94 distinct versions, ~733 MB where ~10 MB of real history existed.
save_csv is delta-based now; this one-off tool brings the existing file in
line with it.

Rule: walking each sheet's snapshots in scan order, a row is deleted when
its csv_text is identical to the previous surviving row for that sheet.
Only *consecutive* duplicates go — an A -> B -> A history keeps all three
rows, exactly what the delta save would have produced.  The `scans` audit
rows are untouched.  load_latest_csv() answers identically before/after.

Dry-run by default; --execute deletes and (unless --no-vacuum) runs VACUUM
to return the space to the filesystem — VACUUM needs free disk roughly the
size of the database.  Hold the fetch cron lock while running so no fetch
writes concurrently:

    sudo flock /opt/gdoc2netcfg/.cache/cron-fetch.lock \\
        python3 scripts/dedupe_csv_snapshots.py --execute [DB]

Default DB: .cache/config.db relative to the working directory.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


def find_duplicate_ids(conn: sqlite3.Connection) -> dict[str, list[int]]:
    """Per sheet, the ids of rows identical to the previous surviving row."""
    dupes: dict[str, list[int]] = {}
    cur = conn.execute(
        "SELECT id, sheet_name, csv_text FROM csv_snapshots "
        "ORDER BY sheet_name, scan_id, id"
    )
    last: dict[str, str] = {}
    for row_id, sheet, text in cur:
        if last.get(sheet) == text:
            dupes.setdefault(sheet, []).append(row_id)
        else:
            last[sheet] = text
    return dupes


def snapshot_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return dict(conn.execute(
        "SELECT sheet_name, count(*) FROM csv_snapshots GROUP BY sheet_name"
    ).fetchall())


def latest_texts(conn: sqlite3.Connection) -> dict[str, str | None]:
    """load_latest_csv() semantics for every sheet — checked before/after."""
    sheets = [r[0] for r in conn.execute(
        "SELECT DISTINCT sheet_name FROM csv_snapshots"
    )]
    out: dict[str, str | None] = {}
    for sheet in sheets:
        row = conn.execute(
            "SELECT cs.csv_text FROM csv_snapshots cs "
            "JOIN scans s ON cs.scan_id = s.id "
            "WHERE cs.sheet_name = ? AND s.finished_at IS NOT NULL "
            "ORDER BY s.id DESC LIMIT 1", (sheet,),
        ).fetchone()
        out[sheet] = row[0] if row else None
    return out


def dedupe(db_path: Path, *, execute: bool, vacuum: bool) -> int:
    if not db_path.exists():
        print(f"database not found: {db_path}", file=sys.stderr)
        return 2
    size_before = db_path.stat().st_size
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 30000")
    before = snapshot_counts(conn)
    latest_before = latest_texts(conn)
    dupes = find_duplicate_ids(conn)

    print(f"{db_path}: {size_before / 1048576:.1f} MB")
    print(f"{'sheet':18}{'snapshots':>10}{'duplicates':>12}{'keep':>8}")
    for sheet, n in sorted(before.items()):
        d = len(dupes.get(sheet, []))
        print(f"{sheet:18}{n:>10}{d:>12}{n - d:>8}")
    total = sum(len(v) for v in dupes.values())
    if not execute:
        print(f"dry run: would delete {total} rows (pass --execute)")
        return 0

    conn.execute("BEGIN")
    for ids in dupes.values():
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            conn.execute(
                f"DELETE FROM csv_snapshots WHERE id IN ({','.join('?' * len(chunk))})",
                chunk,
            )
    conn.execute("COMMIT")

    after = snapshot_counts(conn)
    latest_after = latest_texts(conn)
    if latest_after != latest_before:
        print("ERROR: latest snapshot per sheet changed — refusing to VACUUM; "
              "restore from backup", file=sys.stderr)
        return 1
    if find_duplicate_ids(conn):
        print("ERROR: consecutive duplicates remain after delete", file=sys.stderr)
        return 1
    print(f"deleted {total} rows; remaining per sheet: {after}")
    if vacuum:
        conn.execute("VACUUM")
        print(f"VACUUM done: {db_path.stat().st_size / 1048576:.1f} MB")
    conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("db", nargs="?", default=Path(".cache/config.db"), type=Path)
    ap.add_argument("--execute", action="store_true", help="delete (default: dry run)")
    ap.add_argument("--no-vacuum", action="store_true", help="skip VACUUM after deleting")
    args = ap.parse_args(argv)
    return dedupe(args.db, execute=args.execute, vacuum=not args.no_vacuum)


if __name__ == "__main__":
    sys.exit(main())
