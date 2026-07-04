#!/usr/bin/env python3
"""One-off purge of phantom port-3/5 FDB rows for never-rescanned switches.

Before the dot1qTpFdbPort column guard (issue #10), dot1qTpFdbStatus rows
were recorded as phantom FDB entries on bridge ports 3 (learned) and 5
(mgmt) of every scanned switch. Switches that are still scanned self-heal
on their first post-fix bridge scan; switches that are never scanned again
keep the phantom rows as their live latest state forever. This tool deletes
those phantom rows.

A switch is targeted only when its LATEST bridge row-set still contains
phantom rows — i.e. it was not healed by a post-fix rescan. Run this AFTER
deploying the fix and completing one bridge scan; if every switch is still
unhealed the fix has not been deployed/scanned yet and the tool refuses to
execute.

Phantom identification, within one (hostname, scan_id) row-set:
- a port-3 or port-5 row whose (mac, vlan_id) also exists on a different
  bridge port in the same row-set (the status row duplicated the real one)
- a port-5 row whose MAC is the switch's own bridge MAC (mgmt self entry)

Rows on ports 3/5 matching neither rule are reported but NOT deleted —
they are indistinguishable from a real host on those ports.

Dry-run by default; pass --execute to delete. Writing the production DB
requires root: sudo python3 scripts/purge_phantom_fdb_rows.py --execute
"""
import argparse
import sqlite3
import sys
from pathlib import Path


def _connect(db_path: Path, *, readonly: bool) -> sqlite3.Connection:
    if not db_path.exists():
        raise FileNotFoundError(f"database not found: {db_path}")
    mode = "?mode=ro" if readonly else ""
    conn = sqlite3.connect(f"file:{db_path}{mode}", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def latest_bridge_scan_per_switch(conn: sqlite3.Connection) -> dict[str, int]:
    """hostname -> latest completed scan_id holding its bridge rows.

    Mirrors DiscoveryDB._latest_entity_scans("bridge_switches", "hostname").
    """
    cur = conn.execute(
        "SELECT DISTINCT t.hostname, t.scan_id FROM bridge_switches t "
        "WHERE t.scan_id = ("
        "  SELECT t2.scan_id FROM bridge_switches t2 "
        "  JOIN scans s ON t2.scan_id = s.id "
        "  WHERE s.finished_at IS NOT NULL AND t2.hostname = t.hostname "
        "  ORDER BY s.id DESC LIMIT 1"
        ")"
    )
    return dict(cur.fetchall())


def find_phantom_rows(
    conn: sqlite3.Connection, hostname: str, scan_id: int,
) -> tuple[list[int], list[int]]:
    """Return (phantom_row_ids, unmatched_row_ids) for one row-set.

    phantom: port-3/5 rows caught by the duplicate or self-MAC rule.
    unmatched: port-3/5 rows matching neither rule (left alone).
    """
    bridge_mac = conn.execute(
        "SELECT bridge_mac FROM bridge_switches "
        "WHERE hostname = ? AND scan_id = ?",
        (hostname, scan_id),
    ).fetchone()
    self_mac = bridge_mac["bridge_mac"] if bridge_mac else None

    rows = conn.execute(
        "SELECT id, mac, vlan_id, bridge_port FROM bridge_mac_table "
        "WHERE hostname = ? AND scan_id = ?",
        (hostname, scan_id),
    ).fetchall()

    ports_by_key: dict[tuple[str, int], set[int]] = {}
    for row in rows:
        ports_by_key.setdefault(
            (row["mac"], row["vlan_id"]), set()
        ).add(row["bridge_port"])

    phantoms, unmatched = [], []
    for row in rows:
        if row["bridge_port"] not in (3, 5):
            continue
        other_ports = ports_by_key[(row["mac"], row["vlan_id"])] - {
            row["bridge_port"]
        }
        if other_ports:
            phantoms.append(row["id"])
        elif row["bridge_port"] == 5 and self_mac and row["mac"] == self_mac:
            phantoms.append(row["id"])
        else:
            unmatched.append(row["id"])
    return phantoms, unmatched


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Purge phantom port-3/5 FDB rows for unhealed switches."
    )
    parser.add_argument(
        "--db",
        default=".cache/discovery.db",
        help="path to discovery.db (default: .cache/discovery.db)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually delete rows (default: dry-run report only)",
    )
    args = parser.parse_args(argv)

    conn = _connect(Path(args.db), readonly=not args.execute)
    try:
        latest = latest_bridge_scan_per_switch(conn)
        if not latest:
            print("no bridge scans in this database; nothing to do")
            return 0

        # Classify each switch by its LATEST row-set.
        unhealed: dict[str, tuple[int, list[int], list[int]]] = {}
        for hostname, scan_id in sorted(latest.items()):
            phantoms, unmatched = find_phantom_rows(conn, hostname, scan_id)
            state = "unhealed" if phantoms else "healed"
            print(
                f"{hostname:35s} latest scan {scan_id:6d}: {state}"
                + (f" ({len(phantoms)} phantom rows)" if phantoms else "")
                + (
                    f" [{len(unmatched)} unmatched port-3/5 rows left alone]"
                    if unmatched
                    else ""
                )
            )
            if phantoms:
                unhealed[hostname] = (scan_id, phantoms, unmatched)

        if not unhealed:
            print("\nall switches healed; nothing to purge")
            return 0

        if len(unhealed) == len(latest):
            print(
                "\nERROR: every switch is unhealed — has the fixed code "
                "been deployed and a bridge scan completed? Refusing to "
                "purge a fully pre-fix database.",
                file=sys.stderr,
            )
            return 1

        # Purge the unhealed switches' ENTIRE bridge_mac_table history of
        # phantom rows (every scan, not just the latest): these switches
        # will never be rescanned, so no scan will ever supersede the
        # poisoned row-sets.
        total = 0
        for hostname, (latest_scan, _, _) in sorted(unhealed.items()):
            scan_ids = [
                row["scan_id"]
                for row in conn.execute(
                    "SELECT DISTINCT scan_id FROM bridge_mac_table "
                    "WHERE hostname = ? ORDER BY scan_id",
                    (hostname,),
                )
            ]
            for scan_id in scan_ids:
                phantoms, _ = find_phantom_rows(conn, hostname, scan_id)
                if not phantoms:
                    continue
                total += len(phantoms)
                if args.execute:
                    conn.executemany(
                        "DELETE FROM bridge_mac_table WHERE id = ?",
                        [(row_id,) for row_id in phantoms],
                    )
                print(
                    f"  {hostname} scan {scan_id}: "
                    f"{'deleted' if args.execute else 'would delete'} "
                    f"{len(phantoms)} phantom rows"
                )

        if args.execute:
            conn.commit()
            print(f"\ndeleted {total} phantom rows total")
        else:
            print(f"\ndry-run: would delete {total} phantom rows "
                  f"(re-run with --execute)")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
