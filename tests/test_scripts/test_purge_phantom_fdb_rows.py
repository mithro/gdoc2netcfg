"""Tests for scripts/purge_phantom_fdb_rows.py.

The fixture DB is built through the real DiscoveryDB API (not hand-rolled
DDL) so the test fails if the storage schema drifts from what the purge
script assumes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from gdoc2netcfg.storage.discovery_db import DiscoveryDB

# scripts/purge_phantom_fdb_rows.py is a standalone script, not an
# installed module.
_SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "purge_phantom_fdb_rows.py"
)
_spec = importlib.util.spec_from_file_location("purge_phantom_fdb_rows", _SCRIPT)
purge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(purge)


_STALE_BRIDGE_MAC = "E0:91:F5:0C:D6:DB"

# sw-stale's pre-fix mac_table: one real row, one phantom duplicate of it
# on port 3 (status learned(3) artifact), the switch's own MAC on port 5
# (status mgmt(5) artifact), and a REAL host on port 3 with no duplicate
# (indistinguishable from a phantom — must be left alone).
_REAL_ROW = ["AA:BB:CC:00:00:01", 10, 24, "1/0/24"]
_PHANTOM_DUP_ROW = ["AA:BB:CC:00:00:01", 10, 3, "1/g3"]
_PHANTOM_MGMT_ROW = [_STALE_BRIDGE_MAC, 1, 5, "1/g5"]
_UNMATCHED_PORT3_ROW = ["BB:BB:CC:00:00:02", 20, 3, "1/g3"]

_STALE_MAC_TABLE = [
    _REAL_ROW,
    _PHANTOM_DUP_ROW,
    _PHANTOM_MGMT_ROW,
    _UNMATCHED_PORT3_ROW,
]


def _doc(mac_table: list[list], bridge_mac: str) -> dict:
    """A minimal-but-complete bridge doc accepted by save_bridge."""
    return {
        "mac_table": mac_table,
        "vlan_names": [[1, "default"]],
        "port_pvids": [[1, 1]],
        "port_names": [[1, "Port 1"]],
        "port_aliases": [],
        "port_status": [[1, 1, 1000]],
        "lldp_neighbors": [],
        "vlan_egress_ports": [],
        "vlan_untagged_ports": [],
        "poe_status": [],
        "poe_power": [],
        "box_sensors": [],
        "bridge_mac": bridge_mac,
        "port_statistics": [],
    }


def _make_db(tmp_path: Path, *, healed_scan: bool = True) -> Path:
    """Scan 1: both switches poisoned. Scan 2 (optional): sw-active healed."""
    db_path = tmp_path / "discovery.db"
    db = DiscoveryDB(db_path)
    try:
        active_poisoned = _doc(
            [
                ["CC:BB:CC:00:00:03", 30, 7, "1/0/7"],
                ["CC:BB:CC:00:00:03", 30, 3, "1/g3"],  # phantom dup
            ],
            "E0:91:F5:0C:D6:DC",
        )
        s1 = db.begin_scan("bridge")
        db.save_bridge(s1, {
            "sw-stale": _doc(_STALE_MAC_TABLE, _STALE_BRIDGE_MAC),
            "sw-active": active_poisoned,
        })
        db.finish_scan(s1, host_count=2, changed_count=2)

        if healed_scan:
            # Post-fix scan: sw-active comes back clean; sw-stale is
            # unreachable so scan_bridge carries its baseline forward
            # unchanged (delta save inserts no rows for it).
            active_clean = _doc(
                [["CC:BB:CC:00:00:03", 30, 7, "1/0/7"]],
                "E0:91:F5:0C:D6:DC",
            )
            s2 = db.begin_scan("bridge")
            db.save_bridge(s2, {
                "sw-stale": _doc(_STALE_MAC_TABLE, _STALE_BRIDGE_MAC),
                "sw-active": active_clean,
            })
            db.finish_scan(s2, host_count=2, changed_count=1)
    finally:
        db.close()
    return db_path


def _latest_mac_tables(db_path: Path) -> dict[str, list[list]]:
    db = DiscoveryDB(db_path)
    try:
        latest = db.load_latest_bridge()
        return {name: doc["mac_table"] for name, doc in latest.items()}
    finally:
        db.close()


class TestFindPhantomRows:
    def test_identifies_duplicate_and_mgmt_rows_only(self, tmp_path):
        db_path = _make_db(tmp_path)
        conn = purge._connect(db_path, readonly=True)
        try:
            latest = purge.latest_bridge_scan_per_switch(conn)
            phantoms, unmatched = purge.find_phantom_rows(
                conn, "sw-stale", latest["sw-stale"]
            )
        finally:
            conn.close()
        # duplicate port-3 row + self-MAC port-5 row are phantoms; the
        # unmatched port-3 host is reported but not marked for deletion
        assert len(phantoms) == 2
        assert len(unmatched) == 1


class TestMain:
    def test_dry_run_deletes_nothing(self, tmp_path, capsys):
        db_path = _make_db(tmp_path)
        assert purge.main(["--db", str(db_path)]) == 0
        out = capsys.readouterr().out
        assert "would delete 2 phantom rows" in out
        assert _latest_mac_tables(db_path)["sw-stale"] == _STALE_MAC_TABLE

    def test_execute_purges_stale_switch_only(self, tmp_path, capsys):
        db_path = _make_db(tmp_path)
        assert purge.main(["--db", str(db_path), "--execute"]) == 0
        out = capsys.readouterr().out
        assert "deleted 2 phantom rows total" in out

        tables = _latest_mac_tables(db_path)
        # phantoms gone, real + unmatched rows preserved
        assert tables["sw-stale"] == [_REAL_ROW, _UNMATCHED_PORT3_ROW]
        # healed switch untouched
        assert tables["sw-active"] == [["CC:BB:CC:00:00:03", 30, 7, "1/0/7"]]

    def test_refuses_fully_prefix_database(self, tmp_path, capsys):
        """If no switch is healed, the fix was never deployed+scanned —
        refuse rather than purging every switch in the fleet."""
        db_path = _make_db(tmp_path, healed_scan=False)
        assert purge.main(["--db", str(db_path), "--execute"]) == 1
        err = capsys.readouterr().err
        assert "every switch is unhealed" in err
        assert _latest_mac_tables(db_path)["sw-stale"] == _STALE_MAC_TABLE

    def test_all_healed_is_noop(self, tmp_path, capsys):
        db_path = tmp_path / "discovery.db"
        db = DiscoveryDB(db_path)
        try:
            s1 = db.begin_scan("bridge")
            db.save_bridge(s1, {
                "sw-clean": _doc(
                    [["AA:BB:CC:00:00:01", 10, 24, "1/0/24"]],
                    "E0:91:F5:0C:D6:DB",
                ),
            })
            db.finish_scan(s1, host_count=1, changed_count=1)
        finally:
            db.close()
        assert purge.main(["--db", str(db_path), "--execute"]) == 0
        assert "nothing to purge" in capsys.readouterr().out
