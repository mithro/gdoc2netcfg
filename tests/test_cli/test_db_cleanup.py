"""cmd_db_cleanup_incomplete_scans: manual admin cleanup of crashed scans.

Cleanup is NOT run on open, so an orphaned scan — possibly with committed
child rows — persists until this command is run explicitly.
"""

import argparse
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_db_cleanup_incomplete_scans
from gdoc2netcfg.config import CacheConfig, PipelineConfig
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.storage import open_databases


def _config(tmp_path) -> PipelineConfig:
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    return PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=cache_dir),
    )


def _add_orphan_with_children(db) -> int:
    """Insert an old, never-finished reachability scan with a child row."""
    two_hours_ago = (
        datetime.now(timezone.utc) - timedelta(hours=2)
    ).isoformat()
    cur = db.connection.execute(
        "INSERT INTO scans (scan_type, started_at) VALUES (?, ?)",
        ("reachability", two_hours_ago),
    )
    orphan_id = cur.lastrowid
    db.connection.execute(
        "INSERT INTO reachability (scan_id, hostname, interface_idx, ip, "
        "is_reachable, transmitted, received) "
        "VALUES (?, 'ghost', 0, '10.0.0.9', 0, 3, 0)",
        (orphan_id,),
    )
    db.connection.commit()
    return orphan_id


def test_cleanup_removes_orphan_with_children(tmp_path, capsys):
    config = _config(tmp_path)
    dbs = open_databases(config.cache.directory)
    orphan_id = _add_orphan_with_children(dbs.discovery)
    dbs.close()

    args = argparse.Namespace(config=None, max_age_hours=1)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
        rc = cmd_db_cleanup_incomplete_scans(args)

    assert rc == 0
    out = capsys.readouterr().out
    assert "Discovery DB: removed 1 incomplete scan(s)" in out
    assert "Total: 1 incomplete scan(s) removed." in out

    # Orphan scan and its child row are both gone.
    ro = open_databases(config.cache.directory, read_only=True)
    try:
        assert ro.discovery.connection.execute(
            "SELECT COUNT(*) FROM scans WHERE id = ?", (orphan_id,)
        ).fetchone()[0] == 0
        assert ro.discovery.connection.execute(
            "SELECT COUNT(*) FROM reachability WHERE scan_id = ?", (orphan_id,)
        ).fetchone()[0] == 0
    finally:
        ro.close()


def test_cleanup_spares_recent_and_completed(tmp_path, capsys):
    config = _config(tmp_path)
    dbs = open_databases(config.cache.directory)
    # A completed scan (must survive) ...
    good = dbs.discovery.begin_scan("reachability")
    dbs.discovery.finish_scan(good, host_count=1, changed_count=0)
    # ... and a just-started, still-running scan (younger than the cutoff).
    running = dbs.discovery.begin_scan("reachability")
    dbs.close()

    args = argparse.Namespace(config=None, max_age_hours=1)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
        rc = cmd_db_cleanup_incomplete_scans(args)

    assert rc == 0
    assert "Total: 0 incomplete scan(s) removed." in capsys.readouterr().out
    ro = open_databases(config.cache.directory, read_only=True)
    try:
        ids = {r[0] for r in ro.discovery.connection.execute(
            "SELECT id FROM scans"
        )}
        assert {good, running} <= ids
    finally:
        ro.close()


def test_cleanup_missing_dbs(tmp_path, capsys):
    config = _config(tmp_path)
    args = argparse.Namespace(config=None, max_age_hours=1)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
        rc = cmd_db_cleanup_incomplete_scans(args)
    assert rc == 1
    assert "Database not found" in capsys.readouterr().err
