"""_fresh_scan_age: the DB-based freshness gate for supplement scans (#4).

Replaces the per-scan flat-file mtime checks — a scan command reuses the
DB's latest completed scan when it is younger than the cache window.
"""

import sqlite3
from datetime import UTC, datetime, timedelta

from gdoc2netcfg.cli.main import _fresh_scan_age
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


def _record_scan(config, scan_type: str) -> None:
    dbs = open_databases(config.cache.directory)
    scan_id = dbs.discovery.begin_scan(scan_type)
    dbs.discovery.finish_scan(scan_id, host_count=1, changed_count=0)
    dbs.close()


def test_no_databases_means_no_fresh_scan(tmp_path):
    config = _config(tmp_path)
    assert _fresh_scan_age(config, "snmp") is None


def test_fresh_scan_returns_age(tmp_path):
    config = _config(tmp_path)
    _record_scan(config, "snmp")
    age = _fresh_scan_age(config, "snmp")
    assert age is not None
    assert age < 60

    # Freshness is per scan_type.
    assert _fresh_scan_age(config, "bridge") is None


def test_stale_scan_returns_none(tmp_path):
    config = _config(tmp_path)
    _record_scan(config, "snmp")
    old = (datetime.now(UTC) - timedelta(seconds=600)).isoformat()
    with sqlite3.connect(config.cache.discovery_db_path) as conn:
        conn.execute("UPDATE scans SET finished_at = ?", (old,))
    assert _fresh_scan_age(config, "snmp") is None
