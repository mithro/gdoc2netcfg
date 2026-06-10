"""cmd_db_info must open each DB with its own class.

Regression: it used a generic BaseDatabase (SCHEMA_VERSION 1) open,
which rejects any upgraded database as "newer than the code".
"""

import argparse
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_db_info
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


def test_db_info_reads_upgraded_discovery_db(tmp_path, capsys):
    config = _config(tmp_path)
    dbs = open_databases(config.cache.directory)
    scan_id = dbs.discovery.begin_scan("zigbee")
    dbs.discovery.finish_scan(scan_id, host_count=1, changed_count=1)
    dbs.close()

    args = argparse.Namespace(config=None)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
        rc = cmd_db_info(args)

    assert rc == 0
    out = capsys.readouterr()
    assert "zigbee: 1 scans" in out.out
    assert "Error reading database" not in out.err


def test_db_info_missing_dbs(tmp_path, capsys):
    config = _config(tmp_path)

    args = argparse.Namespace(config=None)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config):
        rc = cmd_db_info(args)

    assert rc == 0
    assert capsys.readouterr().out.count("not created yet") == 2
