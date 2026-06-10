"""_load_or_run_reachability uses the DB only — no flat-file cache (#4)."""

from pathlib import Path
from unittest.mock import patch

from gdoc2netcfg.cli.main import _load_or_run_reachability
from gdoc2netcfg.config import CacheConfig, PipelineConfig
from gdoc2netcfg.models.network import Site


def _config(tmp_path) -> PipelineConfig:
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    return PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=cache_dir),
    )


# One host's worth of scan data in the serialised reachability format —
# finish_scan() fails loud on empty scans, so the mock must return data.
_SCAN_RESULT = {
    "host-a": {
        "interfaces": [
            [{"ip": "10.0.0.1", "transmitted": 1, "received": 1,
              "rtt_avg_ms": 1.0}],
        ],
    },
}


@patch("gdoc2netcfg.supplements.reachability.check_all_hosts_reachability")
def test_fresh_flat_cache_is_ignored(mock_scan, tmp_path):
    """A fresh reachability.json must NOT satisfy the cache check."""
    config = _config(tmp_path)
    import json

    (Path(config.cache.directory) / "reachability.json").write_text(
        json.dumps({"version": 2, "hosts": {}}),
    )
    mock_scan.return_value = _SCAN_RESULT

    result = _load_or_run_reachability(config, hosts=[], force=False)

    mock_scan.assert_called_once()  # scanned despite the fresh flat file
    assert result == _SCAN_RESULT


@patch("gdoc2netcfg.supplements.reachability.check_all_hosts_reachability")
def test_live_scan_does_not_write_flat_cache(mock_scan, tmp_path):
    """A live scan must not produce a reachability.json working file."""
    config = _config(tmp_path)
    mock_scan.return_value = _SCAN_RESULT

    _load_or_run_reachability(config, hosts=[], force=True)

    flat = Path(config.cache.directory) / "reachability.json"
    assert not flat.exists()
