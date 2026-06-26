"""Tests for the reachability daemon's per-cycle pipeline rebuild."""

from unittest.mock import patch

import pytest

from gdoc2netcfg.config import PipelineConfig
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.supplements.mqtt_ha import _rebuild_hosts


def _config():
    return PipelineConfig(site=Site(name="welland", domain="welland.mithis.com"))


def test_rebuild_returns_fresh_hosts():
    # _build_pipeline returns (records, hosts, inventory, result).
    with patch(
        "gdoc2netcfg.cli.main._build_pipeline",
        return_value=([], ["host-a", "host-b"], None, None),
    ):
        hosts = _rebuild_hosts(_config(), previous_hosts=["stale"], cycle=2)
    assert hosts == ["host-a", "host-b"]


def test_rebuild_first_build_failure_propagates():
    # No previous hosts (cycle 1) -> fail loud, no good state to keep.
    with patch(
        "gdoc2netcfg.cli.main._build_pipeline", side_effect=ValueError("boom")
    ), pytest.raises(ValueError, match="boom"):
        _rebuild_hosts(_config(), previous_hosts=None, cycle=1)


def test_rebuild_later_failure_keeps_previous(capsys):
    prev = ["host-a"]
    with patch(
        "gdoc2netcfg.cli.main._build_pipeline", side_effect=ValueError("boom")
    ):
        hosts = _rebuild_hosts(_config(), previous_hosts=prev, cycle=5)
    assert hosts is prev
    assert "keeping previous host list" in capsys.readouterr().err


def test_signal_handler_sets_event_records_signum_silently(capsys):
    import signal
    import threading

    from gdoc2netcfg.supplements.mqtt_ha import _make_signal_handler

    stop = threading.Event()
    caught: dict[str, int] = {}
    handler = _make_signal_handler(stop, caught)

    handler(signal.SIGTERM, None)

    assert stop.is_set()
    assert caught["signum"] == signal.SIGTERM
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == ""


def test_aborted_cycle_does_not_save_or_publish():
    from unittest.mock import MagicMock, patch

    from gdoc2netcfg.supplements.mqtt_ha import run_daemon

    cfg = _config()

    def fake_sweep(hosts, verbose=False, stop_event=None):
        # Simulate SIGTERM landing mid-sweep.
        stop_event.set()
        return {}

    with patch(
        "gdoc2netcfg.supplements.mqtt_ha.mqtt.Client"
    ) as mock_client_cls, patch(
        "gdoc2netcfg.storage.open_databases"
    ) as mock_opendb, patch(
        "gdoc2netcfg.supplements.mqtt_ha._rebuild_hosts", return_value=["h1"]
    ), patch(
        "gdoc2netcfg.supplements.reachability.check_all_hosts_reachability",
        side_effect=fake_sweep,
    ), patch(
        "gdoc2netcfg.cli.main._save_reachability_to_db"
    ) as mock_save, patch(
        "gdoc2netcfg.supplements.mqtt_ha._publish_hosts_to_client"
    ) as mock_publish:
        mock_client_cls.return_value = MagicMock()
        mock_opendb.return_value = MagicMock()
        run_daemon(cfg, interval=300, verbose=False)

    mock_save.assert_not_called()
    mock_publish.assert_not_called()
