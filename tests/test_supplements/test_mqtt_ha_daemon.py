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
