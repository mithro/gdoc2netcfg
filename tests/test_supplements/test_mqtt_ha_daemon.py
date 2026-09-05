"""Tests for the reachability daemon's per-cycle pipeline rebuild."""

from unittest.mock import patch

import pytest

from gdoc2netcfg.config import PipelineConfig
from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.supplements.mqtt_ha import _rebuild_hosts


def _config():
    return PipelineConfig(site=Site(name="welland", domain="welland.mithis.com"))


def test_rebuild_returns_fresh_hosts():
    # _build_pipeline returns (records, hosts, inventory, result).
    with patch(
        "gdoc2netcfg.cli.main._build_pipeline",
        return_value=([], ["host-a", "host-b"], None, ValidationResult()),
    ):
        hosts = _rebuild_hosts(_config(), previous_hosts=["stale"], cycle=2)
    assert hosts == ["host-a", "host-b"]


def test_rebuild_refuses_to_publish_from_invalid_cached_data():
    # Should never happen (fetch already refuses to cache invalid sheets),
    # but if it does, the daemon must fail loud on EVERY cycle — not
    # degrade to a stderr warning that keeps serving from invalid data.
    # This must raise even when a previous_hosts fallback is available:
    # the owner explicitly rejected stderr-only degradation here.
    bad_result = ValidationResult()
    bad_result.add(ConstraintViolation(
        severity=Severity.ERROR, code="missing_mac", message="No MAC address",
        record_id="network:3",
    ))
    with patch(
        "gdoc2netcfg.cli.main._build_pipeline",
        return_value=([], ["host-a", "host-b"], None, bad_result),
    ), pytest.raises(ValueError, match="No MAC address"):
        _rebuild_hosts(_config(), previous_hosts=["host-a"], cycle=5)


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
