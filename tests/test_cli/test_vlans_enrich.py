"""The VLAN Allocations sheet, when configured, is required (#84 E).

Mirrors the Sites sheet rule (test_sites_enrich.py): without it the
VLAN-dependent checks (vlan_mismatch, roaming and BMC net-prefix logic)
silently go quiet, so a configured-but-missing or empty sheet is a hard
error rather than a warning.
"""

import pytest

from gdoc2netcfg.cli.main import _enrich_vlans_from_sheet
from gdoc2netcfg.config import PipelineConfig, SheetConfig
from gdoc2netcfg.models.network import Site

VLAN_CSV = (
    "VLAN,Name,IP Range,Netmask,CIDR,,,Color,For\n"
    "5,net,10.X.5.X,255.255.255.0,/24,,,Red,Network infrastructure\n"
)


def _config(configured=True):
    sheets = [SheetConfig(name="vlan_allocations", url="https://x")] if configured else []
    return PipelineConfig(
        site=Site(name="welland", domain="welland.mithis.com", site_octet=1),
        sheets=sheets,
    )


def test_sets_vlans_from_sheet():
    config = _config()
    _enrich_vlans_from_sheet(config, [("vlan_allocations", VLAN_CSV)])
    assert config.site.ip_prefix_for_vlan("net") == "10.1.5."


def test_configured_but_unavailable_is_an_error():
    with pytest.raises(ValueError, match="VLAN Allocations sheet is configured"):
        _enrich_vlans_from_sheet(_config(), [])


def test_configured_but_empty_is_an_error():
    with pytest.raises(ValueError, match="no VLAN rows"):
        _enrich_vlans_from_sheet(
            _config(), [("vlan_allocations", "VLAN,Name,IP Range\n")])


def test_not_configured_leaves_vlans_unset():
    """No [sheets] vlan_allocations at all: the historical opt-out."""
    config = _config(configured=False)
    _enrich_vlans_from_sheet(config, [])
    assert config.site.vlans == {}
