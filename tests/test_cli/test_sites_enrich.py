"""Tests for wiring Site.all_sites from the Sites sheet (cli/main helpers)."""

import pytest

from gdoc2netcfg.cli.main import _enrich_all_sites_from_sheet
from gdoc2netcfg.config import PipelineConfig, SheetConfig
from gdoc2netcfg.models.network import Site

SITES_CSV = (
    "Domain,Shortname,Public IPv4,Private IPv4,IPv6\n"
    "welland.mithis.com,welland,87.121.95.37,10.1.X.X,2404:e80:a137::/48\n"
    "ten64.welland.mithis.com,ten64.welland,,,2404:e80:a137:01::/56\n"
    "monarto.mithis.com,monarto,,10.2.X.X,\n"
    ",special,,,\n"
    "ps1.mithis.com,ps1,,,\n"
)


def _config(sites_configured=False):
    # all_sites is no longer in the TOML; the Sites sheet is the source.
    sheets = [SheetConfig(name="sites", url="https://x")] if sites_configured else []
    return PipelineConfig(
        site=Site(name="welland", domain="welland.mithis.com"), sheets=sheets
    )


def test_sets_all_sites_from_sheet():
    config = _config()
    _enrich_all_sites_from_sheet(config, [("sites", SITES_CSV)])
    # 'special' is valid; 'ten64.welland' (a host allocation) is excluded.
    assert config.site.all_sites == ("welland", "monarto", "special", "ps1")


def test_not_configured_skips_quietly():
    # No 'sites' under [sheets]: optional opt-out, all_sites left empty, no raise.
    config = _config(sites_configured=False)
    _enrich_all_sites_from_sheet(config, [("vlan_allocations", "x")])
    assert config.site.all_sites == ()


def test_configured_but_unavailable_raises():
    # 'sites' under [sheets] but absent from the fetched data -> hard error.
    config = _config(sites_configured=True)
    with pytest.raises(ValueError, match="unavailable"):
        _enrich_all_sites_from_sheet(config, [("vlan_allocations", "x")])


def test_empty_sheet_raises():
    config = _config()
    with pytest.raises(ValueError, match="no valid site rows"):
        _enrich_all_sites_from_sheet(config, [("sites", "Domain,Shortname\n")])
