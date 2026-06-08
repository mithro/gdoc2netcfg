"""Tests for wiring Site.all_sites from the Sites sheet (cli/main helpers)."""

from gdoc2netcfg.cli.main import _enrich_all_sites_from_sheet
from gdoc2netcfg.config import PipelineConfig
from gdoc2netcfg.models.network import Site

SITES_CSV = (
    "Domain,Shortname,Public IPv4,Private IPv4,IPv6\n"
    "welland.mithis.com,welland,87.121.95.37,10.1.X.X,2404:e80:a137::/48\n"
    "ten64.welland.mithis.com,ten64.welland,,,2404:e80:a137:01::/56\n"
    "monarto.mithis.com,monarto,,10.2.X.X,\n"
    ",special,,,\n"
    "ps1.mithis.com,ps1,,,\n"
)


def _config(all_sites):
    return PipelineConfig(
        site=Site(name="welland", domain="welland.mithis.com", all_sites=all_sites)
    )


def test_sheet_overrides_toml_all_sites():
    config = _config(("welland", "monarto", "ps1"))
    _enrich_all_sites_from_sheet(config, [("sites", SITES_CSV)])
    # 'special' now valid; 'ten64.welland' (a host allocation) excluded.
    assert config.site.all_sites == ("welland", "monarto", "special", "ps1")


def test_absent_sheet_keeps_toml_fallback():
    config = _config(("welland", "monarto"))
    _enrich_all_sites_from_sheet(config, [("vlan_allocations", "x")])
    assert config.site.all_sites == ("welland", "monarto")


def test_empty_sheet_keeps_toml_fallback():
    config = _config(("welland", "monarto"))
    _enrich_all_sites_from_sheet(config, [("sites", "Domain,Shortname\n")])
    assert config.site.all_sites == ("welland", "monarto")
