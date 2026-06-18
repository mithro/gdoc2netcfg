"""_build_hosts_from_csvs excludes non-device sheets by name.

The VLAN Allocations and Sites tabs are not device-record sources.  A single
``_NON_DEVICE_SHEETS`` set drives the skip in both ``_build_hosts_from_csvs``
and ``_build_pipeline``, so those tabs are never parsed as devices and the two
builders cannot drift apart.
"""

from gdoc2netcfg.cli.main import _build_hosts_from_csvs
from gdoc2netcfg.config import CacheConfig, PipelineConfig
from gdoc2netcfg.models.network import Site


def _config(tmp_path) -> PipelineConfig:
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    return PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=cache_dir),
    )


def test_realistic_sites_and_vlan_sheets_contribute_no_hosts(tmp_path):
    config = _config(tmp_path)
    csv_data = [
        ("network",
         "Machine,MAC Address,IP,Interface\n"
         "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"),
        ("sites",
         "Shortname,Domain,Octet\n"
         "welland,welland.example.com,1\n"),
        ("vlan_allocations",
         "VLAN,Name,Subdomain\n10,int,int\n30,net,net\n"),
    ]
    hosts = _build_hosts_from_csvs(config, csv_data)
    assert {h.hostname for h in hosts} == {"switch1"}


def test_sites_sheet_skipped_by_name_even_with_device_columns(tmp_path):
    """The Sites tab is excluded by name, not by content: even if it happens
    to carry Machine/MAC/IP columns its rows must not become hosts (guards the
    skip, which a downstream empty-field filter would otherwise mask)."""
    config = _config(tmp_path)
    csv_data = [
        ("network",
         "Machine,MAC Address,IP,Interface\n"
         "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"),
        ("sites",
         "Machine,MAC Address,IP,Interface\n"
         "bogus,aa:bb:cc:dd:ee:99,10.1.30.99,\n"),
    ]
    hosts = _build_hosts_from_csvs(config, csv_data)
    hostnames = {h.hostname for h in hosts}
    assert "bogus" not in hostnames
    assert hostnames == {"switch1"}
