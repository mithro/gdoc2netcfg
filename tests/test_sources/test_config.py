"""Tests for configuration loading."""

from pathlib import Path

from gdoc2netcfg.config import load_config


class TestLoadConfig:
    def test_load_project_config(self):
        """Load the example config template from the project root."""
        project_root = Path(__file__).parent.parent.parent
        config_path = project_root / "gdoc2netcfg.toml.example"
        config = load_config(config_path)

        # Site
        assert config.site.name == "welland"
        assert config.site.domain == "welland.mithis.com"
        assert config.site.site_octet == 1

        # VLANs and network_subdomains are empty at config load time —
        # they are populated from the VLAN Allocations sheet in the pipeline.
        assert config.site.vlans == {}
        assert config.site.network_subdomains == {}

        # IPv6 prefixes
        assert len(config.site.ipv6_prefixes) >= 1
        assert config.site.ipv6_prefixes[0].prefix == "2404:e80:a137:"

        # Sheets (now includes vlan_allocations)
        assert len(config.sheets) >= 3
        sheet_names = [s.name for s in config.sheets]
        assert "network" in sheet_names
        assert "iot" in sheet_names
        assert "vlan_allocations" in sheet_names

        # Generators
        assert "dnsmasq_internal" in config.generators
        assert config.generators["dnsmasq_internal"].output_dir == "internal"

    def test_load_minimal_config(self, tmp_path: Path):
        """Load a minimal TOML config."""
        config_file = tmp_path / "test.toml"
        config_file.write_text(
            '[site]\nname = "test"\ndomain = "test.example.com"\nsite_octet = 1\n'
        )
        config = load_config(config_file)

        assert config.site.name == "test"
        assert config.site.domain == "test.example.com"
        assert config.site.site_octet == 1
        assert config.site.vlans == {}
        assert config.sheets == []

    def test_site_octet_default(self, tmp_path: Path):
        """site_octet defaults to 0 if not specified."""
        config_file = tmp_path / "test.toml"
        config_file.write_text(
            '[site]\nname = "test"\ndomain = "test.example.com"\n'
        )
        config = load_config(config_file)
        assert config.site.site_octet == 0


def test_ipv6_capability_config_defaults():
    """IPv6 capability config has sensible defaults when section is missing."""
    from gdoc2netcfg.config import IPv6CapabilityConfig
    config = IPv6CapabilityConfig()
    assert config.incapable_hardware_patterns == []
    assert config.incapable_ouis == []


def test_ipv6_capability_config_from_toml(tmp_path):
    """IPv6 capability config is parsed from [ipv6_capability] section."""
    from gdoc2netcfg.config import load_config
    toml_file = tmp_path / "gdoc2netcfg.toml"
    toml_file.write_text('''
[site]
name = "test"
domain = "test.example.com"
site_octet = 1

[ipv6_capability]
incapable_hardware_patterns = ["Athom.*", "RF_R2"]
incapable_ouis = ["aa:bb:cc"]
''')
    config = load_config(toml_file)
    assert config.ipv6_capability.incapable_hardware_patterns == ["Athom.*", "RF_R2"]
    assert config.ipv6_capability.incapable_ouis == ["aa:bb:cc"]
