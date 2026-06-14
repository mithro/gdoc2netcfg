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

        # Reserved settings keys must not leak into the sheet-URL list,
        # and the example's [sheets] creds must parse into SheetsConfig.
        assert set(sheet_names) == {"network", "iot", "vlan_allocations", "sites"}
        assert config.sheets_config.credentials_file == ""
        assert config.sheets_config.token_cache == ".cache/google_oauth_token.json"

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


class TestSheetsConfig:
    def _write(self, tmp_path: Path, body: str) -> Path:
        p = tmp_path / "gdoc2netcfg.toml"
        p.write_text(body)
        return p

    def test_sheets_config_parsed_from_sheets_section(self, tmp_path: Path):
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"

[sheets]
network = "https://example.com/network.csv"
spreadsheet_url = "https://docs.google.com/spreadsheets/d/x/edit"
credentials_file = "client_secret.json"
token_cache = ".cache/tok.json"
service_account_file = "sa.json"
"""))
        assert config.sheets_config.credentials_file == "client_secret.json"
        assert config.sheets_config.token_cache == ".cache/tok.json"
        assert config.sheets_config.service_account_file == "sa.json"

    def test_reserved_keys_are_not_sheet_urls(self, tmp_path: Path):
        """Cred keys in [sheets] must not become SheetConfig entries."""
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"

[sheets]
network = "https://example.com/network.csv"
spreadsheet_url = "https://docs.google.com/spreadsheets/d/x/edit"
credentials_file = "client_secret.json"
token_cache = ".cache/tok.json"
service_account_file = "sa.json"
"""))
        assert [s.name for s in config.sheets] == ["network"]

    def test_sheets_config_defaults(self, tmp_path: Path):
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"
"""))
        assert config.sheets_config.credentials_file == ""
        assert config.sheets_config.token_cache == ".cache/google_oauth_token.json"
        assert config.sheets_config.service_account_file == ""

    def test_zigbee_config_has_no_credential_fields(self):
        import dataclasses

        from gdoc2netcfg.config import ZigbeeConfig
        names = {f.name for f in dataclasses.fields(ZigbeeConfig)}
        assert "credentials_file" not in names
        assert "token_cache" not in names
        assert "service_account_file" not in names


class TestHomeAssistantConfig:
    def _write(self, tmp_path: Path, body: str) -> Path:
        p = tmp_path / "gdoc2netcfg.toml"
        p.write_text(body)
        return p

    def test_mqtt_nested_section_parsed(self, tmp_path: Path):
        """[homeassistant.mqtt] + ssh_host parse onto HomeAssistantConfig."""
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"

[homeassistant]
url = "https://ha.example/"
token = "tok"
ssh_host = "ha.example"

[homeassistant.mqtt]
host = "ha.example"
port = 8883
user = "gdoc2netcfg"
password = "pw"
"""))
        assert config.homeassistant.url == "https://ha.example/"
        assert config.homeassistant.token == "tok"
        assert config.homeassistant.ssh_host == "ha.example"
        assert config.homeassistant.mqtt.host == "ha.example"
        assert config.homeassistant.mqtt.port == 8883
        assert config.homeassistant.mqtt.user == "gdoc2netcfg"
        assert config.homeassistant.mqtt.password == "pw"

    def test_mqtt_defaults(self, tmp_path: Path):
        """Missing [homeassistant.mqtt] / ssh_host fall back to defaults."""
        config = load_config(self._write(tmp_path, """
[site]
name = "test"
domain = "test.example.com"

[homeassistant]
url = "https://ha.example/"
"""))
        assert config.homeassistant.ssh_host == ""
        assert config.homeassistant.mqtt.host == ""
        assert config.homeassistant.mqtt.port == 1883
        assert config.homeassistant.mqtt.user == ""
        assert config.homeassistant.mqtt.password == ""


def test_credentials_db_path():
    from pathlib import Path

    from gdoc2netcfg.config import CacheConfig

    cfg = CacheConfig(directory=Path("/x/.cache"))
    assert cfg.credentials_db_path == Path("/x/.cache/credentials.db")
