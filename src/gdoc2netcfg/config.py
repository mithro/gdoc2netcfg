"""Load pipeline configuration from gdoc2netcfg.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from gdoc2netcfg.models.network import IPv6Prefix, Site


@dataclass
class SheetConfig:
    """Configuration for a single spreadsheet sheet source."""

    name: str
    url: str


@dataclass
class CacheConfig:
    """Configuration for the local CSV cache."""

    directory: Path = field(default_factory=lambda: Path(".cache"))


@dataclass
class GeneratorConfig:
    """Configuration for a single generator.

    Generators produce either a single file (output) or multiple files
    (output_dir). Single-file generators write to 'output'; multi-file
    generators write relative paths under 'output_dir'.
    """

    name: str
    enabled: bool = True
    output: str = ""
    output_dir: str = ""
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class TasmotaConfig:
    """Configuration for Tasmota device management.

    Defines the desired MQTT broker settings that Tasmota devices
    should be configured to use. Used by the configure command to
    compute drift and push correct settings.
    """

    mqtt_host: str = ""
    mqtt_port: int = 1883
    mqtt_user: str = ""
    mqtt_password: str = ""


@dataclass
class ZigbeeSiteConfig:
    """Configuration for a single Zigbee2MQTT site."""

    name: str
    mqtt_host: str = ""
    mqtt_port: int = 1883
    mqtt_user: str = ""
    mqtt_password: str = ""


@dataclass
class ZigbeeConfig:
    """Configuration for Zigbee2MQTT device scanning and sheet updates.

    Supports multiple sites (each with its own MQTT broker).
    Google Sheet credentials can be OAuth2 (default) or service account.
    """

    sites: list[ZigbeeSiteConfig] = field(default_factory=list)
    sheet_name: str = "Zigbee Info"
    credentials_file: str = ""      # OAuth2 client_secret.json path
    token_cache: str = ".cache/google_oauth_token.json"
    service_account_file: str = ""  # Alternative: service account JSON key path


@dataclass
class HomeAssistantConfig:
    """Configuration for Home Assistant integration checks.

    Used by the ha-status command to verify Tasmota devices are
    properly registered and reporting in Home Assistant.
    """

    url: str = ""
    token: str = ""


@dataclass
class PipelineConfig:
    """Full pipeline configuration loaded from gdoc2netcfg.toml.

    Combines topology configuration (Site) with pipeline operational
    parameters (sheets, cache, generators).
    """

    site: Site
    sheets: list[SheetConfig] = field(default_factory=list)
    spreadsheet_url: str = ""  # Edit URL for write access (from [sheets] spreadsheet_url)
    cache: CacheConfig = field(default_factory=CacheConfig)
    generators: dict[str, GeneratorConfig] = field(default_factory=dict)
    tasmota: TasmotaConfig = field(default_factory=TasmotaConfig)
    homeassistant: HomeAssistantConfig = field(default_factory=HomeAssistantConfig)
    zigbee: ZigbeeConfig = field(default_factory=ZigbeeConfig)


def _build_site(data: dict) -> Site:
    """Build a Site from parsed TOML data.

    VLANs and network_subdomains are left empty here — they are
    populated later from the VLAN Allocations spreadsheet sheet
    by the pipeline in cli/main.py.
    """
    site_data = data.get("site", {})

    # Build IPv6 prefixes from [ipv6] section
    ipv6_data = data.get("ipv6", {})
    ipv6_prefixes = [
        IPv6Prefix(prefix=p.strip()) for p in ipv6_data.get("prefixes", [])
    ]
    ipv6_prefixes.extend(
        IPv6Prefix(prefix=p.strip(), enabled=False)
        for p in ipv6_data.get("disabled_prefixes", [])
    )

    all_sites = tuple(s.lower() for s in site_data.get("all_sites", []))

    return Site(
        name=site_data.get("name", ""),
        domain=site_data.get("domain", ""),
        site_octet=site_data.get("site_octet", 0),
        all_sites=all_sites,
        ipv6_prefixes=ipv6_prefixes,
        public_ipv4=site_data.get("public_ipv4"),
    )


def _build_sheets(data: dict) -> list[SheetConfig]:
    """Build sheet configs from parsed TOML data.

    Skips the special 'spreadsheet_url' key (used for write access).
    """
    sheets = []
    for name, url in data.get("sheets", {}).items():
        if name == "spreadsheet_url":
            continue
        sheets.append(SheetConfig(name=name, url=url))
    return sheets


def _build_generators(data: dict) -> dict[str, GeneratorConfig]:
    """Build generator configs from parsed TOML data."""
    generators_section = data.get("generators", {})
    enabled_names = generators_section.get("enabled", [])

    generators: dict[str, GeneratorConfig] = {}
    for name in enabled_names:
        gen_section = generators_section.get(name, {})
        generators[name] = GeneratorConfig(
            name=name,
            enabled=True,
            output=gen_section.get("output", ""),
            output_dir=gen_section.get("output_dir", ""),
            params={
                k: v for k, v in gen_section.items()
                if k not in ("output", "output_dir")
            },
        )
    return generators


def _build_tasmota(data: dict) -> TasmotaConfig:
    """Build Tasmota config from parsed TOML data."""
    section = data.get("tasmota", {})
    if not section:
        return TasmotaConfig()
    return TasmotaConfig(
        mqtt_host=section.get("mqtt_host", ""),
        mqtt_port=section.get("mqtt_port", 1883),
        mqtt_user=section.get("mqtt_user", ""),
        mqtt_password=section.get("mqtt_password", ""),
    )


def _build_zigbee(data: dict) -> ZigbeeConfig:
    """Build Zigbee config from parsed TOML data."""
    section = data.get("zigbee", {})
    if not section:
        return ZigbeeConfig()
    sites = [
        ZigbeeSiteConfig(
            name=s["name"],
            mqtt_host=s.get("mqtt_host", ""),
            mqtt_port=s.get("mqtt_port", 1883),
            mqtt_user=s.get("mqtt_user", ""),
            mqtt_password=s.get("mqtt_password", ""),
        )
        for s in section.get("sites", [])
    ]
    return ZigbeeConfig(
        sites=sites,
        sheet_name=section.get("sheet_name", "Zigbee Info"),
        credentials_file=section.get("credentials_file", ""),
        token_cache=section.get("token_cache", ".cache/google_oauth_token.json"),
        service_account_file=section.get("service_account_file", ""),
    )


def _build_homeassistant(data: dict) -> HomeAssistantConfig:
    """Build Home Assistant config from parsed TOML data."""
    section = data.get("homeassistant", {})
    if not section:
        return HomeAssistantConfig()
    return HomeAssistantConfig(
        url=section.get("url", ""),
        token=section.get("token", ""),
    )


def load_config(config_path: Path | str | None = None) -> PipelineConfig:
    """Load pipeline configuration from a TOML file.

    If config_path is None, looks for gdoc2netcfg.toml in the current
    directory.
    """
    if config_path is None:
        config_path = Path("gdoc2netcfg.toml")
    else:
        config_path = Path(config_path)

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    return PipelineConfig(
        site=_build_site(data),
        sheets=_build_sheets(data),
        spreadsheet_url=data.get("sheets", {}).get("spreadsheet_url", ""),
        cache=CacheConfig(
            directory=Path(data.get("cache", {}).get("directory", ".cache")),
        ),
        generators=_build_generators(data),
        tasmota=_build_tasmota(data),
        homeassistant=_build_homeassistant(data),
        zigbee=_build_zigbee(data),
    )
