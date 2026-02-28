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
class HomeAssistantConfig:
    """Configuration for Home Assistant integration checks.

    Used by the ha-status command to verify Tasmota devices are
    properly registered and reporting in Home Assistant.
    """

    url: str = ""
    token: str = ""


@dataclass
class IPv6CapabilityConfig:
    """Configuration for IPv6 capability detection.

    Controls which devices are detected as IPv6-incapable based on
    hardware column regex patterns and MAC OUI prefixes.
    """

    incapable_hardware_patterns: list[str] = field(default_factory=list)
    incapable_ouis: list[str] = field(default_factory=list)


@dataclass
class PipelineConfig:
    """Full pipeline configuration loaded from gdoc2netcfg.toml.

    Combines topology configuration (Site) with pipeline operational
    parameters (sheets, cache, generators).
    """

    site: Site
    sheets: list[SheetConfig] = field(default_factory=list)
    cache: CacheConfig = field(default_factory=CacheConfig)
    generators: dict[str, GeneratorConfig] = field(default_factory=dict)
    tasmota: TasmotaConfig = field(default_factory=TasmotaConfig)
    homeassistant: HomeAssistantConfig = field(default_factory=HomeAssistantConfig)
    ipv6_capability: IPv6CapabilityConfig = field(default_factory=IPv6CapabilityConfig)


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
    """Build sheet configs from parsed TOML data."""
    sheets = []
    for name, url in data.get("sheets", {}).items():
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


def _build_homeassistant(data: dict) -> HomeAssistantConfig:
    """Build Home Assistant config from parsed TOML data."""
    section = data.get("homeassistant", {})
    if not section:
        return HomeAssistantConfig()
    return HomeAssistantConfig(
        url=section.get("url", ""),
        token=section.get("token", ""),
    )


def _build_ipv6_capability(data: dict) -> IPv6CapabilityConfig:
    """Build IPv6 capability config from parsed TOML data."""
    section = data.get("ipv6_capability", {})
    if not section:
        return IPv6CapabilityConfig()
    return IPv6CapabilityConfig(
        incapable_hardware_patterns=list(section.get("incapable_hardware_patterns", [])),
        incapable_ouis=list(section.get("incapable_ouis", [])),
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
        cache=CacheConfig(
            directory=Path(data.get("cache", {}).get("directory", ".cache")),
        ),
        generators=_build_generators(data),
        tasmota=_build_tasmota(data),
        homeassistant=_build_homeassistant(data),
        ipv6_capability=_build_ipv6_capability(data),
    )
