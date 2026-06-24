"""Load pipeline configuration from gdoc2netcfg.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

from gdoc2netcfg.models.network import IPv6Prefix, Site


@dataclass
class SheetConfig:
    """Configuration for a single spreadsheet sheet source."""

    name: str
    url: str


@dataclass
class CacheConfig:
    """Configuration for the local cache (flat files and SQLite databases)."""

    directory: Path = field(default_factory=lambda: Path(".cache"))

    @property
    def config_db_path(self) -> Path:
        """Path to the configuration SQLite database."""
        return self.directory / "config.db"

    @property
    def discovery_db_path(self) -> Path:
        """Path to the discovery SQLite database."""
        return self.directory / "discovery.db"

    @property
    def credentials_db_path(self) -> Path:
        """Path to the root-only credential SQLite database."""
        return self.directory / "credentials.db"


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
    """Tasmota per-device MQTT credential derivation ([tasmota]).

    `mqtt_secret` derives each device's MqttUser (`tas-<id>`) and MqttPassword
    (`sha256(secret+<id>)`); the broker stores the pre-hashed form. Replaces the
    #30 interim shared `mqtt_user`/`mqtt_password` static login.
    """

    mqtt_secret: str = ""


@dataclass
class Sensors2mqttConfig:
    """sensors2mqtt credential issuance settings ([sensors2mqtt]).

    `mqtt_secret` derives each `local` collector's broker password; it is also
    mirrored into the Ansible vault so Ansible recomputes the identical value.
    `freshness_seconds` is the `status` stale threshold.
    """

    mqtt_secret: str = ""
    freshness_seconds: int = 900


@dataclass
class ZigbeeConfig:
    """Configuration for Zigbee2MQTT device scanning and sheet updates.

    One Zigbee2MQTT instance per site. The broker connection comes from
    [homeassistant.mqtt]; the site name comes from [site]. Presence of the
    [zigbee] section enables the scan (`enabled`). Sheet credentials live
    in SheetsConfig ([sheets]).
    """

    enabled: bool = False
    sheet_name: str = "Zigbee Info"


@dataclass
class SheetsConfig:
    """Google Sheets write-access credentials, from the [sheets] section.

    OAuth2 (credentials_file + token_cache) or a service account
    (service_account_file). Used by sheet-writing commands.
    """

    credentials_file: str = ""      # OAuth2 client_secret.json path
    token_cache: str = ".cache/google_oauth_token.json"
    service_account_file: str = ""  # Alternative: service account JSON key path


@dataclass
class MqttBrokerConfig:
    """Connection to the Home Assistant Mosquitto broker.

    The single MQTT broker connection shared by every gdoc2netcfg MQTT
    client (the reachability publisher and the zigbee scanner), and the
    host/port that Tasmota devices are pointed at. Lives under
    [homeassistant.mqtt] because the broker is the HA Mosquitto add-on.
    """

    host: str = ""
    port: int = 1883
    user: str = ""
    password: str = ""


@dataclass
class HomeAssistantConfig:
    """Configuration for the Home Assistant integration.

    Covers everything that connects to our Home Assistant: the REST /
    WebSocket API (url + token), its Mosquitto broker
    ([homeassistant.mqtt]), and SSH to its host (ssh_host).
    """

    url: str = ""
    token: str = ""
    dashboard_token: str = ""
    ssh_host: str = ""
    mqtt: MqttBrokerConfig = field(default_factory=MqttBrokerConfig)


@dataclass
class PipelineConfig:
    """Full pipeline configuration loaded from gdoc2netcfg.toml.

    Combines topology configuration (Site) with pipeline operational
    parameters (sheets, cache, generators).
    """

    site: Site
    sheets: list[SheetConfig] = field(default_factory=list)
    spreadsheet_url: str = ""  # Edit URL for write access (from [sheets] spreadsheet_url)
    sheets_config: SheetsConfig = field(default_factory=SheetsConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    generators: dict[str, GeneratorConfig] = field(default_factory=dict)
    tasmota: TasmotaConfig = field(default_factory=TasmotaConfig)
    sensors2mqtt: Sensors2mqttConfig = field(default_factory=Sensors2mqttConfig)
    homeassistant: HomeAssistantConfig = field(default_factory=HomeAssistantConfig)
    zigbee: ZigbeeConfig = field(default_factory=ZigbeeConfig)


def _build_site(data: dict) -> Site:
    """Build a Site from parsed TOML data.

    VLANs, network_subdomains and all_sites are left empty here — they are
    populated later by the pipeline (cli/main.py) from the VLAN Allocations
    and Sites spreadsheet sheets.
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

    return Site(
        name=site_data.get("name", ""),
        domain=site_data.get("domain", ""),
        site_octet=site_data.get("site_octet", 0),
        ipv6_prefixes=ipv6_prefixes,
        public_ipv4=site_data.get("public_ipv4"),
    )


# [sheets] keys that are settings, not sheet-name→URL pairs — derived
# from SheetsConfig so a new field can never be misparsed as a URL.
_RESERVED_SHEET_KEYS = frozenset(
    f.name for f in fields(SheetsConfig)
) | {"spreadsheet_url"}


def _build_sheets(data: dict) -> list[SheetConfig]:
    """Build sheet configs from parsed TOML data.

    Skips reserved settings keys (_RESERVED_SHEET_KEYS).
    """
    sheets = []
    for name, url in data.get("sheets", {}).items():
        if name in _RESERVED_SHEET_KEYS:
            continue
        sheets.append(SheetConfig(name=name, url=url))
    return sheets


def _build_sheets_config(data: dict) -> SheetsConfig:
    """Build sheet write-access credentials from the [sheets] section.

    SheetsConfig's dataclass defaults are the single source of truth —
    only keys present in the TOML override them.
    """
    section = data.get("sheets", {})
    return SheetsConfig(**{
        f.name: section[f.name]
        for f in fields(SheetsConfig)
        if f.name in section
    })


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
    return TasmotaConfig(mqtt_secret=section.get("mqtt_secret", ""))


def _build_sensors2mqtt(data: dict) -> Sensors2mqttConfig:
    """Build sensors2mqtt config from parsed TOML data."""
    section = data.get("sensors2mqtt", {})
    if not section:
        return Sensors2mqttConfig()
    return Sensors2mqttConfig(
        mqtt_secret=section.get("mqtt_secret", ""),
        freshness_seconds=section.get("freshness_seconds", 900),
    )


def _build_zigbee(data: dict) -> ZigbeeConfig:
    """Build Zigbee config from parsed TOML data.

    Presence of the [zigbee] section enables the scan for this site; the
    broker comes from [homeassistant.mqtt] and the site name from [site].
    """
    section = data.get("zigbee", {})
    if not section:
        return ZigbeeConfig()
    return ZigbeeConfig(
        enabled=True,
        sheet_name=section.get("sheet_name", "Zigbee Info"),
    )


def _build_homeassistant(data: dict) -> HomeAssistantConfig:
    """Build Home Assistant config from parsed TOML data."""
    section = data.get("homeassistant", {})
    if not section:
        return HomeAssistantConfig()
    mqtt_section = section.get("mqtt", {})
    return HomeAssistantConfig(
        url=section.get("url", ""),
        token=section.get("token", ""),
        dashboard_token=section.get("dashboard_token", ""),
        ssh_host=section.get("ssh_host", ""),
        mqtt=MqttBrokerConfig(
            host=mqtt_section.get("host", ""),
            port=mqtt_section.get("port", 1883),
            user=mqtt_section.get("user", ""),
            password=mqtt_section.get("password", ""),
        ),
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
        sheets_config=_build_sheets_config(data),
        cache=CacheConfig(
            directory=Path(data.get("cache", {}).get("directory", ".cache")),
        ),
        generators=_build_generators(data),
        tasmota=_build_tasmota(data),
        sensors2mqtt=_build_sensors2mqtt(data),
        homeassistant=_build_homeassistant(data),
        zigbee=_build_zigbee(data),
    )
