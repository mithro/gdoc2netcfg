"""Tests for the Tasmota supplement modules (scan, configure, HA status)."""

from unittest.mock import MagicMock, patch

import pytest

from gdoc2netcfg.cli.main import main
from gdoc2netcfg.config import HomeAssistantConfig, TasmotaConfig
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, TasmotaData
from gdoc2netcfg.supplements.tasmota import (
    _UNKNOWN_PREFIX,
    _parse_tasmota_status,
    _unknown_key,
    enrich_hosts_with_tasmota,
    load_tasmota_cache,
    match_unknown_devices,
    save_tasmota_cache,
)
from gdoc2netcfg.supplements.tasmota_configure import (
    ConfigDrift,
    _get_current_value,
    compute_desired_config,
    compute_drift,
    configure_all_tasmota_devices,
    configure_tasmota_device,
)
from gdoc2netcfg.supplements.tasmota_ha import (
    _entity_id_for_host,
    check_ha_status,
)

# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

def _make_host(
    hostname="au-plug-10",
    ip="10.1.90.10",
    mac="aa:bb:cc:dd:ee:10",
    sheet_type="IoT",
    extra=None,
):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        sheet_type=sheet_type,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse(mac),
                ip_addresses=(IPv4Address(ip),),
                dhcp_name=hostname,
            ),
        ],
        extra=extra or {},
    )


def _make_tasmota_data(**overrides):
    """Build a TasmotaData with reasonable defaults for testing."""
    defaults = {
        "device_name": "au-plug-10",
        "friendly_name": "Tasmota",
        "hostname": "au-plug-10",
        "firmware_version": "14.4.1(tasmota)",
        "mqtt_host": "ha.welland.mithis.com",
        "mqtt_port": 1883,
        "mqtt_topic": "au-plug-10",
        "mqtt_client": "DVES_AABBCC",
        "mqtt_user": "tasmota",
        "mac": "AA:BB:CC:DD:EE:10",
        "ip": "10.1.90.10",
        "wifi_ssid": "IoT-Net",
        "wifi_rssi": 72,
        "wifi_signal": -58,
        "uptime": "3T12:34:56",
        "module": "Sonoff Basic",
    }
    defaults.update(overrides)
    return TasmotaData(**defaults)


def _make_tasmota_config(**overrides):
    defaults = {
        "mqtt_host": "ha.welland.mithis.com",
        "mqtt_port": 1883,
        "mqtt_user": "tasmota",
        "mqtt_password": "secret123",
    }
    defaults.update(overrides)
    return TasmotaConfig(**defaults)


# A realistic Tasmota Status 0 JSON response
SAMPLE_STATUS_0 = {
    "Status": {
        "Module": 1,
        "DeviceName": "au-plug-10",
        "FriendlyName": ["Tasmota"],
        "Topic": "au-plug-10",
        "ButtonTopic": "0",
        "Power": 1,
        "PowerOnState": 3,
        "LedState": 1,
        "LedMask": "FFFF",
        "SaveData": 1,
        "SaveState": 1,
        "SwitchTopic": "0",
        "SwitchMode": [0],
        "ButtonRetain": 0,
        "SwitchRetain": 0,
        "SensorRetain": 0,
        "PowerRetain": 0,
        "InfoRetain": 0,
        "StateRetain": 0,
    },
    "StatusPRM": {"Baudrate": 115200, "SerialConfig": "8N1"},
    "StatusFWR": {
        "Version": "14.4.1(tasmota)",
        "BuildDateTime": "2024-12-15T10:30:00",
        "Boot": 31,
        "Core": "2_7_4_9",
        "SDK": "2.2.2-dev(38a443e)",
        "CpuFrequency": 80,
        "Hardware": "ESP8266EX",
    },
    "StatusNET": {
        "Hostname": "au-plug-10",
        "IPAddress": "10.1.90.10",
        "Gateway": "10.1.90.1",
        "Subnetmask": "255.255.255.0",
        "DNSServer1": "10.1.10.1",
        "DNSServer2": "0.0.0.0",
        "Mac": "AA:BB:CC:DD:EE:10",
        "Webserver": 2,
        "WifiConfig": 2,
        "WifiPower": 17.0,
    },
    "StatusMQT": {
        "MqttHost": "ha.welland.mithis.com",
        "MqttPort": 1883,
        "MqttClientMask": "DVES_%06X",
        "MqttClient": "DVES_AABBCC",
        "MqttUser": "tasmota",
        "MAX_PACKET_SIZE": 1200,
        "KEEPALIVE": 30,
        "SOCKET_TIMEOUT": 4,
    },
    "StatusSTS": {
        "Time": "2025-01-15T14:30:00",
        "Uptime": "3T12:34:56",
        "UptimeSec": 303296,
        "Heap": 25,
        "SleepMode": "Dynamic",
        "Sleep": 50,
        "LoadAvg": 19,
        "MqttCount": 1,
        "POWER": "ON",
        "Wifi": {
            "AP": 1,
            "SSId": "IoT-Net",
            "BSSId": "AA:BB:CC:DD:EE:01",
            "Channel": 6,
            "Mode": "11n",
            "RSSI": 72,
            "Signal": -58,
            "LinkCount": 1,
            "Downtime": "0T00:00:03",
        },
    },
}


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------

class TestTasmotaCLIRegistration:
    def test_tasmota_subcommand_in_help(self, capsys):
        try:
            main(["tasmota", "--help"])
        except SystemExit as e:
            assert e.code == 0
        captured = capsys.readouterr()
        assert "tasmota" in captured.out.lower()

    def test_tasmota_scan_in_help(self, capsys):
        try:
            main(["tasmota", "scan", "--help"])
        except SystemExit as e:
            assert e.code == 0
        captured = capsys.readouterr()
        assert "force" in captured.out.lower()

    def test_tasmota_configure_in_help(self, capsys):
        try:
            main(["tasmota", "configure", "--help"])
        except SystemExit as e:
            assert e.code == 0
        captured = capsys.readouterr()
        assert "dry-run" in captured.out.lower()

    def test_tasmota_ha_status_in_help(self, capsys):
        try:
            main(["tasmota", "ha-status", "--help"])
        except SystemExit as e:
            assert e.code == 0
        captured = capsys.readouterr()
        assert "home assistant" in captured.out.lower() or "ha" in captured.out.lower()


# ---------------------------------------------------------------------------
# TasmotaData model
# ---------------------------------------------------------------------------

class TestTasmotaDataModel:
    def test_frozen(self):
        td = _make_tasmota_data()
        with pytest.raises(AttributeError):
            td.device_name = "changed"

    def test_defaults(self):
        td = TasmotaData(
            device_name="test",
            friendly_name="Test",
            hostname="test",
            firmware_version="1.0",
            mqtt_host="broker",
            mqtt_port=1883,
            mqtt_topic="test",
            mqtt_client="client",
            mac="AA:BB:CC:DD:EE:FF",
            ip="10.1.90.1",
        )
        assert td.wifi_ssid == ""
        assert td.wifi_rssi == 0
        assert td.wifi_signal == 0
        assert td.uptime == ""
        assert td.module == ""
        assert td.controls == ()

    def test_controls_tuple(self):
        td = _make_tasmota_data(controls=("desktop", "monitor"))
        assert td.controls == ("desktop", "monitor")


# ---------------------------------------------------------------------------
# _unknown_key helper
# ---------------------------------------------------------------------------

class TestUnknownKey:
    def test_unknown_key(self):
        assert _unknown_key("10.1.90.50") == "_unknown/10.1.90.50"

    def test_prefix_constant(self):
        assert _UNKNOWN_PREFIX == "_unknown/"


# ---------------------------------------------------------------------------
# _parse_tasmota_status
# ---------------------------------------------------------------------------

class TestParseTasmotaStatus:
    def test_full_status_0(self):
        result = _parse_tasmota_status(SAMPLE_STATUS_0)
        assert result["device_name"] == "au-plug-10"
        assert result["friendly_name"] == "Tasmota"
        assert result["hostname"] == "au-plug-10"
        assert result["firmware_version"] == "14.4.1(tasmota)"
        assert result["mqtt_host"] == "ha.welland.mithis.com"
        assert result["mqtt_port"] == 1883
        assert result["mqtt_topic"] == "au-plug-10"
        assert result["mqtt_client"] == "DVES_AABBCC"
        assert result["mac"] == "AA:BB:CC:DD:EE:10"
        assert result["ip"] == "10.1.90.10"
        assert result["wifi_ssid"] == "IoT-Net"
        assert result["wifi_rssi"] == 72
        assert result["wifi_signal"] == -58
        assert result["uptime"] == "3T12:34:56"

    def test_friendly_name_as_string(self):
        """Some firmware versions return FriendlyName as a string."""
        data = {"Status": {"FriendlyName": "My Plug"}}
        result = _parse_tasmota_status(data)
        assert result["friendly_name"] == "My Plug"

    def test_friendly_name_as_list(self):
        data = {"Status": {"FriendlyName": ["Plug 1", "Plug 2"]}}
        result = _parse_tasmota_status(data)
        assert result["friendly_name"] == "Plug 1"

    def test_friendly_name_empty_list(self):
        data = {"Status": {"FriendlyName": []}}
        result = _parse_tasmota_status(data)
        assert result["friendly_name"] == ""

    def test_missing_sections(self):
        """Empty dict should produce defaults for all fields."""
        result = _parse_tasmota_status({})
        assert result["device_name"] == ""
        assert result["mqtt_host"] == ""
        assert result["mqtt_port"] == 1883
        assert result["wifi_rssi"] == 0
        assert result["uptime"] == ""

    def test_module_field(self):
        data = {"Status": {"Module": "Shelly 1"}}
        result = _parse_tasmota_status(data)
        assert result["module"] == "Shelly 1"


# ---------------------------------------------------------------------------
# _fetch_tasmota_status
# ---------------------------------------------------------------------------

class TestFetchTasmotaStatus:
    @patch("gdoc2netcfg.supplements.tasmota.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        import json
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(SAMPLE_STATUS_0).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from gdoc2netcfg.supplements.tasmota import _fetch_tasmota_status

        result = _fetch_tasmota_status("10.1.90.10")
        assert result is not None
        assert result["Status"]["DeviceName"] == "au-plug-10"

    @patch("gdoc2netcfg.supplements.tasmota.urllib.request.urlopen")
    def test_timeout_returns_none(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("timeout")

        from gdoc2netcfg.supplements.tasmota import _fetch_tasmota_status

        result = _fetch_tasmota_status("10.1.90.99")
        assert result is None

    @patch("gdoc2netcfg.supplements.tasmota.urllib.request.urlopen")
    def test_invalid_json_returns_none_with_warning(self, mock_urlopen, capsys):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"<html>Not Tasmota</html>"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from gdoc2netcfg.supplements.tasmota import _fetch_tasmota_status

        result = _fetch_tasmota_status("10.1.90.50")
        assert result is None
        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "10.1.90.50" in captured.err

    @patch("gdoc2netcfg.supplements.tasmota.urllib.request.urlopen")
    def test_connection_refused_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = OSError("Connection refused")

        from gdoc2netcfg.supplements.tasmota import _fetch_tasmota_status

        result = _fetch_tasmota_status("10.1.90.1")
        assert result is None


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------

class TestTasmotaCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_tasmota_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "tasmota.json"
        data = {
            "au-plug-10": {
                "device_name": "au-plug-10",
                "mac": "AA:BB:CC:DD:EE:10",
                "ip": "10.1.90.10",
                "firmware_version": "14.4.1",
            },
            "_unknown/10.1.90.50": {
                "device_name": "rogue",
                "mac": "FF:FF:FF:00:00:01",
                "ip": "10.1.90.50",
            },
        }
        save_tasmota_cache(cache_path, data)
        loaded = load_tasmota_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "deep" / "tasmota.json"
        save_tasmota_cache(cache_path, {"host": {"ip": "1.2.3.4"}})
        assert cache_path.exists()

    def test_save_sorted_keys(self, tmp_path):
        cache_path = tmp_path / "tasmota.json"
        data = {"zebra": {"ip": "1"}, "alpha": {"ip": "2"}}
        save_tasmota_cache(cache_path, data)
        content = cache_path.read_text()
        assert content.index("alpha") < content.index("zebra")


# ---------------------------------------------------------------------------
# enrich_hosts_with_tasmota
# ---------------------------------------------------------------------------

class TestEnrichHostsWithTasmota:
    def test_enrich_from_cache(self):
        host = _make_host()
        cache = {
            "au-plug-10": {
                "device_name": "au-plug-10",
                "friendly_name": "Tasmota",
                "hostname": "au-plug-10",
                "firmware_version": "14.4.1",
                "mqtt_host": "broker",
                "mqtt_port": 1883,
                "mqtt_topic": "au-plug-10",
                "mqtt_client": "DVES_AABBCC",
                "mac": "AA:BB:CC:DD:EE:10",
                "ip": "10.1.90.10",
            },
        }
        enrich_hosts_with_tasmota([host], cache)
        assert host.tasmota_data is not None
        assert host.tasmota_data.device_name == "au-plug-10"
        assert host.tasmota_data.firmware_version == "14.4.1"
        assert host.tasmota_data.mqtt_host == "broker"

    def test_no_cache_entry_leaves_none(self):
        host = _make_host()
        enrich_hosts_with_tasmota([host], {})
        assert host.tasmota_data is None

    def test_unknown_entries_ignored(self):
        """_unknown/{ip} entries should not match any host."""
        host = _make_host()
        cache = {"_unknown/10.1.90.50": {"device_name": "rogue", "ip": "10.1.90.50"}}
        enrich_hosts_with_tasmota([host], cache)
        assert host.tasmota_data is None

    def test_controls_parsed_from_extra(self):
        host = _make_host(extra={"Controls": "desktop, monitor, server"})
        cache = {
            "au-plug-10": {
                "device_name": "au-plug-10",
                "friendly_name": "Tasmota",
                "hostname": "au-plug-10",
                "firmware_version": "14.4.1",
                "mqtt_host": "broker",
                "mqtt_port": 1883,
                "mqtt_topic": "au-plug-10",
                "mqtt_client": "X",
                "mac": "AA:BB:CC:DD:EE:10",
                "ip": "10.1.90.10",
            },
        }
        enrich_hosts_with_tasmota([host], cache)
        assert host.tasmota_data is not None
        assert host.tasmota_data.controls == ("desktop", "monitor", "server")

    def test_controls_with_newlines(self):
        host = _make_host(extra={"Controls": "desktop\nmonitor\r\nserver"})
        cache = {
            "au-plug-10": _min_cache_entry(),
        }
        enrich_hosts_with_tasmota([host], cache)
        assert host.tasmota_data is not None
        assert host.tasmota_data.controls == ("desktop", "monitor", "server")

    def test_controls_empty_string(self):
        host = _make_host(extra={"Controls": ""})
        cache = {
            "au-plug-10": {
                "device_name": "x",
                "friendly_name": "x",
                "hostname": "x",
                "firmware_version": "x",
                "mqtt_host": "x",
                "mqtt_port": 1883,
                "mqtt_topic": "x",
                "mqtt_client": "x",
                "mac": "x",
                "ip": "x",
            },
        }
        enrich_hosts_with_tasmota([host], cache)
        assert host.tasmota_data.controls == ()

    def test_controls_no_controls_key(self):
        host = _make_host(extra={})
        cache = {
            "au-plug-10": {
                "device_name": "x",
                "friendly_name": "x",
                "hostname": "x",
                "firmware_version": "x",
                "mqtt_host": "x",
                "mqtt_port": 1883,
                "mqtt_topic": "x",
                "mqtt_client": "x",
                "mac": "x",
                "ip": "x",
            },
        }
        enrich_hosts_with_tasmota([host], cache)
        assert host.tasmota_data.controls == ()

    def test_enrich_defaults_for_missing_fields(self):
        """Cache entries with only some fields should use defaults."""
        host = _make_host()
        cache = {
            "au-plug-10": {
                "device_name": "plug",
                "friendly_name": "Plug",
                "hostname": "plug",
                "firmware_version": "1.0",
                "mqtt_host": "broker",
                "mqtt_port": 1883,
                "mqtt_topic": "plug",
                "mqtt_client": "c",
                "mac": "AA:BB:CC:DD:EE:10",
                "ip": "10.1.90.10",
                # wifi_ssid, wifi_rssi, wifi_signal, uptime, module omitted
            },
        }
        enrich_hosts_with_tasmota([host], cache)
        assert host.tasmota_data.wifi_ssid == ""
        assert host.tasmota_data.wifi_rssi == 0
        assert host.tasmota_data.uptime == ""
        assert host.tasmota_data.module == ""

    def test_multiple_hosts(self):
        h1 = _make_host(hostname="plug-1", ip="10.1.90.1", mac="aa:bb:cc:dd:ee:01")
        h2 = _make_host(hostname="plug-2", ip="10.1.90.2", mac="aa:bb:cc:dd:ee:02")
        h3 = _make_host(hostname="plug-3", ip="10.1.90.3", mac="aa:bb:cc:dd:ee:03")
        cache = {
            "plug-1": _min_cache_entry(),
            "plug-3": _min_cache_entry(),
        }
        enrich_hosts_with_tasmota([h1, h2, h3], cache)
        assert h1.tasmota_data is not None
        assert h2.tasmota_data is None
        assert h3.tasmota_data is not None


def _min_cache_entry():
    """Minimal cache entry with all required fields."""
    return {
        "device_name": "x",
        "friendly_name": "x",
        "hostname": "x",
        "firmware_version": "x",
        "mqtt_host": "x",
        "mqtt_port": 1883,
        "mqtt_topic": "x",
        "mqtt_client": "x",
        "mac": "x",
        "ip": "x",
    }


# ---------------------------------------------------------------------------
# match_unknown_devices
# ---------------------------------------------------------------------------

class TestMatchUnknownDevices:
    def test_match_by_mac(self):
        host = _make_host(mac="aa:bb:cc:dd:ee:10")
        cache = {
            "au-plug-10": {"device_name": "known"},
            "_unknown/10.1.90.50": {
                "device_name": "rogue",
                "mac": "AA:BB:CC:DD:EE:10",
            },
        }
        matches = match_unknown_devices([host], cache)
        assert len(matches) == 1
        assert matches[0] == ("10.1.90.50", "au-plug-10")

    def test_no_match(self):
        host = _make_host(mac="aa:bb:cc:dd:ee:10")
        cache = {
            "_unknown/10.1.90.50": {
                "device_name": "rogue",
                "mac": "FF:FF:FF:00:00:01",
            },
        }
        matches = match_unknown_devices([host], cache)
        assert len(matches) == 1
        assert matches[0] == ("10.1.90.50", None)

    def test_no_unknowns(self):
        host = _make_host()
        cache = {"au-plug-10": {"device_name": "known"}}
        matches = match_unknown_devices([host], cache)
        assert matches == []

    def test_multiple_unknowns_sorted(self):
        host = _make_host()
        cache = {
            "_unknown/10.1.90.99": {"mac": "11:22:33:44:55:66"},
            "_unknown/10.1.90.50": {"mac": "FF:FF:FF:00:00:01"},
        }
        matches = match_unknown_devices([host], cache)
        assert len(matches) == 2
        # Sorted by key, so .50 comes before .99
        assert matches[0][0] == "10.1.90.50"
        assert matches[1][0] == "10.1.90.99"


# ---------------------------------------------------------------------------
# scan_tasmota (mocked network)
# ---------------------------------------------------------------------------

class TestScanTasmota:
    @patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_scan_known_hosts(self, mock_fetch, mock_sweep, tmp_path):
        from gdoc2netcfg.models.network import VLAN, Site

        mock_fetch.return_value = SAMPLE_STATUS_0
        mock_sweep.return_value = {}

        host = _make_host()
        site = Site(
            name="welland",
            domain="welland.mithis.com",
            site_octet=1,
            vlans={90: VLAN(id=90, name="iot", subdomain="iot")},
        )

        from gdoc2netcfg.supplements.tasmota import scan_tasmota

        cache_path = tmp_path / "tasmota.json"
        result = scan_tasmota([host], cache_path, site, force=True)

        assert "au-plug-10" in result
        assert result["au-plug-10"]["device_name"] == "au-plug-10"
        assert cache_path.exists()

    @patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_scan_discovers_unknown(self, mock_fetch, mock_sweep, tmp_path):
        from gdoc2netcfg.models.network import VLAN, Site

        mock_fetch.return_value = None  # Known host offline
        mock_sweep.return_value = {
            "10.1.90.50": {
                "device_name": "rogue",
                "mac": "FF:FF:FF:00:00:01",
                "ip": "10.1.90.50",
            },
        }

        host = _make_host()
        site = Site(
            name="welland",
            domain="welland.mithis.com",
            site_octet=1,
            vlans={90: VLAN(id=90, name="iot", subdomain="iot")},
        )

        from gdoc2netcfg.supplements.tasmota import scan_tasmota

        cache_path = tmp_path / "tasmota.json"
        result = scan_tasmota([host], cache_path, site, force=True)

        assert "_unknown/10.1.90.50" in result
        assert result["_unknown/10.1.90.50"]["device_name"] == "rogue"

    @patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_scan_skips_known_ip_in_sweep(self, mock_fetch, mock_sweep, tmp_path):
        """If a known host's IP appears in the sweep, don't duplicate it as _unknown."""
        from gdoc2netcfg.models.network import VLAN, Site

        mock_fetch.return_value = SAMPLE_STATUS_0
        # Sweep also finds the same IP
        mock_sweep.return_value = {
            "10.1.90.10": {"device_name": "au-plug-10", "ip": "10.1.90.10"},
        }

        host = _make_host()
        site = Site(
            name="welland",
            domain="welland.mithis.com",
            site_octet=1,
            vlans={90: VLAN(id=90, name="iot", subdomain="iot")},
        )

        from gdoc2netcfg.supplements.tasmota import scan_tasmota

        cache_path = tmp_path / "tasmota.json"
        result = scan_tasmota([host], cache_path, site, force=True)

        assert "au-plug-10" in result
        assert "_unknown/10.1.90.10" not in result

    @patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_scan_uses_cache_when_fresh(self, mock_fetch, mock_sweep, tmp_path):
        from gdoc2netcfg.models.network import Site
        from gdoc2netcfg.supplements.tasmota import save_tasmota_cache, scan_tasmota

        # Pre-populate cache
        cache_path = tmp_path / "tasmota.json"
        existing = {"old-plug": {"device_name": "old"}}
        save_tasmota_cache(cache_path, existing)

        site = Site(name="welland", domain="welland.mithis.com", site_octet=1)
        result = scan_tasmota([], cache_path, site, force=False, max_age=9999)

        # Should return cached data without scanning
        assert result == existing
        mock_fetch.assert_not_called()
        mock_sweep.assert_not_called()

    @patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_scan_skips_non_iot_hosts(self, mock_fetch, mock_sweep, tmp_path):
        from gdoc2netcfg.models.network import VLAN, Site

        mock_sweep.return_value = {}

        host = _make_host(sheet_type="Network")  # Not IoT
        site = Site(
            name="welland",
            domain="welland.mithis.com",
            site_octet=1,
            vlans={90: VLAN(id=90, name="iot", subdomain="iot")},
        )

        from gdoc2netcfg.supplements.tasmota import scan_tasmota

        cache_path = tmp_path / "tasmota.json"
        scan_tasmota([host], cache_path, site, force=True)

        # Network host should not be probed
        mock_fetch.assert_not_called()

    @patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_force_clears_stale_unknowns(self, mock_fetch, mock_sweep, tmp_path):
        """Forced rescan should clear stale _unknown/ entries before re-sweeping."""
        from gdoc2netcfg.models.network import VLAN, Site
        from gdoc2netcfg.supplements.tasmota import save_tasmota_cache, scan_tasmota

        # Pre-populate cache with a stale _unknown entry
        cache_path = tmp_path / "tasmota.json"
        save_tasmota_cache(cache_path, {
            "known-plug": {"device_name": "known"},
            "_unknown/10.1.90.99": {"device_name": "stale-rogue", "ip": "10.1.90.99"},
        })

        mock_fetch.return_value = None
        mock_sweep.return_value = {}  # Sweep finds nothing

        site = Site(
            name="welland",
            domain="welland.mithis.com",
            site_octet=1,
            vlans={90: VLAN(id=90, name="iot", subdomain="iot")},
        )

        result = scan_tasmota([], cache_path, site, force=True)

        # Known entries preserved, stale _unknown/ cleared
        assert "known-plug" in result
        assert "_unknown/10.1.90.99" not in result

    @patch("gdoc2netcfg.supplements.tasmota._scan_subnet")
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_scan_no_iot_vlan(self, mock_fetch, mock_sweep, tmp_path):
        """When site has no 'iot' VLAN, phase 2 sweep is skipped."""
        from gdoc2netcfg.models.network import Site

        mock_fetch.return_value = SAMPLE_STATUS_0

        host = _make_host()
        site = Site(name="welland", domain="welland.mithis.com", site_octet=1)

        from gdoc2netcfg.supplements.tasmota import scan_tasmota

        cache_path = tmp_path / "tasmota.json"
        scan_tasmota([host], cache_path, site, force=True)

        mock_sweep.assert_not_called()


# ---------------------------------------------------------------------------
# _scan_subnet (mocked network)
# ---------------------------------------------------------------------------

class TestScanSubnet:
    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_finds_responding_hosts(self, mock_fetch):
        def side_effect(ip, timeout):
            if ip == "10.1.90.10":
                return SAMPLE_STATUS_0
            return None

        mock_fetch.side_effect = side_effect

        from gdoc2netcfg.supplements.tasmota import _scan_subnet

        result = _scan_subnet("10.1.90.", max_workers=4)
        assert "10.1.90.10" in result
        assert result["10.1.90.10"]["device_name"] == "au-plug-10"
        # All 254 IPs were probed
        assert mock_fetch.call_count == 254

    @patch("gdoc2netcfg.supplements.tasmota._fetch_tasmota_status")
    def test_empty_subnet(self, mock_fetch):
        mock_fetch.return_value = None

        from gdoc2netcfg.supplements.tasmota import _scan_subnet

        result = _scan_subnet("10.1.90.", max_workers=4)
        assert result == {}


# ---------------------------------------------------------------------------
# ConfigDrift model
# ---------------------------------------------------------------------------

class TestConfigDrift:
    def test_frozen(self):
        drift = ConfigDrift(field="DeviceName", current="old", desired="new")
        with pytest.raises(AttributeError):
            drift.field = "changed"

    def test_fields(self):
        drift = ConfigDrift(field="MqttHost", current="old.host", desired="new.host")
        assert drift.field == "MqttHost"
        assert drift.current == "old.host"
        assert drift.desired == "new.host"


# ---------------------------------------------------------------------------
# compute_desired_config
# ---------------------------------------------------------------------------

class TestComputeDesiredConfig:
    def test_basic(self):
        host = _make_host(hostname="au-plug-10")
        config = _make_tasmota_config()
        desired = compute_desired_config(host, config)

        # FriendlyName = machine name (→ HA entity ID basis)
        # DeviceName = machine name when no controls (→ HA device display name)
        assert desired["FriendlyName1"] == "au-plug-10"
        assert desired["DeviceName"] == "au-plug-10"
        assert desired["Hostname"] == "au-plug-10"
        assert desired["Topic"] == "au-plug-10"
        assert desired["MqttHost"] == "ha.welland.mithis.com"
        assert desired["MqttPort"] == "1883"
        assert desired["MqttUser"] == "tasmota"
        assert desired["MqttPassword"] == "secret123"

    def test_friendly_name_always_machine_name(self):
        """FriendlyName is always machine_name for predictable HA entity IDs."""
        host = _make_host(hostname="au-plug-10", extra={"Controls": "desktop"})
        config = _make_tasmota_config()
        desired = compute_desired_config(host, config)
        assert desired["FriendlyName1"] == "au-plug-10"

    def test_device_name_with_controls(self):
        """DeviceName uses human-readable description when controls exist."""
        host = _make_host(extra={"Controls": "desktop, monitor"})
        config = _make_tasmota_config()
        desired = compute_desired_config(host, config)
        assert desired["DeviceName"] == "Power for desktop, monitor"
        assert desired["FriendlyName1"] == "au-plug-10"

    def test_device_name_without_controls(self):
        host = _make_host(extra={})
        config = _make_tasmota_config()
        desired = compute_desired_config(host, config)
        assert desired["DeviceName"] == "au-plug-10"
        assert desired["FriendlyName1"] == "au-plug-10"

    def test_device_name_with_whitespace_controls(self):
        host = _make_host(extra={"Controls": "  "})
        config = _make_tasmota_config()
        desired = compute_desired_config(host, config)
        # Whitespace-only should fall back to machine_name
        assert desired["DeviceName"] == "au-plug-10"

    def test_device_name_with_newline_controls(self):
        host = _make_host(extra={"Controls": "desktop\nmonitor\nserver"})
        config = _make_tasmota_config()
        desired = compute_desired_config(host, config)
        assert desired["DeviceName"] == "Power for desktop, monitor, server"
        assert desired["FriendlyName1"] == "au-plug-10"

    def test_non_plug_still_sets_names(self):
        """All devices get DeviceName and FriendlyName, not just plugs."""
        host = _make_host(hostname="ir-ac-remote")
        config = _make_tasmota_config()
        desired = compute_desired_config(host, config)
        assert desired["DeviceName"] == "ir-ac-remote"
        assert desired["FriendlyName1"] == "ir-ac-remote"
        assert desired["Hostname"] == "ir-ac-remote"
        assert desired["MqttHost"] == "ha.welland.mithis.com"
        assert desired["Topic"] == "ir-ac-remote"


# ---------------------------------------------------------------------------
# _get_current_value
# ---------------------------------------------------------------------------

class TestGetCurrentValue:
    def test_known_fields(self):
        td = _make_tasmota_data(
            device_name="plug",
            friendly_name="My Plug",
            hostname="plug.iot",
            mqtt_topic="plug",
            mqtt_host="broker",
            mqtt_port=1883,
        )
        assert _get_current_value("DeviceName", td) == "plug"
        assert _get_current_value("FriendlyName1", td) == "My Plug"
        assert _get_current_value("Hostname", td) == "plug.iot"
        assert _get_current_value("Topic", td) == "plug"
        assert _get_current_value("MqttHost", td) == "broker"
        assert _get_current_value("MqttPort", td) == "1883"

    def test_mqtt_user_returns_value(self):
        td = _make_tasmota_data(mqtt_user="myuser")
        assert _get_current_value("MqttUser", td) == "myuser"

    def test_mqtt_password_returns_empty(self):
        """MqttPassword can't be read back from devices."""
        td = _make_tasmota_data()
        assert _get_current_value("MqttPassword", td) == ""

    def test_unknown_field(self):
        td = _make_tasmota_data()
        assert _get_current_value("UnknownField", td) == ""


# ---------------------------------------------------------------------------
# compute_drift
# ---------------------------------------------------------------------------

class TestComputeDrift:
    def test_no_drift(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="au-plug-10",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        drifts = compute_drift(host, config)
        assert drifts == []

    def test_device_name_drift(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="wrong-name",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="au-plug-10",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        drifts = compute_drift(host, config)
        assert len(drifts) == 1
        assert drifts[0].field == "DeviceName"
        assert drifts[0].current == "wrong-name"
        assert drifts[0].desired == "au-plug-10"

    def test_mqtt_host_drift(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="au-plug-10",
            mqtt_host="old-broker.local",
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        drifts = compute_drift(host, config)
        fields = {d.field for d in drifts}
        assert "MqttHost" in fields

    def test_multiple_drifts(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="wrong",
            friendly_name="wrong",
            hostname="wrong",
            mqtt_topic="wrong",
            mqtt_host="wrong",
            mqtt_port=9999,
            mqtt_user="wrong",
        )
        config = _make_tasmota_config()
        drifts = compute_drift(host, config)
        # Should detect drift in DeviceName, FriendlyName1, Hostname, Topic,
        # MqttHost, MqttPort, MqttUser (but NOT MqttPassword — can't read back)
        assert len(drifts) == 7
        fields = {d.field for d in drifts}
        assert "MqttUser" in fields
        assert "MqttPassword" not in fields

    def test_no_tasmota_data_raises(self):
        host = _make_host()
        config = _make_tasmota_config()
        with pytest.raises(ValueError, match="no tasmota_data"):
            compute_drift(host, config)

    def test_topic_drift_no_mqtt_host_is_safe(self):
        """Topic change when mqtt_host is empty = initial setup, no warning."""
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="tasmota_AABBCC",  # Default Tasmota topic
            mqtt_host="",  # Not connected to any broker
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        drifts = compute_drift(host, config)
        topic_drifts = [d for d in drifts if d.field == "Topic"]
        assert len(topic_drifts) == 1
        assert topic_drifts[0].warning == ""

    def test_topic_drift_with_mqtt_host_warns(self):
        """Topic change when mqtt_host is set = HA-breaking, gets warning."""
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="old-topic",
            mqtt_host="ha.welland.mithis.com",  # Connected to broker
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        drifts = compute_drift(host, config)
        topic_drifts = [d for d in drifts if d.field == "Topic"]
        assert len(topic_drifts) == 1
        assert topic_drifts[0].warning != ""
        assert "orphan" in topic_drifts[0].warning.lower()
        assert "'old-topic'" in topic_drifts[0].warning  # Topic name
        assert "ha.welland.mithis.com" in topic_drifts[0].warning  # Broker

    def test_non_topic_drift_never_warns(self):
        """Non-Topic drifts should never have warnings."""
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="wrong",
            friendly_name="wrong",
            hostname="wrong",
            mqtt_topic="au-plug-10",  # Topic is correct
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        drifts = compute_drift(host, config)
        for d in drifts:
            assert d.warning == "", f"Unexpected warning on {d.field}"


# ---------------------------------------------------------------------------
# _send_tasmota_command
# ---------------------------------------------------------------------------

class TestSendTasmotaCommand:
    @patch("gdoc2netcfg.supplements.tasmota_configure.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        import json
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"DeviceName": "plug"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from gdoc2netcfg.supplements.tasmota_configure import _send_tasmota_command

        result = _send_tasmota_command("10.1.90.10", "DeviceName plug")
        assert result == {"DeviceName": "plug"}

    @patch("gdoc2netcfg.supplements.tasmota_configure.urllib.request.urlopen")
    def test_timeout_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = OSError("timeout")

        from gdoc2netcfg.supplements.tasmota_configure import _send_tasmota_command

        result = _send_tasmota_command("10.1.90.10", "DeviceName plug")
        assert result is None

    @patch("gdoc2netcfg.supplements.tasmota_configure.urllib.request.urlopen")
    def test_invalid_json_returns_none(self, mock_urlopen, capsys):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from gdoc2netcfg.supplements.tasmota_configure import _send_tasmota_command

        result = _send_tasmota_command("10.1.90.10", "DeviceName plug")
        assert result is None
        captured = capsys.readouterr()
        assert "Warning" in captured.err


# ---------------------------------------------------------------------------
# configure_tasmota_device
# ---------------------------------------------------------------------------

class TestConfigureTasmotaDevice:
    def test_no_tasmota_data(self):
        host = _make_host()
        config = _make_tasmota_config()
        result = configure_tasmota_device(host, config)
        assert result is False

    def test_no_ip_in_tasmota_data(self):
        host = _make_host()
        host.tasmota_data = _make_tasmota_data(ip="")
        config = _make_tasmota_config()
        result = configure_tasmota_device(host, config)
        assert result is False

    def test_no_drift_returns_true(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="au-plug-10",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        result = configure_tasmota_device(host, config)
        assert result is True

    def test_dry_run_does_not_send(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(device_name="wrong")
        config = _make_tasmota_config()

        with patch("gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command") as mock_send:
            result = configure_tasmota_device(host, config, dry_run=True)
            assert result is True
            mock_send.assert_not_called()

    @patch("gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command")
    def test_apply_sends_drifted_plus_password(self, mock_send):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="wrong-name",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="au-plug-10",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
            mqtt_user="tasmota",
        )
        config = _make_tasmota_config()
        mock_send.return_value = {"DeviceName": "au-plug-10"}

        result = configure_tasmota_device(host, config)
        assert result is True

        # Should send DeviceName (drifted) + MqttPassword (always pushed, can't detect drift)
        sent_fields = [call.args[1].split(" ")[0] for call in mock_send.call_args_list]
        assert "DeviceName" in sent_fields
        assert "MqttPassword" in sent_fields
        # MqttUser matches desired, so NOT pushed
        assert "MqttUser" not in sent_fields
        # Should NOT send other unchanged fields
        assert "Hostname" not in sent_fields
        assert "MqttHost" not in sent_fields

    @patch("gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command")
    def test_apply_sends_mqtt_user_when_drifted(self, mock_send):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="au-plug-10",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
            mqtt_user="wrong-user",
        )
        config = _make_tasmota_config()
        mock_send.return_value = {}

        result = configure_tasmota_device(host, config)
        assert result is True

        sent_fields = [call.args[1].split(" ")[0] for call in mock_send.call_args_list]
        assert "MqttUser" in sent_fields
        assert "MqttPassword" in sent_fields

    @patch("gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command")
    def test_apply_failure(self, mock_send):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(device_name="wrong")
        config = _make_tasmota_config()
        mock_send.return_value = None  # All commands fail

        result = configure_tasmota_device(host, config)
        assert result is False

    @patch("gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command")
    def test_topic_rename_on_ha_device_skipped_without_force(self, mock_send):
        """Topic change on HA-connected device should NOT be pushed without --force."""
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="old-topic",
            mqtt_host="ha.welland.mithis.com",  # Connected to broker
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        mock_send.return_value = {"Topic": "au-plug-10"}

        result = configure_tasmota_device(host, config)
        assert result is True

        # Topic should NOT have been sent
        sent_fields = [call.args[1].split(" ")[0] for call in mock_send.call_args_list]
        assert "Topic" not in sent_fields

    @patch("gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command")
    def test_topic_rename_on_ha_device_applied_with_force(self, mock_send):
        """Topic change on HA-connected device SHOULD be pushed with --force."""
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="old-topic",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        mock_send.return_value = {"Topic": "au-plug-10"}

        result = configure_tasmota_device(host, config, force=True)
        assert result is True

        sent_fields = [call.args[1].split(" ")[0] for call in mock_send.call_args_list]
        assert "Topic" in sent_fields

    @patch("gdoc2netcfg.supplements.tasmota_configure._send_tasmota_command")
    def test_topic_initial_setup_applied_without_force(self, mock_send):
        """Topic change when mqtt_host is empty = initial setup, no --force needed."""
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(
            device_name="au-plug-10",
            friendly_name="au-plug-10",
            hostname="au-plug-10",
            mqtt_topic="tasmota_AABBCC",  # Default topic
            mqtt_host="",  # Not connected
            mqtt_port=1883,
        )
        config = _make_tasmota_config()
        mock_send.return_value = {"Topic": "au-plug-10"}

        result = configure_tasmota_device(host, config)
        assert result is True

        sent_fields = [call.args[1].split(" ")[0] for call in mock_send.call_args_list]
        assert "Topic" in sent_fields


# ---------------------------------------------------------------------------
# configure_all_tasmota_devices
# ---------------------------------------------------------------------------

class TestConfigureAllTasmotaDevices:
    def test_counts(self):
        h1 = _make_host(hostname="plug-1", ip="10.1.90.1", mac="aa:bb:cc:dd:ee:01")
        h1.tasmota_data = _make_tasmota_data(
            device_name="plug-1",
            friendly_name="plug-1",
            hostname="plug-1",
            mqtt_topic="plug-1",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
            ip="10.1.90.1",
        )
        h2 = _make_host(hostname="plug-2", ip="10.1.90.2", mac="aa:bb:cc:dd:ee:02")
        # h2 has no tasmota_data -> will fail
        config = _make_tasmota_config()

        success, fail = configure_all_tasmota_devices([h1, h2], config)
        assert success == 1
        assert fail == 1


# ---------------------------------------------------------------------------
# _entity_id_for_host
# ---------------------------------------------------------------------------

class TestEntityIdForHost:
    def test_basic(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(mqtt_topic="au-plug-10")
        assert _entity_id_for_host(host) == "switch.tasmota_au_plug_10"

    def test_dashes_to_underscores(self):
        host = _make_host(hostname="au-plug-big-server")
        host.tasmota_data = _make_tasmota_data(mqtt_topic="au-plug-big-server")
        assert _entity_id_for_host(host) == "switch.tasmota_au_plug_big_server"

    def test_empty_topic_falls_back_to_machine_name(self):
        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(mqtt_topic="")
        assert _entity_id_for_host(host) == "switch.tasmota_au_plug_10"

    def test_no_tasmota_data(self):
        host = _make_host(hostname="au-plug-10")
        assert _entity_id_for_host(host) == "switch.tasmota_au_plug_10"


# ---------------------------------------------------------------------------
# check_ha_status (mocked)
# ---------------------------------------------------------------------------

class TestCheckHAStatus:
    @patch("gdoc2netcfg.supplements.tasmota_ha._query_ha_entity")
    def test_found_entity(self, mock_query):
        mock_query.return_value = {
            "exists": True,
            "entity_id": "switch.tasmota_au_plug_10",
            "state": "on",
            "last_changed": "2025-01-15T14:30:00Z",
            "attributes": {},
        }

        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(mqtt_topic="au-plug-10")
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test")

        results = check_ha_status([host], ha_config)
        assert "au-plug-10" in results
        assert results["au-plug-10"]["exists"] is True
        assert results["au-plug-10"]["state"] == "on"

    @patch("gdoc2netcfg.supplements.tasmota_ha._query_ha_entity")
    def test_missing_entity(self, mock_query):
        mock_query.return_value = {
            "exists": False,
            "entity_id": "switch.tasmota_au_plug_10",
        }

        host = _make_host(hostname="au-plug-10")
        host.tasmota_data = _make_tasmota_data(mqtt_topic="au-plug-10")
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test")

        results = check_ha_status([host], ha_config)
        assert results["au-plug-10"]["exists"] is False

    @patch("gdoc2netcfg.supplements.tasmota_ha._query_ha_entity")
    def test_skips_hosts_without_tasmota_data(self, mock_query):
        host = _make_host(hostname="au-plug-10")
        # No tasmota_data
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test")

        results = check_ha_status([host], ha_config)
        assert results == {}
        mock_query.assert_not_called()

    @patch("gdoc2netcfg.supplements.tasmota_ha._query_ha_entity")
    def test_multiple_hosts_parallel(self, mock_query):
        """Verify all hosts are queried (parallel execution)."""
        mock_query.return_value = {"exists": True, "entity_id": "x", "state": "on",
                                   "last_changed": "", "attributes": {}}

        hosts = []
        for i in range(5):
            h = _make_host(
                hostname=f"plug-{i}",
                ip=f"10.1.90.{i+1}",
                mac=f"aa:bb:cc:dd:ee:{i:02x}",
            )
            h.tasmota_data = _make_tasmota_data(mqtt_topic=f"plug-{i}")
            hosts.append(h)

        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test")
        results = check_ha_status(hosts, ha_config)
        assert len(results) == 5
        assert mock_query.call_count == 5


# ---------------------------------------------------------------------------
# _query_ha_entity (mocked HTTP)
# ---------------------------------------------------------------------------

class TestQueryHAEntity:
    @patch("gdoc2netcfg.supplements.tasmota_ha.urllib.request.urlopen")
    def test_found(self, mock_urlopen):
        import json
        body = json.dumps({
            "state": "on",
            "last_changed": "2025-01-15T14:30:00Z",
            "attributes": {"friendly_name": "Plug"},
        }).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from gdoc2netcfg.supplements.tasmota_ha import _query_ha_entity

        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test-token")
        result = _query_ha_entity(ha_config, "switch.tasmota_au_plug_10")

        assert result["exists"] is True
        assert result["state"] == "on"
        assert result["entity_id"] == "switch.tasmota_au_plug_10"

        # Verify auth header was set
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.get_header("Authorization") == "Bearer test-token"

    @patch("gdoc2netcfg.supplements.tasmota_ha.urllib.request.urlopen")
    def test_not_found_404(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://ha:8123/api/states/switch.tasmota_x",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )

        from gdoc2netcfg.supplements.tasmota_ha import _query_ha_entity

        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test")
        result = _query_ha_entity(ha_config, "switch.tasmota_x")

        assert result["exists"] is False
        assert "error" not in result  # 404 is expected, no error field

    @patch("gdoc2netcfg.supplements.tasmota_ha.urllib.request.urlopen")
    def test_server_error_500(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://ha:8123/api/states/switch.tasmota_x",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=None,
        )

        from gdoc2netcfg.supplements.tasmota_ha import _query_ha_entity

        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test")
        result = _query_ha_entity(ha_config, "switch.tasmota_x")

        assert result["exists"] is False
        assert "error" in result

    @patch("gdoc2netcfg.supplements.tasmota_ha.urllib.request.urlopen")
    def test_connection_error(self, mock_urlopen):
        mock_urlopen.side_effect = OSError("Connection refused")

        from gdoc2netcfg.supplements.tasmota_ha import _query_ha_entity

        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test")
        result = _query_ha_entity(ha_config, "switch.tasmota_x")

        assert result["exists"] is False
        assert "error" in result

    @patch("gdoc2netcfg.supplements.tasmota_ha.urllib.request.urlopen")
    def test_url_trailing_slash_stripped(self, mock_urlopen):
        import json
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"state": "off"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from gdoc2netcfg.supplements.tasmota_ha import _query_ha_entity

        ha_config = HomeAssistantConfig(url="http://ha:8123/", token="t")
        _query_ha_entity(ha_config, "switch.tasmota_x")

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert "//" not in req.full_url.replace("http://", "")
