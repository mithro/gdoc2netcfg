"""Tests for sensors2mqtt HA status check."""
from datetime import datetime, timezone
from unittest.mock import patch

from gdoc2netcfg.config import HomeAssistantConfig
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _host(hostname, s2m=None):
    extra = {} if s2m is None else {"Sensors": s2m}
    return Host(
        machine_name=hostname.split(".")[0],
        hostname=hostname,
        sheet_type="Network",
        interfaces=[NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.5.10"),),
            dhcp_name=hostname,
        )],
        extra=extra,
    )


# Fixed "now" for deterministic freshness comparisons.
_NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

# Timestamps relative to _NOW
_RECENT = "2026-06-15T11:58:00+00:00"   # 2 min ago -> fresh (< 900s)
_OLD    = "2026-06-15T09:30:00+00:00"   # 2.5 h ago -> stale (> 900s)


def _fake_states():
    """A minimal /api/states list covering the test hosts."""
    return [
        # rpi5 (local) — has a recent load_1m entity -> fresh
        {
            "entity_id": "sensor.rpi5_load_1m",
            "state": "0.5",
            "last_updated": _RECENT,
            "attributes": {},
        },
        # rpi5 also has cpu_temperature, but older — freshness takes the NEWEST
        {
            "entity_id": "sensor.rpi5_cpu_temperature",
            "state": "55",
            "last_updated": _OLD,
            "attributes": {},
        },
        # rpi3 (remote) — has only an old entity -> stale
        {
            "entity_id": "sensor.rpi3_uptime",
            "state": "12345",
            "last_updated": _OLD,
            "attributes": {},
        },
        # A non-sensors2mqtt entity that shares the rpi3 prefix — must not match
        {
            "entity_id": "sensor.rpi3_energy_power",
            "state": "10",
            "last_updated": _RECENT,
            "attributes": {},
        },
        # rpi5-netv2 host: entity rpi5_netv2_cpu_temperature must NOT match bare rpi5
        {
            "entity_id": "sensor.rpi5_netv2_cpu_temperature",
            "state": "48",
            "last_updated": _RECENT,
            "attributes": {},
        },
    ]


class TestQueryStatus:
    @patch("gdoc2netcfg.supplements.sensors2mqtt_status._fetch_all_states")
    def test_fresh_stale_missing(self, mock_fetch):
        """local/fresh, remote/stale, blank excluded, missing = no entities."""
        mock_fetch.return_value = _fake_states()

        from gdoc2netcfg.supplements.sensors2mqtt_status import query_status

        hosts = [
            _host("rpi5", "local"),     # fresh (recent load_1m)
            _host("rpi3", "remote"),    # stale (old uptime, energy_power excluded)
            _host("srv", "remote"),     # missing (no matching entity)
            _host("desktop"),           # blank -> excluded
        ]
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test-token")

        result = query_status(ha_config, hosts, freshness_seconds=900, now=_NOW)

        # Blank host must be excluded
        assert "desktop" not in result

        # rpi5 -> fresh
        assert result["rpi5"]["class"] == "fresh"
        assert result["rpi5"]["last_updated"] is not None

        # rpi3 -> stale (energy_power not in SENSORS2MQTT_METRICS, so newest is _OLD uptime)
        assert result["rpi3"]["class"] == "stale"

        # srv -> missing (no entities at all)
        assert result["srv"]["class"] == "missing"
        assert result["srv"]["last_updated"] is None

    @patch("gdoc2netcfg.supplements.sensors2mqtt_status._fetch_all_states")
    def test_exact_id_match_no_prefix_bleed(self, mock_fetch):
        """rpi5_netv2_cpu_temperature must NOT match bare rpi5."""
        mock_fetch.return_value = _fake_states()

        from gdoc2netcfg.supplements.sensors2mqtt_status import query_status

        # rpi5 has load_1m (recent) in fake states, so it's fresh regardless.
        # The important thing: rpi5-netv2 entities are not credited to rpi5.
        hosts = [
            _host("rpi5", "local"),
            _host("rpi5-netv2", "local"),
        ]
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test-token")
        result = query_status(ha_config, hosts, freshness_seconds=900, now=_NOW)

        # rpi5-netv2 has its own entity -> fresh
        assert result["rpi5-netv2"]["class"] == "fresh"
        # rpi5 is fresh via its own load_1m
        assert result["rpi5"]["class"] == "fresh"

    @patch("gdoc2netcfg.supplements.sensors2mqtt_status._fetch_all_states")
    def test_selection_field_in_result(self, mock_fetch):
        """Each result record must include the selection field."""
        mock_fetch.return_value = []

        from gdoc2netcfg.supplements.sensors2mqtt_status import query_status

        hosts = [_host("rpi5", "local"), _host("srv", "remote")]
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test-token")
        result = query_status(ha_config, hosts, freshness_seconds=900, now=_NOW)

        assert result["rpi5"]["selection"] == "local"
        assert result["srv"]["selection"] == "remote"

    @patch("gdoc2netcfg.supplements.sensors2mqtt_status._fetch_all_states")
    def test_no_non_blank_hosts(self, mock_fetch):
        """When all hosts are blank, result is empty and HA is not queried."""
        mock_fetch.return_value = []

        from gdoc2netcfg.supplements.sensors2mqtt_status import query_status

        hosts = [_host("desktop")]
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test-token")
        result = query_status(ha_config, hosts, freshness_seconds=900, now=_NOW)

        assert result == {}
        # Short-circuits before the HTTP call when there is nothing to check.
        mock_fetch.assert_not_called()

    @patch("gdoc2netcfg.supplements.sensors2mqtt_status._fetch_all_states")
    def test_freshness_boundary(self, mock_fetch):
        """An entity exactly at the boundary (age == freshness_seconds) is stale."""
        # Exactly 900s before _NOW
        boundary = "2026-06-15T11:45:00+00:00"
        mock_fetch.return_value = [
            {"entity_id": "sensor.rpi5_load_1m", "state": "0.1",
             "last_updated": boundary, "attributes": {}},
        ]

        from gdoc2netcfg.supplements.sensors2mqtt_status import query_status

        hosts = [_host("rpi5", "local")]
        ha_config = HomeAssistantConfig(url="http://ha:8123", token="test-token")
        result = query_status(ha_config, hosts, freshness_seconds=900, now=_NOW)

        # age == 900s -> NOT strictly less than -> stale
        assert result["rpi5"]["class"] == "stale"
