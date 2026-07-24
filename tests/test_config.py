"""Tests for TOML section builders in config.py."""

import pytest

from gdoc2netcfg.config import _build_gwifi, _build_tasmota, _build_wisp


class TestBuildTasmota:
    def test_missing_section_gives_defaults(self):
        cfg = _build_tasmota({})
        assert cfg.mqtt_secret == ""
        assert cfg.syslog_host == ""
        assert cfg.syslog_port == 514
        assert cfg.syslog_level == 2

    def test_parses_syslog_settings(self):
        cfg = _build_tasmota({"tasmota": {
            "mqtt_secret": "0123456789abcdef0123456789abcdef",
            "syslog_host": "ten64",
            "syslog_port": 1514,
            "syslog_level": 3,
        }})
        assert cfg.syslog_host == "ten64"
        assert cfg.syslog_port == 1514
        assert cfg.syslog_level == 3

    def test_syslog_defaults_when_only_secret_set(self):
        cfg = _build_tasmota({"tasmota": {"mqtt_secret": "x"}})
        assert cfg.syslog_host == ""
        assert cfg.syslog_port == 514
        assert cfg.syslog_level == 2

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="syslog_level"):
            _build_tasmota({"tasmota": {"syslog_level": 7}})

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError, match="syslog_port"):
            _build_tasmota({"tasmota": {"syslog_port": 0}})

    def test_bool_port_raises(self):
        with pytest.raises(ValueError, match="syslog_port"):
            _build_tasmota({"tasmota": {"syslog_port": True}})

    def test_bool_level_raises(self):
        with pytest.raises(ValueError, match="syslog_level"):
            _build_tasmota({"tasmota": {"syslog_level": False}})

    def test_float_level_raises(self):
        with pytest.raises(ValueError, match="syslog_level"):
            _build_tasmota({"tasmota": {"syslog_level": 2.0}})


class TestBuildGwifi:
    def test_missing_section_gives_defaults(self):
        cfg = _build_gwifi({})
        assert cfg.mqtt_secret == ""

    def test_parses_secret(self):
        cfg = _build_gwifi({"gwifi": {
            "mqtt_secret": "0123456789abcdef0123456789abcdef",
        }})
        assert cfg.mqtt_secret == "0123456789abcdef0123456789abcdef"


class TestBuildWisp:
    def test_missing_section_gives_defaults(self):
        cfg = _build_wisp({})
        assert cfg.mqtt_secret == ""

    def test_parses_secret(self):
        cfg = _build_wisp({"wisp": {
            "mqtt_secret": "0123456789abcdef0123456789abcdef",
        }})
        assert cfg.mqtt_secret == "0123456789abcdef0123456789abcdef"
