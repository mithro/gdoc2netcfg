"""Tests for `wifi register-broker`."""
import argparse
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_wifi_register_broker, main
from gdoc2netcfg.config import (
    CacheConfig,
    HomeAssistantConfig,
    MqttBrokerConfig,
    PipelineConfig,
    WifiConfig,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, WifiData
from gdoc2netcfg.models.network import Site


def _host(hostname, sheet_type="WiFi", wifi_data=None):
    return Host(
        machine_name=hostname.split(".")[0],
        hostname=hostname,
        sheet_type=sheet_type,
        interfaces=[NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.6.7"),),
            dhcp_name=hostname,
        )],
        wifi_data=wifi_data,
    )


def _cfg_and_hosts():
    config = PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=".cache"),
        wifi=WifiConfig(mqtt_secret="0123456789abcdef0123456789abcdef"),
        homeassistant=HomeAssistantConfig(
            ssh_host="ha.example",
            mqtt=MqttBrokerConfig(host="mqtt.example", port=1883),
        ),
    )
    hosts = [
        _host("puck07.wifi", wifi_data=WifiData(number=7, serial="SN0007")),
        _host("desktop.network", sheet_type="Network"),
    ]
    return config, hosts


def test_register_broker_calls_core():
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._build_pipeline",
               return_value=(None, hosts, None, None)), \
         patch("gdoc2netcfg.supplements.mqtt_broker.register_logins") as reg:
        rc = cmd_wifi_register_broker(args)
    assert rc == 0
    _ssh, prefix, logins = reg.call_args.args[:3]
    assert prefix == "wifi-"
    assert set(logins) == {"wifi-puck07_wifi"}


def test_register_broker_missing_ssh_host_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.homeassistant.ssh_host = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._build_pipeline",
               return_value=(None, hosts, None, None)):
        rc = cmd_wifi_register_broker(args)
    assert rc == 1 and "ssh_host" in capsys.readouterr().err.lower()


def test_register_broker_empty_secret_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.wifi.mqtt_secret = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._build_pipeline",
               return_value=(None, hosts, None, None)):
        rc = cmd_wifi_register_broker(args)
    assert rc == 1 and "secret" in capsys.readouterr().err.lower()


def test_wifi_no_subcommand_prints_help(capsys):
    assert main(["wifi"]) == 0
    assert "register-broker" in capsys.readouterr().out
