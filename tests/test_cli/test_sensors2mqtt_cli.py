"""Tests for the sensors2mqtt CLI."""
import argparse
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_sensors2mqtt_list, cmd_sensors2mqtt_register
from gdoc2netcfg.config import (
    CacheConfig,
    HomeAssistantConfig,
    MqttBrokerConfig,
    PipelineConfig,
    Sensors2mqttConfig,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.models.network import Site


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


def _cfg_and_hosts():
    config = PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=".cache"),
        sensors2mqtt=Sensors2mqttConfig(mqtt_secret="0123456789abcdef0123456789abcdef"),
        homeassistant=HomeAssistantConfig(
            ssh_host="ha.example",
            mqtt=MqttBrokerConfig(host="mqtt.example", port=1883),
        ),
    )
    hosts = [
        _host("rpi5.iot", "local"),
        _host("srv.network", "remote"),
        _host("desktop.network"),  # blank / no Sensors column
    ]
    return config, hosts


def test_list_classifies(capsys):
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._sensors2mqtt_hosts", return_value=hosts):
        rc = cmd_sensors2mqtt_list(args)
    out = capsys.readouterr().out
    assert rc == 0 and "local" in out and "remote" in out
    assert "secret" not in out.lower() and "password" not in out.lower()


def test_register_calls_core(capsys):
    config, hosts = _cfg_and_hosts()          # mqtt_secret strong; homeassistant.ssh_host set
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._sensors2mqtt_hosts", return_value=hosts), \
         patch("gdoc2netcfg.supplements.mqtt_broker.register_logins") as reg:
        rc = cmd_sensors2mqtt_register(args)
    assert rc == 0
    ssh_host, prefix, logins = reg.call_args.args[:3]
    assert prefix == "s2m-" and set(logins) == {"s2m-rpi5_iot"}


def test_register_empty_secret_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.sensors2mqtt.mqtt_secret = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._sensors2mqtt_hosts", return_value=hosts):
        rc = cmd_sensors2mqtt_register(args)
    assert rc == 1 and "secret" in capsys.readouterr().err.lower()
