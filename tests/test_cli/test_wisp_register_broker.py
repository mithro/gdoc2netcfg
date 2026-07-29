"""Tests for `wisp register-broker`."""
import argparse
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_wisp_register_broker
from gdoc2netcfg.config import (
    CacheConfig,
    HomeAssistantConfig,
    MqttBrokerConfig,
    PipelineConfig,
    WispConfig,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.models.network import Site


def _host(hostname, machine_name=None):
    return Host(
        machine_name=machine_name or hostname.split(".")[0],
        hostname=hostname,
        sheet_type="Network",
        interfaces=[NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.10.5"),),
            dhcp_name=hostname,
        )],
    )


def _cfg_and_hosts():
    config = PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=".cache"),
        wisp=WispConfig(mqtt_secret="0123456789abcdef0123456789abcdef"),
        homeassistant=HomeAssistantConfig(
            ssh_host="ha.example",
            mqtt=MqttBrokerConfig(host="mqtt.example", port=1883),
        ),
    )
    hosts = [
        _host("wisp"),
        _host("desktop.network"),
    ]
    return config, hosts


def test_register_broker_calls_core():
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._build_pipeline",
               return_value=(None, hosts, None, None)), \
         patch("gdoc2netcfg.supplements.mqtt_broker.register_logins") as reg:
        rc = cmd_wisp_register_broker(args)
    assert rc == 0
    _ssh, prefix, logins = reg.call_args.args[:3]
    assert prefix == "wisp-"
    assert set(logins) == {"wisp-wisp"}


def test_register_broker_missing_ssh_host_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.homeassistant.ssh_host = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._build_pipeline",
               return_value=(None, hosts, None, None)):
        rc = cmd_wisp_register_broker(args)
    assert rc == 1 and "ssh_host" in capsys.readouterr().err.lower()


def test_register_broker_empty_secret_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.wisp.mqtt_secret = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._build_pipeline",
               return_value=(None, hosts, None, None)):
        rc = cmd_wisp_register_broker(args)
    assert rc == 1 and "secret" in capsys.readouterr().err.lower()


def test_register_broker_missing_wisp_host_errors(capsys):
    config, hosts = _cfg_and_hosts()
    hosts = [h for h in hosts if h.hostname != "wisp"]
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._build_pipeline",
               return_value=(None, hosts, None, None)):
        rc = cmd_wisp_register_broker(args)
    assert rc == 1 and "wisp" in capsys.readouterr().err.lower()
