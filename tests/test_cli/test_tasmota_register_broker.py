"""Tests for `tasmota register-broker`."""
import argparse
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_tasmota_register_broker
from gdoc2netcfg.config import (
    CacheConfig,
    HomeAssistantConfig,
    MqttBrokerConfig,
    PipelineConfig,
    TasmotaConfig,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, TasmotaData
from gdoc2netcfg.models.network import Site


def _host(hostname, tasmota=False):
    tasmota_data = None
    if tasmota:
        tasmota_data = TasmotaData(
            device_name=hostname,
            friendly_name="Tasmota",
            hostname=hostname,
            firmware_version="14.4.1(tasmota)",
            mqtt_host="ha.welland.mithis.com",
            mqtt_port=1883,
            mqtt_topic=hostname,
            mqtt_client="DVES_AABBCC",
            mac="AA:BB:CC:DD:EE:FF",
            ip="10.1.40.10",
        )
    return Host(
        machine_name=hostname.split(".")[0],
        hostname=hostname,
        sheet_type="IoT",
        interfaces=[NetworkInterface(
            name=None,
            mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.40.10"),),
            dhcp_name=hostname,
        )],
        tasmota_data=tasmota_data,
    )


def _cfg_and_hosts():
    config = PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        cache=CacheConfig(directory=".cache"),
        tasmota=TasmotaConfig(mqtt_secret="0123456789abcdef0123456789abcdef"),
        homeassistant=HomeAssistantConfig(
            ssh_host="ha.example",
            mqtt=MqttBrokerConfig(host="mqtt.example", port=1883),
        ),
    )
    hosts = [
        _host("au-plug-1.iot", tasmota=True),
        _host("desktop.network", tasmota=False),
    ]
    return config, hosts


def test_register_broker_calls_core():
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._tasmota_hosts", return_value=hosts), \
         patch("gdoc2netcfg.supplements.mqtt_broker.register_logins") as reg:
        rc = cmd_tasmota_register_broker(args)
    assert rc == 0
    _ssh, prefix, logins = reg.call_args.args[:3]
    assert prefix == "tas-"
    assert set(logins) == {"tas-au_plug_1_iot"}


def test_register_broker_empty_secret_errors(capsys):
    config, hosts = _cfg_and_hosts()
    config.tasmota.mqtt_secret = ""
    args = argparse.Namespace(config=None, dry_run=False, prune=False)
    with patch("gdoc2netcfg.cli.main._load_config", return_value=config), \
         patch("gdoc2netcfg.cli.main._tasmota_hosts", return_value=hosts):
        rc = cmd_tasmota_register_broker(args)
    assert rc == 1 and "secret" in capsys.readouterr().err.lower()
