"""Tests for `wifi show-login`."""
import argparse
import json
from unittest.mock import patch

from gdoc2netcfg.cli.main import cmd_wifi_show_login, main
from gdoc2netcfg.config import (
    CacheConfig,
    HomeAssistantConfig,
    MqttBrokerConfig,
    PipelineConfig,
    WifiConfig,
)
from gdoc2netcfg.derivations.mqtt_credentials import password as _derive_password
from gdoc2netcfg.derivations.mqtt_credentials import username as _derive_username
from gdoc2netcfg.derivations.wifi_credentials import PREFIX
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, WifiData
from gdoc2netcfg.models.network import Site

SECRET = "0123456789abcdef0123456789abcdef"


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
        wifi=WifiConfig(mqtt_secret=SECRET),
        homeassistant=HomeAssistantConfig(
            ssh_host="ha.example",
            mqtt=MqttBrokerConfig(host="mqtt.example", port=1883),
        ),
    )
    hosts = [
        _host("puck06.wifi", wifi_data=WifiData(number=6, serial="SN0006")),
        _host("puck12.wifi", wifi_data=WifiData(number=12, serial="SN0012")),
        _host("openmesh1.wifi"),  # OpenMesh AP -- no wifi_data, still WiFi sheet
        _host("desktop.network", sheet_type="Network"),  # not a WiFi-sheet host
    ]
    return config, hosts


def _expected(hostname):
    """Derive the expected (username, password) the same way the
    implementation does -- via the shared mqtt_credentials core, never a
    hardcoded fake hash."""
    h = _host(hostname)
    return _derive_username(PREFIX, h), _derive_password(SECRET, h)


def _patch(config, hosts):
    return (
        patch("gdoc2netcfg.cli.main._load_config", return_value=config),
        patch(
            "gdoc2netcfg.cli.main._build_pipeline",
            return_value=(None, hosts, None, None),
        ),
    )


def test_show_login_all_hosts_json(capsys):
    """No positional args -> every WiFi-sheet host, JSON output."""
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, hosts=[], json=True)
    p1, p2 = _patch(config, hosts)
    with p1, p2:
        rc = cmd_wifi_show_login(args)
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"puck06", "puck12", "openmesh1"}
    u6, p6 = _expected("puck06.wifi")
    assert out["puck06"] == {"username": u6, "password": p6}


def test_show_login_single_host_text(capsys):
    """A single machine name -> one 'username password' text line."""
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, hosts=["puck06"], json=False)
    p1, p2 = _patch(config, hosts)
    with p1, p2:
        rc = cmd_wifi_show_login(args)
    assert rc == 0
    u6, p6 = _expected("puck06.wifi")
    assert capsys.readouterr().out == f"{u6} {p6}\n"


def test_show_login_unknown_host_errors(capsys):
    """An unknown machine name -> exit 1, error names the unknown machine."""
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, hosts=["puck99"], json=False)
    p1, p2 = _patch(config, hosts)
    with p1, p2:
        rc = cmd_wifi_show_login(args)
    assert rc == 1
    err = capsys.readouterr().err
    assert "puck99" in err


def test_show_login_non_wifi_host_is_unknown(capsys):
    """A real host from a different sheet is still 'unknown' here -- this
    command only ever knows about WiFi-sheet hosts."""
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, hosts=["desktop"], json=False)
    p1, p2 = _patch(config, hosts)
    with p1, p2:
        rc = cmd_wifi_show_login(args)
    assert rc == 1
    assert "desktop" in capsys.readouterr().err


def test_show_login_never_touches_broker(capsys):
    """This command must never register/verify against the live broker."""
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, hosts=[], json=True)
    p1, p2 = _patch(config, hosts)
    with p1, p2, patch(
        "gdoc2netcfg.supplements.mqtt_broker.register_logins"
    ) as reg:
        rc = cmd_wifi_show_login(args)
    assert rc == 0
    reg.assert_not_called()


def test_show_login_json_shape(capsys):
    """--json shape must be exactly {machine: {"username", "password"}} --
    no extra wrapper keys -- this is the fleet tool's parse contract."""
    config, hosts = _cfg_and_hosts()
    args = argparse.Namespace(config=None, hosts=["puck06", "puck12"], json=True)
    p1, p2 = _patch(config, hosts)
    with p1, p2:
        rc = cmd_wifi_show_login(args)
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"puck06", "puck12"}
    for machine, entry in out.items():
        assert set(entry) == {"username", "password"}
        assert entry["username"] == f"wifi-{machine}_wifi"
        assert entry["username"].startswith(PREFIX)
        assert entry["password"]


def test_show_login_wired_through_main(capsys):
    """Prove the argparse subparser + dispatch elif are actually wired, not
    just the plain function -- a bare parser add without the dispatch
    branch would silently fall through to wifi_parser.print_help()."""
    config, hosts = _cfg_and_hosts()
    p1, p2 = _patch(config, hosts)
    with p1, p2:
        rc = main(["wifi", "show-login", "--json", "puck06"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"puck06"}
