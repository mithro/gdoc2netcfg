"""Tests for Tasmota credential derivation."""
import hashlib

import pytest

from gdoc2netcfg.derivations.tasmota_credentials import (
    PREFIX,
    build_logins,
    select_tasmota,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, TasmotaData


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
        machine_name=hostname.split(".")[0], hostname=hostname,
        sheet_type="IoT", interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.40.10"),), dhcp_name=hostname)],
        tasmota_data=tasmota_data,
    )


def test_prefix():
    assert PREFIX == "tas-"


def test_select_tasmota_only_scanned():
    hosts = [_host("au-plug-1.iot", tasmota=True), _host("desktop", tasmota=False)]
    assert [h.hostname for h in select_tasmota(hosts)] == ["au-plug-1.iot"]


def test_build_logins_derives_for_tasmota_only():
    secret = "0123456789abcdef0123456789abcdef"
    hosts = [_host("au-plug-1.iot", tasmota=True), _host("desktop", tasmota=False)]
    logins = build_logins(secret, hosts)
    assert set(logins) == {"tas-au_plug_1_iot"}
    expected = hashlib.sha256((secret + "au_plug_1_iot").encode()).hexdigest()
    assert logins["tas-au_plug_1_iot"] == expected


def test_build_logins_weak_secret_raises():
    with pytest.raises(ValueError, match="secret"):
        build_logins("short", [_host("au-plug-1.iot", tasmota=True)])


def test_build_logins_collision_raises():
    with pytest.raises(ValueError, match="collide"):
        build_logins("0123456789abcdef0123456789abcdef",
                     [_host("a.b", tasmota=True), _host("a-b", tasmota=True)])
