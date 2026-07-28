"""Tests for WiFi-device credential derivation."""
import hashlib

import pytest

from gdoc2netcfg.derivations.wifi_credentials import (
    PREFIX,
    build_logins,
    select_wifi_hosts,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, WifiData

SECRET = "0123456789abcdef0123456789abcdef"


def make_host(hostname, sheet_type="WiFi", wifi_data=None):
    return Host(
        machine_name=hostname.split(".")[0], hostname=hostname,
        sheet_type=sheet_type, interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.6.10"),), dhcp_name=hostname)],
        wifi_data=wifi_data,
    )


def test_prefix():
    assert PREFIX == "wifi-"


def test_selects_all_wifi_sheet_hosts():
    """Any WiFi-sheet row gets a login, whether or not it carries #/Serial
    (i.e. whether or not it has wifi_data) -- OpenMesh rows have neither."""
    puck = make_host("puck04.wifi", sheet_type="WiFi", wifi_data=WifiData(4, "SER04"))
    openmesh = make_host("om2p-kitchen.wifi", sheet_type="WiFi")   # wifi_data=None
    openmesh2 = make_host("om2p-lounge.wifi", sheet_type="WiFi")   # wifi_data=None
    network = make_host("ten64", sheet_type="Network")
    logins = build_logins(SECRET, [puck, openmesh, openmesh2, network])
    assert set(logins) == {"wifi-puck04_wifi", "wifi-om2p_kitchen_wifi", "wifi-om2p_lounge_wifi"}


def test_empty_selection_fails_loud():
    """Zero WiFi-sheet hosts means the wifi sheet didn't parse — never
    silently register nothing."""
    network_only = [make_host("ten64", sheet_type="Network")]
    with pytest.raises(ValueError, match="no WiFi-sheet hosts"):
        build_logins(SECRET, network_only)


def test_select_wifi_hosts_by_sheet_type():
    hosts = [
        make_host("puck04.wifi", sheet_type="WiFi"),
        make_host("desktop", sheet_type="Network"),
    ]
    assert [h.hostname for h in select_wifi_hosts(hosts)] == ["puck04.wifi"]


def test_build_logins_derives_password():
    hosts = [
        make_host("puck04.wifi", sheet_type="WiFi"),
        make_host("desktop", sheet_type="Network"),
    ]
    logins = build_logins(SECRET, hosts)
    assert set(logins) == {"wifi-puck04_wifi"}
    expected = hashlib.sha256((SECRET + "puck04_wifi").encode()).hexdigest()
    assert logins["wifi-puck04_wifi"] == expected


def test_build_logins_weak_secret_raises():
    with pytest.raises(ValueError, match="secret"):
        build_logins("short", [make_host("puck04.wifi", sheet_type="WiFi")])


def test_build_logins_collision_raises():
    with pytest.raises(ValueError, match="collide"):
        build_logins(SECRET,
                     [make_host("a.b", sheet_type="WiFi"), make_host("a-b", sheet_type="WiFi")])
