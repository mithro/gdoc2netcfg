"""Tests for gwifi puck credential derivation."""
import hashlib

import pytest

from gdoc2netcfg.derivations.gwifi_credentials import (
    PREFIX,
    build_logins,
    select_pucks,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, PuckData


def _host(hostname, puck=False):
    puck_data = None
    if puck:
        puck_data = PuckData(number=4, serial="2831HW00VZA")
    return Host(
        machine_name=hostname.split(".")[0], hostname=hostname,
        sheet_type="WiFi", interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.6.10"),), dhcp_name=hostname)],
        puck_data=puck_data,
    )


def test_prefix():
    assert PREFIX == "gwifi-"


def test_select_pucks_only_puck_data():
    hosts = [_host("puck04.wifi", puck=True), _host("desktop", puck=False)]
    assert [h.hostname for h in select_pucks(hosts)] == ["puck04.wifi"]


def test_build_logins_derives_for_pucks_only():
    secret = "0123456789abcdef0123456789abcdef"
    hosts = [_host("puck04.wifi", puck=True), _host("desktop", puck=False)]
    logins = build_logins(secret, hosts)
    assert set(logins) == {"gwifi-puck04_wifi"}
    expected = hashlib.sha256((secret + "puck04_wifi").encode()).hexdigest()
    assert logins["gwifi-puck04_wifi"] == expected


def test_build_logins_weak_secret_raises():
    with pytest.raises(ValueError, match="secret"):
        build_logins("short", [_host("puck04.wifi", puck=True)])


def test_build_logins_collision_raises():
    with pytest.raises(ValueError, match="collide"):
        build_logins("0123456789abcdef0123456789abcdef",
                     [_host("a.b", puck=True), _host("a-b", puck=True)])
