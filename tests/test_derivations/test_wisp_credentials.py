"""Tests for wisp service credential derivation."""
import hashlib

import pytest

from gdoc2netcfg.derivations.wisp_credentials import (
    PREFIX,
    build_logins,
    select_wisp,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _host(hostname, machine_name=None):
    machine_name = machine_name if machine_name is not None else hostname.split(".")[0]
    return Host(
        machine_name=machine_name, hostname=hostname,
        sheet_type="Network", interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.10.10"),), dhcp_name=hostname)],
    )


def test_prefix():
    assert PREFIX == "wisp-"


def test_select_wisp_finds_the_single_host():
    hosts = [_host("wisp"), _host("ten64")]
    assert select_wisp(hosts).hostname == "wisp"


def test_select_wisp_absent_raises():
    with pytest.raises(ValueError, match="wisp"):
        select_wisp([_host("ten64")])


def test_select_wisp_picks_hostname_over_machine_name_mirror():
    """A `wisp.wifi` mirror host sharing machine_name='wisp' (added by the
    wifi-sheet tenwrt merge) must not be confused with the real service
    host — selection is keyed on hostname, not machine_name."""
    hosts = [_host("wisp"), _host("wisp.wifi", machine_name="wisp")]
    assert select_wisp(hosts).hostname == "wisp"


def test_select_wisp_duplicate_raises():
    hosts = [_host("wisp"), _host("wisp", machine_name="wisp-b")]
    with pytest.raises(ValueError, match="multiple"):
        select_wisp(hosts)


def test_build_logins_derives_for_wisp():
    secret = "0123456789abcdef0123456789abcdef"
    hosts = [_host("wisp"), _host("ten64")]
    logins = build_logins(secret, hosts)
    assert set(logins) == {"wisp-wisp"}
    expected = hashlib.sha256((secret + "wisp").encode()).hexdigest()
    assert logins["wisp-wisp"] == expected


def test_build_logins_weak_secret_raises():
    with pytest.raises(ValueError, match="secret"):
        build_logins("short", [_host("wisp")])


def test_build_logins_absent_raises():
    with pytest.raises(ValueError, match="wisp"):
        build_logins("0123456789abcdef0123456789abcdef", [_host("ten64")])
