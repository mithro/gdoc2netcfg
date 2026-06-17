"""Tests for sensors2mqtt host selection + login building."""
import pytest

from gdoc2netcfg.derivations.sensors2mqtt import (
    build_logins,
    classify,
    select_local,
    select_non_blank,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _host(hostname, s2m=None):
    extra = {} if s2m is None else {"Sensors": s2m}
    return Host(machine_name=hostname.split(".")[0], hostname=hostname,
                sheet_type="Network", interfaces=[NetworkInterface(
                    name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.5.10"),), dhcp_name=hostname)],
                extra=extra)


class TestClassify:
    def test_values(self):
        assert classify(_host("a", "local")) == "local"
        assert classify(_host("a", "remote")) == "remote"
        assert classify(_host("a", "")) == "blank"
        assert classify(_host("a", None)) == "blank"

    def test_case_and_whitespace(self):
        assert classify(_host("a", " Local ")) == "local"

    def test_unrecognized_raises(self):
        with pytest.raises(ValueError, match="Sensors"):
            classify(_host("a", "maybe"))

    def test_proxy(self):
        assert classify(_host("pi1.fpgas", "proxy")) == "proxy"


class TestSelect:
    def test_select_local(self):
        hosts = [_host("a", "local"), _host("b", "remote"), _host("c")]
        assert [h.hostname for h in select_local(hosts)] == ["a"]

    def test_select_non_blank(self):
        hosts = [_host("a", "local"), _host("b", "remote"), _host("c")]
        assert sorted(h.hostname for h in select_non_blank(hosts)) == ["a", "b"]

    def test_proxy_no_login_but_checked(self):
        hosts = [_host("a", "local"), _host("b", "proxy"), _host("c")]
        assert [h.hostname for h in select_local(hosts)] == ["a"]
        assert sorted(h.hostname for h in select_non_blank(hosts)) == ["a", "b"]


class TestBuildLogins:
    def test_local_only_with_prefix_and_password(self):
        import hashlib
        secret = "0123456789abcdef0123456789abcdef"
        hosts = [_host("rpi5.iot", "local"), _host("srv", "remote")]
        logins = build_logins(secret, hosts)
        assert set(logins) == {"s2m-rpi5_iot"}
        expected = hashlib.sha256((secret + "rpi5_iot").encode()).hexdigest()
        assert logins["s2m-rpi5_iot"] == expected

    def test_weak_secret_raises(self):
        with pytest.raises(ValueError, match="secret"):
            build_logins("short", [_host("a", "local")])

    def test_collision_raises(self):
        with pytest.raises(ValueError, match="collide"):
            build_logins("0123456789abcdef0123456789abcdef",
                         [_host("a.b", "local"), _host("a-b", "local")])

    def test_proxy_excluded(self):
        secret = "0123456789abcdef0123456789abcdef"
        logins = build_logins(secret, [_host("a", "proxy"), _host("b", "local")])
        assert set(logins) == {"s2m-b"}
