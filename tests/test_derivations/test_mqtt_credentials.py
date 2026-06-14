"""Tests for the pure MQTT credential derivation."""
import pytest

from gdoc2netcfg.derivations.mqtt_credentials import (
    check_collisions,
    credential_key,
    password,
    require_strong_secret,
    username,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _host(hostname: str) -> Host:
    return Host(
        machine_name=hostname.split(".")[0],
        hostname=hostname,
        sheet_type="Network",
        interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.5.10"),), dhcp_name=hostname,
        )],
    )


class TestDerivation:
    def test_credential_key_is_node_id_of_hostname(self):
        assert credential_key(_host("big-storage")) == "big_storage"
        assert credential_key(_host("bmc.big-storage")) == "bmc_big_storage"

    def test_username_carries_prefix(self):
        assert username("s2m-", _host("rpi5.iot")) == "s2m-rpi5_iot"
        assert username("tas-", _host("au-plug-1.iot")) == "tas-au_plug_1_iot"

    def test_password_is_sha256_secret_plus_id_hex(self):
        assert password("testsecret", _host("big-storage")) == \
            "1a1c7e1c69578988a9fa6473f57924659e3e8eb2e4203fd63d8e6ea1fb11dc72"
        assert password("testsecret", _host("rpi5.iot")) == \
            "7f066df7bae33d26adc121786e8355b5afa4eaab04cf7bd667ff24992644bd27"

    def test_password_is_64_lowercase_hex(self):
        p = password("testsecret", _host("big-storage"))
        assert len(p) == 64 and p == p.lower() and all(c in "0123456789abcdef" for c in p)

    def test_bmc_and_parent_differ(self):
        assert password("s", _host("big-storage")) != password("s", _host("bmc.big-storage"))


class TestCollisionGuard:
    def test_distinct_ids_ok(self):
        check_collisions([_host("big-storage"), _host("rpi5.iot")])

    def test_colliding_ids_raise(self):
        with pytest.raises(ValueError, match="collide"):
            check_collisions([_host("a.b"), _host("a-b")])


class TestStrongSecretGuard:
    def test_empty_raises(self):
        with pytest.raises(ValueError, match="secret"):
            require_strong_secret("")

    def test_short_raises(self):
        with pytest.raises(ValueError, match="secret"):
            require_strong_secret("tooshort")

    def test_strong_ok(self):
        require_strong_secret("0123456789abcdef0123456789abcdef")
