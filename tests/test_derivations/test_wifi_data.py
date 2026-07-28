"""Tests for wifi-device identity derivation from WiFi-sheet extra columns."""
import pytest

from gdoc2netcfg.derivations.wifi_data import enrich_hosts_with_wifi_data
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, WifiData


def _host(machine_name, hostname=None, sheet_type="WiFi", extra=None):
    return Host(
        machine_name=machine_name,
        hostname=hostname or machine_name,
        sheet_type=sheet_type,
        interfaces=[NetworkInterface(
            name=None, mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
            ip_addresses=(IPv4Address("10.1.60.10"),), dhcp_name=hostname or machine_name)],
        extra=extra or {},
    )


def test_happy_path_attaches_wifi_data():
    host = _host("puck04", extra={"#": "4", "Serial": "2831HW00VZA"})
    enrich_hosts_with_wifi_data([host])
    assert host.wifi_data == WifiData(number=4, serial="2831HW00VZA")


def test_machine_name_mismatch_raises():
    host = _host("puck05", extra={"#": "4", "Serial": "2831HW00VZA"})
    with pytest.raises(ValueError, match="puck05"):
        enrich_hosts_with_wifi_data([host])


def test_number_outside_range_raises():
    host = _host("puck00", extra={"#": "0", "Serial": "2831HW00VZA"})
    with pytest.raises(ValueError, match="0"):
        enrich_hosts_with_wifi_data([host])

    host2 = _host("puck100", extra={"#": "100", "Serial": "2831HW00VZB"})
    with pytest.raises(ValueError, match="100"):
        enrich_hosts_with_wifi_data([host2])


def test_non_integer_number_raises_with_hostname():
    host = _host("puck04", hostname="puck04.wifi", extra={"#": "four", "Serial": "2831HW00VZA"})
    with pytest.raises(ValueError, match="puck04.wifi"):
        enrich_hosts_with_wifi_data([host])


def test_duplicate_numbers_across_hosts_raise():
    host1 = _host("puck04", extra={"#": "4", "Serial": "2831HW00VZA"})
    host2 = _host("puck04", hostname="puck04-lan", extra={"#": "4", "Serial": "2831HW00VZZ"})
    with pytest.raises(ValueError, match="duplicate"):
        enrich_hosts_with_wifi_data([host1, host2])


def test_duplicate_serials_across_hosts_raise():
    host1 = _host("puck04", extra={"#": "4", "Serial": "2831HW00VZA"})
    host2 = _host("puck05", extra={"#": "5", "Serial": "2831HW00VZA"})
    with pytest.raises(ValueError, match="duplicate"):
        enrich_hosts_with_wifi_data([host1, host2])


def test_wifi_host_without_puck_columns_is_none():
    host = _host("home-mesh-1", extra={})
    enrich_hosts_with_wifi_data([host])
    assert host.wifi_data is None


def test_partial_data_raises():
    host = _host("puck04", extra={"#": "4"})
    with pytest.raises(ValueError, match="partial"):
        enrich_hosts_with_wifi_data([host])

    host2 = _host("puck04", extra={"Serial": "2831HW00VZA"})
    with pytest.raises(ValueError, match="partial"):
        enrich_hosts_with_wifi_data([host2])


def test_non_wifi_sheet_ignored_even_with_extras():
    host = _host("puck04", sheet_type="Network", extra={"#": "4", "Serial": "2831HW00VZA"})
    enrich_hosts_with_wifi_data([host])
    assert host.wifi_data is None
