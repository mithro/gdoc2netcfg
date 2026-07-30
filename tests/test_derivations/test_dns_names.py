"""Tests for DNS name derivations.

Ported from the doctests in dnsmasq.py:common_suffix() and name computation.
"""

from gdoc2netcfg.derivations.dns_names import (
    common_suffix,
    compute_dhcp_name,
    compute_hostname,
)


class TestComputeHostname:
    def test_network_device(self):
        assert compute_hostname("Desktop", "Network") == "desktop"

    def test_iot_device(self):
        assert compute_hostname("thermostat", "IoT") == "thermostat.iot"

    def test_test_device(self):
        assert compute_hostname("board", "Test") == "board.test"

    def test_wifi_device(self):
        assert compute_hostname("puck04", "WiFi") == "puck04.wifi"

    def test_strips_whitespace(self):
        assert compute_hostname("  desktop  ", "Network") == "desktop"


class TestComputeDhcpName:
    def test_no_interface(self):
        assert compute_dhcp_name("desktop", "", "Network") == "desktop"

    def test_with_interface(self):
        assert compute_dhcp_name("desktop", "eth0", "Network") == "eth0-desktop"

    def test_iot_no_interface(self):
        assert compute_dhcp_name("thermostat", "", "IoT") == "thermostat.iot"

    def test_iot_with_interface(self):
        assert compute_dhcp_name("camera", "eth0", "IoT") == "eth0-camera.iot"

    def test_wifi_no_interface(self):
        assert compute_dhcp_name("puck04", "", "WiFi") == "puck04.wifi"

    def test_wifi_with_interface(self):
        assert compute_dhcp_name("puck04", "wan", "WiFi") == "wan-puck04.wifi"

    def test_test_sheet_has_no_dhcp_suffix(self):
        """Preserved asymmetry: Test suffixes hostname but NOT dhcp name."""
        assert compute_dhcp_name("box", "", "Test") == "box"

    def test_bmc_interface(self):
        assert compute_dhcp_name("server", "bmc", "Network") == "bmc-server"

    def test_strips_whitespace(self):
        assert compute_dhcp_name("  server  ", "  eth0  ", "Network") == "eth0-server"


class TestCommonSuffix:
    """Ported directly from dnsmasq.py doctests."""

    def test_identical_pair(self):
        assert common_suffix("a", "a") == "a"

    def test_identical_triple(self):
        assert common_suffix("a", "a", "a") == "a"

    def test_no_common_suffix(self):
        assert common_suffix("a", "a", "b") == ""

    def test_partial_match(self):
        assert common_suffix("aa", "a") == "a"

    def test_no_suffix_different(self):
        assert common_suffix("ab", "a") == ""

    def test_one_char_suffix(self):
        assert common_suffix("aba", "aa") == "a"

    def test_two_char_suffix(self):
        assert common_suffix("abca", "aca") == "ca"

    def test_single_string(self):
        assert common_suffix("abca") == "abca"

    def test_real_world_interfaces(self):
        """eth1.ten64 and eth2.ten64 should produce ten64."""
        assert common_suffix("eth1.ten64", "eth2.ten64") == ".ten64"

    def test_hostname_with_interface_prefix(self):
        """eno0.desktop and eno1.desktop → .desktop"""
        assert common_suffix("eno0.desktop", "eno1.desktop") == ".desktop"
