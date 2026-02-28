"""Tests for IPv6 capability detection."""

from gdoc2netcfg.derivations.ipv6_capability import (
    ESPRESSIF_OUIS,
    detect_ipv6_capability,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _make_host(hostname, mac, ip="10.1.90.51", extra=None):
    ipv4 = IPv4Address(ip)
    iface = NetworkInterface(
        name=None,
        mac=MACAddress.parse(mac),
        ip_addresses=(ipv4,),
        dhcp_name=hostname,
    )
    return Host(
        machine_name=hostname,
        hostname=hostname,
        sheet_type="IoT",
        interfaces=[iface],
        default_ipv4=ipv4,
        extra=extra or {},
    )


class TestEspressifOuiDetection:
    """Hosts with Espressif MAC OUIs are IPv6-incapable."""

    def test_espressif_oui_detected(self):
        # 7C:2C:67 is an Espressif OUI (Athom plugs)
        host = _make_host("au-plug-1", "7C:2C:67:D9:BA:24")
        assert detect_ipv6_capability(host) is False

    def test_itead_oui_detected(self):
        # C4:4F:33 is ITEAD (Sonoff devices)
        host = _make_host("bridge-433-1", "C4:4F:33:E7:04:FA")
        assert detect_ipv6_capability(host) is False

    def test_non_espressif_mac_is_capable(self):
        # Regular NIC MAC — not in OUI set
        host = _make_host("desktop", "aa:bb:cc:dd:ee:ff")
        assert detect_ipv6_capability(host) is True

    def test_netgear_mac_is_capable(self):
        # Netgear switches support IPv6
        host = _make_host("switch", "38:94:ed:b7:cd:e0")
        assert detect_ipv6_capability(host) is True

    def test_oui_set_has_known_prefixes(self):
        assert "7c:2c:67" in ESPRESSIF_OUIS
        assert "c4:4f:33" in ESPRESSIF_OUIS
        assert "5c:cf:7f" in ESPRESSIF_OUIS


class TestHardwarePatternDetection:
    """Hosts matching hardware column regex patterns are IPv6-incapable."""

    def test_athom_plug_pattern(self):
        host = _make_host("au-plug-1", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "Athom Plug V3"})
        patterns = ["Athom.*"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False

    def test_rf_r2_pattern(self):
        host = _make_host("light1", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "RF_R2"})
        patterns = ["RF_R2"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False

    def test_mini_pattern(self):
        host = _make_host("switch1", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "MINI"})
        patterns = ["MINI$"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False

    def test_no_hardware_column_is_capable(self):
        host = _make_host("desktop", "aa:bb:cc:dd:ee:ff")
        patterns = ["Athom.*", "RF_R2"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is True

    def test_unmatched_hardware_is_capable(self):
        host = _make_host("server", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "Raspberry Pi 5"})
        patterns = ["Athom.*", "RF_R2"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is True

    def test_pattern_is_case_insensitive(self):
        host = _make_host("plug", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "athom plug v3"})
        patterns = ["Athom.*"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False


class TestCombinedDetection:
    """OUI and hardware patterns work together (OR logic)."""

    def test_oui_match_overrides_no_hardware(self):
        # Espressif OUI, no hardware column
        host = _make_host("esp-device", "7C:2C:67:D9:BA:24")
        assert detect_ipv6_capability(host) is False

    def test_hardware_match_overrides_unknown_oui(self):
        # Unknown OUI, but matching hardware pattern
        host = _make_host("plug", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "Athom Plug V3"})
        assert detect_ipv6_capability(host, hardware_patterns=["Athom.*"]) is False

    def test_extra_ouis_extend_detection(self):
        host = _make_host("custom", "11:22:33:44:55:66")
        assert detect_ipv6_capability(host) is True
        assert detect_ipv6_capability(host, extra_ouis={"11:22:33"}) is False
