"""Tests for the shared reachability module."""

import socket
from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    InterfaceReachability,
    PingResult,
    _detect_ip_version,
    check_all_hosts_reachability,
    check_port_open,
    check_reachable,
)


class TestPingResult:
    def test_truthy_when_received(self):
        assert PingResult(5, 3, 1.2)
        assert PingResult(5, 1)

    def test_falsy_when_none_received(self):
        assert not PingResult(5, 0)
        assert not PingResult(0, 0)

    def test_immutable(self):
        pr = PingResult(5, 3)
        try:
            pr.received = 0
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestCheckReachable:
    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_reachable_host(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.1 (10.1.10.1) 56(84) bytes of data.\n"
            "5 packets transmitted, 5 received, 0% packet loss\n"
            "rtt min/avg/max/mdev = 0.100/0.250/0.400/0.100 ms\n"
        )
        result = check_reachable("10.1.10.1")
        assert result
        assert result.transmitted == 5
        assert result.received == 5
        assert result.rtt_avg_ms == 0.250

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_unreachable_host(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.99 (10.1.10.99) 56(84) bytes of data.\n"
            "5 packets transmitted, 0 received, 100% packet loss\n"
        )
        result = check_reachable("10.1.10.99")
        assert not result
        assert result.transmitted == 5
        assert result.received == 0
        assert result.rtt_avg_ms is None

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_custom_packet_count(self, mock_run):
        mock_run.return_value.stdout = "3 packets transmitted, 3 received"
        result = check_reachable("10.1.10.1", packets=3)
        assert result
        assert result.transmitted == 3
        assert result.received == 3
        args = mock_run.call_args[0][0]
        assert "-c" in args
        assert "3" in args

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_partial_response_still_reachable(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.1 (10.1.10.1) 56(84) bytes of data.\n"
            "5 packets transmitted, 2 received, 60% packet loss\n"
            "rtt min/avg/max/mdev = 0.500/1.200/1.900/0.500 ms\n"
        )
        result = check_reachable("10.1.10.1")
        assert result
        assert result.transmitted == 5
        assert result.received == 2
        assert result.rtt_avg_ms == 1.200

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_ping_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        result = check_reachable("10.1.10.1")
        assert not result
        assert result.transmitted == 0
        assert result.received == 0


class TestCheckPortOpen:
    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_port_open(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 0
        assert check_port_open("10.1.10.1", 22) is True
        mock_sock.connect_ex.assert_called_once_with(("10.1.10.1", 22))
        mock_sock.close.assert_called_once()

    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_port_closed(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 111  # Connection refused
        assert check_port_open("10.1.10.1", 443) is False
        mock_sock.connect_ex.assert_called_once_with(("10.1.10.1", 443))

    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_custom_timeout(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 0
        check_port_open("10.1.10.1", 80, timeout=2.0)
        mock_sock.settimeout.assert_called_once_with(2.0)

    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_socket_always_closed(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.side_effect = OSError("network error")
        try:
            check_port_open("10.1.10.1", 22)
        except OSError:
            pass
        mock_sock.close.assert_called_once()


def _make_ipv6(addr):
    """Create an IPv6Address with a dummy prefix (for test convenience)."""
    return IPv6Address(addr, prefix="2001:db8:1:")


def _make_host(hostname, ip, ipv6_addrs=None):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ip_addresses=(
                    IPv4Address(ip),
                    *[_make_ipv6(a) for a in (ipv6_addrs or [])],
                ),
            )
        ],
    )


def _make_multi_iface_host(hostname, ips, ipv6_per_iface=None):
    ifaces = [
        NetworkInterface(
            name=f"eth{i}",
            mac=MACAddress.parse(f"aa:bb:cc:dd:ee:{i:02x}"),
            ip_addresses=(
                IPv4Address(ip),
                *[_make_ipv6(a) for a in (ipv6_per_iface or {}).get(i, [])],
            ),
        )
        for i, ip in enumerate(ips)
    ]
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=ifaces,
    )


class TestHostReachability:
    def test_with_active_ips(self):
        hr = HostReachability(hostname="server", active_ips=("10.1.10.1",))
        assert hr.hostname == "server"
        assert hr.active_ips == ("10.1.10.1",)
        assert hr.is_up is True

    def test_defaults(self):
        hr = HostReachability(hostname="server")
        assert hr.active_ips == ()
        assert hr.is_up is False

    def test_is_up_derived_from_active_ips(self):
        """is_up is a property derived from active_ips, not an independent field."""
        up = HostReachability(hostname="a", active_ips=("10.0.0.1",))
        down = HostReachability(hostname="b", active_ips=())
        assert up.is_up is True
        assert down.is_up is False

    def test_immutable(self):
        hr = HostReachability(hostname="server", active_ips=("10.1.10.1",))
        try:
            hr.hostname = "other"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestCheckAllHostsReachability:
    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_all_hosts_up(self, mock_reachable):
        mock_reachable.return_value = True
        hosts = [_make_host("server", "10.1.10.1"), _make_host("desktop", "10.1.10.2")]

        result = check_all_hosts_reachability(hosts)

        assert len(result) == 2
        assert result["server"].is_up is True
        assert result["server"].active_ips == ("10.1.10.1",)
        assert result["desktop"].is_up is True

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_host_down(self, mock_reachable):
        mock_reachable.return_value = False
        hosts = [_make_host("server", "10.1.10.1")]

        result = check_all_hosts_reachability(hosts)

        assert result["server"].is_up is False
        assert result["server"].active_ips == ()

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_multi_interface_partial(self, mock_reachable):
        """Only some IPs respond — active_ips should contain just those."""
        def side_effect(ip):
            return ip == "10.1.10.1"

        mock_reachable.side_effect = side_effect
        hosts = [_make_multi_iface_host("server", ["10.1.10.1", "10.1.10.2"])]

        result = check_all_hosts_reachability(hosts)

        assert result["server"].is_up is True
        assert result["server"].active_ips == ("10.1.10.1",)

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_empty_hosts(self, mock_reachable):
        result = check_all_hosts_reachability([])
        assert result == {}
        mock_reachable.assert_not_called()

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_sorted_by_reversed_hostname(self, mock_reachable):
        """Hosts are processed sorted by reversed hostname components."""
        mock_reachable.return_value = True
        hosts = [
            _make_host("zebra.example.com", "10.1.10.3"),
            _make_host("alpha.example.com", "10.1.10.1"),
        ]

        result = check_all_hosts_reachability(hosts)

        # Both should be present regardless of order
        assert "zebra.example.com" in result
        assert "alpha.example.com" in result


def _make_hr(hostname, pings_per_iface):
    """Build a HostReachability with properly populated interfaces.

    Args:
        hostname: Host name.
        pings_per_iface: List of lists of (ip, PingResult) tuples, one
            inner list per interface.
    """
    ifaces = tuple(
        InterfaceReachability(pings=tuple(pings))
        for pings in pings_per_iface
    )
    active: list[str] = []
    for ir in ifaces:
        active.extend(ir.active_ips)
    return HostReachability(
        hostname=hostname,
        active_ips=tuple(active),
        interfaces=ifaces,
    )


class TestSharedIPReachability:
    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_shared_ip_pinged_once(self, mock_reachable):
        """Two NICs sharing the same IP should only produce one ping."""
        mock_reachable.return_value = PingResult(10, 10, 1.0)
        # Two interfaces, same IP, different MACs
        host = _make_multi_iface_host("roku", ["10.1.10.50", "10.1.10.50"])

        result = check_all_hosts_reachability([host])

        assert result["roku"].is_up is True
        assert result["roku"].active_ips == ("10.1.10.50",)
        # Should ping once, not twice
        mock_reachable.assert_called_once_with("10.1.10.50")


# ---------------------------------------------------------------------------
# New dual-stack tests
# ---------------------------------------------------------------------------


class TestIPVersionDetection:
    def test_ipv4(self):
        assert _detect_ip_version("10.1.10.1") == 4
        assert _detect_ip_version("192.168.0.1") == 4

    def test_ipv6(self):
        assert _detect_ip_version("2001:db8::1") == 6
        assert _detect_ip_version("::1") == 6
        assert _detect_ip_version("2404:e80:a137:110::1") == 6

    def test_invalid_raises(self):
        import pytest
        with pytest.raises(ValueError):
            _detect_ip_version("not-an-ip")


class TestCheckPortOpenDualStack:
    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_ipv4_uses_af_inet(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 0
        check_port_open("10.1.10.1", 22)
        mock_socket_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)

    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_ipv6_uses_af_inet6(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 0
        check_port_open("2001:db8::1", 22)
        mock_socket_cls.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)


class TestInterfaceReachability:
    def test_dual_stack(self):
        ir = InterfaceReachability(pings=(
            ("10.1.10.1", PingResult(10, 10, 1.0)),
            ("2001:db8::1", PingResult(10, 10, 0.5)),
        ))
        assert ir.active_ips == ("10.1.10.1", "2001:db8::1")
        assert ir.active_ipv4 == ("10.1.10.1",)
        assert ir.active_ipv6 == ("2001:db8::1",)
        assert ir.has_ipv4 is True
        assert ir.has_ipv6 is True
        assert ir.reachability_mode == "dual-stack"

    def test_ipv4_only(self):
        ir = InterfaceReachability(pings=(
            ("10.1.10.1", PingResult(10, 10, 1.0)),
            ("2001:db8::1", PingResult(10, 0)),
        ))
        assert ir.active_ips == ("10.1.10.1",)
        assert ir.active_ipv4 == ("10.1.10.1",)
        assert ir.active_ipv6 == ()
        assert ir.has_ipv4 is True
        assert ir.has_ipv6 is False
        assert ir.reachability_mode == "ipv4-only"

    def test_ipv6_only(self):
        ir = InterfaceReachability(pings=(
            ("10.1.10.1", PingResult(10, 0)),
            ("2001:db8::1", PingResult(10, 10, 0.5)),
        ))
        assert ir.reachability_mode == "ipv6-only"
        assert ir.has_ipv4 is False
        assert ir.has_ipv6 is True

    def test_unreachable(self):
        ir = InterfaceReachability(pings=(
            ("10.1.10.1", PingResult(10, 0)),
            ("2001:db8::1", PingResult(10, 0)),
        ))
        assert ir.active_ips == ()
        assert ir.reachability_mode == "unreachable"

    def test_empty_pings(self):
        ir = InterfaceReachability()
        assert ir.active_ips == ()
        assert ir.reachability_mode == "unreachable"

    def test_immutable(self):
        ir = InterfaceReachability(pings=(("10.1.10.1", PingResult(10, 10)),))
        try:
            ir.pings = ()
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestHostReachabilityDualStack:
    def test_dual_stack(self):
        hr = HostReachability(
            hostname="server",
            active_ips=("10.1.10.1", "2001:db8::1"),
        )
        assert hr.is_up is True
        assert hr.active_ipv4 == ("10.1.10.1",)
        assert hr.active_ipv6 == ("2001:db8::1",)
        assert hr.has_ipv4 is True
        assert hr.has_ipv6 is True
        assert hr.reachability_mode == "dual-stack"

    def test_ipv4_only(self):
        hr = HostReachability(
            hostname="server",
            active_ips=("10.1.10.1",),
        )
        assert hr.reachability_mode == "ipv4-only"
        assert hr.has_ipv4 is True
        assert hr.has_ipv6 is False

    def test_ipv6_only(self):
        hr = HostReachability(
            hostname="server",
            active_ips=("2001:db8::1",),
        )
        assert hr.reachability_mode == "ipv6-only"
        assert hr.has_ipv4 is False
        assert hr.has_ipv6 is True

    def test_unreachable(self):
        hr = HostReachability(hostname="server")
        assert hr.reachability_mode == "unreachable"
        assert hr.has_ipv4 is False
        assert hr.has_ipv6 is False

    def test_multiple_ipv4_and_ipv6(self):
        hr = HostReachability(
            hostname="server",
            active_ips=("10.1.10.1", "10.1.20.1", "2001:db8::1", "2001:db8::2"),
        )
        assert hr.active_ipv4 == ("10.1.10.1", "10.1.20.1")
        assert hr.active_ipv6 == ("2001:db8::1", "2001:db8::2")
        assert hr.reachability_mode == "dual-stack"

    def test_interfaces_field(self):
        ir = InterfaceReachability(pings=(("10.1.10.1", PingResult(10, 10)),))
        hr = HostReachability(
            hostname="server",
            active_ips=("10.1.10.1",),
            interfaces=(ir,),
        )
        assert len(hr.interfaces) == 1
        assert hr.interfaces[0].active_ips == ("10.1.10.1",)


class TestCheckAllHostsDualStack:
    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_both_v4_and_v6_pinged(self, mock_reachable):
        """Host with IPv6 should have both v4 and v6 pinged."""
        mock_reachable.return_value = PingResult(10, 10, 1.0)
        host = _make_host("server", "10.1.10.1", ipv6_addrs=["2001:db8::1"])

        result = check_all_hosts_reachability([host])

        assert result["server"].is_up is True
        assert "10.1.10.1" in result["server"].active_ips
        assert "2001:db8::1" in result["server"].active_ips
        # Should have been called for both IPs
        assert mock_reachable.call_count == 2

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_v4_up_v6_down(self, mock_reachable):
        """IPv4 reachable but IPv6 not — should be ipv4-only."""
        def side_effect(ip):
            if ":" in ip:
                return PingResult(10, 0)
            return PingResult(10, 10, 1.0)

        mock_reachable.side_effect = side_effect
        host = _make_host("server", "10.1.10.1", ipv6_addrs=["2001:db8::1"])

        result = check_all_hosts_reachability([host])

        assert result["server"].is_up is True
        assert result["server"].active_ips == ("10.1.10.1",)
        assert result["server"].reachability_mode == "ipv4-only"

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_v6_up_v4_down(self, mock_reachable):
        """IPv6 reachable but IPv4 not — should be ipv6-only."""
        def side_effect(ip):
            if ":" in ip:
                return PingResult(10, 10, 0.5)
            return PingResult(10, 0)

        mock_reachable.side_effect = side_effect
        host = _make_host("server", "10.1.10.1", ipv6_addrs=["2001:db8::1"])

        result = check_all_hosts_reachability([host])

        assert result["server"].is_up is True
        assert result["server"].active_ips == ("2001:db8::1",)
        assert result["server"].reachability_mode == "ipv6-only"

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_no_ipv6_only_v4_pinged(self, mock_reachable):
        """Host without IPv6 addresses should only have IPv4 pinged."""
        mock_reachable.return_value = PingResult(10, 10, 1.0)
        host = _make_host("server", "10.1.10.1")

        result = check_all_hosts_reachability([host])

        assert result["server"].active_ips == ("10.1.10.1",)
        mock_reachable.assert_called_once_with("10.1.10.1")

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_deduplication_across_v4_and_v6(self, mock_reachable):
        """Same IP on multiple interfaces should only be pinged once."""
        mock_reachable.return_value = PingResult(10, 10, 1.0)
        # Two interfaces with same IPv4 but different IPv6
        host = _make_multi_iface_host(
            "server",
            ["10.1.10.1", "10.1.10.1"],
            ipv6_per_iface={0: ["2001:db8::1"], 1: ["2001:db8::1"]},
        )

        check_all_hosts_reachability([host])

        # IPv4 and IPv6 each pinged once despite two interfaces
        pinged_ips = sorted(call.args[0] for call in mock_reachable.call_args_list)
        assert pinged_ips == ["10.1.10.1", "2001:db8::1"]

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_interface_reachability_populated(self, mock_reachable):
        """check_all_hosts_reachability should populate interfaces field."""
        mock_reachable.return_value = PingResult(10, 10, 1.0)
        host = _make_host("server", "10.1.10.1", ipv6_addrs=["2001:db8::1"])

        result = check_all_hosts_reachability([host])

        hr = result["server"]
        assert len(hr.interfaces) == 1
        assert len(hr.interfaces[0].pings) == 2
