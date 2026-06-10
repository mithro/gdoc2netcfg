"""Tests for shared SNMP infrastructure."""

from unittest.mock import AsyncMock, patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.snmp_common import (
    try_snmp_credentials,
)


def _make_host(hostname="switch", ip="10.1.10.1", extra=None):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ip_addresses=(IPv4Address(ip),),
                dhcp_name=hostname,
            ),
        ],
        extra=extra or {},
    )


class TestTrySNMPCredentials:
    @patch("gdoc2netcfg.supplements.snmp_common.collect_snmp_tables", new_callable=AsyncMock)
    def test_public_community_succeeds(self, mock_collect):
        mock_collect.return_value = {
            "snmp_version": "v2c",
            "system_info": {"sysName": "device"},
        }
        host = _make_host()
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is not None
        assert result["system_info"]["sysName"] == "device"
        assert mock_collect.call_count == 1

    @patch("gdoc2netcfg.supplements.snmp_common.collect_snmp_tables", new_callable=AsyncMock)
    def test_fallback_to_custom_community(self, mock_collect):
        mock_collect.side_effect = [
            None,
            {"snmp_version": "v2c", "system_info": {"sysName": "device"}},
        ]
        host = _make_host(extra={"SNMP Community": "secret"})
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is not None
        assert mock_collect.call_count == 2

    @patch("gdoc2netcfg.supplements.snmp_common.collect_snmp_tables", new_callable=AsyncMock)
    def test_all_credentials_fail(self, mock_collect):
        mock_collect.return_value = None
        host = _make_host()
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is None

    @patch("gdoc2netcfg.supplements.snmp_common.collect_snmp_tables", new_callable=AsyncMock)
    def test_skips_duplicate_community(self, mock_collect):
        mock_collect.return_value = None
        host = _make_host(extra={"SNMP Community": "public"})
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is None
        assert mock_collect.call_count == 1
