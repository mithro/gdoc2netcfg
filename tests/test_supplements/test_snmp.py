"""Tests for the SNMP supplement."""

from unittest.mock import AsyncMock, patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.snmp import (
    _dict_to_tuples,
    _row_list_to_tuples,
    _rows_from_walk,
    enrich_hosts_with_snmp,
    load_snmp_cache,
    save_snmp_cache,
    scan_snmp,
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


class TestSNMPCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_snmp_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "snmp.json"
        data = {
            "switch": {
                "snmp_version": "v2c",
                "system_info": {"sysName": "switch-1"},
                "interfaces": [],
                "ip_addresses": [],
                "raw": {},
            }
        }
        save_snmp_cache(cache_path, data)
        loaded = load_snmp_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "snmp.json"
        save_snmp_cache(cache_path, {"host": {"snmp_version": "v2c"}})
        assert cache_path.exists()


class TestRowsFromWalk:
    def test_empty_input(self):
        assert _rows_from_walk([]) == []

    def test_single_row(self):
        walk = [
            ("1.3.6.1.2.1.2.2.1.1.1", "1"),
            ("1.3.6.1.2.1.2.2.1.2.1", "eth0"),
        ]
        rows = _rows_from_walk(walk)
        assert len(rows) == 1
        # Both columns share index "1"
        assert "1.3.6.1.2.1.2.2.1.1" in rows[0]
        assert "1.3.6.1.2.1.2.2.1.2" in rows[0]

    def test_multiple_rows(self):
        walk = [
            ("1.3.6.1.2.1.2.2.1.1.1", "1"),
            ("1.3.6.1.2.1.2.2.1.1.2", "2"),
            ("1.3.6.1.2.1.2.2.1.2.1", "eth0"),
            ("1.3.6.1.2.1.2.2.1.2.2", "eth1"),
        ]
        rows = _rows_from_walk(walk)
        assert len(rows) == 2


class TestConversionHelpers:
    def test_dict_to_tuples(self):
        result = _dict_to_tuples({"a": "1", "b": "2"})
        assert ("a", "1") in result
        assert ("b", "2") in result

    def test_dict_to_tuples_empty(self):
        assert _dict_to_tuples({}) == ()

    def test_row_list_to_tuples(self):
        rows = [{"col1": "val1"}, {"col2": "val2"}]
        result = _row_list_to_tuples(rows)
        assert len(result) == 2
        assert result[0] == (("col1", "val1"),)
        assert result[1] == (("col2", "val2"),)

    def test_row_list_to_tuples_empty(self):
        assert _row_list_to_tuples([]) == ()


class TestEnrichHostsWithSNMP:
    def test_enriches_matching_hosts(self):
        hosts = [_make_host("switch", "10.1.10.1"), _make_host("desktop", "10.1.10.2")]
        snmp_cache = {
            "switch": {
                "snmp_version": "v2c",
                "system_info": {"sysName": "switch-1"},
                "interfaces": [{"ifIndex": "1", "ifDescr": "eth0"}],
                "ip_addresses": [],
                "raw": {"1.3.6.1.2.1.1.5.0": "switch-1"},
            }
        }
        enrich_hosts_with_snmp(hosts, snmp_cache)

        assert hosts[0].snmp_data is not None
        assert hosts[0].snmp_data.snmp_version == "v2c"
        assert ("sysName", "switch-1") in hosts[0].snmp_data.system_info
        assert len(hosts[0].snmp_data.interfaces) == 1
        assert hosts[1].snmp_data is None

    def test_no_snmp_data(self):
        hosts = [_make_host()]
        enrich_hosts_with_snmp(hosts, {})
        assert hosts[0].snmp_data is None

    def test_enrich_creates_immutable_snmpdata(self):
        hosts = [_make_host()]
        snmp_cache = {
            "switch": {
                "snmp_version": "v2c",
                "system_info": {"sysName": "sw"},
                "interfaces": [],
                "ip_addresses": [],
                "raw": {},
            }
        }
        enrich_hosts_with_snmp(hosts, snmp_cache)
        data = hosts[0].snmp_data
        assert data is not None
        try:
            data.snmp_version = "v3"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestScanSNMP:
    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_scan_finds_snmp(self, mock_try, tmp_path):
        mock_try.return_value = {
            "snmp_version": "v2c",
            "system_info": {"sysName": "switch-1"},
            "interfaces": [],
            "ip_addresses": [],
            "raw": {},
        }
        reachability = {
            "switch": HostReachability(
                hostname="switch", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host()
        result = scan_snmp(
            [host], {}, reachability=reachability,
        )

        assert "switch" in result
        assert result["switch"]["system_info"]["sysName"] == "switch-1"
        mock_try.assert_called_once()

    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_scan_skips_unreachable_with_reachability(self, mock_try, tmp_path):
        reachability = {
            "switch": HostReachability(hostname="switch", active_ips=()),
        }
        host = _make_host()
        result = scan_snmp([host], {}, reachability=reachability)

        assert result == {}
        mock_try.assert_not_called()

    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_scan_uses_reachable_ip(self, mock_try, tmp_path):
        mock_try.return_value = {
            "snmp_version": "v2c",
            "system_info": {},
            "interfaces": [],
            "ip_addresses": [],
            "raw": {},
        }
        reachability = {
            "switch": HostReachability(
                hostname="switch", active_ips=("10.1.10.1",)
            ),
        }
        host = _make_host()
        scan_snmp([host], {}, reachability=reachability)

        # Should have been called with the reachable IP
        call_args = mock_try.call_args
        assert call_args[0][0] == "10.1.10.1"

    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_scan_merges_baseline(self, mock_try):
        """Fresh results merge over the baseline; unscanned hosts persist."""
        mock_try.return_value = {
            "snmp_version": "v2c",
            "system_info": {"sysName": "sw"},
            "interfaces": [],
            "ip_addresses": [],
            "raw": {},
        }
        reachability = {
            "switch": HostReachability(
                hostname="switch", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host()
        baseline = {"other-switch": {"snmp_version": "v2c"}}

        result = scan_snmp(
            [host], baseline, reachability=reachability,
        )

        assert "switch" in result
        assert result["other-switch"] == {"snmp_version": "v2c"}
        # The input baseline is not mutated.
        assert "switch" not in baseline

    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_scan_no_snmp_response(self, mock_try, tmp_path):
        mock_try.return_value = None
        reachability = {
            "switch": HostReachability(
                hostname="switch", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host()
        result = scan_snmp(
            [host], {}, reachability=reachability,
        )

        assert "switch" not in result

    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_scan_skips_without_reachability(self, mock_try, tmp_path):
        """Without reachability data, hosts are skipped."""
        host = _make_host()
        result = scan_snmp([host], {}, reachability=None)

        assert result == {}
        mock_try.assert_not_called()


class TestTrySNMPCredentials:
    @patch("gdoc2netcfg.supplements.snmp._collect_snmp_data", new_callable=AsyncMock)
    def test_public_community_succeeds(self, mock_collect):
        mock_collect.return_value = {
            "snmp_version": "v2c",
            "system_info": {"sysName": "device"},
        }
        from gdoc2netcfg.supplements.snmp import _try_snmp_credentials

        host = _make_host()
        result = _try_snmp_credentials("10.1.10.1", host)

        assert result is not None
        assert result["system_info"]["sysName"] == "device"
        # Should only have tried once (public succeeded)
        assert mock_collect.call_count == 1

    @patch("gdoc2netcfg.supplements.snmp._collect_snmp_data", new_callable=AsyncMock)
    def test_fallback_to_custom_community(self, mock_collect):
        # First call (public) fails, second call (custom) succeeds
        mock_collect.side_effect = [
            None,
            {"snmp_version": "v2c", "system_info": {"sysName": "device"}},
        ]
        from gdoc2netcfg.supplements.snmp import _try_snmp_credentials

        host = _make_host(extra={"SNMP Community": "secret"})
        result = _try_snmp_credentials("10.1.10.1", host)

        assert result is not None
        assert mock_collect.call_count == 2

    @patch("gdoc2netcfg.supplements.snmp._collect_snmp_data", new_callable=AsyncMock)
    def test_all_credentials_fail(self, mock_collect):
        mock_collect.return_value = None
        from gdoc2netcfg.supplements.snmp import _try_snmp_credentials

        host = _make_host()
        result = _try_snmp_credentials("10.1.10.1", host)

        assert result is None

    @patch("gdoc2netcfg.supplements.snmp._collect_snmp_data", new_callable=AsyncMock)
    def test_skips_duplicate_community(self, mock_collect):
        """If custom community is 'public', don't try it twice."""
        mock_collect.return_value = None
        from gdoc2netcfg.supplements.snmp import _try_snmp_credentials

        host = _make_host(extra={"SNMP Community": "public"})
        result = _try_snmp_credentials("10.1.10.1", host)

        assert result is None
        # Should only try once — "public" custom == "public" default
        assert mock_collect.call_count == 1


class TestScanSNMPMultiIP:
    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_tries_all_ips_until_success(self, mock_try, tmp_path):
        """Should try SNMP on each reachable IP until one succeeds."""
        # First IP fails, second succeeds
        mock_try.side_effect = [
            None,
            {"snmp_version": "v2c", "system_info": {"sysName": "switch"}},
        ]
        reachability = {
            "switch": HostReachability(
                hostname="switch",
                active_ips=("10.1.10.1", "2001:db8::1"),
            ),
        }
        host = _make_host("switch", "10.1.10.1")
        result = scan_snmp(
            [host], {}, reachability=reachability,
        )

        assert "switch" in result
        # Both IPs tried
        assert mock_try.call_count == 2
        assert mock_try.call_args_list[0].args[0] == "10.1.10.1"
        assert mock_try.call_args_list[1].args[0] == "2001:db8::1"

    @patch("gdoc2netcfg.supplements.snmp._try_snmp_credentials")
    def test_stops_on_first_success(self, mock_try, tmp_path):
        """Should stop trying IPs after the first SNMP success."""
        mock_try.return_value = {
            "snmp_version": "v2c",
            "system_info": {"sysName": "switch"},
        }
        reachability = {
            "switch": HostReachability(
                hostname="switch",
                active_ips=("10.1.10.1", "2001:db8::1"),
            ),
        }
        host = _make_host("switch", "10.1.10.1")
        scan_snmp(
            [host], {}, reachability=reachability,
        )

        # Should only try first IP since it succeeded
        mock_try.assert_called_once()
