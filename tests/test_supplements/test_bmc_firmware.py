"""Tests for the BMC firmware supplement."""

from unittest.mock import patch

from gdoc2netcfg.derivations.hardware import (
    HARDWARE_SUPERMICRO_BMC,
    HARDWARE_SUPERMICRO_BMC_LEGACY,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.bmc_firmware import (
    _extract_series,
    _is_snmp_capable,
    _parse_mc_info,
    _try_ipmi_credentials,
    enrich_hosts_with_bmc_firmware,
    load_bmc_firmware_cache,
    refine_bmc_hardware_type,
    save_bmc_firmware_cache,
    scan_bmc_firmware,
)
from gdoc2netcfg.supplements.reachability import HostReachability


def _make_host(
    hostname="bmc.server",
    ip="10.1.5.10",
    hardware_type=HARDWARE_SUPERMICRO_BMC,
    extra=None,
):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("ac:1f:6b:00:11:22"),
                ip_addresses=(IPv4Address(ip),),
                dhcp_name=hostname,
            ),
        ],
        hardware_type=hardware_type,
        extra=extra or {},
    )


# Real ipmitool mc info output from an X11 BMC
X11_MC_INFO = """\
Device ID                 : 32
Device Revision           : 1
Firmware Revision         : 1.74
IPMI Version              : 2.0
Manufacturer ID           : 47488
Manufacturer Name         : Supermicro
Product ID                : 2404 (0x0964)
Product Name              : X11SPM-T(P)F
Device Available          : yes
Provides Device SDRs      : yes
Additional Device Support :
    Sensor Device
    SDR Repository Device
    SEL Device
    FRU Inventory Device
    IPMB Event Receiver
    IPMB Event Generator
    Chassis Device
Aux Firmware Rev Info     :
    0x00
    0x00
    0x00
    0x00
"""

# Real ipmitool mc info output from an X9 BMC
X9_MC_INFO = """\
Device ID                 : 32
Device Revision           : 1
Firmware Revision         : 3.40
IPMI Version              : 2.0
Manufacturer ID           : 47488
Manufacturer Name         : Supermicro
Product ID                : 1566 (0x061e)
Product Name              : X9SCV-LN4F+
Device Available          : yes
Provides Device SDRs      : yes
Additional Device Support :
    Sensor Device
    SDR Repository Device
    SEL Device
    FRU Inventory Device
    IPMB Event Receiver
    IPMB Event Generator
    Chassis Device
Aux Firmware Rev Info     :
    0x00
    0x00
    0x00
    0x00
"""


class TestParseMcInfo:
    def test_parse_x11_output(self):
        result = _parse_mc_info(X11_MC_INFO)
        assert result is not None
        assert result["Product Name"] == "X11SPM-T(P)F"
        assert result["Firmware Revision"] == "1.74"
        assert result["IPMI Version"] == "2.0"
        assert result["Manufacturer Name"] == "Supermicro"

    def test_parse_x9_output(self):
        result = _parse_mc_info(X9_MC_INFO)
        assert result is not None
        assert result["Product Name"] == "X9SCV-LN4F+"
        assert result["Firmware Revision"] == "3.40"

    def test_parse_empty_output(self):
        assert _parse_mc_info("") is None

    def test_parse_garbage_output(self):
        assert _parse_mc_info("Connection timed out\n") is None


class TestExtractSeries:
    def test_x11(self):
        assert _extract_series("X11SPM-T(P)F") == 11

    def test_x9(self):
        assert _extract_series("X9SCV-LN4F+") == 9

    def test_x10(self):
        assert _extract_series("X10SRi-F") == 10

    def test_x12(self):
        assert _extract_series("X12SPL-F") == 12

    def test_x13(self):
        assert _extract_series("X13SEI-TF") == 13

    def test_no_match(self):
        assert _extract_series("Unknown") is None

    def test_empty_string(self):
        assert _extract_series("") is None


class TestIsSnmpCapable:
    def test_series_11_capable(self):
        assert _is_snmp_capable(11) is True

    def test_series_10_capable(self):
        assert _is_snmp_capable(10) is True

    def test_series_12_capable(self):
        assert _is_snmp_capable(12) is True

    def test_series_9_not_capable(self):
        assert _is_snmp_capable(9) is False

    def test_series_8_not_capable(self):
        assert _is_snmp_capable(8) is False

    def test_none_conservatively_capable(self):
        assert _is_snmp_capable(None) is True


class TestBMCFirmwareCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_bmc_firmware_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "bmc_firmware.json"
        data = {
            "bmc.server": {
                "product_name": "X11SPM-T(P)F",
                "firmware_revision": "1.74",
                "ipmi_version": "2.0",
                "series": 11,
                "snmp_capable": True,
            }
        }
        save_bmc_firmware_cache(cache_path, data)
        loaded = load_bmc_firmware_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "bmc_firmware.json"
        save_bmc_firmware_cache(cache_path, {"host": {}})
        assert cache_path.exists()


class TestEnrichHostsWithBMCFirmware:
    def test_enriches_matching_host(self):
        hosts = [_make_host("bmc.server")]
        fw_cache = {
            "bmc.server": {
                "product_name": "X11SPM-T(P)F",
                "firmware_revision": "1.74",
                "ipmi_version": "2.0",
                "series": 11,
                "snmp_capable": True,
            }
        }
        enrich_hosts_with_bmc_firmware(hosts, fw_cache)

        info = hosts[0].bmc_firmware_info
        assert info is not None
        assert info.product_name == "X11SPM-T(P)F"
        assert info.firmware_revision == "1.74"
        assert info.ipmi_version == "2.0"
        assert info.series == 11
        assert info.snmp_capable is True

    def test_no_cache_entry(self):
        hosts = [_make_host("bmc.other")]
        enrich_hosts_with_bmc_firmware(hosts, {})
        assert hosts[0].bmc_firmware_info is None

    def test_enrich_creates_frozen_instance(self):
        hosts = [_make_host()]
        fw_cache = {
            "bmc.server": {
                "product_name": "X11SPM-T(P)F",
                "firmware_revision": "1.74",
                "ipmi_version": "2.0",
                "series": 11,
                "snmp_capable": True,
            }
        }
        enrich_hosts_with_bmc_firmware(hosts, fw_cache)
        info = hosts[0].bmc_firmware_info
        assert info is not None
        try:
            info.product_name = "modified"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestRefineBMCHardwareType:
    def test_x9_reclassified_as_legacy(self):
        hosts = [_make_host()]
        fw_cache = {
            "bmc.server": {
                "product_name": "X9SCV-LN4F+",
                "firmware_revision": "3.40",
                "ipmi_version": "2.0",
                "series": 9,
                "snmp_capable": False,
            }
        }
        enrich_hosts_with_bmc_firmware(hosts, fw_cache)
        refine_bmc_hardware_type(hosts)
        assert hosts[0].hardware_type == HARDWARE_SUPERMICRO_BMC_LEGACY

    def test_x11_stays_as_bmc(self):
        hosts = [_make_host()]
        fw_cache = {
            "bmc.server": {
                "product_name": "X11SPM-T(P)F",
                "firmware_revision": "1.74",
                "ipmi_version": "2.0",
                "series": 11,
                "snmp_capable": True,
            }
        }
        enrich_hosts_with_bmc_firmware(hosts, fw_cache)
        refine_bmc_hardware_type(hosts)
        assert hosts[0].hardware_type == HARDWARE_SUPERMICRO_BMC

    def test_no_firmware_info_stays_as_bmc(self):
        hosts = [_make_host()]
        refine_bmc_hardware_type(hosts)
        assert hosts[0].hardware_type == HARDWARE_SUPERMICRO_BMC

    def test_non_bmc_host_unaffected(self):
        hosts = [_make_host(hardware_type="netgear-switch")]
        refine_bmc_hardware_type(hosts)
        assert hosts[0].hardware_type == "netgear-switch"


class TestTryIPMICredentials:
    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_default_credentials_succeed(self, mock_run):
        mock_run.return_value = {
            "Product Name": "X11SPM-T(P)F",
            "Firmware Revision": "1.74",
            "IPMI Version": "2.0",
        }
        host = _make_host()
        result = _try_ipmi_credentials("10.1.5.10", host)

        assert result is not None
        assert result["Product Name"] == "X11SPM-T(P)F"
        mock_run.assert_called_once_with("10.1.5.10", "ADMIN", "ADMIN")

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_fallback_to_custom_credentials(self, mock_run):
        # Default ADMIN/ADMIN fails, custom succeeds
        mock_run.side_effect = [
            None,
            {"Product Name": "X11SPM-T(P)F", "Firmware Revision": "1.74", "IPMI Version": "2.0"},
        ]
        host = _make_host(extra={"IPMI Username": "root", "IPMI Password": "secret"})
        result = _try_ipmi_credentials("10.1.5.10", host)

        assert result is not None
        assert mock_run.call_count == 2
        mock_run.assert_any_call("10.1.5.10", "ADMIN", "ADMIN")
        mock_run.assert_any_call("10.1.5.10", "root", "secret")

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_all_credentials_fail(self, mock_run):
        mock_run.return_value = None
        host = _make_host()
        result = _try_ipmi_credentials("10.1.5.10", host)
        assert result is None

    @patch("gdoc2netcfg.supplements.bmc_firmware._run_ipmitool_mc_info")
    def test_skips_duplicate_credentials(self, mock_run):
        """If custom creds are ADMIN/ADMIN, don't try twice."""
        mock_run.return_value = None
        host = _make_host(extra={"IPMI Username": "ADMIN", "IPMI Password": "ADMIN"})
        result = _try_ipmi_credentials("10.1.5.10", host)

        assert result is None
        assert mock_run.call_count == 1


class TestScanBMCFirmware:
    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_scan_finds_firmware(self, mock_try, tmp_path):
        mock_try.return_value = {
            "Product Name": "X11SPM-T(P)F",
            "Firmware Revision": "1.74",
            "IPMI Version": "2.0",
        }
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server", active_ips=("10.1.5.10",),
            ),
        }
        host = _make_host()
        result = scan_bmc_firmware(
            [host], {}, reachability=reachability,
        )

        assert "bmc.server" in result
        assert result["bmc.server"]["product_name"] == "X11SPM-T(P)F"
        assert result["bmc.server"]["series"] == 11
        assert result["bmc.server"]["snmp_capable"] is True
        mock_try.assert_called_once()

    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_scan_x9_firmware(self, mock_try, tmp_path):
        mock_try.return_value = {
            "Product Name": "X9SCV-LN4F+",
            "Firmware Revision": "3.40",
            "IPMI Version": "2.0",
        }
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server", active_ips=("10.1.5.10",),
            ),
        }
        host = _make_host()
        result = scan_bmc_firmware(
            [host], {}, reachability=reachability,
        )

        assert result["bmc.server"]["series"] == 9
        assert result["bmc.server"]["snmp_capable"] is False

    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_scan_skips_non_bmc_hosts(self, mock_try, tmp_path):
        host = _make_host(hardware_type="netgear-switch")
        result = scan_bmc_firmware([host], {})

        assert result == {}
        mock_try.assert_not_called()

    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_scan_skips_unreachable(self, mock_try, tmp_path):
        reachability = {
            "bmc.server": HostReachability(hostname="bmc.server", active_ips=()),
        }
        host = _make_host()
        result = scan_bmc_firmware(
            [host], {}, reachability=reachability,
        )

        assert result == {}
        mock_try.assert_not_called()

    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_scan_uses_reachable_ip(self, mock_try, tmp_path):
        mock_try.return_value = {
            "Product Name": "X11SPM-T(P)F",
            "Firmware Revision": "1.74",
            "IPMI Version": "2.0",
        }
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server", active_ips=("10.1.5.10",),
            ),
        }
        host = _make_host()
        scan_bmc_firmware(
            [host], {}, reachability=reachability,
        )

        call_args = mock_try.call_args
        assert call_args[0][0] == "10.1.5.10"

    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_scan_merges_baseline(self, mock_try):
        """Fresh results merge over the baseline; unscanned hosts persist."""
        mock_try.return_value = {
            "Product Name": "X11SPM-T(P)F",
            "Firmware Revision": "1.74",
            "IPMI Version": "2.0",
        }
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server", active_ips=("10.1.5.10",),
            ),
        }
        host = _make_host()
        baseline = {"bmc.other": {"product_name": "X9", "series": 9}}

        result = scan_bmc_firmware(
            [host], baseline, reachability=reachability,
        )

        assert "bmc.server" in result
        assert result["bmc.other"] == {"product_name": "X9", "series": 9}
        # The input baseline is not mutated.
        assert "bmc.server" not in baseline

    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_scan_no_ipmi_response(self, mock_try, tmp_path):
        mock_try.return_value = None
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server", active_ips=("10.1.5.10",),
            ),
        }
        host = _make_host()
        result = scan_bmc_firmware(
            [host], {}, reachability=reachability,
        )

        assert "bmc.server" not in result


class TestScanBMCFirmwareMultiIP:
    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_tries_all_ips_until_success(self, mock_try, tmp_path):
        """Should try ipmitool on each reachable IP until one succeeds."""
        mock_try.side_effect = [
            None,
            {"Product Name": "X11SPM-T(P)F", "Firmware Revision": "1.74", "IPMI Version": "2.0"},
        ]
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server",
                active_ips=("10.1.5.10", "2001:db8::10"),
            ),
        }
        host = _make_host()
        result = scan_bmc_firmware(
            [host], {}, reachability=reachability,
        )

        assert "bmc.server" in result
        # Both IPs tried
        assert mock_try.call_count == 2

    @patch("gdoc2netcfg.supplements.bmc_firmware._try_ipmi_credentials")
    def test_stops_on_first_success(self, mock_try, tmp_path):
        """Should stop trying IPs after first ipmitool success."""
        mock_try.return_value = {
            "Product Name": "X11SPM-T(P)F",
            "Firmware Revision": "1.74",
            "IPMI Version": "2.0",
        }
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server",
                active_ips=("10.1.5.10", "2001:db8::10"),
            ),
        }
        host = _make_host()
        scan_bmc_firmware(
            [host], {}, reachability=reachability,
        )

        # Should only try first IP since it succeeded
        mock_try.assert_called_once()
