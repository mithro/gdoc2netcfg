"""Tests for the Raspberry Pi hardware-identity supplement and its sheet rows."""

from __future__ import annotations

import json

import pytest

from gdoc2netcfg.models.addressing import MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.rpi_hardware import (
    RpiHardware,
    is_rpi_host,
    parse_probe_output,
    probe_script,
)
from gdoc2netcfg.supplements.rpi_hardware_sheet import (
    _EXPECTED_HEADER,
    record_to_row,
)

# A verbatim probe result from rpiz-serial on 2026-09-09, trimmed to the
# fields the parser reads plus the login banner the pool image prints.
_PROBE_STDOUT = "Password set for pi\n" + json.dumps({
    "model": "Raspberry Pi Zero W Rev 1.1",
    "verdict": {
        "header": ["Waveshare PoE-ETH-USB-HUB-HAT (1a40:0101 hub with RTL8152 on port 4)"],
        "power": "PoE through the Waveshare PoE-ETH-USB-HUB-HAT bonnet",
        "evidence": ["power port: throttled=0x0"],
        "fpga": [],
        "summary": {
            "model": "Raspberry Pi Zero W Rev 1.1",
            "serial": "000000005157f671",
            "revision": "9000c1",
            "header": ["Waveshare PoE-ETH-USB-HUB-HAT"],
            "power_class": "bonnet-poe",
            "fpga": [],
            "rtc_battery": None,
            "fan": None,
            "max_current_ma": None,
            "ext5v_v": None,
        },
    },
})


def _host(name: str, macs: list[str]) -> Host:
    return Host(
        machine_name=name, hostname=name,
        interfaces=[
            NetworkInterface(name=f"eth{i}", mac=MACAddress(m))
            for i, m in enumerate(macs)
        ],
    )


def test_probe_script_is_packaged():
    src = probe_script()
    assert src.startswith("#!/usr/bin/env python3")
    assert "def summary(" in src


def test_parse_probe_output_skips_banner_and_keeps_summary():
    rec = parse_probe_output(_PROBE_STDOUT, "tim")
    assert rec == RpiHardware(
        model="Raspberry Pi Zero W Rev 1.1", serial="000000005157f671",
        revision="9000c1", power_class="bonnet-poe",
        header=["Waveshare PoE-ETH-USB-HUB-HAT"], fpga=[],
        rtc_battery=None, fan=None, max_current_ma=None, probe_user="tim",
    )
    doc = rec.to_doc()
    assert RpiHardware.from_doc(doc) == rec
    assert "ext5v_v" not in doc, "the volatile input voltage is not stored"


def test_parse_probe_output_fpga_keeps_only_identity_keys():
    payload = json.loads(_PROBE_STDOUT.split("\n", 1)[1])
    payload["verdict"]["summary"]["fpga"] = [
        {"kind": "netv2", "dna": "0x00742c4e63b9085c", "idcode": "0x3631093",
         "how": "PCIe 10ee:7024", "slot": "0001:01:00.0"},
    ]
    rec = parse_probe_output(json.dumps(payload), "tim")
    assert rec.fpga == [{"kind": "netv2", "dna": "0x00742c4e63b9085c", "idcode": "0x3631093"}]


@pytest.mark.parametrize("stdout", ["", "no json here", '{"model": "x"}'])
def test_parse_probe_output_fails_loud(stdout: str):
    with pytest.raises(ValueError):
        parse_probe_output(stdout, "tim")


def test_is_rpi_host_by_oui_and_name():
    assert is_rpi_host(_host("rpi5-netv2", ["2c:cf:67:16:bd:98"]))
    assert is_rpi_host(_host("kiosk", ["b8:27:eb:0d:a9:1a"]))       # OUI, odd name
    assert is_rpi_host(_host("rpiz-dash-1", []))                    # name, no MAC yet
    assert not is_rpi_host(_host("ten64", ["0c:c4:7a:16:3b:4a"]))
    assert not is_rpi_host(_host("pi3.fpgas", ["b8:27:eb:00:00:01"]))  # pool rows excluded
    assert not is_rpi_host(_host("hifive1", ["b8:27:eb:00:00:02"]))


def test_record_to_row_matches_header():
    doc = {
        "model": "Raspberry Pi 5 Model B Rev 1.1", "serial": "c36b093f773d46b8",
        "revision": "a04171", "power_class": "gpio-poe-hat",
        "header": ["Waveshare PoE M.2 HAT+ (B)"],
        "fpga": [{"kind": "acorn"}], "rtc_battery": True, "fan": True,
        "max_current_ma": 3000, "probe_user": "pi",
    }
    row = record_to_row("welland", "pi-sw2-p47", doc)
    assert len(row) == len(_EXPECTED_HEADER)
    assert dict(zip(_EXPECTED_HEADER, row)) == {
        "Site": "welland", "Machine": "pi-sw2-p47", "Pi Serial": "c36b093f773d46b8",
        "Model": "Raspberry Pi 5 Model B Rev 1.1", "Rev Code": "a04171",
        "Header": "Waveshare PoE M.2 HAT+ (B)", "Power": "gpio-poe-hat",
        "FPGA": "acorn", "FPGA Identity": "", "RTC Battery": "yes", "Fan": "yes",
        "USB-C Limit mA": "3000", "Probe User": "pi",
    }


def test_record_to_row_blank_for_non_pi5_fields():
    doc = {
        "model": "Raspberry Pi 4 Model B Rev 1.5", "serial": "10000000ce8e3593",
        "revision": "b03115", "power_class": "undetermined",
        "header": ["Pmod HAT Adaptor"],
        "fpga": [{"kind": "arty", "serial": "210319B301DE"}], "rtc_battery": None,
        "fan": None, "max_current_ma": None, "probe_user": "pi",
    }
    row = dict(zip(_EXPECTED_HEADER, record_to_row("welland", "pi-sw2-p16", doc)))
    assert row["FPGA"] == "arty"
    assert row["FPGA Identity"] == "210319B301DE"
    assert row["RTC Battery"] == row["Fan"] == row["USB-C Limit mA"] == ""
