"""`gdoc2netcfg interfaces` — read-only, cache-only listing of every interface
the sheet knows per machine, for cross-checking an independently maintained
copy of the same facts (issue #82: welland-ansible-rpi's network_interfaces).
"""
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from gdoc2netcfg.cli.main import main


def _rec(machine, interface, mac, ip="", site="welland", sheet="IoT", row=1,
         dns_only=False):
    return SimpleNamespace(sheet_name=sheet, row_number=row, machine=machine,
                           mac_address=mac, ip=ip, interface=interface,
                           site=site, dns_only=dns_only, extra={})


RECORDS = [
    _rec("rpi5-pmod", "eth0", "98:FE:54:13:F5:6E", "10.X.90.232", row=143),
    _rec("rpi5-pmod", "wlan0", "98:fe:54:13:f5:70", "10.X.90.233", row=144),
    _rec("rpi4-gwifi", "eth0", "dc:a6:32:05:a0:1c", "10.X.90.214", sheet="Network", row=61),
    _rec("rpi4-gwifi", "eth-glan", "00:e0:4c:68:00:7a", "", sheet="Network", row=63),
    _rec("rpi4-gwifi", "wlanE", "6c:1f:f7:51:29:74", "", sheet="Network", row=65),
    _rec("reterm1", "eth0", "2c:cf:67:bb:49:a1", "10.X.90.174", site="monarto", row=200),
    _rec("ten64", "wg0", "", "10.X.0.1", sheet="Network", row=5, dns_only=True),
    _rec("", "", "", "", row=9),                       # blank sheet row
    # a switch's default/only NIC: the sheet leaves the interface name empty
    _rec("sw-only", "", "aa:bb:cc:dd:ee:ff", "10.X.5.22", sheet="Network", row=7),
    # the IoT sheet cross-referencing a Network-sheet machine by IP only (no
    # MAC, no interface) — the pipeline's build_hosts treats such a row as a
    # reference to the MAC'd row, never as another interface
    _rec("rpi5-pmod", "", "", "10.X.90.232", sheet="IoT", row=300),
    _rec("rpi5-pmod", "", "", "10.X.90.233", sheet="IoT", row=301),
]


def _patchers(records=RECORDS):
    return [
        patch("gdoc2netcfg.cli.main._load_config",
              return_value=SimpleNamespace(site=SimpleNamespace(name="welland"))),
        patch("gdoc2netcfg.cli.main._sheet_records", return_value=list(records)),
    ]


@pytest.fixture
def patched():
    ctx = _patchers()
    for p in ctx:
        p.start()
    try:
        yield
    finally:
        for p in ctx:
            p.stop()


def test_json_groups_every_interface_by_machine_across_sites(patched, capsys):
    assert main(["interfaces", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) == {"rpi5-pmod", "rpi4-gwifi", "reterm1", "ten64", "sw-only"}
    assert doc["reterm1"]["site"] == "monarto"           # other-site machines included
    assert [i["name"] for i in doc["rpi4-gwifi"]["interfaces"]] == ["eth0", "eth-glan", "wlanE"]


def test_json_normalises_mac_and_keeps_raw_ip(patched, capsys):
    main(["interfaces", "--json", "rpi5-pmod"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["rpi5-pmod"]["interfaces"][0] == {
        "name": "eth0", "mac": "98:fe:54:13:f5:6e", "ip": "10.X.90.232",
        "dns_only": False, "sheet": "IoT", "row": 143,
    }


def test_ip_cross_reference_rows_are_folded_into_the_macced_interface(patched, capsys):
    """rpi5-pmod on the real sheet (2026-10-21): two IoT rows with only an IP
    duplicated the two MAC'd Network rows; reported as interfaces they would
    make every such host look like it has two undeclared NICs."""
    main(["interfaces", "--json", "rpi5-pmod"])
    doc = json.loads(capsys.readouterr().out)
    assert [i["name"] for i in doc["rpi5-pmod"]["interfaces"]] == ["eth0", "wlan0"]


def test_ip_only_row_without_a_macced_twin_is_kept(patched, capsys):
    # A genuine DNS-only endpoint whose IP no MAC'd row claims stays visible.
    main(["interfaces", "--json", "ten64"])
    doc = json.loads(capsys.readouterr().out)
    assert [i["name"] for i in doc["ten64"]["interfaces"]] == ["wg0"]


def test_dns_only_and_default_interface_rows(patched, capsys):
    main(["interfaces", "--json", "ten64", "sw-only"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["ten64"]["interfaces"] == [
        {"name": "wg0", "mac": "", "ip": "10.X.0.1", "dns_only": True,
         "sheet": "Network", "row": 5}]
    assert doc["sw-only"]["interfaces"][0]["name"] == ""   # the sheet's default/only NIC


def test_machine_filter_and_site_filter(patched, capsys):
    assert main(["interfaces", "--json", "--site", "monarto"]) == 0
    assert set(json.loads(capsys.readouterr().out)) == {"reterm1"}
    assert main(["interfaces", "--json", "rpi4-gwifi", "reterm1"]) == 0
    assert set(json.loads(capsys.readouterr().out)) == {"rpi4-gwifi", "reterm1"}


def test_unknown_machine_is_exit_1_not_an_empty_green_answer(patched, capsys):
    assert main(["interfaces", "--json", "rpi5-pmod", "no-such-box"]) == 1
    err = capsys.readouterr().err
    assert "no-such-box" in err


def test_text_mode_one_line_per_interface(patched, capsys):
    assert main(["interfaces", "rpi5-pmod"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == [
        "welland rpi5-pmod eth0 98:fe:54:13:f5:6e 10.X.90.232",
        "welland rpi5-pmod wlan0 98:fe:54:13:f5:70 10.X.90.233",
    ]


def test_sheet_records_reads_the_cache_only():
    """No fetch, no pipeline, no database: records come straight from the
    cached CSVs through the normal parser."""
    from gdoc2netcfg.cli import main as cli

    csv_text = ("Machine,MAC Address,IP,Interface,Site\n"
                "box,aa:bb:cc:dd:ee:01,10.X.90.5,eth0,welland\n")
    with patch("gdoc2netcfg.cli.main._fetch_or_load_csvs",
               return_value=[("IoT", csv_text)]) as fetch:
        recs = cli._sheet_records(SimpleNamespace())
    assert fetch.call_args.kwargs.get("use_cache") is True
    assert [(r.machine, r.interface, r.mac_address) for r in recs] == [
        ("box", "eth0", "aa:bb:cc:dd:ee:01")]


def test_metadata_only_rows_are_not_interfaces(capsys):
    """rpi5-rfbridge / rpi4-esp / rpicm1-serial on the real sheet (2026-10-21):
    an IoT row naming the machine with no interface, no MAC and no IP (plug /
    location metadata only) must not come back as an interface."""
    records = RECORDS + [_rec("rpi4-gwifi", "", "", "", sheet="IoT", row=170)]
    ctx = _patchers(records)
    for p in ctx:
        p.start()
    try:
        main(["interfaces", "--json", "rpi4-gwifi"])
    finally:
        for p in ctx:
            p.stop()
    doc = json.loads(capsys.readouterr().out)
    assert [i["name"] for i in doc["rpi4-gwifi"]["interfaces"]] == ["eth0", "eth-glan", "wlanE"]
