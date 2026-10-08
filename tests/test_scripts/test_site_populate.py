"""Tests for the site_populate placement classifier (pure logic only)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "site_populate.py"
_spec = importlib.util.spec_from_file_location("site_populate", _SCRIPT)
site_populate = importlib.util.module_from_spec(_spec)
# Register before exec: the module defines dataclasses, and with
# `from __future__ import annotations` the dataclass machinery looks the
# module up in sys.modules by name to resolve its KW_ONLY sentinel check.
sys.modules["site_populate"] = site_populate
_spec.loader.exec_module(site_populate)

SiteEvidence = site_populate.SiteEvidence
classify_site = site_populate.classify_site


def ev(**kw):
    base = dict(machine="d", current_site="", ip="10.X.20.5",
                seen_welland=False, seen_monarto=False, on_roam_vlan=False)
    base.update(kw)
    return SiteEvidence(**base)


def test_seen_only_welland_is_welland():
    p = classify_site(ev(seen_welland=True))
    assert p.suggested == "welland" and p.confidence == "high"


def test_seen_only_monarto_is_monarto():
    p = classify_site(ev(seen_monarto=True))
    assert p.suggested == "monarto" and p.confidence == "high"


def test_seen_both_sites_is_roam():
    p = classify_site(ev(seen_welland=True, seen_monarto=True))
    assert p.suggested == "roam" and p.confidence == "high"


def test_on_roam_vlan_is_roam():
    p = classify_site(ev(on_roam_vlan=True))
    assert p.suggested == "roam"


def test_no_evidence_is_unknown_never_guessed():
    p = classify_site(ev())
    assert p.suggested is None and p.confidence == "unknown"


def test_roam_with_site_literal_ip_is_flagged():
    # seen at both (->roam) but carries a welland-only literal IP: contradiction
    p = classify_site(ev(seen_welland=True, seen_monarto=True, ip="10.1.20.5"))
    assert p.suggested == "roam"
    assert any("literal" in f.lower() for f in p.flags)


def test_existing_value_preserved_as_low_confidence_when_no_live_evidence():
    p = classify_site(ev(current_site="welland"))
    assert p.suggested == "welland" and p.confidence == "low"


def test_roam_octets_from_vlan_csv(tmp_path):
    p = tmp_path / "vlan_allocations.csv"
    p.write_text(
        "VLAN ID,VLAN Name,Subnet,Mask,CIDR,,,Colour,Notes\n"
        "10,int,10.X.10.X,255.255.255.0,/24,,,Grey,infra\n"
        "20,roam,10.X.20.X,255.255.255.0,/24,,,Purple,WiFi and wired hosts\n"
    )
    assert site_populate._roam_octets_from_csv(p, "roam") == {20}


def test_roam_octets_from_real_header(tmp_path):
    # The live VLAN Allocations CSV labels the subnet column "IP Range".
    p = tmp_path / "vlan_allocations.csv"
    p.write_text(
        "VLAN,Name,IP Range,Netmask,CIDR,,,Color,For\n"
        "10,int,10.X.10.X,255.255.248.0,/21,,,Blue,Internal wired hosts\n"
        "20,roam,10.X.20.X,255.255.255.0,/24,,,Purple,WiFi and wired hosts\n"
    )
    assert site_populate._roam_octets_from_csv(p, "roam") == {20}


def test_roam_octets_absent_vlan_is_empty(tmp_path):
    p = tmp_path / "vlan_allocations.csv"
    p.write_text("VLAN ID,VLAN Name,Subnet\n10,int,10.X.10.X\n")
    assert site_populate._roam_octets_from_csv(p, "roam") == set()


def test_norm_mac():
    assert site_populate._norm_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert site_populate._norm_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"
    assert site_populate._norm_mac("  aa:bb:cc:dd:ee:ff ") == "AA:BB:CC:DD:EE:FF"
    assert site_populate._norm_mac("none") is None
    assert site_populate._norm_mac("") is None


def test_base_machine_strips_aggregate_suffix():
    assert site_populate._base_machine("desktop - 12") == "desktop"
    assert site_populate._base_machine("big-storage - 15") == "big-storage"
    assert site_populate._base_machine("power9-a - 17") == "power9-a"
    assert site_populate._base_machine("desktop") == "desktop"
    assert site_populate._base_machine("left.nvmeof") == "left.nvmeof"


def test_residual_site_welland_rules():
    for m in ("sw-bb-100g", "ports.sw-bb-25g", "sw-netgear-m4300-16x-poe-s1",
              "sw-netgear-poe-micro1", "power9-a", "power9-b", "desktop",
              "left.nvmeof", "right.nvmeof", "hifive-unmatched-1", "dell-c410x-2",
              # Tim's 2026-10-08 second batch: AV, power, fritz-box, remaining
              # netgear switches, and gpu are all welland.
              "samsung-tv", "yamaha-receiver", "bluray-player",
              "hp-power", "ups-rack", "ups-test", "tplink-powerline",
              "fritz-box-7390-1", "fritz-box-7270-1",
              "sw-netgear-gsm7252ps-s3", "sw-netgear-s3300-2",
              "sw-netgear-gs110emx-dev", "gpu"):
        assert site_populate._residual_site(m) == "welland", m


def test_residual_site_carl_is_roam():
    for m in ("carl-laptop", "carl-twist", "carlfk-x1c", "carlfk-gw"):
        assert site_populate._residual_site(m) == "roam", m


def test_residual_site_pixel_is_roam():
    # All pixel phones roam (Tim 2026-10-08); case-insensitive (sheet mixes
    # "pixel6" and "Pixel-3a-XL").
    for m in ("pixel6", "pixel-7-pro", "pixel-3a-xl", "Pixel-3a-XL"):
        assert site_populate._residual_site(m) == "roam", m


def test_residual_site_kindle_dash_encodes_site_in_name():
    assert site_populate._residual_site("kindle-welland-dash") == "welland"
    assert site_populate._residual_site("kindle-monarto-dash") == "monarto"


def test_residual_site_unknown_stays_none():
    # Still unruled after the second batch: build-farm compute, home-automation
    # IoT, and non-pixel personal devices.
    for m in ("hls-fpga-node-2", "opi1pc-a", "qnap", "puck01", "big-storage",
              "opener1", "light3", "mac-mini", "sager-chromeosflex"):
        assert site_populate._residual_site(m) is None, m


def test_discovery_db_opened_read_only(monkeypatch):
    # The proposal is read-only: it must open discovery.db with read_only=True
    # (mode=ro), or a non-root run fails on the root-owned prod DB and a root
    # run takes write locks on the DB the reachability daemon is writing.
    import gdoc2netcfg.storage.discovery_db as dmod

    calls = {}

    class _Rec:
        def __init__(self, path, *, read_only=False):
            calls["path"], calls["read_only"] = path, read_only

    monkeypatch.setattr(dmod, "DiscoveryDB", _Rec)
    # A string path (e.g. argparse --monarto-db) must be coerced to Path, or
    # BaseDatabase._connect_read_only's db_path.exists() raises AttributeError.
    site_populate._open_readonly("some/discovery.db")
    assert calls == {"path": Path("some/discovery.db"), "read_only": True}
