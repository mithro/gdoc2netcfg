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
