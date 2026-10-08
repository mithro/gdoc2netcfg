"""Tests for the site-missing conditional-format installer (pure logic only)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = (Path(__file__).resolve().parents[2] / "scripts"
           / "site-missing-format.py")
_spec = importlib.util.spec_from_file_location("site_missing_format", _SCRIPT)
site_missing_format = importlib.util.module_from_spec(_spec)
sys.modules["site_missing_format"] = site_missing_format
_spec.loader.exec_module(site_missing_format)

m = site_missing_format


def test_col_letter():
    assert m._col_letter(0) == "A"
    assert m._col_letter(6) == "G"
    assert m._col_letter(25) == "Z"
    assert m._col_letter(26) == "AA"


def test_header_info_network_layout():
    # network: an annotation row, then the header on row 2 (0-based idx 1).
    rows = [
        ["", "", "2404:e80:a137::"],
        ["Site", "Machine", "Interface", "Notes"],
        ["welland", "ten64", "mgmt", ""],
    ]
    assert m._header_info(rows) == (1, 0, 1)


def test_header_info_iot_layout():
    rows = [["Name", "Device ID", "MAC Address", "IP", "Type", "Connection",
             "Site", "Physical Location", "Machine", "Human Name"]]
    assert m._header_info(rows) == (0, 6, 8)


def test_header_info_falls_back_to_name_when_no_machine():
    rows = [["Site", "Name", "IP"]]
    assert m._header_info(rows) == (0, 0, 1)


def test_header_info_raises_without_site():
    import pytest
    with pytest.raises(ValueError, match="no header row"):
        m._header_info([["Foo", "Bar"], ["a", "b"]])


def test_header_info_raises_site_without_machine():
    import pytest
    with pytest.raises(ValueError, match="no machine column"):
        m._header_info([["Site", "IP", "Notes"]])


def test_rule_formula_anchors_at_first_data_row():
    # network: machine col B (1), site col A (0), first data row 3.
    assert m._rule_formula(1, 0, 3) == '=AND($B3<>"",$A3="")'
    # iot: machine col I (8), site col G (6), first data row 2.
    assert m._rule_formula(8, 6, 2) == '=AND($I2<>"",$G2="")'


def test_our_rule_regex_matches_our_shape_only():
    assert m._OUR_RULE_RE.match('=AND($B3<>"",$A3="")')
    assert m._OUR_RULE_RE.match('=AND($I2<>"",$G2="")')
    # A different rule (e.g. a hand-made highlight) must NOT be claimed as ours.
    assert not m._OUR_RULE_RE.match('=$A3="welland"')
    assert not m._OUR_RULE_RE.match('=ISBLANK($A3)')


def test_our_rule_indices_finds_only_our_rules_descending():
    cfs = [
        {"booleanRule": {"condition": {"type": "CUSTOM_FORMULA", "values": [
            {"userEnteredValue": '=AND($B3<>"",$A3="")'}]}}},
        {"booleanRule": {"condition": {"type": "CUSTOM_FORMULA", "values": [
            {"userEnteredValue": '=$A3="welland"'}]}}},  # someone else's rule
        {"booleanRule": {"condition": {"type": "CUSTOM_FORMULA", "values": [
            {"userEnteredValue": '=AND($I2<>"", $G2="")'}]}}},  # spaces ok
        {"gradientRule": {}},  # not a boolean rule at all
    ]
    # Indices 0 and 2 are ours; returned high-to-low for safe deletion.
    assert m._our_rule_indices(cfs) == [2, 0]


def test_requests_for_tab_deletes_then_adds():
    rows = [["x"], ["Site", "Machine", "Interface"], ["welland", "ten64", ""]]
    existing = [
        {"booleanRule": {"condition": {"type": "CUSTOM_FORMULA", "values": [
            {"userEnteredValue": '=AND($B3<>"",$A3="")'}]}}},
    ]
    reqs = m._requests_for_tab(1476589425, rows, existing)
    # One delete (the pre-existing rule of ours) then one add.
    assert [list(r)[0] for r in reqs] == ["deleteConditionalFormatRule",
                                          "addConditionalFormatRule"]
    add = reqs[-1]["addConditionalFormatRule"]
    assert add["index"] == 0
    rng = add["rule"]["ranges"][0]
    assert rng == {"sheetId": 1476589425, "startRowIndex": 2,
                   "startColumnIndex": 0, "endColumnIndex": 1}
    cond = add["rule"]["booleanRule"]["condition"]
    assert cond["values"][0]["userEnteredValue"] == '=AND($B3<>"",$A3="")'
    # Red background flagged as an error colour.
    assert add["rule"]["booleanRule"]["format"]["backgroundColor"]["red"] > 0.8
