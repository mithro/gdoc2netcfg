"""Every device row must carry a Site value known to the Sites sheet.

A blank Site (site_missing) or an unrecognised value (site_unknown) is an
ERROR — the graceful sheet-contract replacement for the former hard ValueError
in ip_remap. Rows without a machine name (spacers/section labels) are skipped.
"""

from types import SimpleNamespace

from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.constraints.validators import validate_sites

ALL = ("welland", "monarto", "roam", "special")


def _rec(machine="d1", site="", ip="10.X.20.5", sheet="network", row=1):
    return SimpleNamespace(sheet_name=sheet, machine=machine, site=site,
                           row_number=row, ip=ip)


def _site(all_sites=ALL):
    return SimpleNamespace(all_sites=tuple(all_sites))


def test_blank_site_on_device_row_is_error():
    r = _rec(machine="d1", site="", ip="10.X.20.5")
    res = validate_sites([r], _site())
    assert [v.code for v in res.violations] == ["site_missing"]
    assert res.violations[0].severity is Severity.ERROR
    assert res.violations[0].field == "Site"


def test_unknown_value_is_error():
    r = _rec(machine="d1", site="back shed", ip="10.X.20.5")
    res = validate_sites([r], _site())
    assert [v.code for v in res.violations] == ["site_unknown"]
    assert res.violations[0].severity is Severity.ERROR


def test_valid_values_are_clean():
    recs = [_rec(machine="a", site="welland"), _rec(machine="b", site="monarto"),
            _rec(machine="c", site="roam"), _rec(machine="d", site="special")]
    assert validate_sites(recs, _site()).violations == []


def test_capitalised_valid_value_is_not_unknown():
    # The membership check lowercases first, so "Welland" is valid, not unknown.
    r = _rec(machine="d1", site="Welland")
    assert validate_sites([r], _site()).violations == []


def test_blank_spacer_row_without_machine_is_ignored():
    # Section-header / spacer rows carry no machine and never become hosts.
    r = _rec(machine="", site="")
    assert validate_sites([r], _site()).violations == []


def test_blank_site_with_nonstandard_ip_still_errors():
    # The rule keys off blank Site + a machine, never the IP shape: a blank-Site
    # device with a tailscale 100.x literal is still site_missing.
    r = _rec(machine="laptop", site="", ip="100.110.251.12")
    assert [v.code for v in validate_sites([r], _site()).violations] \
        == ["site_missing"]


def test_no_sites_sheet_skips_site_validation_entirely():
    # No Sites sheet configured -> all_sites empty -> the documented historical
    # opt-out: neither blank nor unknown Site is flagged (matches the removed
    # ip_remap guard and cli.main._enrich_all_sites_from_sheet). Production
    # always has a populated Sites sheet, so the rule is in force there.
    assert validate_sites([_rec(machine="d1", site="")],
                          _site(all_sites=())).violations == []
    assert validate_sites([_rec(machine="d1", site="whatever")],
                          _site(all_sites=())).violations == []
