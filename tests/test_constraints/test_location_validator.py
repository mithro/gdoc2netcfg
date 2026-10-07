from types import SimpleNamespace

from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.constraints.validators import validate_locations


def _rec(machine, loc, key="Physical Location", sheet="iot", row=1):
    return SimpleNamespace(
        sheet_name=sheet, machine=machine, row_number=row, extra={key: loc}
    )


def test_confusable_locations_are_error():
    recs = [_rec("a", "Sound Proof Rack"), _rec("b", "Soundproof Rack", row=2)]
    res = validate_locations(recs)
    assert any(
        v.code == "location_confusable" and v.severity == Severity.ERROR
        for v in res.violations
    )


def test_consistent_locations_are_clean():
    recs = [
        _rec("a", "Back Shed - Soundproof Rack"),
        _rec("b", "Back Shed - Soundproof Rack", row=2),
    ]
    assert validate_locations(recs).violations == []


def test_network_location_column_also_checked():
    recs = [
        _rec("a", "Server Room", key="Location", sheet="network"),
        _rec("b", "server  room", key="Location", sheet="network", row=2),
    ]
    assert any(v.code == "location_confusable" for v in validate_locations(recs).violations)


def test_trailing_whitespace_is_not_confusable():
    # Leading/trailing whitespace parses to the SAME location path (the renderer
    # strips it), so it must NOT be an ERROR that blocks generate.
    recs = [_rec("a", "Back Shed"), _rec("b", "Back Shed ", row=2)]
    assert validate_locations(recs).violations == []


def test_separator_spacing_is_not_confusable():
    # Extra spaces around the ' - ' separator parse to the same path too.
    recs = [_rec("a", "Back Shed - Rack"), _rec("b", "Back Shed -  Rack", row=2)]
    assert validate_locations(recs).violations == []
