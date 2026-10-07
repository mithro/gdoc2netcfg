from types import SimpleNamespace

from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.constraints.validators import validate_controls


def _rec(machine, controls="", sheet="iot", site="welland", row=1):
    return SimpleNamespace(
        sheet_name=sheet,
        machine=machine,
        site=site,
        row_number=row,
        extra={"Controls": controls} if controls else {},
    )


def _host(machine, hostname=None):
    return SimpleNamespace(machine_name=machine, hostname=hostname or machine)


def _site():
    return SimpleNamespace(name="welland", domain="welland.mithis.com")


def test_unresolved_controls_target_is_error():
    recs = [_rec("au-plug-3", "bar heater")]
    res = validate_controls(recs, [_host("au-plug-3")], _site())
    codes = [(v.code, v.severity) for v in res.violations]
    assert ("controls_unresolved", Severity.ERROR) in codes


def test_resolvable_controls_target_is_clean():
    recs = [_rec("au-plug-4", "desktop")]
    res = validate_controls(recs, [_host("au-plug-4"), _host("desktop")], _site())
    assert res.violations == []


def test_appliance_prefix_controls_is_valid():
    recs = [_rec("au-plug-3", "appliance: bar heater")]
    res = validate_controls(recs, [_host("au-plug-3")], _site())
    assert res.violations == []
