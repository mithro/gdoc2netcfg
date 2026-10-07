from types import SimpleNamespace
from unittest.mock import patch

from gdoc2netcfg.cli.main import main


def _rec(machine, controls="", site="welland", sheet="IoT"):
    return SimpleNamespace(sheet_name=sheet, machine=machine, site=site,
                           extra={"Controls": controls} if controls else {})


def _host(machine):
    return SimpleNamespace(machine_name=machine, hostname=machine)


def _cfg():
    return SimpleNamespace(site=SimpleNamespace(name="welland",
                                                domain="welland.mithis.com"))


def _zrec(machine, controls, site="welland"):
    return SimpleNamespace(sheet_name="zigbee", machine=machine, site=site,
                           extra={"Controls": controls})


def _patchers(records, bridge=None, zigbee=()):
    return [
        patch("gdoc2netcfg.cli.main._load_config", return_value=_cfg()),
        patch("gdoc2netcfg.cli.main._build_pipeline",
              return_value=(records, [_host("desktop")], None, None)),
        patch("gdoc2netcfg.cli.main._load_latest_from_db", return_value=bridge),
        patch("gdoc2netcfg.cli.main._zigbee_controls_records",
              return_value=list(zigbee)),
    ]


def test_power_tree(capsys):
    recs = [_rec("mains-welland", "au-plug-4"), _rec("au-plug-4", "desktop")]
    ctx = _patchers(recs)
    for p in ctx:
        p.start()
    try:
        assert main(["power", "tree"]) == 0
    finally:
        for p in ctx:
            p.stop()
    out = capsys.readouterr().out
    assert "mains: mains-welland" in out
    assert "tasmota: au-plug-4" in out


def test_power_downstream(capsys):
    recs = [_rec("mains-welland", "au-plug-4"), _rec("au-plug-4", "desktop")]
    ctx = _patchers(recs)
    for p in ctx:
        p.start()
    try:
        assert main(["power", "downstream", "au-plug-4"]) == 0
    finally:
        for p in ctx:
            p.stop()
    assert "desktop" in capsys.readouterr().out


def test_power_tree_includes_zigbee(capsys):
    recs = [_rec("mains-welland", "au-plug-4"), _rec("au-plug-4", "desktop")]
    ctx = _patchers(recs, zigbee=[_zrec("Z5", "desktop")])
    for p in ctx:
        p.start()
    try:
        assert main(["power", "tree"]) == 0
    finally:
        for p in ctx:
            p.stop()
    assert "zigbee: Z5" in capsys.readouterr().out


def test_power_upstream_unknown_node_exit_1(capsys):
    ctx = _patchers([_rec("au-plug-4", "desktop")])
    for p in ctx:
        p.start()
    try:
        assert main(["power", "upstream", "nonexistent"]) == 1
    finally:
        for p in ctx:
            p.stop()
    assert "nonexistent" in capsys.readouterr().err


def _stale_bridge():
    return {"sw-ghost": {"port_names": [(1, "1/0/1")],
                         "poe_status": [(1, 1, 3)],
                         "lldp_neighbors": [(1, "desktop", "x", "y", None)]}}


def test_power_tree_refuses_on_stale_switch(capsys):
    recs = [_rec("au-plug-4", "desktop")]
    ctx = _patchers(recs, bridge=_stale_bridge())
    for p in ctx:
        p.start()
    try:
        assert main(["power", "tree"]) == 1
    finally:
        for p in ctx:
            p.stop()
    assert "stale" in capsys.readouterr().err.lower()


def test_power_tree_best_effort_renders_anyway(capsys):
    recs = [_rec("au-plug-4", "desktop")]
    ctx = _patchers(recs, bridge=_stale_bridge())
    for p in ctx:
        p.start()
    try:
        assert main(["power", "tree", "--best-effort"]) == 0
    finally:
        for p in ctx:
            p.stop()
    assert "mains: meter-welland" in capsys.readouterr().out
