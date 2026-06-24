import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ha-create-reachability-dashboard.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("ha_dash_gen", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _host(machine, hostname, topic, controls=(), ipv4="10.1.91.10"):
    return SimpleNamespace(
        machine_name=machine,
        hostname=hostname,
        first_ipv4=ipv4,
        tasmota_data=SimpleNamespace(mqtt_topic=topic, controls=tuple(controls)),
    )


def test_is_plug(mod):
    assert mod._is_plug("au-plug-10")
    assert mod._is_plug("us-plug-2")
    assert not mod._is_plug("au-plug")       # no number
    assert not mod._is_plug("ir-ac-remote")  # not a plug
    assert not mod._is_plug("big-storage")


def test_select_plug_hosts_filters_and_sorts(mod):
    hosts = [
        _host("us-plug-2", "us-plug-2", "us_plug_2"),
        _host("au-plug-2", "au-plug-2.iot", "au-plug-2"),
        _host("au-plug-10", "au-plug-10.iot", "au-plug-10"),
        SimpleNamespace(machine_name="ir-ac-remote", hostname="ir-ac-remote",
                        first_ipv4=None, tasmota_data=SimpleNamespace(
                            mqtt_topic="ir-ac-remote", controls=())),
        SimpleNamespace(machine_name="big-storage", hostname="big-storage",
                        first_ipv4=None, tasmota_data=None),  # not tasmota
    ]
    out = mod._select_plug_hosts(hosts)
    assert [h.machine_name for h in out] == ["au-plug-2", "au-plug-10", "us-plug-2"]


def test_build_plug_data(mod):
    h = _host("au-plug-10", "au-plug-10.iot", "au-plug-10",
              controls=("rpiz-dash-1", "sw-bb-25g"), ipv4="10.1.91.10")
    d = mod._build_plug_data(h, "welland.mithis.com")
    assert d == {
        "machine": "au-plug-10",
        "topic": "au_plug_10",
        "nid": "au_plug_10_iot",
        "fqdn": "au-plug-10.iot.welland.mithis.com",
        "ipv4": "10.1.91.10",
        "controls": ["rpiz-dash-1", "sw-bb-25g"],
    }


def test_build_plug_data_no_ipv4(mod):
    h = _host("au-plug-99", "au-plug-99.iot", "au-plug-99", ipv4=None)
    assert mod._build_plug_data(h, "welland.mithis.com")["ipv4"] == ""


def test_verify_plug_entities_warns_on_missing(mod, capsys):
    plugs = [
        {"machine": "au-plug-10", "topic": "au_plug_10"},
        {"machine": "au-plug-99", "topic": "au_plug_99"},  # entities absent
    ]
    states = [
        {"entity_id": "switch.au_plug_10"},
        {"entity_id": "sensor.au_plug_10_energy_power"},
    ]
    warnings = mod._verify_plug_entities(plugs, states)
    assert len(warnings) == 1
    assert "au-plug-99" in warnings[0]
    assert "au-plug-99" in capsys.readouterr().err


def test_verify_plug_entities_all_present(mod):
    plugs = [{"machine": "au-plug-10", "topic": "au_plug_10"}]
    states = [
        {"entity_id": "switch.au_plug_10"},
        {"entity_id": "sensor.au_plug_10_energy_power"},
    ]
    assert mod._verify_plug_entities(plugs, states) == []
