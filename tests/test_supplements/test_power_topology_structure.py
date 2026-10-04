"""Structural tests: location, meter root, BMC, stale switch, render (Spec A)."""

from types import SimpleNamespace

from gdoc2netcfg.supplements.power_topology import (
    PowerGraph,
    add_controls_edges,
)


def _site():
    return SimpleNamespace(name="welland", domain="welland.mithis.com")


# ---- Task 4: PowerNode carries location + note --------------------------


def test_node_carries_location_from_record():
    rec = SimpleNamespace(
        sheet_name="iot", machine="au-plug-46", site="welland", row_number=1,
        extra={"Controls": "sw-bb-25g",
               "Physical Location": "Back Shed - Soundproof Rack"},
    )
    g = PowerGraph()
    add_controls_edges(g, [rec], [], _site())
    assert g.nodes["au-plug-46"].location == ("Back Shed", "Soundproof Rack")


def test_node_without_location_is_empty_tuple():
    rec = SimpleNamespace(
        sheet_name="iot", machine="au-plug-9", site="welland", row_number=2,
        extra={},
    )
    g = PowerGraph()
    add_controls_edges(g, [rec], [], _site())
    assert g.nodes["au-plug-9"].location == ()
