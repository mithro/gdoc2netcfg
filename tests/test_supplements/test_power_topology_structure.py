"""Structural tests: location, meter root, BMC, stale switch, render (Spec A)."""

from types import SimpleNamespace

from gdoc2netcfg.supplements.power_topology import (
    NameResolver,
    PowerGraph,
    PowerNode,
    add_bmc_edges,
    add_controls_edges,
    add_poe_edges,
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


# ---- Task 5: BMC power-control edges ------------------------------------


def test_bmc_powers_its_host():
    g = PowerGraph()
    g.add_node(PowerNode("big-storage", "host", "big-storage",
                         location=("Server Room",)))
    bmc = SimpleNamespace(hostname="bmc.big-storage", machine_name="big-storage")
    add_bmc_edges(g, [bmc])
    assert g.nodes["bmc.big-storage"].category == "bmc"
    assert "bmc.big-storage" in g.parents_of("big-storage")
    # inherits the parent's location
    assert g.nodes["bmc.big-storage"].location == ("Server Room",)


def test_bmc_without_parent_node_warns_no_edge():
    g = PowerGraph()
    add_bmc_edges(g, [SimpleNamespace(hostname="bmc.ghost", machine_name="ghost")])
    assert "bmc.ghost" in g.nodes
    assert g.children_of("bmc.ghost") == set()
    assert any("ghost" in w for w in g.warnings)


# ---- Task 6: stale-switch exclusion -------------------------------------


def test_stale_bridge_switch_excluded():
    g = PowerGraph()  # empty inventory
    bridge = {
        "sw-ghost": {
            "port_names": [(1, "1/0/1")],
            "poe_status": [(1, 1, 3)],
            "lldp_neighbors": [(1, "somehost", "x", "y", None)],
        }
    }
    add_poe_edges(g, bridge, NameResolver(set(), "welland.mithis.com"))
    assert "sw-ghost" not in g.nodes
    assert any("sw-ghost" in w and "stale" in w.lower() for w in g.warnings)


def test_in_inventory_switch_keeps_poe_subtree():
    g = PowerGraph()
    g.add_node(PowerNode("sw-real", "host", "sw-real"))
    bridge = {
        "sw-real": {
            "port_names": [(1, "1/0/1")],
            "poe_status": [(1, 1, 3)],
            "lldp_neighbors": [(1, "desktop", "x", "y", None)],
        }
    }
    add_poe_edges(g, bridge, NameResolver({"sw-real", "desktop"}, "welland.mithis.com"))
    assert "sw-real 1/0/1" in g.nodes
    assert "sw-real 1/0/1" in g.children_of("sw-real")
