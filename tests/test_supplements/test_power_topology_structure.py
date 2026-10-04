"""Structural tests: location, meter root, BMC, stale switch, render (Spec A)."""

from types import SimpleNamespace

from gdoc2netcfg.supplements.power_topology import (
    NameResolver,
    PowerGraph,
    PowerNode,
    add_bmc_edges,
    add_controls_edges,
    add_poe_edges,
    render_tree,
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


def test_appliance_prefix_creates_valid_leaf():
    rec = SimpleNamespace(
        sheet_name="iot", machine="au-plug-3", site="welland", row_number=1,
        extra={"Controls": "appliance: bar heater", "Physical Location": "Lounge"},
    )
    g = PowerGraph()
    add_controls_edges(g, [rec], [], _site())
    appl = [nid for nid, n in g.nodes.items() if n.category == "appliance"]
    assert len(appl) == 1
    assert g.nodes[appl[0]].label == "bar heater"
    assert appl[0] in g.children_of("au-plug-3")
    assert g.nodes[appl[0]].location == ("Lounge",)  # inherits controller location
    assert not any("matches no known" in w for w in g.warnings)


def test_host_with_bmc_substring_not_treated_as_bmc():
    # A first label that merely CONTAINS 'bmc' (e.g. 'webmc') is not a BMC;
    # a prefix match avoids a self-loop (hostname == machine_name) that would
    # otherwise raise PowerCycleError and break the whole power command.
    g = PowerGraph()
    g.add_node(PowerNode("webmc", "host", "webmc"))
    add_bmc_edges(g, [SimpleNamespace(hostname="webmc", machine_name="webmc")])
    assert g.nodes["webmc"].category == "host"
    assert "webmc" not in g.children_of("webmc")


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


# ---- Task 7: render_tree — meter, locations, flags, natural sort --------


def _g_rack():
    g = PowerGraph()
    rack = ("Back Shed", "Soundproof Rack")
    g.add_node(PowerNode("au-plug-47", "tasmota", "au-plug-47", location=rack))
    g.add_node(PowerNode("ups-apc-srv3k", "ups", "ups-apc-srv3k", location=rack,
                         note="monitored by rpi4-ups"))
    g.add_node(PowerNode("au-plug-48", "tasmota", "au-plug-48", location=rack))
    g.add_node(PowerNode("sw-bb-25g", "host", "sw-bb-25g", location=rack))
    g.add_edge("au-plug-47", "ups-apc-srv3k")
    g.add_edge("ups-apc-srv3k", "au-plug-48")
    g.add_edge("au-plug-48", "sw-bb-25g")
    return g


def test_render_meter_root_and_location_nesting():
    lines = render_tree(_g_rack(), "welland").splitlines()
    assert lines[0] == "mains: meter-welland"
    assert any(line.strip() == "[Back Shed]" for line in lines)
    assert any(line.strip() == "[Soundproof Rack]" for line in lines)
    assert any("ups: ups-apc-srv3k (monitored by rpi4-ups)" in line for line in lines)


def test_render_cross_location_flag():
    g = PowerGraph()
    g.add_node(PowerNode("au-plug-20", "tasmota", "au-plug-20", location=("Office",)))
    g.add_node(PowerNode("monitors", "host", "monitors", location=("Lounge",)))
    g.add_edge("au-plug-20", "monitors")
    assert "⚠ loc=Lounge" in render_tree(g, "welland")


def test_render_ports_natural_sorted():
    g = PowerGraph()
    g.add_node(PowerNode("sw", "host", "sw", location=("Rack",)))
    for p in ("sw 1/0/11", "sw 1/0/2", "sw 1/0/1"):
        g.add_node(PowerNode(p, "poe", p, location=("Rack",)))
        g.add_edge("sw", p)
    out = render_tree(g, "welland")
    labels = [line.split("poe:")[1].strip() for line in out.splitlines() if "poe:" in line]
    assert labels == ["sw 1/0/1", "sw 1/0/2", "sw 1/0/11"]


def test_render_multi_feed_flags_each_edge_independently():
    # Review Focus #1: a node fed from two locations appears under each,
    # flagged per edge.
    g = PowerGraph()
    g.add_node(PowerNode("plugA", "tasmota", "plugA", location=("Office",)))
    g.add_node(PowerNode("plugB", "tasmota", "plugB", location=("Lounge",)))
    g.add_node(PowerNode("dev", "host", "dev", location=("Garage",)))
    g.add_edge("plugA", "dev")
    g.add_edge("plugB", "dev")
    assert render_tree(g, "welland").count("⚠ loc=Garage") == 2


def test_render_unlocated_node_flagged_and_bucketed():
    # Review Focus #2: a node with no location is placed + flagged, not lost.
    g = PowerGraph()
    g.add_node(PowerNode("mystery", "host", "mystery"))
    out = render_tree(g, "welland")
    assert "[unknown location]" in out
    assert "⚠ loc unknown" in out
