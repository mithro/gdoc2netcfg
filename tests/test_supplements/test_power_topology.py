from gdoc2netcfg.supplements.power_topology import (
    PowerGraph, PowerNode, infra_category,
)


def test_infra_category():
    assert infra_category("ups-soundproof") == "ups"
    assert infra_category("mains-welland") == "mains"
    assert infra_category("busbar-aux") == "busbar"
    assert infra_category("strip-bench") == "strip"
    assert infra_category("au-plug-4") is None
    assert infra_category("desktop") is None


def test_graph_add_and_roots():
    g = PowerGraph()
    g.add_node(PowerNode("mains-welland", "mains", "mains-welland"))
    g.add_node(PowerNode("au-plug-4", "tasmota", "au-plug-4"))
    g.add_node(PowerNode("desktop", "host", "desktop"))
    g.add_edge("mains-welland", "au-plug-4")
    g.add_edge("au-plug-4", "desktop")
    assert g.roots() == ["mains-welland"]
    assert g.children_of("au-plug-4") == {"desktop"}
    assert g.parents_of("desktop") == {"au-plug-4"}
