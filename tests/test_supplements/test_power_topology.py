from types import SimpleNamespace

import pytest

from gdoc2netcfg.supplements.power_topology import (
    NameResolver,
    PowerCycleError,
    PowerGraph,
    PowerNode,
    add_controls_edges,
    add_poe_edges,
    check_acyclic,
    downstream,
    hosts_not_reaching_mains,
    infra_category,
    powered,
    render_tree,
    render_upstream,
    upstream_levels,
)


def _rec(machine, controls="", site="", sheet="IoT"):
    return SimpleNamespace(sheet_name=sheet, machine=machine, site=site,
                           extra={"Controls": controls} if controls else {})


def _host(machine, hostname=None):
    return SimpleNamespace(machine_name=machine, hostname=hostname or machine)


def _site(name="welland", domain="welland.mithis.com"):
    return SimpleNamespace(name=name, domain=domain)


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


def test_resolver_strips_domain_and_first_label():
    r = NameResolver({"ten64", "desktop"}, "welland.mithis.com")
    assert r.resolve("desktop") == "desktop"
    assert r.resolve("ten64.welland.mithis.com") == "ten64"
    assert r.resolve("ten64.monarto.mithis.com") == "ten64"   # first-label fallback
    assert r.resolve("nope") is None


def test_controls_plug_to_host_and_chain():
    recs = [
        _rec("au-plug-48", "au-plug-46"),
        _rec("au-plug-46", "sw-bb-25g"),
        _rec("ups-soundproof", "au-plug-48"),
    ]
    hosts = [_host("sw-bb-25g")]
    g = PowerGraph()
    add_controls_edges(g, recs, hosts, _site())
    assert g.children_of("ups-soundproof") == {"au-plug-48"}
    assert g.children_of("au-plug-48") == {"au-plug-46"}
    assert g.children_of("au-plug-46") == {"sw-bb-25g"}
    assert g.nodes["ups-soundproof"].category == "ups"
    assert g.nodes["au-plug-48"].category == "tasmota"


def test_controls_site_scoping_excludes_other_site():
    recs = [_rec("au-plug-9", "ten64", site="monarto")]
    g = PowerGraph()
    add_controls_edges(g, recs, [], _site(name="welland"))
    assert "au-plug-9" not in g.nodes          # monarto controller excluded


def test_controls_unresolved_target_warns_and_keeps_leaf():
    recs = [_rec("au-plug-1", "ac")]            # "ac" is not a known host
    g = PowerGraph()
    add_controls_edges(g, recs, [], _site())
    assert "ac" in g.nodes
    assert g.nodes["ac"].category == "unresolved"
    assert any("ac" in w for w in g.warnings)
    assert g.children_of("au-plug-1") == {"ac"}


def _bridge(poe, names, aliases=(), lldp=()):
    return {"sw-s1": {
        "poe_status": list(poe), "port_names": list(names),
        "port_aliases": list(aliases), "lldp_neighbors": list(lldp),
    }}


def _resolver(ids):
    return NameResolver(set(ids), "welland.mithis.com")


def test_poe_delivering_alias_edge():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    g.add_node(PowerNode("rpi5-pmod", "host", "rpi5-pmod"))
    add_poe_edges(
        g,
        _bridge([(1, 1, 3)], [(1, "1/0/1")], aliases=[(1, "eth0.rpi5-pmod")]),
        _resolver(["sw-s1", "rpi5-pmod"]),
    )
    assert "sw-s1 1/0/1" in g.nodes
    assert g.nodes["sw-s1 1/0/1"].category == "poe"
    assert g.children_of("sw-s1") == {"sw-s1 1/0/1"}
    assert g.children_of("sw-s1 1/0/1") == {"rpi5-pmod"}


def test_poe_searching_no_edge():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    add_poe_edges(g, _bridge([(4, 1, 2)], [(4, "1/0/4")]), _resolver(["sw-s1"]))
    assert "sw-s1 1/0/4" not in g.nodes


def test_poe_off_with_alias_edge():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    g.add_node(PowerNode("tweed", "host", "tweed"))
    add_poe_edges(
        g, _bridge([(5, 2, 1)], [(5, "1/0/5")], aliases=[(5, "eth0.tweed")]),
        _resolver(["sw-s1", "tweed"]),
    )
    assert g.children_of("sw-s1 1/0/5") == {"tweed"}


def test_poe_alias_unresolved_warns_and_leaf():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    add_poe_edges(
        g, _bridge([(7, 1, 3)], [(7, "1/0/7")], aliases=[(7, "eth0.ghost")]),
        _resolver(["sw-s1"]),
    )
    assert g.nodes["ghost"].category == "unresolved"
    assert g.children_of("sw-s1 1/0/7") == {"ghost"}
    assert any("ghost" in w for w in g.warnings)


def test_poe_missing_portname_raises():
    # Port names a host (alias) but is absent from port_names -> cannot
    # fabricate a label, must raise.
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    with pytest.raises(ValueError, match="no ifName"):
        add_poe_edges(
            g, _bridge([(1, 1, 3)], [], aliases=[(1, "eth0.rpi5-pmod")]),
            _resolver(["sw-s1"]),
        )


def test_poe_out_of_range_raises():
    g = PowerGraph()
    g.add_node(PowerNode("sw-s1", "host", "sw-s1"))
    with pytest.raises(ValueError, match="out of range"):
        add_poe_edges(g, _bridge([(1, 9, 3)], [(1, "1/0/1")]), _resolver(["sw-s1"]))


def test_cycle_raises():
    g = PowerGraph()
    for n in ("a", "b"):
        g.add_node(PowerNode(n, "tasmota", n))
    g.add_edge("a", "b")
    g.add_edge("b", "a")
    with pytest.raises(PowerCycleError):
        check_acyclic(g)


def test_mains_termination_warns():
    g = PowerGraph()
    g.add_node(PowerNode("mains-w", "mains", "mains-w"))
    g.add_node(PowerNode("au-plug-1", "tasmota", "au-plug-1"))
    g.add_node(PowerNode("desktop", "host", "desktop"))   # fed by a parentless plug
    g.add_node(PowerNode("au-plug-2", "tasmota", "au-plug-2"))
    g.add_edge("mains-w", "au-plug-1")
    g.add_edge("au-plug-2", "desktop")   # au-plug-2 has no mains upstream
    bad = hosts_not_reaching_mains(g)
    assert "desktop" in bad
    assert "au-plug-1" not in bad
    assert any("desktop" in w for w in g.warnings)


def _chain_graph():
    g = PowerGraph()
    for n, c in [("mains-w", "mains"), ("p47", "tasmota"), ("ups-x", "ups"),
                 ("p48", "tasmota"), ("p46", "tasmota"), ("sw-bb", "host")]:
        g.add_node(PowerNode(n, c, n))
    g.add_edge("mains-w", "p47")
    g.add_edge("p47", "ups-x")
    g.add_edge("ups-x", "p48")
    g.add_edge("p48", "p46")
    g.add_edge("p46", "sw-bb")
    return g


def test_downstream_chain():
    g = _chain_graph()
    assert downstream(g, "p48") == {"p46", "sw-bb"}
    assert downstream(g, "p47") == {"ups-x", "p48", "p46", "sw-bb"}


def test_downstream_redundant_feed_drops_nothing():
    g = PowerGraph()
    for n, c in [("mains-w", "mains"), ("p10", "tasmota"), ("p11", "tasmota"),
                 ("srv", "host")]:
        g.add_node(PowerNode(n, c, n))
    g.add_edge("mains-w", "p10")
    g.add_edge("mains-w", "p11")
    g.add_edge("p10", "srv")
    g.add_edge("p11", "srv")        # redundant second feed
    assert downstream(g, "p10") == set()   # srv still fed by p11


def test_powered_excludes_blocked_subtree():
    g = _chain_graph()
    assert "sw-bb" in powered(g)
    assert "sw-bb" not in powered(g, blocked=frozenset({"p48"}))


def test_upstream_levels_order():
    g = _chain_graph()
    assert upstream_levels(g, "sw-bb") == [
        ["p46"], ["p48"], ["ups-x"], ["p47"], ["mains-w"],
    ]


def test_render_upstream_lines():
    g = _chain_graph()
    assert render_upstream(g, "sw-bb") == (
        "tasmota: p46\n"
        "tasmota: p48\n"
        "ups: ups-x\n"
        "tasmota: p47\n"
        "mains: mains-w"
    )


def test_render_tree_shape():
    g = PowerGraph()
    for n, c in [("mains-w", "mains"), ("p1", "tasmota"), ("d", "host")]:
        g.add_node(PowerNode(n, c, n))
    g.add_edge("mains-w", "p1")
    g.add_edge("p1", "d")
    assert render_tree(g) == (
        "mains: mains-w\n"
        "└─ tasmota: p1\n"
        "   └─ host: d"
    )
