from types import SimpleNamespace

from gdoc2netcfg.supplements.power_topology import (
    NameResolver, PowerGraph, PowerNode, add_controls_edges, infra_category,
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
