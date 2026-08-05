"""Tests for the Zigbee topology renderers (DOT + text tree)."""

import pytest

from gdoc2netcfg.supplements.zigbee import ZigbeeBridgeInfo, ZigbeeDevice
from gdoc2netcfg.supplements.zigbee_topology import (
    generate_zigbee_text_tree,
    generate_zigbee_topology,
)


def _device(
    name: str,
    *,
    parent: str = "",
    availability: str = "online",
    device_type: str = "EndDevice",
    model: str = "TS0601",
    description: str = "",
    ieee: str | None = None,
    site: str = "welland",
    link_quality: int | None = None,
    kind: str = "",
) -> ZigbeeDevice:
    """Build a ZigbeeDevice with only the fields the renderer cares about."""
    return ZigbeeDevice(
        site=site,
        ieee_address=ieee or f"0x{abs(hash(name)) & 0xFFFFFFFFFFFFFFFF:016x}",
        friendly_name=name,
        object_id="",
        device_type=device_type,
        model_id=model,
        manufacturer="",
        model=model,
        power_source="",
        software_build_id="",
        date_code="",
        last_seen=None,
        link_quality=link_quality,
        availability=availability,
        network_address=None,
        description=description,
        definition_description="",
        connected_via=parent,
        connected_via_kind=kind or ("parent" if parent else ""),
    )


def _bridge() -> ZigbeeBridgeInfo:
    return ZigbeeBridgeInfo(
        site="welland",
        z2m_version="2.9.2",
        coordinator_ieee="0x00124b001cccafc1",
        coordinator_type="EmberZNet",
        channel=11,
        pan_id="0x189e",
    )


def test_coord_rooted_tree() -> None:
    """Coordinator with direct end-device + router-with-child renders correctly."""
    devices = [
        _device("B1", parent="Coordinator"),
        _device("Z1", parent="Coordinator", device_type="Router"),
        _device("T2", parent="Z1"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    # Header
    assert "Zigbee Mesh - welland" in out
    assert "Z2M 2.9.2" in out
    assert "Devices: 3" in out
    # Coordinator-rooted shape
    assert "Coordinator" in out
    assert "├─ ● [E]      B1  (TS0601)" in out
    assert "└─ ● [R]      Z1  (TS0601)" in out
    # Nested under Z1 — Z1 is the *last* child of Coordinator so the
    # continuation prefix is three spaces (no vertical bar).
    assert "   └─ ● [E]      T2  (TS0601)" in out
    # No orphan / hidden footers
    assert "Orphan sub-trees" not in out
    assert "no known parent" not in out
    assert "hidden" not in out


def test_offline_orphan_is_excluded_but_offline_with_parent_is_kept() -> None:
    """Filter rule mirrors the DOT path: drop offline+orphan, keep offline+parent."""
    devices = [
        _device("B1", parent="Coordinator", availability="online"),
        _device("B2", parent="Coordinator", availability="offline"),  # kept
        _device("B3", availability="offline"),                        # dropped
        _device("B4", availability="offline"),                        # dropped
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "B1" in out
    assert "B2" in out
    assert "● [E]      B2" not in out           # B2 is offline → open circle
    assert "○ [E]      B2  (TS0601)" in out
    assert "B3" not in out
    assert "B4" not in out
    assert "(2 offline+orphan device(s) hidden)" in out


def test_orphan_router_with_children_renders_as_subtree() -> None:
    """Online router with no uplink but children appears under 'Orphan sub-trees'."""
    devices = [
        _device("Coord-Child", parent="Coordinator"),
        _device("Z8", device_type="Router"),                # no parent
        _device("B15", parent="Z8"),
        _device("Z9", parent="Z8", device_type="Router"),
        _device("B10", parent="Z9"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "Orphan sub-trees (router with no known uplink):" in out
    # Z8 is the orphan root, listed indented (no branch char)
    assert "  ● [R]      Z8  (TS0601)" in out
    # B15 hangs off Z8, Z9 also hangs off Z8 with a deeper child
    assert "  ├─ ● [E]      B15 (TS0601)" in out or "  └─ ● [E]      B15 (TS0601)" in out
    assert "  └─ ● [R]      Z9  (TS0601)" in out
    # Coord-rooted side still rendered
    assert "└─ ● [E]      Coord-Child" in out


def test_true_orphan_listed_separately() -> None:
    """Online device with no parent and no children appears under the
    'no known parent' section, not as a sub-tree root."""
    devices = [
        _device("B1", parent="Coordinator"),
        _device("B17"),  # online, no parent, no children
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "Devices with no known parent" in out
    assert "  ● [E]      B17 (TS0601)" in out
    assert "Orphan sub-trees" not in out


def test_description_shown_before_model() -> None:
    devices = [
        _device(
            "T1",
            parent="Coordinator",
            model="SNZB-02D",
            description="Lounge temp",
        ),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "● [E]      T1  Lounge temp (SNZB-02D)" in out


def test_short_names_pad_to_three_characters() -> None:
    """Z7 and Z17 occupy the same width so their models align."""
    devices = [
        _device("Z7", parent="Coordinator", device_type="Router"),
        _device("Z17", parent="Coordinator", device_type="Router"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    z7_line = next(line for line in out.splitlines() if " Z7 " in line)
    z17_line = next(line for line in out.splitlines() if " Z17 " in line)
    assert z7_line.index("(TS0601)") == z17_line.index("(TS0601)")


def test_multiline_description_is_collapsed() -> None:
    """A raw newline in a Z2M description must not break the tree layout."""
    devices = [
        _device(
            "Z7",
            parent="Coordinator",
            device_type="Router",
            model="E22x4",
            description="rpi4-ups\nBack Shed, Soundproof Rack",
        ),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "rpi4-ups / Back Shed, Soundproof Rack (E22x4)" in out
    # No output line may be a bare description fragment.
    assert "\nBack Shed" not in out


def test_child_of_filtered_parent_is_still_rendered() -> None:
    """An online child whose router parent was dropped by the
    offline+orphan filter must appear under 'parent that is not shown'
    — never silently vanish."""
    devices = [
        _device("B1", parent="Coordinator"),
        # Z8 is offline with no known uplink -> filtered out entirely.
        _device("Z8", device_type="Router", availability="offline"),
        # ...but its online child survives the filter.
        _device("B22", parent="Z8"),
        # And the child can have its own children.
        _device("B23", parent="B22"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "Sub-trees under a parent that is not shown:" in out
    assert "B22 (TS0601)  [parent: Z8]" in out
    assert "└─ ● [E]      B23" in out          # walked under B22
    assert "(1 offline+orphan device(s) hidden)" in out


def test_parent_as_raw_ieee_is_still_rendered() -> None:
    """_build_parent_map falls back to the raw IEEE when the networkmap
    node list lacks the target — the child must still render."""
    devices = [
        _device("B1", parent="0x00124b0012345678"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "Sub-trees under a parent that is not shown:" in out
    assert "B1  (TS0601)  [parent: 0x00124b0012345678]" in out


def test_routing_loop_fails_loud() -> None:
    """Two routers claiming each other as parent are unreachable from
    any root — corrupt data must raise, not silently disappear."""
    devices = [
        _device("Z1", parent="Z2", device_type="Router"),
        _device("Z2", parent="Z1", device_type="Router"),
    ]
    with pytest.raises(RuntimeError, match="unreachable from any rendered root"):
        generate_zigbee_text_tree(devices, _bridge(), "welland")


def test_note_renders_under_header() -> None:
    devices = [_device("B1", parent="Coordinator")]
    out = generate_zigbee_text_tree(
        devices, _bridge(), "welland",
        note="WARNING: scan failed; showing last saved data",
    )
    header_idx = out.splitlines().index("Zigbee Mesh - welland")
    assert (
        out.splitlines()[header_idx + 2]
        == "WARNING: scan failed; showing last saved data"
    )


def test_every_kept_device_is_rendered() -> None:
    """Completeness: the union of all sections covers every kept device."""
    devices = [
        _device("B1", parent="Coordinator"),
        _device("Z1", parent="Coordinator", device_type="Router"),
        _device("T2", parent="Z1"),
        _device("Z8", device_type="Router"),          # orphan root
        _device("B15", parent="Z8"),
        _device("B17"),                                # true orphan
        _device("B22", parent="Gone"),                 # detached root
        _device("B99", availability="offline"),        # filtered
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    for name in ("B1", "Z1", "T2", "Z8", "B15", "B17", "B22"):
        assert f" {name} " in out or f" {name}\n" in out or out.endswith(name)
    assert "B99" not in out


def test_link_quality_bar_levels() -> None:
    """The signal bar has one lit segment per quality level, padded with
    '_' to a fixed 4-column width; it sits between the role tag and the
    name (a 4-space spacer when there is no reading)."""
    devices = [
        _device("B1", parent="Coordinator", link_quality=200),  # strong
        _device("B2", parent="Coordinator", link_quality=120),  # good
        _device("B3", parent="Coordinator", link_quality=50),   # workable
        _device("B4", parent="Coordinator", link_quality=10),   # poor
        _device("B5", parent="Coordinator"),  # link_quality=None
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "● [E] ▂▄▆█ B1  (TS0601)" in out
    assert "● [E] ▂▄▆_ B2  (TS0601)" in out
    assert "● [E] ▂▄__ B3  (TS0601)" in out
    assert "● [E] ▂___ B4  (TS0601)" in out
    # No bar at all when the scan captured no reading.
    b5_line = next(line for line in out.splitlines() if "B5" in line)
    assert "● [E]      B5  (TS0601)" in b5_line


def test_link_quality_colour_grading() -> None:
    devices = [
        _device("B1", parent="Coordinator", link_quality=150),  # good
        _device("B2", parent="Coordinator", link_quality=50),   # workable
        _device("B3", parent="Coordinator", link_quality=10),   # poor
    ]
    out = generate_zigbee_text_tree(
        devices, _bridge(), "welland", use_color=True,
    )
    # Lit segments graded green/yellow/red; unlit '_' placeholders dim grey.
    assert "\033[32m▂▄▆\033[0m\033[90m_\033[0m" in out   # good: 3 lit
    assert "\033[33m▂▄\033[0m\033[90m__\033[0m" in out   # workable: 2 lit
    assert "\033[31m▂\033[0m\033[90m___\033[0m" in out   # poor: 1 lit


def test_children_use_natural_sort() -> None:
    """B2 sorts before B10 (numeric-aware), not after (lexicographic)."""
    devices = [
        _device("B10", parent="Z1"),
        _device("B2", parent="Z1"),
        _device("B1", parent="Z1"),
        _device("Z1", parent="Coordinator", device_type="Router"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert out.index("B1 ") < out.index("B2 ") < out.index("B10 ")


def test_orphans_use_natural_sort() -> None:
    devices = [
        _device("W10"),
        _device("W2"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert out.index("W2 ") < out.index("W10 ")


def test_color_off_emits_no_ansi_escapes() -> None:
    devices = [_device("B1", parent="Coordinator")]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland", use_color=False)
    assert "\033[" not in out


def test_color_on_wraps_markers() -> None:
    devices = [
        _device("B1", parent="Coordinator", availability="online"),
        _device("B2", parent="Coordinator", availability="offline"),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland", use_color=True)
    # green for online, red for offline
    assert "\033[32m●\033[0m" in out
    assert "\033[31m○\033[0m" in out
    # Header is bolded
    assert "\033[1mZigbee Mesh - welland\033[0m" in out


def test_no_bridge_still_renders() -> None:
    devices = [_device("B1", parent="Coordinator")]
    out = generate_zigbee_text_tree(devices, None, "welland")
    assert "Zigbee Mesh - welland" in out
    assert "Z2M" not in out  # bridge-line skipped
    assert "B1" in out


def test_empty_devices_lists_no_children_message() -> None:
    out = generate_zigbee_text_tree([], _bridge(), "welland")
    assert "Devices: 0" in out
    assert "Coordinator  (no children in networkmap)" in out


def test_dot_escapes_quotes_and_newlines() -> None:
    """A description with quotes/newlines must produce valid DOT."""
    devices = [
        _device(
            "Z1",
            parent="Coordinator",
            device_type="Router",
            description='The "good" plug\nsecond line',
        ),
    ]
    dot = generate_zigbee_topology(devices, _bridge(), "welland")
    # The quote is escaped inside the label; no raw newline survives.
    assert '\\"good\\"' in dot
    assert "\nsecond line" not in dot
    assert "second line" in dot
    # Every line must have balanced unescaped quotes (cheap validity check).
    for line in dot.splitlines():
        unescaped = line.replace('\\"', "")
        assert unescaped.count('"') % 2 == 0, line


def test_dot_graph_id_is_quoted() -> None:
    """A site name with a hyphen is not a bare DOT identifier."""
    dot = generate_zigbee_topology([], _bridge(), "my-site")
    assert 'digraph "zigbee_my-site" {' in dot


def test_dot_coordinator_label_escapes_backslashes() -> None:
    """Bridge fields flow into the coordinator label — a backslash in
    them must not reach the DOT output unescaped."""
    bridge = ZigbeeBridgeInfo(
        site="welland", z2m_version="2.9.2",
        coordinator_ieee="0x00", coordinator_type="Ember\\ZNet",
        channel=11, pan_id="0x189e",
    )
    dot = generate_zigbee_topology([], bridge, "welland")
    assert "Ember\\\\ZNet" in dot


def test_dot_note_appended_to_graph_title() -> None:
    dot = generate_zigbee_topology(
        [], _bridge(), "welland", note="WARNING: stale data",
    )
    assert "Zigbee Mesh — welland\\nWARNING: stale data" in dot


def test_dot_renderer_still_works_alongside_text() -> None:
    """Sanity check that the DOT generator wasn't broken by the additions."""
    devices = [
        _device("B1", parent="Coordinator"),
        _device("Z1", parent="Coordinator", device_type="Router"),
        _device("T2", parent="Z1"),
    ]
    dot = generate_zigbee_topology(devices, _bridge(), "welland")
    assert 'digraph "zigbee_welland"' in dot
    assert '"B1" -> "Coordinator"' in dot
    assert '"T2" -> "Z1"' in dot


def test_mesh_anchored_router_gets_tag_and_legend() -> None:
    devices = [
        _device("R5", parent="Coordinator", device_type="Router",
                kind="mesh", link_quality=130),
        _device("T1", parent="R5", link_quality=90),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    r5_line = next(line for line in out.splitlines() if "R5" in line)
    assert "[mesh]" in r5_line
    t1_line = next(line for line in out.splitlines() if "T1" in line)
    assert "[mesh]" not in t1_line
    assert "routers keep no parent records" in out
    assert "with uplink info: 2/2 (1 via mesh)" in out


def test_no_mesh_no_legend() -> None:
    devices = [_device("T1", parent="Coordinator", link_quality=90)]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "[mesh]" not in out
    assert "routers keep no parent records" not in out


def test_dot_mesh_edge_is_dashed() -> None:
    devices = [
        _device("R5", parent="Coordinator", device_type="Router",
                kind="mesh"),
        _device("T1", parent="R5"),
    ]
    dot = generate_zigbee_topology(devices, _bridge(), "welland")
    assert '"R5" -> "Coordinator" [style=dashed];' in dot
    assert '"T1" -> "R5";' in dot
