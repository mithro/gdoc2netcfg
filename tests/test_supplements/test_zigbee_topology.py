"""Tests for the Zigbee topology renderers (DOT + text tree)."""

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
        link_quality=None,
        availability=availability,
        network_address=None,
        description=description,
        definition_description="",
        connected_via=parent,
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
    assert "├─ ● [E] B1 (TS0601)" in out
    assert "└─ ● [R] Z1 (TS0601)" in out
    # Nested under Z1 — Z1 is the *last* child of Coordinator so the
    # continuation prefix is three spaces (no vertical bar).
    assert "   └─ ● [E] T2 (TS0601)" in out
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
    assert "● [E] B2" not in out                # B2 is offline → open circle
    assert "○ [E] B2 (TS0601)" in out
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
    assert "  ● [R] Z8 (TS0601)" in out
    # B15 hangs off Z8, Z9 also hangs off Z8 with a deeper child
    assert "  ├─ ● [E] B15 (TS0601)" in out or "  └─ ● [E] B15 (TS0601)" in out
    assert "  └─ ● [R] Z9 (TS0601)" in out
    # Coord-rooted side still rendered
    assert "└─ ● [E] Coord-Child" in out


def test_true_orphan_listed_separately() -> None:
    """Online device with no parent and no children appears under the
    'no known parent' section, not as a sub-tree root."""
    devices = [
        _device("B1", parent="Coordinator"),
        _device("B17"),  # online, no parent, no children
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert "Devices with no known parent" in out
    assert "  ● [E] B17 (TS0601)" in out
    assert "Orphan sub-trees" not in out


def test_description_is_quoted_when_present() -> None:
    devices = [
        _device(
            "T1",
            parent="Coordinator",
            model="SNZB-02D",
            description="Lounge temp",
        ),
    ]
    out = generate_zigbee_text_tree(devices, _bridge(), "welland")
    assert '● [E] T1 (SNZB-02D) "Lounge temp"' in out


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
    assert '"rpi4-ups / Back Shed, Soundproof Rack"' in out
    # No output line may be a bare description fragment.
    assert "\nBack Shed" not in out


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


def test_dot_renderer_still_works_alongside_text() -> None:
    """Sanity check that the DOT generator wasn't broken by the additions."""
    devices = [
        _device("B1", parent="Coordinator"),
        _device("Z1", parent="Coordinator", device_type="Router"),
        _device("T2", parent="Z1"),
    ]
    dot = generate_zigbee_topology(devices, _bridge(), "welland")
    assert "digraph zigbee_welland" in dot
    assert '"B1" -> "Coordinator"' in dot
    assert '"T2" -> "Z1"' in dot
