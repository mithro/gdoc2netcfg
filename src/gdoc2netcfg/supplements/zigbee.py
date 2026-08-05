"""Zigbee2MQTT device scanning via MQTT.

Connects to each configured site's MQTT broker, subscribes to Z2M's
retained bridge/devices and bridge/info topics, and collects per-device
availability state.  Results are persisted to discovery.db by the CLI
(scan_type ``zigbee``) as ONE DOCUMENT PER SITE — ``{"bridge": ...,
"devices": {ieee: ...}}`` — mirroring the per-site cache files this
replaced.  Sites are independent: scanning one site never touches
another site's document, and a device listed by two sites (moved
without removing the old Z2M entry) keeps both registry views.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import MqttBrokerConfig


class ZigbeeScanError(Exception):
    """Raised after a zigbee scan when one or more sites failed."""


@dataclass(frozen=True)
class ZigbeeDevice:
    """A single Zigbee device as reported by Zigbee2MQTT."""

    site: str
    ieee_address: str
    friendly_name: str
    object_id: str          # options.object_id (stable HA entity ID root)
    device_type: str        # "EndDevice", "Router", etc.
    model_id: str           # device-reported raw model string
    manufacturer: str       # from definition.vendor or manufacturer field
    model: str              # from definition.model (Z2M known model name)
    power_source: str
    software_build_id: str  # firmware version string
    date_code: str
    last_seen: int | None   # Unix milliseconds epoch, or None
    link_quality: int | None
    availability: str       # "online" / "offline" / "unknown"
    network_address: int | None
    description: str = ""             # user-set description in Z2M (top-level field)
    definition_description: str = ""  # Z2M model description (definition.description)
    connected_via: str = ""           # uplink device friendly_name from networkmap
    connected_via_kind: str = ""      # "parent" (child/parent record) or "mesh"
                                      # (router anchored via strongest sibling
                                      # link); "" when no uplink is known
    disabled: bool = False            # Z2M "disabled" flag (device kept in the
                                      # registry but not communicated with)

    @property
    def last_seen_str(self) -> str:
        """ISO-formatted last-seen timestamp, or empty string."""
        if self.last_seen is None:
            return ""
        dt = datetime.fromtimestamp(self.last_seen / 1000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class ZigbeeBridgeInfo:
    """Zigbee2MQTT bridge and coordinator information."""

    site: str
    z2m_version: str
    coordinator_ieee: str
    coordinator_type: str
    channel: int
    pan_id: str


def _parse_device(site: str, d: dict, availability: dict[str, str]) -> ZigbeeDevice:
    """Parse a single device entry from a Z2M bridge/devices payload."""
    ieee = d.get("ieee_address", "")
    friendly = d.get("friendly_name", "")
    options = d.get("options") or {}
    object_id = options.get("object_id", "")

    definition = d.get("definition") or {}
    manufacturer = definition.get("vendor") or d.get("manufacturer") or ""
    model = definition.get("model", "")
    definition_description = definition.get("description", "")
    description = d.get("description", "")  # user-set description in Z2M (top-level field)

    avail = availability.get(friendly, "unknown")

    last_seen = d.get("last_seen")
    if isinstance(last_seen, str):
        # Z2M sometimes emits an ISO string instead of a millisecond epoch.
        try:
            dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            last_seen = int(dt.timestamp() * 1000)
        except ValueError:
            last_seen = None

    return ZigbeeDevice(
        site=site,
        ieee_address=ieee,
        friendly_name=friendly,
        object_id=object_id,
        device_type=d.get("type", ""),
        model_id=d.get("model_id") or "",
        manufacturer=manufacturer,
        model=model,
        power_source=d.get("power_source") or "",
        software_build_id=d.get("software_build_id") or "",
        date_code=d.get("date_code") or "",
        last_seen=last_seen,
        link_quality=d.get("link_quality"),
        availability=avail,
        network_address=d.get("network_address"),
        description=description,
        definition_description=definition_description,
        disabled=bool(d.get("disabled", False)),
    )


def _parse_bridge_info(site: str, info: dict) -> ZigbeeBridgeInfo:
    """Parse a Z2M bridge/info payload."""
    coord = info.get("coordinator", {})
    network = info.get("network", {})

    channel = network.get("channel", 0)
    pan_id_raw = network.get("pan_id", 0)
    if isinstance(pan_id_raw, int):
        pan_id = f"0x{pan_id_raw:04x}"
    else:
        pan_id = str(pan_id_raw)

    return ZigbeeBridgeInfo(
        site=site,
        z2m_version=info.get("version", ""),
        coordinator_ieee=coord.get("ieee_address", ""),
        coordinator_type=coord.get("type", ""),
        channel=channel,
        pan_id=pan_id,
    )


def _request_networkmap(
    mqtt_config: MqttBrokerConfig,
    site_name: str,
    timeout: float = 600.0,
    verbose: bool = False,
) -> dict:
    """Request the Z2M network map via MQTT.

    Publishes to zigbee2mqtt/bridge/request/networkmap and waits for the
    response on zigbee2mqtt/bridge/response/networkmap.  Returns the full
    response envelope (``{"data": ..., "status": "ok"}``).

    Raises RuntimeError on connection failure, timeout, an undecodable
    payload, or a non-ok response status.  Callers must NOT treat a
    failed networkmap as "no parents" — that would silently erase
    previously-recorded parent data (the site keeps its baseline via
    scan_zigbee's error contract instead).
    """
    import paho.mqtt.client as mqtt

    result: dict = {}
    connected = threading.Event()
    done = threading.Event()

    def on_connect(
        client: mqtt.Client,
        userdata: object,
        flags: mqtt.ConnectFlags,
        reason_code: mqtt.ReasonCode,
        properties: object,
    ) -> None:
        if reason_code == 0:
            client.subscribe("zigbee2mqtt/bridge/response/networkmap")
            connected.set()

    def on_message(
        client: mqtt.Client,
        userdata: object,
        msg: mqtt.MQTTMessage,
    ) -> None:
        if msg.topic == "zigbee2mqtt/bridge/response/networkmap":
            try:
                result["response"] = json.loads(msg.payload.decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                result["decode_error"] = f"{type(e).__name__}: {e}"
            done.set()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    if mqtt_config.user:
        client.username_pw_set(mqtt_config.user, mqtt_config.password)

    client.connect(mqtt_config.host, mqtt_config.port, keepalive=30)
    client.loop_start()

    try:
        if not connected.wait(timeout=10.0):
            raise RuntimeError(
                f"Networkmap: connection timeout for {site_name}"
            )

        if verbose:
            print(
                f"  [{site_name}] Requesting network map "
                f"(timeout {timeout:.0f}s)...",
                file=sys.stderr,
            )

        # routes=False skips per-device routing table queries which are very
        # slow (>3min on welland with offline devices).  The neighbor table
        # relationship fields are sufficient to determine parent links.
        client.publish(
            "zigbee2mqtt/bridge/request/networkmap",
            json.dumps({"type": "raw", "routes": False}),
        )

        if not done.wait(timeout=timeout):
            raise RuntimeError(
                f"Networkmap timed out after {timeout:.0f}s for {site_name}"
            )
    finally:
        client.loop_stop()
        client.disconnect()

    if "decode_error" in result:
        raise RuntimeError(
            f"Networkmap response from {site_name} was not valid JSON: "
            f"{result['decode_error']}"
        )

    response = result["response"]
    if not isinstance(response, dict):
        raise RuntimeError(
            f"Networkmap response from {site_name} has unexpected type "
            f"{type(response).__name__}"
        )
    status = response.get("status")
    if status != "ok":
        raise RuntimeError(
            f"Networkmap request failed for {site_name}: "
            f"status={status!r} error={response.get('error')!r}"
        )
    return response


def _networkmap_nodes_links(networkmap: dict) -> tuple[list, list]:
    """Validate a raw networkmap response and return its (nodes, links).

    Raises RuntimeError if the response is not shaped like a raw
    networkmap — an unexpected shape must not silently reduce to "no
    parents" (indistinguishable from an empty mesh).  A real raw map
    always contains at least the coordinator node.
    """
    value = networkmap.get("data", {}).get("value")
    if not isinstance(value, dict):
        raise RuntimeError(
            "Networkmap response is missing data.value — "
            f"got keys {sorted(networkmap)}"
        )
    nodes = value.get("nodes")
    links = value.get("links")
    if not isinstance(nodes, list) or not isinstance(links, list):
        raise RuntimeError(
            "Networkmap data.value is missing nodes/links lists — "
            f"got keys {sorted(value)}"
        )
    if not nodes:
        raise RuntimeError(
            "Networkmap contains no nodes — a raw map always includes "
            "at least the coordinator"
        )
    return nodes, links


def _build_parent_map(networkmap: dict) -> dict[str, tuple[str, int | None]]:
    """Map ieee_address -> (parent friendly_name, link LQI) from a networkmap.

    Uses Zigbee neighbor table relationship types:
      - relationship=1 (IS_CHILD): source's parent is target — most reliable
      - relationship=0 (IS_PARENT): source is parent of target — secondary signal

    Relationship=2 (IS_SIBLING) is not a parent record — routers are
    mesh peers of each other; see ``_anchor_mesh_routers`` for how
    parentless routers are attached to the tree via sibling links.

    The LQI is the quality of the child<->parent link itself (raw
    networkmap ``linkquality`` field), which is the meaningful signal
    number for a routing topology.

    Raises RuntimeError on an unexpected response shape (see
    ``_networkmap_nodes_links``).
    """
    nodes, links = _networkmap_nodes_links(networkmap)

    # ieee -> friendly_name lookup (includes Coordinator)
    ieee_to_name: dict[str, str] = {}
    for node in nodes:
        ieee_to_name[node["ieeeAddr"]] = node.get("friendlyName", node["ieeeAddr"])

    # Build parent map: device_ieee -> (parent_friendly_name, link_lqi)
    parent_map: dict[str, tuple[str, int | None]] = {}

    # Pass 1: rel=1 links (source is child of target) — most reliable
    for link in links:
        if link.get("relationship") != 1:
            continue
        source_ieee = link.get("sourceIeeeAddr") or link.get("source", {}).get("ieeeAddr", "")
        target_ieee = link.get("targetIeeeAddr") or link.get("target", {}).get("ieeeAddr", "")
        if source_ieee and target_ieee:
            parent_map[source_ieee] = (
                ieee_to_name.get(target_ieee, target_ieee),
                link.get("linkquality"),
            )

    # Pass 2: rel=0 links (source is parent of target) — fill gaps only
    for link in links:
        if link.get("relationship") != 0:
            continue
        source_ieee = link.get("sourceIeeeAddr") or link.get("source", {}).get("ieeeAddr", "")
        target_ieee = link.get("targetIeeeAddr") or link.get("target", {}).get("ieeeAddr", "")
        if source_ieee and target_ieee and target_ieee not in parent_map:
            parent_map[target_ieee] = (
                ieee_to_name.get(source_ieee, source_ieee),
                link.get("linkquality"),
            )

    return parent_map


def _anchor_mesh_routers(
    devices: list[ZigbeeDevice],
    networkmap: dict,
) -> tuple[list[ZigbeeDevice], int]:
    """Attach parentless routers to the tree via their sibling links.

    Routers in a Zigbee mesh are peers: after joining they keep no
    parent/child relationship, only IS_SIBLING (relationship=2) neighbor
    entries.  A router with no rel-0/1 record is therefore NOT an orphan
    — it is reachable through the mesh.  This pass anchors each such
    router to its strongest sibling that is itself already anchored to
    the Coordinator (directly, via a parent chain, or via an earlier
    mesh anchor), setting ``connected_via`` with
    ``connected_via_kind="mesh"``.

    Sibling entries with LQI 0 are stale never-heard rows and are not
    usable as anchors.  A router whose every sibling is unanchored or
    stale keeps ``connected_via=""`` and still shows in the orphan
    section — that is real signal, not a rendering gap.

    Returns the updated device list and the number of routers anchored.
    """
    nodes, links = _networkmap_nodes_links(networkmap)
    ieee_to_name: dict[str, str] = {}
    for node in nodes:
        ieee_to_name[node["ieeeAddr"]] = node.get("friendlyName", node["ieeeAddr"])

    by_name = {d.friendly_name: d for d in devices}

    # Sibling adjacency: name -> [(neighbor_name, lqi, measured_at_neighbor)].
    # A rel=2 link's LQI is measured by the TARGET (the neighbor-table
    # owner) receiving the SOURCE; prefer edges where the anchor is the
    # receiver, matching the parent-link LQI convention.
    edges: dict[str, list[tuple[str, int, bool]]] = {}
    for link in links:
        if link.get("relationship") != 2:
            continue
        src = link.get("sourceIeeeAddr") or link.get("source", {}).get("ieeeAddr", "")
        tgt = link.get("targetIeeeAddr") or link.get("target", {}).get("ieeeAddr", "")
        lqi = link.get("linkquality")
        if not src or not tgt or not isinstance(lqi, int) or lqi <= 0:
            continue
        src_name = ieee_to_name.get(src, src)
        tgt_name = ieee_to_name.get(tgt, tgt)
        edges.setdefault(src_name, []).append((tgt_name, lqi, True))
        edges.setdefault(tgt_name, []).append((src_name, lqi, False))

    # Names already anchored: Coordinator plus every device whose
    # connected_via chain reaches it.
    parent_of = {
        d.friendly_name: d.connected_via for d in devices if d.connected_via
    }
    anchored = {"Coordinator"}
    for name in parent_of:
        chain, cur = [], name
        while cur in parent_of and cur not in anchored and cur not in chain:
            chain.append(cur)
            cur = parent_of[cur]
        if cur in anchored or cur == "Coordinator":
            anchored.update(chain)

    def anchorable(name: str) -> bool:
        if name == "Coordinator":
            return True
        d = by_name.get(name)
        return d is not None and d.device_type == "Router"

    updated = {d.friendly_name: d for d in devices}
    mesh_count = 0
    progress = True
    while progress:
        progress = False
        for d in sorted(devices, key=lambda d: d.friendly_name):
            cur = updated[d.friendly_name]
            if cur.device_type != "Router" or cur.connected_via:
                continue
            candidates = [
                (lqi, at_neighbor, neighbor)
                for neighbor, lqi, at_neighbor in edges.get(cur.friendly_name, [])
                if neighbor in anchored and anchorable(neighbor)
            ]
            if not candidates:
                continue
            lqi, _at_neighbor, neighbor = max(candidates)
            updated[cur.friendly_name] = replace(
                cur,
                connected_via=neighbor,
                connected_via_kind="mesh",
                link_quality=cur.link_quality if cur.link_quality is not None else lqi,
            )
            anchored.add(cur.friendly_name)
            mesh_count += 1
            progress = True

    return [updated[d.friendly_name] for d in devices], mesh_count


def _validate_parents(site_name: str, devices: list[ZigbeeDevice]) -> None:
    """Reject parent links that point at a non-routing device.

    Only Routers and the Coordinator can have children in a Zigbee
    mesh; a networkmap link claiming an EndDevice as someone's parent
    is corrupt neighbor-table data.  Fail loud rather than render a
    topology that cannot exist.
    """
    by_name = {d.friendly_name: d for d in devices}
    violations = []
    for d in devices:
        if not d.connected_via or d.connected_via == "Coordinator":
            continue
        parent = by_name.get(d.connected_via)
        # A parent name not in the device list (e.g. a renamed or
        # removed device) has no type to check — leave it be; the
        # topology renderer lists the device under "parent not shown".
        if parent is not None and parent.device_type != "Router":
            violations.append(
                f"{d.friendly_name} claims parent {parent.friendly_name} "
                f"which is a {parent.device_type}, not a Router"
            )
    if violations:
        raise RuntimeError(
            f"[{site_name}] Networkmap reports non-router parent(s) — "
            "corrupt neighbor-table data:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )


def scan_zigbee_site(
    site_name: str,
    mqtt_config: MqttBrokerConfig,
    timeout: float = 15.0,
    networkmap_timeout: float = 600.0,
    availability_collect_s: float = 2.0,
    verbose: bool = False,
) -> tuple[list[ZigbeeDevice], ZigbeeBridgeInfo | None]:
    """Scan a single site's Zigbee2MQTT instance via MQTT.

    Subscribes to the retained bridge/devices and bridge/info topics,
    then waits briefly to collect per-device availability messages
    (also retained, arrive immediately).  After collecting devices,
    requests the network map to determine parent routing relationships.

    Returns (devices, bridge_info).  Raises RuntimeError on connection
    failure or if no device list arrives within the timeout.
    """
    import paho.mqtt.client as mqtt

    state: dict = {
        "devices_raw": None,
        "info_raw": None,
        "availability": {},
        "connect_error": None,
    }
    devices_event = threading.Event()
    info_event = threading.Event()

    def on_connect(
        client: mqtt.Client,
        userdata: object,
        flags: mqtt.ConnectFlags,
        reason_code: mqtt.ReasonCode,
        properties: object,
    ) -> None:
        if reason_code != 0:
            state["connect_error"] = f"reason_code={reason_code}"
            devices_event.set()
            info_event.set()
            return
        # Subscribe to bridge/devices LAST.  Its retained payload is
        # huge (hundreds of KB on a 60-device mesh) and while it drains,
        # Mosquitto DROPS the retained deliveries for any subscription
        # made after it on the same connection — observed on welland:
        # devices arrived but bridge/info and every availability topic
        # were silently missing (regardless of QoS).  The small topics
        # drain instantly, so subscribing to them first is safe.
        client.subscribe("zigbee2mqtt/bridge/info")
        client.subscribe("zigbee2mqtt/+/availability")
        client.subscribe("zigbee2mqtt/bridge/devices")
        if verbose:
            print(
                f"  [{site_name}] Connected to {mqtt_config.host}:{mqtt_config.port}",
                file=sys.stderr,
            )

    def on_message(
        client: mqtt.Client,
        userdata: object,
        msg: mqtt.MQTTMessage,
    ) -> None:
        topic = msg.topic
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if topic == "zigbee2mqtt/bridge/devices":
            state["devices_raw"] = payload
            devices_event.set()
        elif topic == "zigbee2mqtt/bridge/info":
            state["info_raw"] = payload
            info_event.set()
        elif topic.startswith("zigbee2mqtt/") and topic.endswith("/availability"):
            # topic: zigbee2mqtt/<friendly_name>/availability
            device_name = topic[len("zigbee2mqtt/"):-len("/availability")]
            if isinstance(payload, dict):
                avail_state = payload.get("state", "")
            else:
                avail_state = str(payload)
            state["availability"][device_name] = avail_state

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    if mqtt_config.user:
        client.username_pw_set(mqtt_config.user, mqtt_config.password)

    if verbose:
        print(
            f"  [{site_name}] Connecting to {mqtt_config.host}:{mqtt_config.port}...",
            file=sys.stderr,
        )

    client.connect(mqtt_config.host, mqtt_config.port, keepalive=30)
    client.loop_start()

    try:
        if not devices_event.wait(timeout=timeout):
            raise RuntimeError(
                f"Timeout waiting for zigbee2mqtt/bridge/devices from {site_name} "
                f"(waited {timeout}s)"
            )

        if state["connect_error"]:
            raise RuntimeError(
                f"MQTT connect failed for {site_name}: {state['connect_error']}"
            )

        if not info_event.wait(timeout=5.0):
            if verbose:
                print(
                    f"  [{site_name}] Warning: no bridge/info received",
                    file=sys.stderr,
                )

        # Collect availability messages (retained, arrive almost immediately)
        time.sleep(availability_collect_s)
    finally:
        client.loop_stop()
        client.disconnect()

    devices_raw = state["devices_raw"]
    if not isinstance(devices_raw, list):
        raise RuntimeError(
            f"Unexpected bridge/devices payload from {site_name}: {type(devices_raw)}"
        )

    availability = state["availability"]
    devices = [
        _parse_device(site_name, d, availability)
        for d in devices_raw
        if d.get("type") != "Coordinator"
    ]

    bridge_info: ZigbeeBridgeInfo | None = None
    if state["info_raw"] is not None:
        bridge_info = _parse_bridge_info(site_name, state["info_raw"])

    if verbose:
        version_str = f", Z2M {bridge_info.z2m_version}" if bridge_info else ""
        print(
            f"  [{site_name}] Found {len(devices)} device(s){version_str}",
            file=sys.stderr,
        )

    # Request network map to determine parent routing relationships.
    # A failed networkmap raises: treating it as "no parents" would
    # persist connected_via="" for every device, silently erasing the
    # previously-recorded topology (scan_zigbee keeps the site's
    # baseline document on error instead).
    networkmap = _request_networkmap(
        mqtt_config, site_name, timeout=networkmap_timeout, verbose=verbose,
    )
    parent_map = _build_parent_map(networkmap)
    updated = []
    for d in devices:
        parent, link_lqi = parent_map.get(d.ieee_address, ("", None))
        # Z2M 2.x bridge/devices no longer reports link_quality, so
        # the parent link's LQI from the networkmap is usually the
        # only signal reading available.  A device-reported value
        # still wins when present.
        lqi = d.link_quality if d.link_quality is not None else link_lqi
        updated.append(replace(
            d,
            connected_via=parent,
            connected_via_kind="parent" if parent else "",
            link_quality=lqi,
        ))
    devices = updated
    # Routers keep no parent records once joined (they are mesh peers);
    # anchor parentless routers via their strongest sibling link.
    devices, mesh_count = _anchor_mesh_routers(devices, networkmap)
    _validate_parents(site_name, devices)
    assigned = sum(1 for d in devices if d.connected_via)
    if verbose:
        mesh_str = (
            f" ({mesh_count} router(s) anchored via mesh sibling)"
            if mesh_count else ""
        )
        print(
            f"  [{site_name}] Network map: {assigned}/{len(devices)} "
            f"device(s) have uplink info{mesh_str}",
            file=sys.stderr,
        )

    return devices, bridge_info


def scan_zigbee(
    site_name: str,
    mqtt_config: MqttBrokerConfig,
    baseline: dict[str, dict] | None,
    *,
    verbose: bool = False,
) -> tuple[dict[str, dict], list[str]]:
    """Scan this site's Zigbee2MQTT instance via MQTT.

    Returns ``(data, errors)``.  *data* maps the site name -> ``{"bridge":
    bridge-info | None, "devices": {ieee: device}}`` — a single-entry
    document keyed by site so DB storage stays per-site.  A successful
    scan REPLACES the document WHOLESALE — the retained MQTT topics are
    the authoritative full device list, so a device absent from them has
    been removed from the Z2M instance.  A failed scan keeps the baseline
    document and returns an error string instead, so a transient broker
    outage doesn't discard the last-known device list.  Any other site's
    stale baseline document is dropped (the save then tombstones it).
    """
    if not mqtt_config.host:
        raise RuntimeError(
            "No [homeassistant.mqtt] host configured for the zigbee scan"
        )

    data = {
        site: doc for site, doc in (baseline or {}).items()
        if site == site_name
    }
    errors: list[str] = []

    try:
        devices, bridge = scan_zigbee_site(site_name, mqtt_config, verbose=verbose)
    except (RuntimeError, OSError) as e:
        errors.append(f"{site_name}: {e}")
        return data, errors

    data[site_name] = {
        "bridge": asdict(bridge) if bridge is not None else None,
        "devices": {d.ieee_address: asdict(d) for d in devices},
    }

    return data, errors


def raise_for_zigbee_errors(errors: list[str]) -> None:
    """Fail loud if a zigbee scan reported per-site errors.

    scan_zigbee keeps the results of the sites that succeeded and
    RETURNS the per-site failures instead of raising, so the caller can
    save the good results first and then surface the failures here.
    This keeps both "never silently discard data" and "fail loud"
    satisfied.
    """
    if errors:
        raise ZigbeeScanError(
            f"{len(errors)} zigbee site scan error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )
