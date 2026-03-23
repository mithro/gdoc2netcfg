"""Publish host reachability to Home Assistant via MQTT discovery.

Converts gdoc2netcfg's reachability scan data into HA-compatible MQTT
discovery payloads and state messages.  Each host becomes an HA device
with connectivity, presence, and diagnostic entities.  Each interface
gets its own connectivity, IP, MAC, and RTT sensors.

Discovery payloads are retained so HA rediscovers entities on restart.
State messages are NOT retained — expire_after handles staleness.
Bridge availability uses LWT for automatic offline marking.

See docs/ha-mqtt-discovery-reference.md for the HA MQTT discovery format.
"""

from __future__ import annotations

import json
import re
import signal
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import paho.mqtt.client as mqtt

if TYPE_CHECKING:
    from gdoc2netcfg.config import PipelineConfig, TasmotaConfig
    from gdoc2netcfg.models.host import Host, VirtualInterface
    from gdoc2netcfg.supplements.reachability import (
        HostReachability,
        InterfaceReachability,
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DISCOVERY_PREFIX = "homeassistant"
STATE_PREFIX = "gdoc2netcfg"
BRIDGE_AVAIL_TOPIC = f"{STATE_PREFIX}/bridge/availability"
ORIGIN = {
    "name": "gdoc2netcfg",
    "url": "https://github.com/mithro/gdoc2netcfg",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node_id(name: str) -> str:
    """Derive MQTT node_id from a host's hostname.

    Replaces non-alphanumeric characters with underscores.

    Uses hostname (not machine_name) because BMC hosts share their
    parent's machine_name (e.g. both "big-storage" and
    "bmc.big-storage" have machine_name="big-storage"), which would
    cause entity ID collisions.  Hostname is always unique.

    Example: "big-storage" -> "big_storage"
    Example: "bmc.big-storage" -> "bmc_big_storage"
    Example: "au-plug-1.iot" -> "au_plug_1_iot"
    """
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


def _iface_slug(vi: VirtualInterface) -> str:
    """Derive interface slug for MQTT topics and unique_ids.

    Uses the interface name if set, otherwise "default".
    Example: "eth0" -> "eth0", None -> "default"
    """
    name = vi.name if vi.name else "default"
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


def _iface_entity_state_topic(
    entity: EntityDef,
    nid: str,
    slug: str,
) -> tuple[str, str | None]:
    """Derive the state topic and JSON attributes topic for an interface entity.

    Returns (state_topic, json_attributes_topic_or_None).
    """
    if entity.suffix.endswith("_connectivity"):
        return f"{STATE_PREFIX}/{nid}/{slug}/connectivity/state", None
    elif entity.suffix.endswith("_stack_mode"):
        return f"{STATE_PREFIX}/{nid}/{slug}/stack_mode/state", None
    elif entity.suffix.endswith("_ipv4"):
        return f"{STATE_PREFIX}/{nid}/{slug}/ipv4/state", None
    elif entity.suffix.endswith("_mac"):
        return f"{STATE_PREFIX}/{nid}/{slug}/mac/state", None
    elif entity.suffix.endswith("_rtt"):
        return (
            f"{STATE_PREFIX}/{nid}/{slug}/rtt/state",
            f"{STATE_PREFIX}/{nid}/{slug}/rtt/attributes",
        )
    else:
        raise ValueError(f"Unknown entity suffix: {entity.suffix}")


# ---------------------------------------------------------------------------
# Entity definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EntityDef:
    """Definition of a single HA entity for MQTT discovery.

    Attributes:
        component: HA platform type (binary_sensor, sensor, device_tracker).
        suffix: Unique suffix for this entity within the device.
        name: Display name (None = main entity of device).
        device_class: HA device class (connectivity, duration, etc.).
        state_class: HA state class (measurement, etc.).
        entity_category: HA entity category (diagnostic, config, or None).
        unit: Unit of measurement.
        icon: MDI icon override.
        suggested_display_precision: Decimal places for display.
        source_type: For device_tracker only (router, gps, etc.).
        payload_on: For binary_sensor ON state.
        payload_off: For binary_sensor OFF state.
        payload_home: For device_tracker home state.
        payload_not_home: For device_tracker away state.
        expire_after: Seconds before entity goes unavailable without update.
        value_template: Jinja2 template to extract value from JSON state.
        json_attributes_topic_suffix: If set, use this suffix for attributes topic.
    """

    component: str
    suffix: str
    name: str | None = None
    device_class: str | None = None
    state_class: str | None = None
    entity_category: str | None = None
    unit: str | None = None
    icon: str | None = None
    suggested_display_precision: int | None = None
    source_type: str | None = None
    payload_on: str | None = None
    payload_off: str | None = None
    payload_home: str | None = None
    payload_not_home: str | None = None
    expire_after: int | None = None
    value_template: str | None = None
    json_attributes_topic_suffix: str | None = None


# Host-level entities
HOST_CONNECTIVITY = EntityDef(
    component="binary_sensor",
    suffix="connectivity",
    name=None,  # Main entity — HA uses device name
    device_class="connectivity",
    payload_on="ON",
    payload_off="OFF",
    expire_after=600,
)

HOST_TRACKER = EntityDef(
    component="device_tracker",
    suffix="tracker",
    name="Network presence",
    source_type="router",
    payload_home="home",
    payload_not_home="not_home",
)

HOST_STACK_MODE = EntityDef(
    component="sensor",
    suffix="stack_mode",
    name="Stack mode",
    entity_category="diagnostic",
    icon="mdi:ip-network",
)


def _iface_entities(iface_slug: str, iface_name: str | None) -> list[EntityDef]:
    """Build entity definitions for a single interface."""
    display = iface_name or "default"
    return [
        EntityDef(
            component="binary_sensor",
            suffix=f"{iface_slug}_connectivity",
            name=display,
            device_class="connectivity",
            payload_on="ON",
            payload_off="OFF",
            expire_after=600,
        ),
        EntityDef(
            component="sensor",
            suffix=f"{iface_slug}_stack_mode",
            name=f"{display} stack mode",
            entity_category="diagnostic",
            icon="mdi:ip-network",
        ),
        EntityDef(
            component="sensor",
            suffix=f"{iface_slug}_ipv4",
            name=f"{display} IPv4",
            entity_category="diagnostic",
            icon="mdi:ip-network",
        ),
        EntityDef(
            component="sensor",
            suffix=f"{iface_slug}_mac",
            name=f"{display} MAC",
            entity_category="diagnostic",
            icon="mdi:ethernet",
        ),
        EntityDef(
            component="sensor",
            suffix=f"{iface_slug}_rtt",
            name=f"{display} RTT",
            device_class="duration",
            state_class="measurement",
            unit="ms",
            entity_category="diagnostic",
            suggested_display_precision=1,
        ),
    ]


# ---------------------------------------------------------------------------
# Discovery payload builders
# ---------------------------------------------------------------------------

def _device_dict(host: Host) -> dict:
    """Build HA device registry dict for a host."""
    nid = _node_id(host.hostname)
    device: dict = {
        "identifiers": [f"gdoc2netcfg_{nid}"],
        "name": host.hostname,
    }

    # Add all MAC addresses as connections for cross-integration merging
    macs = host.all_macs
    if macs:
        device["connections"] = [["mac", str(m).lower()] for m in macs]

    # Configuration URL — first IPv4
    first_ip = host.first_ipv4
    if first_ip:
        device["configuration_url"] = f"http://{first_ip}"

    # Suggested area from spreadsheet
    location = host.extra.get("Physical Location", "").strip()
    if location:
        device["suggested_area"] = location

    return device


def _availability_list(
    host: Host,
    hosts_by_name: dict[str, Host] | None = None,
) -> tuple[list[dict], str | None]:
    """Build availability list for an entity.

    Returns (availability_list, availability_mode).
    The base availability is always the bridge topic.
    If the host is controlled by a Tasmota plug, adds the plug's
    power state topic so HA shows "unavailable" when plug is off.

    Hosts that ARE Tasmota plugs (have a Controls column) are skipped
    for the reverse lookup — they control others, they aren't controlled.
    """
    avail: list[dict] = [
        {
            "topic": BRIDGE_AVAIL_TOPIC,
            "payload_available": "online",
            "payload_not_available": "offline",
        },
    ]
    mode = None

    # Only look for a controlling plug if this host doesn't have a Controls
    # entry itself (plugs control other devices, they aren't controlled).
    has_controls = bool(host.extra.get("Controls", "").strip())
    if not has_controls and hosts_by_name:
        # Check if any Tasmota device lists this host in its controls
        for other_host in hosts_by_name.values():
            if other_host.tasmota_data is None:
                continue
            if host.machine_name in other_host.tasmota_data.controls:
                # This host is powered by other_host's Tasmota plug
                mqtt_topic = other_host.tasmota_data.mqtt_topic
                avail.append({
                    "topic": f"stat/{mqtt_topic}/POWER",
                    "payload_available": "ON",
                    "payload_not_available": "OFF",
                })
                mode = "all"
                break

    return avail, mode


def discovery_payload(
    entity: EntityDef,
    node_id: str,
    device_dict: dict,
    avail_list: list[dict],
    avail_mode: str | None,
    state_topic: str,
    json_attr_topic: str | None = None,
) -> dict:
    """Build a complete HA MQTT discovery payload."""
    unique_id = f"gdoc2netcfg_{node_id}_{entity.suffix}"

    # Explicit entity_id so it's stable regardless of device name_by_user
    # or cross-integration device merging.  Full domain-qualified form.
    default_eid = f"{entity.component}.gdoc2netcfg_{node_id}_{entity.suffix}"

    payload: dict = {
        "unique_id": unique_id,
        "default_entity_id": default_eid,
        "state_topic": state_topic,
        "device": device_dict,
        "origin": ORIGIN,
        "availability": avail_list,
    }

    if avail_mode:
        payload["availability_mode"] = avail_mode

    # Name: None means main entity (HA uses device name)
    if entity.name is not None:
        payload["name"] = entity.name
    else:
        payload["name"] = None

    if entity.device_class:
        payload["device_class"] = entity.device_class
    if entity.state_class:
        payload["state_class"] = entity.state_class
    if entity.entity_category:
        payload["entity_category"] = entity.entity_category
    if entity.unit:
        payload["unit_of_measurement"] = entity.unit
    if entity.icon:
        payload["icon"] = entity.icon
    if entity.suggested_display_precision is not None:
        payload["suggested_display_precision"] = entity.suggested_display_precision
    if entity.source_type:
        payload["source_type"] = entity.source_type
    if entity.payload_on:
        payload["payload_on"] = entity.payload_on
    if entity.payload_off:
        payload["payload_off"] = entity.payload_off
    if entity.payload_home:
        payload["payload_home"] = entity.payload_home
    if entity.payload_not_home:
        payload["payload_not_home"] = entity.payload_not_home
    if entity.expire_after is not None:
        payload["expire_after"] = entity.expire_after
    if entity.value_template:
        payload["value_template"] = entity.value_template
    if json_attr_topic:
        payload["json_attributes_topic"] = json_attr_topic

    return payload


def discovery_topic(entity: EntityDef, node_id: str) -> str:
    """Build the MQTT discovery topic for an entity."""
    unique_id = f"gdoc2netcfg_{node_id}_{entity.suffix}"
    return (
        f"{DISCOVERY_PREFIX}/{entity.component}/"
        f"gdoc2netcfg_{node_id}/{unique_id}/config"
    )


# ---------------------------------------------------------------------------
# State builders
# ---------------------------------------------------------------------------

def build_host_state(
    host: Host,
    hr: HostReachability,
) -> dict[str, str | dict]:
    """Build state messages for host-level entities.

    Returns dict mapping state topic suffix to payload string/dict.
    """
    nid = _node_id(host.hostname)
    states: dict[str, str | dict] = {}

    # Connectivity: ON/OFF
    states[f"{STATE_PREFIX}/{nid}/connectivity/state"] = (
        "ON" if hr.is_up else "OFF"
    )

    # Device tracker: home/not_home
    states[f"{STATE_PREFIX}/{nid}/tracker/state"] = (
        "home" if hr.is_up else "not_home"
    )

    # Device tracker attributes
    tracker_attrs: dict = {"host_name": host.hostname}
    first_ip = host.first_ipv4
    if first_ip:
        tracker_attrs["ip"] = str(first_ip)
    macs = host.all_macs
    if macs:
        tracker_attrs["mac"] = str(macs[0]).lower()
    states[f"{STATE_PREFIX}/{nid}/tracker/attributes"] = json.dumps(
        tracker_attrs,
    )

    # Stack mode
    states[f"{STATE_PREFIX}/{nid}/stack_mode/state"] = hr.reachability_mode

    return states


def build_interface_state(
    host: Host,
    vi: VirtualInterface,
    ir: InterfaceReachability,
) -> dict[str, str | dict]:
    """Build state messages for interface-level entities.

    Returns dict mapping state topic to payload string.
    """
    nid = _node_id(host.hostname)
    slug = _iface_slug(vi)
    prefix = f"{STATE_PREFIX}/{nid}/{slug}"
    states: dict[str, str | dict] = {}

    # Interface connectivity
    is_up = len(ir.active_ips) > 0
    states[f"{prefix}/connectivity/state"] = "ON" if is_up else "OFF"

    # Stack mode
    states[f"{prefix}/stack_mode/state"] = ir.reachability_mode

    # IPv4 — every VirtualInterface must have an IPv4; ValueError here
    # means the host-builder produced a broken interface.
    states[f"{prefix}/ipv4/state"] = str(vi.ipv4)

    # MAC — every VirtualInterface groups physical NICs, so macs must
    # be non-empty.
    if not vi.macs:
        raise ValueError(
            f"VirtualInterface {vi.name!r} for {host.machine_name!r} "
            f"has no MACs — bug in host-builder pipeline."
        )
    states[f"{prefix}/mac/state"] = str(vi.macs[0]).lower()

    # RTT — build JSON with per-IP ping data
    rtt_data: dict = {}
    best_rtt: float | None = None
    for ip_str, ping in ir.pings:
        rtt_data[ip_str] = {
            "transmitted": ping.transmitted,
            "received": ping.received,
            "rtt_avg_ms": ping.rtt_avg_ms,
        }
        if ping.rtt_avg_ms is not None:
            if best_rtt is None or ping.rtt_avg_ms < best_rtt:
                best_rtt = ping.rtt_avg_ms

    if best_rtt is not None:
        states[f"{prefix}/rtt/state"] = f"{best_rtt:.1f}"
    else:
        states[f"{prefix}/rtt/state"] = ""

    # JSON attributes for RTT entity
    states[f"{prefix}/rtt/attributes"] = json.dumps(rtt_data)

    return states


# ---------------------------------------------------------------------------
# Shared publish logic (used by both one-shot and daemon)
# ---------------------------------------------------------------------------

def _publish_hosts_to_client(
    client: mqtt.Client,
    hosts: list[Host],
    reachability: dict[str, HostReachability],
    hosts_by_name: dict[str, Host],
    verbose: bool = False,
) -> tuple[int, int, int]:
    """Publish discovery + state for all hosts to an MQTT client.

    Discovery is published for ALL hosts first, then a 2-second delay
    allows HA to process config and subscribe to state topics, then
    state is published for all hosts.  Without this delay, HA misses
    the initial state because it hasn't subscribed yet when the state
    messages arrive.

    Returns (published_count, discovery_count, state_count).
    Raises KeyError if a host has no reachability entry.
    Raises ValueError if interface counts don't match.
    """
    import time

    published = 0
    discovery_count = 0
    state_count = 0

    # Pre-validate all hosts before publishing anything
    sorted_hosts = sorted(hosts, key=lambda h: h.hostname)
    for host in sorted_hosts:
        if host.hostname not in reachability:
            raise KeyError(
                f"No reachability data for host {host.hostname!r}. "
                f"This indicates a bug in the scan or stale data."
            )
        hr = reachability[host.hostname]
        vis = host.virtual_interfaces
        if len(vis) != len(hr.interfaces):
            raise ValueError(
                f"Host {host.hostname!r} has {len(vis)} virtual "
                f"interfaces but reachability has "
                f"{len(hr.interfaces)} interface entries. "
                f"This indicates a data consistency bug."
            )

    # Phase 1: Publish ALL discovery payloads (retained)
    for host in sorted_hosts:
        nid = _node_id(host.hostname)
        hr = reachability[host.hostname]
        dev_dict = _device_dict(host)
        avail_list, avail_mode = _availability_list(host, hosts_by_name)

        # Host-level discovery
        for entity in [HOST_CONNECTIVITY, HOST_TRACKER, HOST_STACK_MODE]:
            if entity == HOST_CONNECTIVITY:
                state_topic = f"{STATE_PREFIX}/{nid}/connectivity/state"
            elif entity == HOST_TRACKER:
                state_topic = f"{STATE_PREFIX}/{nid}/tracker/state"
            else:
                state_topic = f"{STATE_PREFIX}/{nid}/stack_mode/state"

            json_attr = None
            if entity == HOST_TRACKER:
                json_attr = f"{STATE_PREFIX}/{nid}/tracker/attributes"

            payload = discovery_payload(
                entity, nid, dev_dict, avail_list, avail_mode,
                state_topic, json_attr,
            )
            topic = discovery_topic(entity, nid)
            client.publish(topic, json.dumps(payload), retain=True)
            discovery_count += 1

        # Interface-level discovery
        for vi in host.virtual_interfaces:
            slug = _iface_slug(vi)
            for entity in _iface_entities(slug, vi.name):
                st, ja = _iface_entity_state_topic(entity, nid, slug)
                payload = discovery_payload(
                    entity, nid, dev_dict, avail_list, avail_mode,
                    st, ja,
                )
                topic = discovery_topic(entity, nid)
                client.publish(topic, json.dumps(payload), retain=True)
                discovery_count += 1

    # Wait for HA to process discovery and subscribe to state topics
    if verbose:
        print(
            f"Published {discovery_count} discovery messages, "
            f"waiting 2s for HA to subscribe...",
            file=sys.stderr,
        )
    time.sleep(2)

    # Phase 2: Publish ALL state messages (not retained)
    for host in sorted_hosts:
        nid = _node_id(host.hostname)
        hr = reachability[host.hostname]

        # Host-level state
        host_states = build_host_state(host, hr)
        for topic, payload_val in host_states.items():
            client.publish(topic, payload_val, retain=False)
            state_count += 1

        # Interface-level state
        vis = host.virtual_interfaces
        for vi_idx, vi in enumerate(vis):
            ir = hr.interfaces[vi_idx]
            iface_states = build_interface_state(host, vi, ir)
            for topic, payload_val in iface_states.items():
                client.publish(topic, payload_val, retain=False)
                state_count += 1

        published += 1

    return published, discovery_count, state_count


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------

def publish_all_hosts(
    hosts: list[Host],
    reachability: dict[str, HostReachability],
    mqtt_config: TasmotaConfig,
    verbose: bool = False,
) -> int:
    """One-shot publish: discovery + state for all hosts.

    Connects to the MQTT broker, publishes all discovery payloads
    (retained), state messages (not retained), and bridge availability
    (retained), then disconnects cleanly.

    Returns the number of hosts published.
    """
    hosts_by_name = {h.machine_name: h for h in hosts}

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="gdoc2netcfg-reachability",
    )
    client.username_pw_set(mqtt_config.mqtt_user, mqtt_config.mqtt_password)

    # Set LWT before connecting — broker publishes this if we disconnect
    # unexpectedly
    client.will_set(BRIDGE_AVAIL_TOPIC, "offline", retain=True)

    if verbose:
        print("Connecting to MQTT broker...", file=sys.stderr)

    client.connect(
        mqtt_config.mqtt_host, mqtt_config.mqtt_port, keepalive=120,
    )
    client.loop_start()

    try:
        published, discovery_count, state_count = _publish_hosts_to_client(
            client, hosts, reachability, hosts_by_name,
            verbose=verbose,
        )

        # Bridge availability — we're online
        client.publish(BRIDGE_AVAIL_TOPIC, "online", retain=True)

        if verbose:
            print(
                f"Published {discovery_count} discovery + {state_count} state "
                f"messages for {published} hosts.",
                file=sys.stderr,
            )

        return published

    finally:
        client.disconnect()
        client.loop_stop()


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

def run_daemon(
    config: PipelineConfig,
    interval: int = 300,
    verbose: bool = True,
) -> None:
    """Run as a daemon: scan reachability and publish to MQTT in a loop.

    Handles SIGTERM and SIGINT for clean shutdown.
    Saves reachability.json cache on each cycle so CLI tools share data.

    Assumes the caller has already validated that mqtt_host is configured.
    """
    from gdoc2netcfg.supplements.reachability import (
        check_all_hosts_reachability,
        save_reachability_cache,
    )

    stop_event = threading.Event()

    def signal_handler(signum, frame):
        print(
            f"\nReceived signal {signum}, shutting down...",
            file=sys.stderr,
        )
        stop_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Build pipeline once
    from gdoc2netcfg.cli.main import _build_pipeline

    mqtt_config = config.tasmota

    # Set up persistent MQTT connection with LWT
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="gdoc2netcfg-reachability-daemon",
    )
    client.username_pw_set(mqtt_config.mqtt_user, mqtt_config.mqtt_password)
    client.will_set(BRIDGE_AVAIL_TOPIC, "offline", retain=True)

    if verbose:
        print(
            f"Connecting to MQTT "
            f"{mqtt_config.mqtt_host}:{mqtt_config.mqtt_port}...",
            file=sys.stderr,
        )

    client.connect(
        mqtt_config.mqtt_host, mqtt_config.mqtt_port, keepalive=120,
    )
    client.loop_start()

    try:
        _, hosts, _inventory, _result = _build_pipeline(config)
        hosts_by_name = {h.machine_name: h for h in hosts}
        cache_path = Path(config.cache.directory) / "reachability.json"

        cycle = 0
        while not stop_event.is_set():
            cycle += 1
            if verbose:
                print(
                    f"\n--- Cycle {cycle} ---",
                    file=sys.stderr,
                )

            # Scan reachability
            reachability = check_all_hosts_reachability(
                hosts, verbose=verbose,
            )

            # Save cache for CLI tools
            save_reachability_cache(cache_path, reachability)

            # Publish discovery + state using shared helper
            published, disc, state = _publish_hosts_to_client(
                client, hosts, reachability, hosts_by_name,
                verbose=verbose,
            )

            # Bridge online
            client.publish(BRIDGE_AVAIL_TOPIC, "online", retain=True)

            if verbose:
                print(
                    f"Published {disc} discovery + {state} state "
                    f"for {published} hosts. Next scan in {interval}s.",
                    file=sys.stderr,
                )

            stop_event.wait(timeout=interval)

    finally:
        # Mark bridge offline on clean shutdown
        client.publish(BRIDGE_AVAIL_TOPIC, "offline", retain=True)
        client.disconnect()
        client.loop_stop()
        if verbose:
            print("MQTT daemon stopped.", file=sys.stderr)
