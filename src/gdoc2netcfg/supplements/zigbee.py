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
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import ZigbeeConfig, ZigbeeSiteConfig


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


def scan_zigbee_site(
    site_name: str,
    mqtt_config: ZigbeeSiteConfig,
    timeout: float = 15.0,
    availability_collect_s: float = 2.0,
    verbose: bool = False,
) -> tuple[list[ZigbeeDevice], ZigbeeBridgeInfo | None]:
    """Scan a single site's Zigbee2MQTT instance via MQTT.

    Subscribes to the retained bridge/devices and bridge/info topics,
    then waits briefly to collect per-device availability messages
    (also retained, arrive immediately).

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
        client.subscribe("zigbee2mqtt/bridge/devices")
        client.subscribe("zigbee2mqtt/bridge/info")
        client.subscribe("zigbee2mqtt/+/availability")
        if verbose:
            print(
                f"  [{site_name}] Connected to {mqtt_config.mqtt_host}:{mqtt_config.mqtt_port}",
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

    if mqtt_config.mqtt_user:
        client.username_pw_set(mqtt_config.mqtt_user, mqtt_config.mqtt_password)

    if verbose:
        print(
            f"  [{site_name}] Connecting to {mqtt_config.mqtt_host}:{mqtt_config.mqtt_port}...",
            file=sys.stderr,
        )

    client.connect(mqtt_config.mqtt_host, mqtt_config.mqtt_port, keepalive=30)
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

    return devices, bridge_info


def scan_zigbee(
    zigbee_config: ZigbeeConfig,
    baseline: dict[str, dict] | None,
    *,
    verbose: bool = False,
) -> tuple[dict[str, dict], list[str]]:
    """Scan all configured Zigbee2MQTT sites via MQTT.

    Returns ``(data, errors)``.  *data* maps site name -> ``{"bridge":
    bridge-info | None, "devices": {ieee: device}}`` — one document per
    site, like the per-site cache files this replaced.  A successfully
    scanned site's document is REPLACED WHOLESALE — the retained MQTT
    topics are the authoritative full device list, so a device absent
    from them has been removed from that Z2M instance.  A failed site
    keeps its baseline document and adds an error string instead.  The
    caller persists *data* first, then fails loud via
    raise_for_zigbee_errors — so one unreachable broker can't discard
    the other site's results.

    Baseline entries for sites no longer in the config are dropped
    (the save tombstones them); a device listed by two sites (moved
    between sites without removing the old registry entry) keeps both
    sites' views — each site's sheet run projects its own view.
    """
    if not zigbee_config.sites:
        raise RuntimeError("No zigbee sites configured in gdoc2netcfg.toml")

    configured = {site_cfg.name for site_cfg in zigbee_config.sites}
    data = {
        site: doc for site, doc in (baseline or {}).items()
        if site in configured
    }
    errors: list[str] = []

    for site_cfg in zigbee_config.sites:
        if not site_cfg.mqtt_host:
            raise RuntimeError(
                f"No mqtt_host configured for zigbee site '{site_cfg.name}'"
            )

        try:
            devices, bridge = scan_zigbee_site(
                site_cfg.name, site_cfg, verbose=verbose,
            )
        except (RuntimeError, OSError) as e:
            errors.append(f"{site_cfg.name}: {e}")
            continue

        data[site_cfg.name] = {
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
