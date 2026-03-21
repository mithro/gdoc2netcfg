"""Tasmota Home Assistant integration check and sync.

Queries the Home Assistant REST API to verify that Tasmota devices
are properly registered and reporting state.  Devices with relays
appear as switch entities; relay-less devices (IR blasters, bridges)
appear as sensor-only.  The check fetches all HA states in one bulk
request and matches by the entity-name prefix derived from each
device's machine_name.

The sync function pushes device metadata (name_by_user) from the
spreadsheet into HA's device registry via the WebSocket API.
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import HomeAssistantConfig
    from gdoc2netcfg.models.host import Host


def _slug_for_host(host: Host) -> str:
    """Derive the HA entity slug prefix for a Tasmota host.

    When DeviceName == FriendlyName (which we enforce), the HA Tasmota
    integration names entities as ``{domain}.{slug}_{sensor_type}``.
    Slugify lowercases and replaces non-alphanumeric characters with
    underscores.
    """
    return host.machine_name.replace("-", "_").replace(".", "_").lower()


def _fetch_all_states(ha_config: HomeAssistantConfig) -> list[dict]:
    """Fetch all entity states from the Home Assistant REST API."""
    url = f"{ha_config.url.rstrip('/')}/api/states"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {ha_config.token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30.0) as resp:
        return json.loads(resp.read())


def check_ha_status(
    hosts: list[Host],
    ha_config: HomeAssistantConfig,
    max_workers: int = 16,
    verbose: bool = False,
) -> dict[str, dict]:
    """Check Home Assistant for Tasmota device entities.

    Fetches all HA entity states in a single request, then matches
    each Tasmota host by its entity-name prefix.  Devices with relay
    entities (switches) report switch state; relay-less devices (IR
    blasters, sensor bridges) report as registered with sensor count.

    Args:
        hosts: Hosts with tasmota_data attached.
        ha_config: Home Assistant connection config.
        max_workers: Unused (kept for API compatibility).
        verbose: Print progress to stderr.

    Returns:
        Mapping of hostname to status dict with keys:
        exists, entity_id/entities, state, last_changed.
    """
    tasmota_hosts = [
        h for h in sorted(hosts, key=lambda h: h.hostname)
        if h.tasmota_data is not None
    ]
    if not tasmota_hosts:
        return {}

    try:
        all_states = _fetch_all_states(ha_config)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as e:
        if verbose:
            print(f"  Error fetching HA states: {e}", file=sys.stderr)
        return {
            h.hostname: {"exists": False, "error": str(e)}
            for h in tasmota_hosts
        }

    # Index entities by slug prefix for fast lookup.
    # e.g. "switch.au_plug_1" and "sensor.au_plug_1_energy_power"
    # both have prefix "au_plug_1".
    prefix_to_entities: dict[str, list[dict]] = {}
    for entity in all_states:
        eid = entity["entity_id"]
        domain, slug = eid.split(".", 1)
        prefix_to_entities.setdefault(slug, []).append(entity)
        # Also index by the prefix before the first sensor-type suffix,
        # so "au_plug_1_energy_power" is findable under "au_plug_1".
        # We do this by checking if slug starts with any known device prefix.
        # (handled below in the matching loop instead)

    results: dict[str, dict] = {}

    for host in tasmota_hosts:
        slug = _slug_for_host(host)

        # Find all entities whose slug starts with this device's prefix.
        matching: list[dict] = []
        for entity in all_states:
            eid = entity["entity_id"]
            entity_slug = eid.split(".", 1)[1]
            if entity_slug == slug or entity_slug.startswith(slug + "_"):
                matching.append(entity)

        switches = [e for e in matching if e["entity_id"].startswith("switch.")]
        sensors = [e for e in matching if e["entity_id"].startswith("sensor.")]

        if switches:
            # Device has relay entities — report the primary switch state.
            sw = switches[0]
            status: dict = {
                "exists": True,
                "entity_id": sw["entity_id"],
                "state": sw.get("state", "unknown"),
                "last_changed": sw.get("last_changed", ""),
                "entity_count": len(matching),
            }
        elif sensors:
            # Relay-less device (IR blaster, bridge) — sensors only.
            status = {
                "exists": True,
                "entity_id": sensors[0]["entity_id"],
                "state": f"{len(sensors)} sensors",
                "last_changed": sensors[0].get("last_changed", ""),
                "entity_count": len(matching),
            }
        else:
            status = {"exists": False, "entity_count": 0}

        results[host.hostname] = status

        if verbose:
            if status["exists"]:
                state = status.get("state", "?")
                count = status["entity_count"]
                print(
                    f"  {host.hostname:30s}  {status['entity_id']:40s}  "
                    f"state={state}  ({count} entities)",
                    file=sys.stderr,
                )
            else:
                expected = f"switch.{slug}"
                print(
                    f"  {host.hostname:30s}  {expected:40s}  NOT FOUND",
                    file=sys.stderr,
                )

    return results


# ---------------------------------------------------------------------------
# HA device metadata sync
# ---------------------------------------------------------------------------


def _desired_name_by_user(host: Host) -> str:
    """Compose the desired name_by_user for a Tasmota device.

    Follows the Zigbee2MQTT convention: ``(code) description``.
    The description is the comma-separated list of hostnames this
    device controls (from the spreadsheet "Controls" column).
    Devices with no controls get just ``(code)``.
    """
    code = host.machine_name
    controls = host.tasmota_data.controls if host.tasmota_data else ()
    if controls:
        return f"({code}) {', '.join(controls)}"
    return f"({code})"


async def _sync_ha_devices(
    hosts: list[Host],
    ha_config: HomeAssistantConfig,
    dry_run: bool = False,
) -> list[tuple[str, str, str]]:
    """Sync Tasmota device metadata to HA via WebSocket API.

    Matches devices by MAC address, then sets name_by_user to the
    ``(code) controlled-hostnames`` format.

    Returns list of (machine_name, old_value, new_value) for changes made.
    """
    import websockets

    tasmota_hosts = [h for h in hosts if h.tasmota_data is not None]
    if not tasmota_hosts:
        return []

    # Build MAC -> (host, desired_name) mapping.
    mac_to_desired: dict[str, tuple[Host, str]] = {}
    for host in tasmota_hosts:
        mac = host.tasmota_data.mac.lower()
        mac_to_desired[mac] = (host, _desired_name_by_user(host))

    ws_url = ha_config.url.rstrip("/").replace("http://", "ws://").replace(
        "https://", "wss://"
    ) + "/api/websocket"

    changes: list[tuple[str, str, str]] = []

    async with websockets.connect(ws_url, max_size=10 * 1024 * 1024) as ws:
        # Authenticate
        await ws.recv()  # auth_required
        await ws.send(json.dumps({"type": "auth", "access_token": ha_config.token}))
        auth_resp = json.loads(await ws.recv())
        if auth_resp.get("type") != "auth_ok":
            raise RuntimeError(f"HA WebSocket auth failed: {auth_resp}")

        msg_id = 1

        # Fetch device registry
        await ws.send(json.dumps({"id": msg_id, "type": "config/device_registry/list"}))
        msg_id += 1
        dev_resp = json.loads(await ws.recv())
        if not dev_resp.get("success"):
            raise RuntimeError(f"Failed to list devices: {dev_resp.get('error')}")

        # Match HA devices to our hosts by MAC
        for device in dev_resp["result"]:
            device_mac = None
            for conn_type, conn_val in device.get("connections", []):
                if conn_type == "mac":
                    device_mac = conn_val.lower()

            if device_mac not in mac_to_desired:
                continue

            host, desired_name = mac_to_desired[device_mac]
            current_name = device.get("name_by_user") or ""

            if current_name == desired_name:
                continue

            changes.append((host.machine_name, current_name, desired_name))

            if not dry_run:
                await ws.send(json.dumps({
                    "id": msg_id,
                    "type": "config/device_registry/update",
                    "device_id": device["id"],
                    "name_by_user": desired_name,
                }))
                msg_id += 1
                update_resp = json.loads(await ws.recv())
                if not update_resp.get("success"):
                    err = update_resp.get("error", {}).get("message", "unknown")
                    raise RuntimeError(
                        f"Failed to update {host.machine_name}: {err}"
                    )

    return changes


def sync_ha_devices(
    hosts: list[Host],
    ha_config: HomeAssistantConfig,
    dry_run: bool = False,
) -> list[tuple[str, str, str]]:
    """Synchronous wrapper for _sync_ha_devices."""
    return asyncio.run(_sync_ha_devices(hosts, ha_config, dry_run=dry_run))
