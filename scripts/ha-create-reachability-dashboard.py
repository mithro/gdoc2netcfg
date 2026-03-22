#!/usr/bin/env python3
"""Create a Home Assistant dashboard for gdoc2netcfg reachability.

Connects to the HA WebSocket API and creates a dedicated Lovelace
dashboard showing host connectivity, presence, RTT, and interface
status from the gdoc2netcfg MQTT publisher.

Usage:
    uv run scripts/ha-create-reachability-dashboard.py
    uv run scripts/ha-create-reachability-dashboard.py --delete
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.request

from gdoc2netcfg.config import load_config


def _fetch_our_entities(config) -> dict[str, list[dict]]:
    """Fetch all gdoc2netcfg entities from HA, grouped by type."""
    url = f"{config.homeassistant.url.rstrip('/')}/api/states"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {config.homeassistant.token}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        states = json.loads(resp.read())

    prefix = "gdoc2netcfg_"
    ours = [e for e in states if prefix in e["entity_id"]]

    # Classify entities
    connectivity = []
    trackers = []
    stack_mode = []
    rtt = []

    for e in ours:
        eid = e["entity_id"]
        if eid.startswith("device_tracker."):
            trackers.append(e)
        elif eid.endswith("_rtt"):
            rtt.append(e)
        elif eid.endswith("_connectivity"):
            connectivity.append(e)
        elif eid.endswith("_stack_mode"):
            stack_mode.append(e)

    return {
        "connectivity": sorted(connectivity, key=lambda e: e["entity_id"]),
        "trackers": sorted(trackers, key=lambda e: e["entity_id"]),
        "stack_mode": sorted(stack_mode, key=lambda e: e["entity_id"]),
        "rtt": sorted(rtt, key=lambda e: e["entity_id"]),
    }


def _build_dashboard_config(entities: dict[str, list[dict]]) -> dict:
    """Build the Lovelace dashboard YAML config."""

    conn = entities["connectivity"]
    trackers = entities["trackers"]
    rtt = entities["rtt"]

    summary_template = (
        "{% set conn = states.binary_sensor "
        "| selectattr('entity_id', 'match', 'binary_sensor\\\\.gdoc2netcfg_.*_connectivity$') "
        "| list %}"
        "{% set on = conn | selectattr('state', 'eq', 'on') | list | count %}"
        "{% set off = conn | selectattr('state', 'eq', 'off') | list | count %}"
        "{% set unavail = conn | selectattr('state', 'eq', 'unavailable') | list | count %}"
        "{% set trackers = states.device_tracker "
        "| selectattr('entity_id', 'match', 'device_tracker\\\\.gdoc2netcfg_') "
        "| list %}"
        "{% set home = trackers | selectattr('state', 'eq', 'home') | list | count %}"
        "{% set away = trackers | selectattr('state', 'eq', 'not_home') | list | count %}"
        "\n"
        "| | Count |\n"
        "|---|---:|\n"
        "| **Connected** | {{ on }} |\n"
        "| **Disconnected** | {{ off }} |\n"
        "| **Unavailable** | {{ unavail }} |\n"
        "| **Home** | {{ home }} |\n"
        "| **Away** | {{ away }} |\n"
    )

    views = [
        {
            "title": "Overview",
            "path": "overview",
            "icon": "mdi:network",
            "cards": [
                # Summary
                {
                    "type": "markdown",
                    "title": "Network Status",
                    "content": summary_template,
                },
                # Online hosts
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "glance",
                        "title": "Online Hosts",
                        "show_state": False,
                    },
                    "state_filter": ["on"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in conn
                    ],
                },
                # Offline hosts
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "glance",
                        "title": "Offline Hosts",
                        "show_state": False,
                    },
                    "state_filter": ["off"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in conn
                    ],
                },
                # Unavailable hosts
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "glance",
                        "title": "Unavailable",
                        "show_state": False,
                    },
                    "state_filter": ["unavailable"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in conn
                    ],
                },
            ],
        },
        {
            "title": "Presence",
            "path": "presence",
            "icon": "mdi:home-account",
            "cards": [
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "glance",
                        "title": "Home",
                        "show_state": False,
                    },
                    "state_filter": ["home"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in trackers
                    ],
                },
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "glance",
                        "title": "Away",
                        "show_state": False,
                    },
                    "state_filter": ["not_home"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in trackers
                    ],
                },
            ],
        },
        {
            "title": "Latency",
            "path": "latency",
            "icon": "mdi:timer-outline",
            "cards": [
                # RTT sensors with values, sorted by value descending
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "entities",
                        "title": "Round-Trip Time (online hosts)",
                    },
                    "state_filter": [
                        {"operator": ">", "value": "0"},
                    ],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in rtt
                    ],
                },
            ],
        },
        {
            "title": "Stack Mode",
            "path": "stack-mode",
            "icon": "mdi:ip-network",
            "cards": [
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "entities",
                        "title": "Dual-Stack",
                    },
                    "state_filter": ["dual-stack"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in entities["stack_mode"]
                    ],
                },
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "entities",
                        "title": "IPv4 Only",
                    },
                    "state_filter": ["ipv4-only"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in entities["stack_mode"]
                    ],
                },
                {
                    "type": "entity-filter",
                    "card": {
                        "type": "entities",
                        "title": "IPv6 Only",
                    },
                    "state_filter": ["ipv6-only"],
                    "entities": [
                        {"entity": e["entity_id"]}
                        for e in entities["stack_mode"]
                    ],
                },
            ],
        },
    ]

    return {"views": views}


async def _push_dashboard(config, dashboard_config: dict, delete: bool = False) -> None:
    """Create or update the dashboard via HA WebSocket API."""
    import websockets

    ws_url = (
        config.homeassistant.url.rstrip("/")
        .replace("http://", "ws://")
        .replace("https://", "wss://")
        + "/api/websocket"
    )

    async with websockets.connect(ws_url, max_size=10 * 1024 * 1024) as ws:
        await ws.recv()  # auth_required
        await ws.send(json.dumps({
            "type": "auth",
            "access_token": config.homeassistant.token,
        }))
        auth = json.loads(await ws.recv())
        if auth.get("type") != "auth_ok":
            raise RuntimeError(f"Auth failed: {auth}")

        msg_id = 1

        # List existing dashboards
        await ws.send(json.dumps({
            "id": msg_id,
            "type": "lovelace/dashboards/list",
        }))
        msg_id += 1
        resp = json.loads(await ws.recv())
        if not resp.get("success"):
            raise RuntimeError(f"Failed to list dashboards: {resp}")

        existing = [d for d in resp["result"]
                     if d.get("url_path") == "network-reachability"]

        if delete:
            if existing:
                await ws.send(json.dumps({
                    "id": msg_id,
                    "type": "lovelace/dashboards/delete",
                    "dashboard_id": existing[0]["id"],
                }))
                msg_id += 1
                del_resp = json.loads(await ws.recv())
                if del_resp.get("success"):
                    print("Deleted dashboard 'network-reachability'")
                else:
                    print(f"Failed to delete: {del_resp.get('error')}")
            else:
                print("Dashboard 'network-reachability' not found")
            return

        # Create dashboard if it doesn't exist
        if not existing:
            await ws.send(json.dumps({
                "id": msg_id,
                "type": "lovelace/dashboards/create",
                "url_path": "network-reachability",
                "title": "Network Reachability",
                "icon": "mdi:network",
                "require_admin": False,
                "show_in_sidebar": True,
            }))
            msg_id += 1
            create_resp = json.loads(await ws.recv())
            if not create_resp.get("success"):
                raise RuntimeError(
                    f"Failed to create dashboard: {create_resp.get('error')}"
                )
            print("Created dashboard 'network-reachability'")
        else:
            print("Dashboard 'network-reachability' already exists, updating...")

        # Save the config
        await ws.send(json.dumps({
            "id": msg_id,
            "type": "lovelace/config/save",
            "url_path": "network-reachability",
            "config": dashboard_config,
        }))
        msg_id += 1
        save_resp = json.loads(await ws.recv())
        if not save_resp.get("success"):
            raise RuntimeError(
                f"Failed to save config: {save_resp.get('error')}"
            )
        print("Dashboard config saved")


def main():
    delete = "--delete" in sys.argv

    config = load_config()
    if not config.homeassistant.url or not config.homeassistant.token:
        print(
            "Error: [homeassistant] url and token must be configured",
            file=sys.stderr,
        )
        sys.exit(1)

    if delete:
        asyncio.run(_push_dashboard(config, {}, delete=True))
        return

    print("Fetching entities from HA...")
    entities = _fetch_our_entities(config)
    print(
        f"  {len(entities['connectivity'])} connectivity, "
        f"{len(entities['trackers'])} trackers, "
        f"{len(entities['rtt'])} RTT, "
        f"{len(entities['stack_mode'])} stack_mode"
    )

    print("Building dashboard config...")
    dashboard_config = _build_dashboard_config(entities)

    print("Pushing to Home Assistant...")
    asyncio.run(_push_dashboard(config, dashboard_config))

    url = config.homeassistant.url.rstrip("/")
    print(f"\nDashboard available at: {url}/network-reachability/overview")


if __name__ == "__main__":
    main()
