#!/usr/bin/env python3
"""Display a table of all Tasmota and Zigbee2MQTT switch devices in Home Assistant.

Shows name, type, what each device controls, and its location.
Tasmota data comes from the gdoc2netcfg spreadsheet; Z2M data from the HA device registry.
Outputs markdown tables.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import urllib.request

import websockets

# Short model names for compactness
MODEL_SHORT = {
    "Athom Plug V3": "Athom Plug",
    "Sonoff S31": "Sonoff S31",
    "Smart plug (without power monitoring)": "Tuya Plug",
    "TRETAKT smart plug": "IKEA TRETAKT",
    "Light controller": "Tuya Light Ctrl",
    "Millimeter wave motion detection": "mmWave Sensor",
    "ZHA ZBBridge": "ZBBridge",
}

STATE_ICON = {
    "on": "\U0001f7e2",          # green circle
    "off": "\u26aa",              # white circle
    "unavailable": "\U0001f534",  # red circle
}


def natural_sort_key(s: str) -> list:
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", s)]


def short_model(model: str) -> str:
    return MODEL_SHORT.get(model, model)


def state_icon(state: str) -> str:
    return STATE_ICON.get(state, "\u2753")  # question mark fallback


async def get_ha_data(url: str, token: str) -> tuple:
    """Fetch device registry, entity registry, and area registry from HA."""
    ws_url = url.rstrip("/").replace("http://", "ws://").replace(
        "https://", "wss://"
    ) + "/api/websocket"

    async with websockets.connect(ws_url, max_size=10 * 1024 * 1024) as ws:
        await ws.recv()
        await ws.send(json.dumps({"type": "auth", "access_token": token}))
        auth = json.loads(await ws.recv())
        if auth.get("type") != "auth_ok":
            raise RuntimeError(f"HA auth failed: {auth}")

        mid = 1
        results = {}
        for req_type in [
            "config_entries/get",
            "config/device_registry/list",
            "config/entity_registry/list",
            "config/area_registry/list",
        ]:
            await ws.send(json.dumps({"id": mid, "type": req_type}))
            mid += 1
            results[req_type] = json.loads(await ws.recv())["result"]

    return (
        {e["entry_id"]: e for e in results["config_entries/get"]},
        results["config/device_registry/list"],
        {a["area_id"]: a["name"] for a in results["config/area_registry/list"]},
        results["config/entity_registry/list"],
    )


def get_states(url: str, token: str) -> dict[str, str]:
    """Fetch current entity states via REST API."""
    req = urllib.request.Request(
        f"{url.rstrip('/')}/api/states",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=30.0) as resp:
        return {e["entity_id"]: e["state"] for e in json.loads(resp.read())}


def _display_width(s: str) -> int:
    """Return the terminal display width of a string, accounting for wide chars."""
    import unicodedata
    w = 0
    for ch in s:
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ("W", "F"):
            w += 2
        else:
            w += 1
    return w


def _pad(s: str, width: int, align: str = "l") -> str:
    """Pad a string to a display width, accounting for wide chars."""
    dw = _display_width(s)
    padding = max(0, width - dw)
    if align == "c":
        left = padding // 2
        right = padding - left
        return " " * left + s + " " * right
    if align == "r":
        return " " * padding + s
    return s + " " * padding


def md_row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def md_sep(widths: list[int], aligns: list[str] | None = None) -> str:
    if aligns is None:
        aligns = ["l"] * len(widths)
    parts = []
    for w, a in zip(widths, aligns):
        if a == "c":
            parts.append(":" + "-" * (w - 2) + ":")
        elif a == "r":
            parts.append("-" * (w - 1) + ":")
        else:
            parts.append("-" * w)
    return "| " + " | ".join(parts) + " |"


def print_md_table(headers: list[str], rows: list[list[str]]) -> None:
    """Print a markdown table with auto-sized columns."""
    widths = [_display_width(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _display_width(cell))

    # State column (index 2) is center-aligned
    aligns = ["l"] * len(headers)
    aligns[2] = "c"

    print(md_row([_pad(h, w, a) for h, w, a in zip(headers, widths, aligns)]))
    print(md_sep(widths, aligns))
    for row in rows:
        print(md_row([_pad(c, w, a) for c, w, a in zip(row, widths, aligns)]))


def main() -> int:
    from gdoc2netcfg.config import load_config

    config = load_config()
    ha_url = config.homeassistant.url
    ha_token = config.homeassistant.token

    if not ha_url or not ha_token:
        print("Error: [homeassistant] url and token must be configured", file=sys.stderr)
        return 1

    # Load gdoc2netcfg pipeline for Tasmota metadata
    from gdoc2netcfg.cli.main import _build_pipeline

    _records, hosts, _inventory, _result = _build_pipeline(config)
    tasmota_by_mac = {}
    for h in hosts:
        if h.tasmota_data:
            mac = h.tasmota_data.mac.lower()
            tasmota_by_mac[mac] = h

    # Fetch HA data
    entries, devices, areas, entities = asyncio.run(
        get_ha_data(ha_url, ha_token)
    )
    states = get_states(ha_url, ha_token)

    # Map device_id -> first switch entity
    dev_switch = {}
    for e in entities:
        if e["entity_id"].startswith("switch.") and e.get("device_id") not in dev_switch:
            dev_switch[e["device_id"]] = e

    target_domains = {"tasmota", "mqtt"}
    rows_by_integration: dict[str, list[dict]] = {}

    for dev in devices:
        did = dev["id"]
        sw = dev_switch.get(did)
        if not sw:
            continue

        domain = None
        for ceid in dev.get("config_entries", []):
            entry = entries.get(ceid)
            if entry and entry["domain"] in target_domains:
                domain = entry["domain"]
                break
        if domain not in target_domains:
            continue

        if dev.get("name", "").startswith("Zigbee2MQTT Bridge"):
            continue

        state = states.get(sw["entity_id"], "?")
        area = areas.get(dev.get("area_id", ""), "")
        model = dev.get("model") or ""

        if domain == "tasmota":
            device_mac = None
            for conn_type, conn_val in dev.get("connections", []):
                if conn_type == "mac":
                    device_mac = conn_val.lower()

            host = tasmota_by_mac.get(device_mac)
            if host:
                name = host.machine_name
                controls = ", ".join(host.tasmota_data.controls) if host.tasmota_data else ""
                location = host.extra.get("Physical Location", "")
                integration = "Tasmota"
            else:
                name = dev.get("name") or "?"
                controls = ""
                location = area
                integration = "Tasmota"
        else:
            display = dev.get("name_by_user") or dev.get("name") or "?"
            m = re.match(r"\((.+?)\)\s*(.*)", display)
            if m:
                name = m.group(1)
                controls = m.group(2)
            else:
                name = display
                controls = ""
            location = area
            integration = "Zigbee2MQTT"

        rows_by_integration.setdefault(integration, []).append({
            "name": name,
            "model": model,
            "state": state,
            "controls": controls,
            "location": location,
        })

    headers = ["Name", "Model", "State", "Controls", "Location"]

    for integration in ["Tasmota", "Zigbee2MQTT"]:
        rows = rows_by_integration.get(integration, [])
        if not rows:
            continue
        rows.sort(key=lambda r: natural_sort_key(r["name"]))

        print(f"\n### {integration} ({len(rows)} switches)\n")
        table_rows = [
            [
                r["name"],
                short_model(r["model"]),
                state_icon(r["state"]),
                r["controls"],
                r["location"],
            ]
            for r in rows
        ]
        print_md_table(headers, table_rows)

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
