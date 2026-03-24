#!/usr/bin/env python3
"""Create a Network Reachability dashboard for Home Assistant.

Generates a self-contained HTML file with structural host/network
data and deploys it to HA's /config/www/ directory.  The HTML
connects to HA's WebSocket API at runtime for live entity states.

The structural data (host list, entity IDs, network grouping, PoE
mappings) is baked in at generation time.  Live data (connectivity,
RTT, stack mode, plug/PoE state) comes from HA WebSocket.

Usage:
    uv run scripts/ha-create-reachability-dashboard.py
    uv run scripts/ha-create-reachability-dashboard.py --delete
"""

from __future__ import annotations

import asyncio
import html
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

from gdoc2netcfg.config import load_config
from gdoc2netcfg.models.addressing import IPv6Address

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NETWORK_ORDER = [
    "net", "pwr", "store", "int", "roam", "iot",
    "sm", "fpgas", "guest",
    "t-fpgas", "t-sm", "sdr", "tmp",
]

NETWORK_DISPLAY = {
    "net": "Network Infrastructure",
    "pwr": "Power",
    "store": "Storage",
    "int": "Internal",
    "roam": "Roaming",
    "iot": "IoT",
    "sm": "Server Management",
    "fpgas": "FPGAs",
    "guest": "Guest",
    "t-fpgas": "Transit: FPGAs",
    "t-sm": "Transit: Server Management",
    "sdr": "SDR",
    "tmp": "Temporary",
    "unknown": "Unknown",
}

HA_HOST = "ha.welland.mithis.com"
HA_WWW_PATH = "/config/www/network-reachability.html"
HA_PANEL_URL = "/local/network-reachability.html"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node_id(name: str) -> str:
    """Derive MQTT node_id from a host's hostname."""
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


def _iface_slug(vi) -> str:
    """Derive interface slug for entity IDs."""
    name = vi.name if vi.name else "default"
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


def _esc(s: str) -> str:
    """HTML-escape a string."""
    return html.escape(s, quote=True)


def _ipv6_common_prefix(site) -> str:
    """Get the common IPv6 prefix for the site."""
    prefixes = site.active_ipv6_prefixes
    return prefixes[0].prefix if prefixes else ""


def _ipv6_suffix(vi, prefix: str) -> str:
    """Extract IPv6 suffix from a VirtualInterface."""
    if not prefix:
        return ""
    for ip in vi.ip_addresses:
        if isinstance(ip, IPv6Address):
            addr = ip.address
            return addr[len(prefix):] if addr.startswith(prefix) else addr
    return ""


# ---------------------------------------------------------------------------
# Pipeline loading
# ---------------------------------------------------------------------------

def _load_pipeline(config):
    """Load hosts from pipeline with VLAN and Tasmota enrichment."""
    from gdoc2netcfg.cli.main import _enrich_site_from_vlan_sheet, _fetch_or_load_csvs
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.tasmota import enrich_hosts_with_tasmota, load_tasmota_cache

    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)

    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        all_records.extend(parse_csv(csv_text, name))

    if not all_records:
        raise RuntimeError("No device records found in any sheet.")

    hosts = build_hosts(all_records, config.site)

    tasmota_cache_path = Path(config.cache.directory) / "tasmota.json"
    tasmota_cache = load_tasmota_cache(tasmota_cache_path)
    enrich_hosts_with_tasmota(hosts, tasmota_cache)

    return hosts


def _group_hosts_by_network(hosts, site):
    """Group hosts by VLAN subdomain."""
    from gdoc2netcfg.derivations.vlan import ip_to_subdomain, ip_to_vlan_id

    networks: dict[str, list] = {}
    for host in hosts:
        first_ip = host.first_ipv4
        if first_ip is None:
            continue
        subdomain = ip_to_subdomain(first_ip, site)
        if subdomain is None:
            vlan_id = ip_to_vlan_id(first_ip, site)
            if vlan_id is not None and vlan_id in site.vlans:
                subdomain = site.vlans[vlan_id].subdomain
        networks.setdefault(subdomain or "unknown", []).append(host)

    for v in networks.values():
        v.sort(key=lambda h: h.hostname)
    return networks


# ---------------------------------------------------------------------------
# Controls (Tasmota + PoE) — structural mapping
# ---------------------------------------------------------------------------

def _build_controls_map(
    hosts, config, ha_states: list[dict],
) -> dict[str, list[dict]]:
    """Build machine_name -> [{name, url, entity_id, type}, ...].

    Entity states are fetched live by the JS, so we only store the
    entity_id here (not the current state).
    """
    domain = config.site.domain
    controls_map: dict[str, list[dict]] = {}

    for host in hosts:
        if host.tasmota_data is None:
            continue
        mqtt_topic = host.tasmota_data.mqtt_topic
        plug_eid = f"switch.{_node_id(mqtt_topic)}"
        ctrl_url = f"http://ipv4.{host.hostname}.{domain}"
        for controlled in host.tasmota_data.controls:
            controls_map.setdefault(controlled, []).append({
                "name": host.machine_name,
                "url": ctrl_url,
                "entity_id": plug_eid,
                "type": "plug",
            })

    # Switch port controls — link status, speed, PoE
    # Collect all per-port entity data from HA, keyed by (switch, port).
    # The JS reads live state via WebSocket using a port prefix to
    # construct entity_ids (sensor.{pp}_link, sensor.{pp}_speed, etc.).
    port_re = re.compile(
        r"^(?:sensor|switch|button)\.(.+)_port_(\d+)_(.+)$",
    )
    port_data: dict[tuple[str, str], dict[str, str]] = {}
    # Track actual entity_ids for PoE control (suffix varies per switch model)
    port_eids: dict[tuple[str, str], dict[str, str]] = {}
    for e in ha_states:
        m = port_re.match(e["entity_id"])
        if m:
            sw, port, suffix = m.groups()
            key = (sw, port)
            port_data.setdefault(key, {})[suffix] = e["state"]
            port_eids.setdefault(key, {})[suffix] = e["entity_id"]

    # Regex to strip interface-name prefixes from port descriptions.
    # Matches technical interface names (eth0, 10g1, oob2, 1/0/49,
    # gi27, lag, eth-local, etc.) but NOT hostname components like
    # bmc, openmesh, or device names.
    _iface_pfx_re = re.compile(
        r"^(?:"
        r"eth\d+|eth-\w+"               # eth0, eth9, eth-local, eth-uplink
        r"|eno\d+|enp\w+|en\d+"         # eno1, enp3s0, en1
        r"|lan\d*"                       # lan, lan0
        r"|(?:10|25|40|100)g\d+"         # 10g1, 25g1, 40g1, 100g1
        r"|oob\d+"                       # oob1, oob2
        r"|gi\d+|te\d+|xe\d+|fo\d+"     # gi27, te1 (Cisco/Juniper)
        r"|lag\d*"                       # lag, lag1
        r"|\d+(?:/[\w]+)+"              # 1/0/49, 1/xg51 (slot/port)
        r")\.",                          # followed by dot
    )

    # Reverse lookup: map all known host identifiers to machine_name
    # so port descriptions like "bmc.big-storage" (hostname) match
    # machine_name "big-storage".
    name_to_machine: dict[str, str] = {}
    for host in hosts:
        name_to_machine[host.machine_name] = host.machine_name
        name_to_machine[host.hostname] = host.machine_name

    for (sw, port), data in port_data.items():
        desc = data.get("description", "").strip()
        if not desc:
            continue
        # Must have link or PoE data to be useful
        if "link" not in data and not any(
            s.startswith("poe") for s in data if s != "poe_status"
            and s != "poe_admin" and s != "poe_power"
        ):
            continue

        m = _iface_pfx_re.match(desc)
        stripped = desc[m.end():] if m else desc

        # Resolve to machine_name via reverse lookup
        machine = name_to_machine.get(stripped)
        if machine is None and "." in stripped:
            # Try without subdomain (e.g. "openmesh.wifi" -> "openmesh")
            machine = name_to_machine.get(stripped.split(".")[0])
        if machine is None:
            continue

        pp = f"{sw}_port_{port}"
        eids = port_eids.get((sw, port), {})

        # Find PoE control entity_id from actual HA entities.
        # Per-device monitors append device name to suffix
        # (e.g. "poe_rpi5_pmod" not "poe"), so we can't construct
        # the entity_id — we must look it up.
        # Prefer exact "poe" over "poe_force" (more reliable state).
        poe_eid = ""
        for sfx, eid in eids.items():
            if not eid.startswith("switch."):
                continue
            if sfx == "poe":
                poe_eid = eid
                break
            if sfx.startswith("poe") and "force" not in sfx and "admin" not in sfx:
                poe_eid = eid
                break
        if not poe_eid:
            for sfx, eid in eids.items():
                if eid.startswith("switch.") and sfx.startswith("poe_force"):
                    poe_eid = eid
                    break

        controls_map.setdefault(machine, []).append({
            "name": sw.replace("_", "-") + f" p{port}",
            "url": "",
            "entity_id": poe_eid,
            "pp": pp,
            "type": "port",
        })

    return controls_map


# ---------------------------------------------------------------------------
# Structural data builder
# ---------------------------------------------------------------------------

def _build_host_data(host, controls_map, ipv6_prefix, domain):
    """Build structural JSON for one host (no live state)."""
    nid = _node_id(host.hostname)
    fqdn = f"{host.hostname}.{domain}"

    interfaces = []
    for vi in host.virtual_interfaces:
        slug = _iface_slug(vi)
        iface_name = vi.name or "default"
        iface_fqdn = f"{vi.name}.{fqdn}" if vi.name else fqdn
        interfaces.append({
            "name": iface_name,
            "fqdn": iface_fqdn,
            "slug": slug,
            "ipv6_suffix": _ipv6_suffix(vi, ipv6_prefix),
            # Entity ID prefix for this interface
            "ep": f"gdoc2netcfg_{nid}_{slug}",
        })

    return {
        "hostname": host.hostname,
        "fqdn": fqdn,
        "nid": nid,
        # Entity ID prefix for host-level entities
        "hp": f"gdoc2netcfg_{nid}",
        "location": host.extra.get("Physical Location", "").strip(),
        "controls": controls_map.get(host.machine_name, []),
        "interfaces": interfaces,
    }


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

_HTML_TEMPLATE_PATH = Path(__file__).parent / "ha-reachability-dashboard.html"


def _generate_html(networks, controls_map, ipv6_prefix, domain, config):
    """Generate the complete HTML dashboard."""
    network_data = []
    for subdomain in NETWORK_ORDER:
        if subdomain not in networks:
            continue
        network_data.append({
            "subdomain": subdomain,
            "display_name": NETWORK_DISPLAY.get(subdomain, subdomain.title()),
            "hosts": [
                _build_host_data(h, controls_map, ipv6_prefix, domain)
                for h in networks[subdomain]
            ],
        })
    for subdomain in sorted(networks.keys()):
        if subdomain not in NETWORK_ORDER:
            network_data.append({
                "subdomain": subdomain,
                "display_name": NETWORK_DISPLAY.get(subdomain, subdomain.title()),
                "hosts": [
                    _build_host_data(h, controls_map, ipv6_prefix, domain)
                    for h in networks[subdomain]
                ],
            })

    # Escape </ in JSON to prevent script tag breakout (XSS)
    data_json = json.dumps(
        network_data, separators=(",", ":"),
    ).replace("</", r"<\/")

    # WebSocket URL — use the public HTTPS endpoint so it works
    # from pages loaded over HTTPS (avoids mixed content blocking).
    ws_url = f"wss://ha.{domain}/api/websocket"

    template = _HTML_TEMPLATE_PATH.read_text()
    return (
        template
        .replace("__DATA_JSON__", data_json)
        .replace("__IPV6_PREFIX__", _esc(ipv6_prefix))
        .replace("__DOMAIN__", _esc(domain))
        .replace("__HA_WS_URL__", _esc(ws_url))
        .replace("__HA_TOKEN__", _esc(config.homeassistant.token))
    )


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

def _deploy_html(html_content: str) -> None:
    """Write the HTML file to HA's www directory via ssh + sudo tee."""
    result = subprocess.run(
        ["ssh", HA_HOST,
         f"sudo tee {shlex.quote(HA_WWW_PATH)} > /dev/null"],
        input=html_content, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Deploy failed: {result.stderr.strip()}")
    print(f"Deployed to {HA_HOST}:{HA_WWW_PATH}")


def _fetch_ha_states(config) -> list[dict]:
    """Fetch all entity states from HA API."""
    import urllib.request

    url = f"{config.homeassistant.url.rstrip('/')}/api/states"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {config.homeassistant.token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception:
        return []


async def _ensure_iframe_dashboard(config) -> None:
    """Create or update the Lovelace iframe dashboard in HA."""
    import time

    import websockets

    ws_url = (
        config.homeassistant.url.rstrip("/")
        .replace("http://", "ws://")
        .replace("https://", "wss://")
        + "/api/websocket"
    )

    async with websockets.connect(ws_url, max_size=10 * 1024 * 1024) as ws:
        await ws.recv()
        await ws.send(json.dumps({
            "type": "auth",
            "access_token": config.homeassistant.token,
        }))
        auth = json.loads(await ws.recv())
        if auth.get("type") != "auth_ok":
            raise RuntimeError(f"Auth failed: {auth}")

        msg_id = 1
        await ws.send(json.dumps({
            "id": msg_id, "type": "lovelace/dashboards/list",
        }))
        msg_id += 1
        resp = json.loads(await ws.recv())
        if not resp.get("success"):
            return

        existing = [d for d in resp["result"]
                     if d.get("url_path") == "network-reachability"]

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
            resp = json.loads(await ws.recv())
            if not resp.get("success"):
                print(f"Failed to create dashboard: {resp.get('error')}")
                return
            print("Created dashboard 'network-reachability'")

        bust = int(time.time())
        await ws.send(json.dumps({
            "id": msg_id,
            "type": "lovelace/config/save",
            "url_path": "network-reachability",
            "config": {
                "views": [{
                    "title": "Network Reachability",
                    "path": "default",
                    "icon": "mdi:network",
                    "panel": True,
                    "cards": [{
                        "type": "iframe",
                        "url": f"{HA_PANEL_URL}?v={bust}",
                        "aspect_ratio": "",
                    }],
                }],
            },
        }))
        msg_id += 1
        resp = json.loads(await ws.recv())
        if resp.get("success"):
            print("Dashboard iframe config saved")
        else:
            print(f"Failed: {resp.get('error')}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    delete = "--delete" in sys.argv
    config = load_config()
    if not config.homeassistant.url or not config.homeassistant.token:
        print("Error: [homeassistant] url and token required", file=sys.stderr)
        sys.exit(1)

    if delete:
        return

    print("Loading pipeline data...")
    hosts = _load_pipeline(config)
    print(f"  {len(hosts)} hosts loaded")

    print("Grouping by network...")
    networks = _group_hosts_by_network(hosts, config.site)
    for sd in NETWORK_ORDER:
        if sd in networks:
            print(f"  {sd}: {len(networks[sd])} hosts")
    for sd in sorted(networks.keys()):
        if sd not in NETWORK_ORDER:
            print(f"  {sd}: {len(networks[sd])} hosts")

    print("Fetching HA states for PoE mappings...")
    ha_states = _fetch_ha_states(config)
    print(f"  {len(ha_states)} entities")

    controls_map = _build_controls_map(hosts, config, ha_states)
    ipv6_prefix = _ipv6_common_prefix(config.site)
    domain = config.site.domain
    ctrl_count = sum(len(v) for v in controls_map.values())
    print(f"  {ctrl_count} control entries for {len(controls_map)} hosts")

    print("Generating HTML...")
    html_content = _generate_html(
        networks, controls_map, ipv6_prefix, domain, config,
    )
    print(f"  {len(html_content):,} bytes")

    print("Deploying...")
    _deploy_html(html_content)
    asyncio.run(_ensure_iframe_dashboard(config))

    print(f"\nDashboard at: https://ha.{domain}/network-reachability/default")


if __name__ == "__main__":
    main()
