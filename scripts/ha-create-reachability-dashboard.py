#!/usr/bin/env python3
"""Create a Network Reachability dashboard for Home Assistant.

Generates a self-contained HTML file with host/interface reachability
data and copies it to HA's /config/www/ directory for serving at
/local/network-reachability.html.  Also registers an iframe panel
in HA via the WebSocket API so it appears in the sidebar.

The HTML is static (regenerated each daemon cycle) with client-side
JavaScript for fold/unfold of multi-interface hosts, column sorting,
and auto-refresh.

Usage:
    uv run scripts/ha-create-reachability-dashboard.py
    uv run scripts/ha-create-reachability-dashboard.py --delete
"""

from __future__ import annotations

import asyncio
import html
import json
import re
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
# Entity ID helpers (must match mqtt_ha.py)
# ---------------------------------------------------------------------------

def _node_id(name: str) -> str:
    """Derive MQTT node_id from a host's hostname."""
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


def _iface_slug(vi) -> str:
    """Derive interface slug for entity IDs."""
    name = vi.name if vi.name else "default"
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


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
        records = parse_csv(csv_text, name)
        all_records.extend(records)

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
        if subdomain is None:
            subdomain = "unknown"
        networks.setdefault(subdomain, []).append(host)

    for network_hosts in networks.values():
        network_hosts.sort(key=lambda h: h.hostname)

    return networks


def _build_controls_map(hosts) -> dict[str, tuple[str, str]]:
    """Build reverse mapping: machine_name -> (ctrl_name, ctrl_hostname)."""
    controls_map: dict[str, tuple[str, str]] = {}
    for host in hosts:
        if host.tasmota_data is None:
            continue
        for controlled in host.tasmota_data.controls:
            controls_map[controlled] = (host.machine_name, host.hostname)
    return controls_map


def _ipv6_common_prefix(site) -> str:
    """Get the common IPv6 prefix for the site."""
    prefixes = site.active_ipv6_prefixes
    if not prefixes:
        return ""
    return prefixes[0].prefix


def _ipv6_suffix(vi, prefix: str) -> str:
    """Extract IPv6 suffix from a VirtualInterface."""
    if not prefix:
        return ""
    for ip in vi.ip_addresses:
        if isinstance(ip, IPv6Address):
            addr = ip.address
            if addr.startswith(prefix):
                return addr[len(prefix):]
            return addr
    return ""


def _load_reachability(config) -> dict[str, dict]:
    """Load reachability cache as raw JSON."""
    cache_path = Path(config.cache.directory) / "reachability.json"
    if not cache_path.exists():
        return {}
    try:
        with open(cache_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict) or data.get("version") != 2:
        return {}
    return data.get("hosts", {})


# ---------------------------------------------------------------------------
# Data building
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """HTML-escape a string."""
    return html.escape(s, quote=True)


def _build_host_data(
    host,
    controls_map: dict[str, tuple[str, str]],
    ipv6_prefix: str,
    domain: str,
    reachability: dict[str, dict],
) -> dict:
    """Build a JSON-serialisable dict for one host."""
    fqdn = f"{host.hostname}.{domain}"

    reach = reachability.get(host.hostname, {})
    iface_reach = reach.get("interfaces", [])

    any_up = False
    has_v4 = False
    has_v6 = False
    for ir_pings in iface_reach:
        for ping in ir_pings:
            if ping.get("received", 0) > 0:
                any_up = True
                if ":" in ping.get("ip", ""):
                    has_v6 = True
                else:
                    has_v4 = True

    if not any_up:
        host_status, host_stack = "off", "down"
    elif has_v4 and has_v6:
        host_status, host_stack = "on", "dual"
    elif has_v4:
        host_status, host_stack = "on", "v4"
    elif has_v6:
        host_status, host_stack = "on", "v6"
    else:
        host_status, host_stack = "off", "down"

    location = host.extra.get("Physical Location", "").strip()
    ctrl_info = controls_map.get(host.machine_name)
    ctrl_name = ctrl_info[0] if ctrl_info else ""
    ctrl_fqdn = f"ipv4.{ctrl_info[1]}.{domain}" if ctrl_info else ""

    interfaces = []
    for vi_idx, vi in enumerate(host.virtual_interfaces):
        iface_name = vi.name or "default"
        iface_fqdn = f"{vi.name}.{fqdn}" if vi.name else fqdn
        ipv6_suf = _ipv6_suffix(vi, ipv6_prefix)

        ir_pings = iface_reach[vi_idx] if vi_idx < len(iface_reach) else []
        iface_up = False
        iface_v4 = False
        iface_v6 = False
        best_rtt: float | None = None
        for ping in ir_pings:
            if ping.get("received", 0) > 0:
                iface_up = True
                if ":" in ping.get("ip", ""):
                    iface_v6 = True
                else:
                    iface_v4 = True
                rtt = ping.get("rtt_avg_ms")
                if rtt is not None and (best_rtt is None or rtt < best_rtt):
                    best_rtt = rtt

        if not iface_up:
            iface_status, iface_stack = "off", "down"
        elif iface_v4 and iface_v6:
            iface_status, iface_stack = "on", "dual"
        elif iface_v4:
            iface_status, iface_stack = "on", "v4"
        elif iface_v6:
            iface_status, iface_stack = "on", "v6"
        else:
            iface_status, iface_stack = "off", "down"

        interfaces.append({
            "name": iface_name,
            "fqdn": iface_fqdn,
            "ipv4": str(vi.ipv4),
            "ipv6_suffix": ipv6_suf,
            "mac": str(vi.macs[0]).lower() if vi.macs else "",
            "status": iface_status,
            "stack": iface_stack,
            "rtt": round(best_rtt, 1) if best_rtt is not None else None,
        })

    return {
        "hostname": host.hostname,
        "fqdn": fqdn,
        "status": host_status,
        "stack": host_stack,
        "location": location,
        "ctrl_name": ctrl_name,
        "ctrl_fqdn": ctrl_fqdn,
        "interfaces": interfaces,
    }


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

_HTML_TEMPLATE_PATH = Path(__file__).parent / "ha-reachability-dashboard.html"


def _generate_html(
    networks: dict[str, list],
    controls_map: dict[str, tuple[str, str]],
    ipv6_prefix: str,
    domain: str,
    reachability: dict[str, dict],
) -> str:
    """Generate the complete HTML dashboard."""
    network_data = []
    for subdomain in NETWORK_ORDER:
        if subdomain not in networks:
            continue
        hosts_data = [
            _build_host_data(h, controls_map, ipv6_prefix, domain, reachability)
            for h in networks[subdomain]
        ]
        network_data.append({
            "subdomain": subdomain,
            "display_name": NETWORK_DISPLAY.get(subdomain, subdomain.title()),
            "hosts": hosts_data,
        })
    for subdomain in sorted(networks.keys()):
        if subdomain not in NETWORK_ORDER:
            hosts_data = [
                _build_host_data(h, controls_map, ipv6_prefix, domain, reachability)
                for h in networks[subdomain]
            ]
            network_data.append({
                "subdomain": subdomain,
                "display_name": NETWORK_DISPLAY.get(subdomain, subdomain.title()),
                "hosts": hosts_data,
            })

    data_json = json.dumps(network_data, separators=(",", ":"))
    template = _HTML_TEMPLATE_PATH.read_text()
    return template.replace("__DATA_JSON__", data_json).replace(
        "__IPV6_PREFIX__", _esc(ipv6_prefix),
    ).replace("__DOMAIN__", _esc(domain))


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

def _deploy_html(html_content: str) -> None:
    """Write the HTML file to HA's www directory via ssh + sudo tee."""
    result = subprocess.run(
        ["ssh", HA_HOST, f"sudo tee {HA_WWW_PATH} > /dev/null"],
        input=html_content, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Deploy failed: {result.stderr.strip()}"
        )
    print(f"Deployed to {HA_HOST}:{HA_WWW_PATH}")


async def _ensure_iframe_dashboard(config) -> None:
    """Create or update the Lovelace iframe dashboard in HA."""
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
            "id": msg_id,
            "type": "lovelace/dashboards/list",
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
            create_resp = json.loads(await ws.recv())
            if not create_resp.get("success"):
                print(f"Failed to create dashboard: {create_resp.get('error')}")
                return
            print("Created dashboard 'network-reachability'")

        # Save the iframe config with cache-busting query parameter
        import time
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
        save_resp = json.loads(await ws.recv())
        if save_resp.get("success"):
            print("Dashboard iframe config saved")
        else:
            print(f"Failed to save config: {save_resp.get('error')}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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
        asyncio.run(_ensure_iframe_dashboard(config))  # reuse for delete path
        # TODO: add actual delete support if needed
        return

    print("Loading pipeline data...")
    hosts = _load_pipeline(config)
    print(f"  {len(hosts)} hosts loaded")

    print("Grouping by network...")
    networks = _group_hosts_by_network(hosts, config.site)
    for subdomain in NETWORK_ORDER:
        if subdomain in networks:
            print(f"  {subdomain}: {len(networks[subdomain])} hosts")
    for subdomain in sorted(networks.keys()):
        if subdomain not in NETWORK_ORDER:
            print(f"  {subdomain}: {len(networks[subdomain])} hosts")

    controls_map = _build_controls_map(hosts)
    ipv6_prefix = _ipv6_common_prefix(config.site)
    domain = config.site.domain
    reachability = _load_reachability(config)

    print(f"  Controls: {len(controls_map)} hosts powered by Tasmota plugs")
    print(f"  IPv6 prefix: {ipv6_prefix or '(none)'}")
    print(f"  Domain: {domain}")
    print(f"  Reachability: {len(reachability)} hosts cached")

    print("Generating HTML...")
    html_content = _generate_html(
        networks, controls_map, ipv6_prefix, domain, reachability,
    )
    print(f"  {len(html_content):,} bytes")

    print("Deploying...")
    _deploy_html(html_content)

    # Ensure the Lovelace iframe dashboard exists in HA
    asyncio.run(_ensure_iframe_dashboard(config))

    print(f"\nDashboard at: https://ha.{domain}/network-reachability/default")


if __name__ == "__main__":
    main()
