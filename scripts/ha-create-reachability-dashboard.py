#!/usr/bin/env python3
"""Create a Home Assistant dashboard for gdoc2netcfg reachability.

Connects to the HA WebSocket API and creates a dedicated Lovelace
dashboard showing host connectivity grouped by network (VLAN subdomain)
in data-dense HTML tables with live Jinja2 state lookups.

Three views provide different sort orders:
  by-name    — alphabetical by hostname (default)
  by-status  — online first, then offline, then unavailable
  by-rtt     — fastest RTT first (generation-time order from cache)

Usage:
    uv run scripts/ha-create-reachability-dashboard.py
    uv run scripts/ha-create-reachability-dashboard.py --delete
"""

from __future__ import annotations

import asyncio
import json
import re
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
    # Transit and special VLANs
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

SORT_VIEWS = ["by-name", "by-status", "by-rtt"]


# ---------------------------------------------------------------------------
# Entity ID helpers (must match mqtt_ha.py exactly)
# ---------------------------------------------------------------------------

def _node_id(machine_name: str) -> str:
    """Derive MQTT node_id from machine_name.

    Replaces non-alphanumeric characters with underscores.
    Example: "big-storage" -> "big_storage"
    """
    return re.sub(r"[^a-zA-Z0-9]", "_", machine_name).lower()


def _iface_slug(vi) -> str:
    """Derive interface slug for entity IDs.

    Uses the interface name if set, otherwise "default".
    """
    name = vi.name if vi.name else "default"
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


# ---------------------------------------------------------------------------
# Pipeline loading
# ---------------------------------------------------------------------------

def _load_pipeline(config):
    """Load hosts from pipeline with VLAN and Tasmota enrichment.

    Uses cached CSVs (no network fetch), parses into hosts, enriches
    with Tasmota data for the Controls column.

    Returns list of Host objects.
    """
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

    # Enrich with Tasmota data for Controls column
    tasmota_cache_path = Path(config.cache.directory) / "tasmota.json"
    tasmota_cache = load_tasmota_cache(tasmota_cache_path)
    enrich_hosts_with_tasmota(hosts, tasmota_cache)

    return hosts


def _group_hosts_by_network(hosts, site):
    """Group hosts by VLAN subdomain network name.

    Handles both site-local VLANs (via ip_to_subdomain, matching on
    third octet) and global VLANs (via ip_to_vlan_id, matching on
    second octet for e.g. fpgas at 10.21.X.X, sm at 10.41.X.X).

    Returns dict mapping subdomain name (e.g. "iot", "net") to list
    of Host objects, sorted alphabetically within each group.
    """
    from gdoc2netcfg.derivations.vlan import ip_to_subdomain, ip_to_vlan_id

    networks: dict[str, list] = {}
    for host in hosts:
        first_ip = host.first_ipv4
        if first_ip is None:
            continue

        # Try site-local subdomain first (matches 10.{site_octet}.X.Y)
        subdomain = ip_to_subdomain(first_ip, site)

        # Fall back to global/transit VLAN lookup
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


def _build_controls_map(hosts):
    """Build reverse mapping: machine_name -> controlling Tasmota plug name.

    Scans all hosts with Tasmota data and inverts the controls list,
    so we can look up "which plug powers this device?" for any host.
    """
    controls_map: dict[str, str] = {}
    for host in hosts:
        if host.tasmota_data is None:
            continue
        for controlled in host.tasmota_data.controls:
            controls_map[controlled] = host.machine_name
    return controls_map


def _load_rtt_cache(config) -> dict[str, float | None]:
    """Load last-known RTT data from reachability cache for sort ordering.

    Reads reachability.json directly (ignoring max_age) and extracts
    the best RTT per hostname across all interfaces. Used for the
    by-rtt view's generation-time sort order.

    Returns dict mapping hostname to best RTT in ms (or None if unreachable).
    """
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

    rtt_map: dict[str, float | None] = {}
    for hostname, host_data in data.get("hosts", {}).items():
        best_rtt: float | None = None
        for iface_pings in host_data.get("interfaces", []):
            for ping in iface_pings:
                rtt = ping.get("rtt_avg_ms")
                if rtt is not None and (best_rtt is None or rtt < best_rtt):
                    best_rtt = rtt
        rtt_map[hostname] = best_rtt
    return rtt_map


# ---------------------------------------------------------------------------
# IPv6 helpers
# ---------------------------------------------------------------------------

def _ipv6_common_prefix(site) -> str:
    """Get the common IPv6 prefix for the site (e.g. '2404:e80:a137:')."""
    prefixes = site.active_ipv6_prefixes
    if not prefixes:
        return ""
    return prefixes[0].prefix


def _ipv6_suffix(vi, prefix: str) -> str:
    """Extract IPv6 suffix from a VirtualInterface.

    Strips the common site prefix to show only the VLAN+host part,
    e.g. '2404:e80:a137:110::150' with prefix '2404:e80:a137:'
    becomes '110::150'.
    """
    if not prefix:
        return "\u2014"
    for ip in vi.ip_addresses:
        if isinstance(ip, IPv6Address):
            addr = ip.address
            if addr.startswith(prefix):
                return addr[len(prefix):]
            return addr
    return "\u2014"


# ---------------------------------------------------------------------------
# Template generation
# ---------------------------------------------------------------------------

def _table_header(sort_key: str) -> str:
    """Generate HTML table header row with sort-linked column headers.

    Clickable headers navigate between the 3 sort views.  The active
    sort column gets a bold label with a down-triangle indicator.
    """
    def _col(label, target_sort):
        if target_sort == sort_key:
            return f"<b>{label}&nbsp;\u25be</b>"
        return f'<a href="/network-reachability/{target_sort}">{label}</a>'

    return (
        "<tr>"
        f'<th style="padding:4px 6px">{_col("St", "by-status")}</th>'
        f'<th style="padding:4px 6px">{_col("Host", "by-name")}</th>'
        '<th style="padding:4px 6px">Iface</th>'
        '<th style="padding:4px 6px">Stack</th>'
        '<th style="padding:4px 6px">IPv4</th>'
        '<th style="padding:4px 6px">IPv6</th>'
        '<th style="padding:4px 6px">MAC</th>'
        f'<th style="padding:4px 6px">{_col("RTT", "by-rtt")}</th>'
        '<th style="padding:4px 6px">Location</th>'
        '<th style="padding:4px 6px">Controls</th>'
        "</tr>"
    )


def _row_template(
    host,
    vi,
    is_first_iface: bool,
    controls_map: dict[str, str],
    ipv6_prefix: str,
) -> str:
    """Generate Jinja2 HTML table row for one interface.

    The row uses Jinja2 template expressions for live data (status,
    stack mode, IPv4, MAC, RTT) and baked-in static data (host name,
    interface name, IPv6 suffix, location, controls).

    Opacity is set dynamically: 1.0 for online, 0.5 for offline,
    0.35 for unavailable.
    """
    nid = _node_id(host.machine_name)
    slug = _iface_slug(vi)

    conn_eid = f"binary_sensor.gdoc2netcfg_{nid}_{slug}_connectivity"
    stack_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_stack_mode"
    ipv4_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_ipv4"
    mac_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_mac"
    rtt_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_rtt"

    iface_display = vi.name or "default"
    host_cell = f"<b>{host.machine_name}</b>" if is_first_iface else ""
    location = host.extra.get("Physical Location", "").strip() or "\u2014"
    controller = controls_map.get(host.machine_name, "\u2014")
    ipv6_suf = _ipv6_suffix(vi, ipv6_prefix)

    td = 'style="padding:4px 6px"'

    # Stack mode abbreviations
    # NB: closing }} must be in an f-string (}}}} → }}) not a plain
    # string where }}}} would be four literal braces.
    stack_expr = (
        f"{{{{ states('{stack_eid}')"
        "|replace('dual-stack','dual')"
        "|replace('ipv4-only','v4')"
        "|replace('ipv6-only','v6')"
        "|replace('unavailable','\u2014')"
        f"|replace('unknown','\u2014') }}}}"
    )

    # RTT with fallback
    rtt_expr = (
        f"{{% set r=states('{rtt_eid}') %}}"
        "{% if r not in ['unknown','unavailable',''] %}"
        "{{ r }}ms"
        "{% else %}\u2014{% endif %}"
    )

    # IPv4 with fallback
    ipv4_expr = (
        f"{{{{ states('{ipv4_eid}')"
        "|replace('unavailable','\u2014')"
        f"|replace('unknown','\u2014') }}}}"
    )

    # MAC with fallback
    mac_expr = (
        f"{{{{ states('{mac_eid}')"
        "|replace('unavailable','\u2014')"
        f"|replace('unknown','\u2014') }}}}"
    )

    # Status emoji
    status_expr = (
        f"{{% if is_state('{conn_eid}','on') %}}"
        "\U0001f7e2"
        f"{{% elif is_state('{conn_eid}','off') %}}"
        "\U0001f534"
        "{% else %}\u26ab{% endif %}"
    )

    # Opacity based on connectivity state
    opacity_expr = (
        f"{{% if is_state('{conn_eid}','on') %}}1"
        f"{{% elif is_state('{conn_eid}','off') %}}0.5"
        "{% else %}0.35{% endif %}"
    )

    return (
        f'<tr style="opacity:{opacity_expr}">'
        f"<td {td}>{status_expr}</td>"
        f"<td {td}>{host_cell}</td>"
        f"<td {td}>{iface_display}</td>"
        f"<td {td}>{stack_expr}</td>"
        f"<td {td}>{ipv4_expr}</td>"
        f"<td {td}>{ipv6_suf}</td>"
        f"<td {td}>{mac_expr}</td>"
        f"<td {td}>{rtt_expr}</td>"
        f"<td {td}>{location}</td>"
        f"<td {td}>{controller}</td>"
        "</tr>"
    )


def _build_network_table(
    subdomain: str,
    hosts: list,
    sort_key: str,
    controls_map: dict[str, str],
    ipv6_prefix: str,
    rtt_cache: dict[str, float | None],
) -> dict:
    """Generate a Lovelace markdown card for one network's table.

    Returns a card config dict with a Jinja2 HTML table template.
    The row order depends on sort_key:
      by-name   — alphabetical by hostname
      by-status — multi-pass: online rows, offline rows, unavailable rows
      by-rtt    — sorted by last-known RTT from reachability cache
    """
    display_name = NETWORK_DISPLAY.get(subdomain, subdomain.title())
    host_count = len(hosts)

    title = f"{display_name} ({subdomain}) \u2014 {host_count} hosts"
    if ipv6_prefix:
        title += f" \u2014 IPv6: {ipv6_prefix}"

    # Determine row order
    if sort_key == "by-rtt":
        def _rtt_sort_key(h):
            rtt = rtt_cache.get(h.hostname)
            return (0, rtt) if rtt is not None else (1, 0)
        ordered_hosts = sorted(hosts, key=_rtt_sort_key)
    else:
        ordered_hosts = sorted(hosts, key=lambda h: h.hostname)

    # Build the HTML table
    lines = [
        '<table style="width:100%;border-collapse:collapse;font-size:0.85em">',
        _table_header(sort_key),
    ]

    if sort_key == "by-status":
        # Multi-pass: emit each interface 3 times with guards so only
        # the matching pass renders.  This achieves live status-based
        # grouping within the Jinja2 template.
        for condition in ("on", "off", "unavailable"):
            for host in ordered_hosts:
                vis = host.virtual_interfaces
                for vi_idx, vi in enumerate(vis):
                    nid = _node_id(host.machine_name)
                    slug = _iface_slug(vi)
                    conn_eid = (
                        f"binary_sensor.gdoc2netcfg_{nid}_{slug}_connectivity"
                    )
                    row = _row_template(
                        host, vi, vi_idx == 0,
                        controls_map, ipv6_prefix,
                    )
                    if condition in ("on", "off"):
                        lines.append(
                            f"{{% if is_state('{conn_eid}','{condition}') %}}"
                            f"{row}"
                            "{% endif %}"
                        )
                    else:
                        # "unavailable" catches anything not on/off
                        lines.append(
                            f"{{% if not is_state('{conn_eid}','on') "
                            f"and not is_state('{conn_eid}','off') %}}"
                            f"{row}"
                            "{% endif %}"
                        )
    else:
        # Single pass: by-name or by-rtt
        for host in ordered_hosts:
            vis = host.virtual_interfaces
            for vi_idx, vi in enumerate(vis):
                lines.append(_row_template(
                    host, vi, vi_idx == 0,
                    controls_map, ipv6_prefix,
                ))

    lines.append("</table>")

    return {
        "type": "markdown",
        "title": title,
        "content": "\n".join(lines),
    }


def _build_summary_template() -> str:
    """Build the live-count summary template.

    Uses Jinja2 to count entities by state at render time, so the
    summary always reflects current HA state without regeneration.
    """
    return (
        "{% set conn = states.binary_sensor "
        "| selectattr('entity_id', 'match', "
        "'binary_sensor\\\\.gdoc2netcfg_.*_connectivity$') "
        "| list %}"
        "{% set on = conn | selectattr('state', 'eq', 'on') "
        "| list | count %}"
        "{% set off = conn | selectattr('state', 'eq', 'off') "
        "| list | count %}"
        "{% set unavail = conn "
        "| rejectattr('state', 'eq', 'on') "
        "| rejectattr('state', 'eq', 'off') "
        "| list | count %}"
        "{% set trackers = states.device_tracker "
        "| selectattr('entity_id', 'match', "
        "'device_tracker\\\\.gdoc2netcfg_') "
        "| list %}"
        "{% set home = trackers | selectattr('state', 'eq', 'home') "
        "| list | count %}"
        "{% set away = trackers "
        "| selectattr('state', 'eq', 'not_home') "
        "| list | count %}"
        "\n"
        "| | Count |\n"
        "|---|---:|\n"
        "| \U0001f7e2 **Connected** | {{ on }} |\n"
        "| \U0001f534 **Disconnected** | {{ off }} |\n"
        "| \u26ab **Unavailable** | {{ unavail }} |\n"
        "| \U0001f3e0 **Home** | {{ home }} |\n"
        "| \U0001f6b6 **Away** | {{ away }} |\n"
    )


# ---------------------------------------------------------------------------
# Dashboard builder
# ---------------------------------------------------------------------------

def _build_dashboard_config(
    networks: dict[str, list],
    controls_map: dict[str, str],
    ipv6_prefix: str,
    rtt_cache: dict[str, float | None],
) -> dict:
    """Build the Lovelace dashboard config with 3 sorted views.

    Each view contains a summary card followed by one table card per
    network (VLAN subdomain), ordered by NETWORK_ORDER.  Unknown
    networks appear at the end.
    """
    view_meta = {
        "by-name": ("By Name", "mdi:sort-alphabetical-ascending"),
        "by-status": ("By Status", "mdi:traffic-light"),
        "by-rtt": ("By RTT", "mdi:timer-outline"),
    }

    views = []
    for sort_key in SORT_VIEWS:
        view_title, icon = view_meta[sort_key]

        cards: list[dict] = [
            {
                "type": "markdown",
                "title": "Network Status",
                "content": _build_summary_template(),
            },
        ]

        # Per-network table cards in defined order
        for subdomain in NETWORK_ORDER:
            if subdomain not in networks:
                continue
            cards.append(_build_network_table(
                subdomain, networks[subdomain], sort_key,
                controls_map, ipv6_prefix, rtt_cache,
            ))

        # Any networks not in NETWORK_ORDER (e.g. "unknown")
        for subdomain in sorted(networks.keys()):
            if subdomain not in NETWORK_ORDER:
                cards.append(_build_network_table(
                    subdomain, networks[subdomain], sort_key,
                    controls_map, ipv6_prefix, rtt_cache,
                ))

        views.append({
            "title": view_title,
            "path": sort_key,
            "icon": icon,
            "cards": cards,
        })

    return {"views": views}


# ---------------------------------------------------------------------------
# Push to HA (unchanged from original)
# ---------------------------------------------------------------------------

async def _push_dashboard(
    config, dashboard_config: dict, delete: bool = False,
) -> None:
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
        asyncio.run(_push_dashboard(config, {}, delete=True))
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
    rtt_cache = _load_rtt_cache(config)

    print(
        f"  Controls: {len(controls_map)} hosts powered by Tasmota plugs"
    )
    print(f"  IPv6 prefix: {ipv6_prefix or '(none)'}")
    print(
        f"  RTT cache: {sum(1 for v in rtt_cache.values() if v is not None)}"
        f"/{len(rtt_cache)} hosts with RTT data"
    )

    print("Building dashboard config...")
    dashboard_config = _build_dashboard_config(
        networks, controls_map, ipv6_prefix, rtt_cache,
    )

    # Report template sizes
    for view in dashboard_config["views"]:
        total = sum(len(c.get("content", "")) for c in view["cards"])
        print(f"  {view['path']}: {len(view['cards'])} cards, {total:,} bytes")

    print("Pushing to Home Assistant...")
    asyncio.run(_push_dashboard(config, dashboard_config))

    url = config.homeassistant.url.rstrip("/")
    print(f"\nDashboard available at: {url}/network-reachability/by-name")


if __name__ == "__main__":
    main()
