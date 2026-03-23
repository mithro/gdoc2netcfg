#!/usr/bin/env python3
"""Create a Home Assistant dashboard for gdoc2netcfg reachability.

Connects to the HA WebSocket API and creates a dedicated Lovelace
dashboard showing host connectivity grouped by network (VLAN subdomain)
using collapsible <details> blocks per host with interface tables.

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

def _node_id(name: str) -> str:
    """Derive MQTT node_id from a host's hostname.

    Replaces non-alphanumeric characters with underscores.
    Must match mqtt_ha.py's _node_id() — both use host.hostname.

    Example: "big-storage" -> "big_storage"
    Example: "bmc.big-storage" -> "bmc_big_storage"
    Example: "au-plug-1.iot" -> "au_plug_1_iot"
    """
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


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


def _build_controls_map(hosts) -> dict[str, tuple[str, str]]:
    """Build reverse mapping: machine_name -> (ctrl_machine_name, ctrl_hostname).

    Scans all hosts with Tasmota data and inverts the controls list,
    so we can look up "which plug powers this device?" for any host.
    Stores both machine_name (for display) and hostname (for FQDN link).
    """
    controls_map: dict[str, tuple[str, str]] = {}
    for host in hosts:
        if host.tasmota_data is None:
            continue
        for controlled in host.tasmota_data.controls:
            controls_map[controlled] = (host.machine_name, host.hostname)
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
    """Generate HTML table header with sort-linked columns.

    Two status columns: col 1 for host-level St, col 2 for
    interface-level St.  Clickable headers navigate sort views.
    """
    def _col(label, target):
        if target == sort_key:
            return f"<b>{label}\u00a0\u25be</b>"
        return f'<a href="/network-reachability/{target}">{label}</a>'

    th = 'style="padding:4px 6px;text-align:left"'
    return (
        f"<tr>"
        f'<th {th}>{_col("St", "by-status")}</th>'
        f'<th {th}></th>'  # interface St (no header text)
        f'<th {th}>{_col("Name", "by-name")}</th>'
        f'<th {th}>Stack</th>'
        f'<th {th}>IPv4</th>'
        f'<th {th}>IPv6</th>'
        f'<th {th}>MAC</th>'
        f'<th {th}>{_col("RTT", "by-rtt")}</th>'
        f'<th {th}>Location</th>'
        f'<th {th}>Controls</th>'
        f"</tr>"
    )


# JavaScript (no curly braces that conflict with Jinja2) to toggle
# interface rows below a host row.  Walks nextElementSibling until
# it hits another host row (class "hr").
_TOGGLE_JS = (
    "var o=this.dataset.open!=='0';"
    "this.dataset.open=o?'0':'1';"
    "this.querySelector('.fi').textContent=o?'\\u25b6 ':'\\u25bc ';"
    "var r=this.nextElementSibling;"
    "while(r&&r.className!=='hr')"
    "{r.style.display=o?'none':'';r=r.nextElementSibling;}"
)


def _location_and_controls(
    host, controls_map: dict[str, tuple[str, str]], domain: str,
) -> tuple[str, str]:
    """Return (location_html, controls_html) for a host."""
    location = host.extra.get("Physical Location", "").strip() or "\u2014"
    ctrl_info = controls_map.get(host.machine_name)
    if ctrl_info:
        ctrl_name, ctrl_hostname = ctrl_info
        ctrl_fqdn = f"ipv4.{ctrl_hostname}.{domain}"
        controls = f'<a href="http://{ctrl_fqdn}">{ctrl_name}</a>'
    else:
        controls = "\u2014"
    return location, controls


def _iface_cells(host, vi, ipv6_prefix: str, domain: str) -> dict:
    """Compute Jinja2 expressions and static data for one interface.

    Returns a dict with keys: setup, status, stack, iface_link,
    ipv4_link, ipv6_link, mac_cell, rtt_cell, opacity, conn_eid.
    """
    nid = _node_id(host.hostname)
    slug = _iface_slug(vi)

    conn_eid = f"binary_sensor.gdoc2netcfg_{nid}_{slug}_connectivity"
    stack_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_stack_mode"
    ipv4_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_ipv4"
    mac_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_mac"
    rtt_eid = f"sensor.gdoc2netcfg_{nid}_{slug}_rtt"

    iface_name = vi.name or "default"
    ipv6_suf = _ipv6_suffix(vi, ipv6_prefix)

    fqdn = f"{host.hostname}.{domain}"
    iface_fqdn = f"{vi.name}.{fqdn}" if vi.name else fqdn

    setup = (
        f"{{% set _ic=states('{conn_eid}') %}}"
        f"{{% set _is=states('{stack_eid}') %}}"
    )

    status = (
        "{% if _ic=='on' %}\U0001f7e2"
        "{% elif _ic=='off' %}\U0001f534"
        "{% else %}\u26ab{% endif %}"
    )

    stack = (
        "{% if _is=='dual-stack' %}4\u00b76"
        "{% elif _is=='ipv4-only' %}4"
        "{% elif _is=='ipv6-only' %}6"
        "{% else %}\u2014{% endif %}"
    )

    # Interface name link: stack-dependent prefix
    iface_link = (
        "{% set _ip='ipv4.' if _is=='ipv4-only' "
        "else ('ipv6.' if _is=='ipv6-only' else '') %}"
        f'<a href="http://{{{{ _ip }}}}{iface_fqdn}">'
        f"{iface_name}</a>"
    )

    # IPv4 always links to ipv4.<iface>.<host>.<domain>
    ipv4_link = (
        f"{{% set _v4=states('{ipv4_eid}') %}}"
        "{% if _v4 not in ['unavailable','unknown'] %}"
        f'<a href="http://ipv4.{iface_fqdn}">'
        "{{ _v4 }}</a>"
        "{% else %}\u2014{% endif %}"
    )

    # IPv6 links to ipv6.<iface>.<host>.<domain>
    if ipv6_suf != "\u2014":
        ipv6_link = f'<a href="http://ipv6.{iface_fqdn}">{ipv6_suf}</a>'
    else:
        ipv6_link = "\u2014"

    mac_cell = (
        f"{{% set _mac=states('{mac_eid}') %}}"
        "{% if _mac not in ['unavailable','unknown'] %}"
        "<code>{{ _mac }}</code>"
        "{% else %}\u2014{% endif %}"
    )

    rtt_cell = (
        f"{{% set _rtt=states('{rtt_eid}') %}}"
        "{% if _rtt not in ['unknown','unavailable',''] %}"
        "{{ _rtt }}ms"
        "{% else %}\u2014{% endif %}"
    )

    opacity = (
        "{% if _ic=='on' %}1"
        "{% elif _ic=='off' %}0.5"
        "{% else %}0.35{% endif %}"
    )

    return {
        "setup": setup, "status": status, "stack": stack,
        "iface_link": iface_link, "ipv4_link": ipv4_link,
        "ipv6_link": ipv6_link, "mac_cell": mac_cell,
        "rtt_cell": rtt_cell, "opacity": opacity,
        "conn_eid": conn_eid,
    }


def _single_row(
    host,
    vi,
    controls_map: dict[str, tuple[str, str]],
    ipv6_prefix: str,
    domain: str,
) -> str:
    """Generate a combined host+interface row for single-interface hosts.

    Shows host status in col 1, interface status in col 2, hostname,
    then all interface data on one line.
    """
    nid = _node_id(host.hostname)
    fqdn = f"{host.hostname}.{domain}"
    host_conn_eid = f"binary_sensor.gdoc2netcfg_{nid}_connectivity"
    host_stack_eid = f"sensor.gdoc2netcfg_{nid}_stack_mode"

    c = _iface_cells(host, vi, ipv6_prefix, domain)
    location, controls = _location_and_controls(host, controls_map, domain)

    host_setup = (
        f"{{% set _hc=states('{host_conn_eid}') %}}"
        f"{{% set _hs=states('{host_stack_eid}') %}}"
        "{% set _hp='ipv4.' if _hs=='ipv4-only' "
        "else ('ipv6.' if _hs=='ipv6-only' else '') %}"
    )
    host_status = (
        "{% if _hc=='on' %}\U0001f7e2"
        "{% elif _hc=='off' %}\U0001f534"
        "{% else %}\u26ab{% endif %}"
    )
    hostname_link = (
        f'<a href="http://{{{{ _hp }}}}{fqdn}">'
        f"<b>{host.hostname}</b></a>"
    )

    td = 'style="padding:4px 6px;white-space:nowrap"'
    tde = 'style="padding:4px 6px"'
    return (
        f"{host_setup}{c['setup']}"
        f'<tr class="hr" style="opacity:{c["opacity"]};'
        f'border-top:2px solid var(--divider-color,#e0e0e0)">'
        f"<td {td}>{host_status}</td>"
        f"<td {tde}></td>"
        f"<td {td}>{hostname_link}</td>"
        f"<td {td}>{c['stack']}</td>"
        f"<td {td}>{c['ipv4_link']}</td>"
        f"<td {td}>{c['ipv6_link']}</td>"
        f"<td {td}>{c['mac_cell']}</td>"
        f"<td {td}>{c['rtt_cell']}</td>"
        f"<td {td}>{location}</td>"
        f"<td {td}>{controls}</td>"
        "</tr>"
    )


def _multi_host_row(
    host,
    controls_map: dict[str, tuple[str, str]],
    domain: str,
) -> str:
    """Generate the host header row for a multi-interface host.

    Includes a fold indicator (\u25bc) and onclick handler to toggle
    visibility of the interface rows below.
    """
    nid = _node_id(host.hostname)
    fqdn = f"{host.hostname}.{domain}"

    host_conn_eid = f"binary_sensor.gdoc2netcfg_{nid}_connectivity"
    host_stack_eid = f"sensor.gdoc2netcfg_{nid}_stack_mode"

    setup = (
        f"{{% set _hc=states('{host_conn_eid}') %}}"
        f"{{% set _hs=states('{host_stack_eid}') %}}"
        "{% set _hp='ipv4.' if _hs=='ipv4-only' "
        "else ('ipv6.' if _hs=='ipv6-only' else '') %}"
    )
    status = (
        "{% if _hc=='on' %}\U0001f7e2"
        "{% elif _hc=='off' %}\U0001f534"
        "{% else %}\u26ab{% endif %}"
    )
    stack = (
        "{% if _hs=='dual-stack' %}4\u00b76"
        "{% elif _hs=='ipv4-only' %}4"
        "{% elif _hs=='ipv6-only' %}6"
        "{% else %}\u2014{% endif %}"
    )
    hostname_link = (
        f'<a href="http://{{{{ _hp }}}}{fqdn}">'
        f"<b>{host.hostname}</b></a>"
    )
    fold_indicator = '<span class="fi">\u25bc</span>'
    location, controls = _location_and_controls(host, controls_map, domain)
    opacity = (
        "{% if _hc=='on' %}1"
        "{% elif _hc=='off' %}0.5"
        "{% else %}0.35{% endif %}"
    )

    td = 'style="padding:4px 6px;white-space:nowrap"'
    tde = 'style="padding:4px 6px"'

    return (
        f"{setup}"
        f'<tr class="hr" data-open="1" onclick="{_TOGGLE_JS}" '
        f'style="cursor:pointer;opacity:{opacity};'
        f'border-top:2px solid var(--divider-color,#e0e0e0)">'
        f"<td {td}>{status}</td>"
        f"<td {td}>{fold_indicator}</td>"
        f"<td {td}>{hostname_link}</td>"
        f"<td {td}>{stack}</td>"
        f"<td {tde}></td>"
        f"<td {tde}></td>"
        f"<td {tde}></td>"
        f"<td {tde}></td>"
        f"<td {td}>{location}</td>"
        f"<td {td}>{controls}</td>"
        "</tr>"
    )


def _iface_row(host, vi, ipv6_prefix: str, domain: str) -> str:
    """Generate a table row for one interface under a multi-interface host.

    Interface rows fill the second St column and leave the first
    (host St) empty.  Name is indented.  No class="hr" so the
    toggle JS skips over these when walking siblings.
    """
    c = _iface_cells(host, vi, ipv6_prefix, domain)

    td = 'style="padding:2px 6px;white-space:nowrap"'
    tdi = 'style="padding:2px 6px 2px 16px;white-space:nowrap"'

    return (
        f"{c['setup']}"
        f'<tr style="opacity:{c["opacity"]}">'
        f"<td {td}></td>"
        f"<td {td}>{c['status']}</td>"
        f"<td {tdi}>{c['iface_link']}</td>"
        f"<td {td}>{c['stack']}</td>"
        f"<td {td}>{c['ipv4_link']}</td>"
        f"<td {td}>{c['ipv6_link']}</td>"
        f"<td {td}>{c['mac_cell']}</td>"
        f"<td {td}>{c['rtt_cell']}</td>"
        f"<td {td}></td>"
        f"<td {td}></td>"
        "</tr>"
    )


def _host_rows(
    host,
    controls_map: dict[str, tuple[str, str]],
    ipv6_prefix: str,
    domain: str,
) -> list[str]:
    """Generate all table rows for one host.

    Single-interface hosts get one combined row.  Multi-interface
    hosts get a clickable host row (with fold toggle) plus
    individual interface rows underneath.
    """
    vis = host.virtual_interfaces
    if len(vis) == 1:
        return [_single_row(host, vis[0], controls_map, ipv6_prefix, domain)]

    rows = [_multi_host_row(host, controls_map, domain)]
    for vi in vis:
        rows.append(_iface_row(host, vi, ipv6_prefix, domain))
    return rows


def _build_network_table(
    subdomain: str,
    hosts: list,
    sort_key: str,
    controls_map: dict[str, tuple[str, str]],
    ipv6_prefix: str,
    rtt_cache: dict[str, float | None],
    domain: str,
) -> dict:
    """Generate a Lovelace markdown card with a single table per network.

    Host rows and interface rows alternate in one table.  Host rows
    use the first St column; interface rows use the second.  For
    by-status, each host group (host row + interface rows) is wrapped
    in a Jinja2 conditional for live status-based sorting.
    """
    display_name = NETWORK_DISPLAY.get(subdomain, subdomain.title())
    host_count = len(hosts)

    title = f"{display_name} ({subdomain}) \u2014 {host_count} hosts"
    if ipv6_prefix:
        title += f" \u2014 IPv6: {ipv6_prefix}"

    # Determine host order
    if sort_key == "by-rtt":
        def _rtt_sort_key(h):
            rtt = rtt_cache.get(h.hostname)
            return (0, rtt) if rtt is not None else (1, 0)
        ordered_hosts = sorted(hosts, key=_rtt_sort_key)
    else:
        ordered_hosts = sorted(hosts, key=lambda h: h.hostname)

    lines = [
        '<table style="width:100%;border-collapse:collapse;font-size:0.85em">',
        _table_header(sort_key),
    ]

    if sort_key == "by-status":
        # Multi-pass: single-interface hosts get full row, multi-
        # interface hosts get host-only row (no interface rows) to
        # stay within HA's 4 MB WebSocket limit.
        for condition in ("on", "off", "unavailable"):
            for host in ordered_hosts:
                nid = _node_id(host.hostname)
                host_conn_eid = (
                    f"binary_sensor.gdoc2netcfg_{nid}_connectivity"
                )
                vis = host.virtual_interfaces
                if len(vis) == 1:
                    block = _single_row(
                        host, vis[0], controls_map, ipv6_prefix, domain,
                    )
                else:
                    block = _multi_host_row(
                        host, controls_map, domain,
                    )
                if condition in ("on", "off"):
                    lines.append(
                        f"{{% if is_state('{host_conn_eid}',"
                        f"'{condition}') %}}"
                        f"{block}"
                        "{% endif %}"
                    )
                else:
                    lines.append(
                        f"{{% if not is_state('{host_conn_eid}','on') "
                        f"and not is_state('{host_conn_eid}','off') %}}"
                        f"{block}"
                        "{% endif %}"
                    )
    else:
        for host in ordered_hosts:
            lines.extend(_host_rows(
                host, controls_map, ipv6_prefix, domain,
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
    controls_map: dict[str, tuple[str, str]],
    ipv6_prefix: str,
    rtt_cache: dict[str, float | None],
    domain: str,
) -> dict:
    """Build the Lovelace dashboard config with 3 sorted views.

    Each view contains a summary card followed by one card per
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

        # Per-network cards in defined order
        for subdomain in NETWORK_ORDER:
            if subdomain not in networks:
                continue
            cards.append(_build_network_table(
                subdomain, networks[subdomain], sort_key,
                controls_map, ipv6_prefix, rtt_cache, domain,
            ))

        # Any networks not in NETWORK_ORDER (e.g. "unknown")
        for subdomain in sorted(networks.keys()):
            if subdomain not in NETWORK_ORDER:
                cards.append(_build_network_table(
                    subdomain, networks[subdomain], sort_key,
                    controls_map, ipv6_prefix, rtt_cache, domain,
                ))

        # panel: true + vertical-stack for full viewport width
        views.append({
            "title": view_title,
            "path": sort_key,
            "icon": icon,
            "panel": True,
            "cards": [
                {
                    "type": "vertical-stack",
                    "cards": cards,
                },
            ],
        })

    return {"views": views}


# ---------------------------------------------------------------------------
# Push to HA (unchanged)
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
    domain = config.site.domain

    print(
        f"  Controls: {len(controls_map)} hosts powered by Tasmota plugs"
    )
    print(f"  IPv6 prefix: {ipv6_prefix or '(none)'}")
    print(f"  Domain: {domain}")
    print(
        f"  RTT cache: {sum(1 for v in rtt_cache.values() if v is not None)}"
        f"/{len(rtt_cache)} hosts with RTT data"
    )

    print("Building dashboard config...")
    dashboard_config = _build_dashboard_config(
        networks, controls_map, ipv6_prefix, rtt_cache, domain,
    )

    # Report template sizes per view (dig into vertical-stack)
    for view in dashboard_config["views"]:
        vstack = view["cards"][0]  # the vertical-stack wrapper
        inner = vstack["cards"]
        total = sum(len(c.get("content", "")) for c in inner)
        print(f"  {view['path']}: {len(inner)} cards, {total:,} bytes")

    print("Pushing to Home Assistant...")
    asyncio.run(_push_dashboard(config, dashboard_config))

    print(f"\nDashboard available at: https://ha.{domain}/network-reachability/by-name")


if __name__ == "__main__":
    main()
