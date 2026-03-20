"""Supplement: Tasmota IoT device discovery and status collection.

Discovers Tasmota-based WiFi smart plugs on the IoT VLAN by querying
their HTTP API (Status 0). Two-phase scanning: first probe known IoT
hosts by IP, then sweep the full IoT subnet to find unregistered devices.
Results are cached in tasmota.json.

This is a read-only supplement — configuration push lives in
tasmota_configure.py.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import TasmotaData

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.models.network import Site

_UNKNOWN_PREFIX = "_unknown/"


def _unknown_key(ip: str) -> str:
    """Build cache key for an unknown device by IP."""
    return f"{_UNKNOWN_PREFIX}{ip}"


def _fetch_tasmota_status(ip: str, timeout: float = 3.0) -> dict | None:
    """Fetch Status 0 from a Tasmota device via HTTP.

    Args:
        ip: IPv4 address of the device.
        timeout: HTTP request timeout in seconds.

    Returns:
        Parsed JSON dict from Status 0 response, or None on failure.
    """
    url = f"http://{ip}/cm?cmnd=Status%200"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        # Device responded but returned non-JSON — log as warning since
        # this indicates an unexpected device or firmware issue.
        print(
            f"Warning: {ip} responded but returned invalid JSON",
            file=sys.stderr,
        )
        return None


def _parse_tasmota_status(data: dict) -> dict:
    """Extract relevant fields from a Tasmota Status 0 response.

    The Status 0 response contains nested sections:
      Status.DeviceName, Status.FriendlyName
      StatusNET.Hostname, StatusNET.Mac, StatusNET.IPAddress
      StatusMQT.MqttHost, MqttPort, MqttClient, MqttUser
      StatusFWR.Version
      StatusSTS.UptimeSec, Uptime
      StatusSTS.Wifi.SSId, RSSI, Signal

    Args:
        data: Raw JSON dict from Status 0.

    Returns:
        Flattened dict with extracted fields.
    """
    status = data.get("Status", {})
    net = data.get("StatusNET", {})
    mqtt = data.get("StatusMQT", {})
    fwr = data.get("StatusFWR", {})
    sts = data.get("StatusSTS", {})
    wifi = sts.get("Wifi", {})

    # FriendlyName can be a list or a string
    friendly = status.get("FriendlyName", [""])
    if isinstance(friendly, list):
        friendly = friendly[0] if friendly else ""

    return {
        "device_name": status.get("DeviceName", ""),
        "friendly_name": friendly,
        "hostname": net.get("Hostname", ""),
        "firmware_version": fwr.get("Version", ""),
        "mqtt_host": mqtt.get("MqttHost", ""),
        "mqtt_port": mqtt.get("MqttPort", 1883),
        "mqtt_topic": status.get("Topic", ""),
        "mqtt_client": mqtt.get("MqttClient", ""),
        "mqtt_user": mqtt.get("MqttUser", ""),
        "mac": net.get("Mac", ""),
        "ip": net.get("IPAddress", ""),
        "wifi_ssid": wifi.get("SSId", ""),
        "wifi_rssi": wifi.get("RSSI", 0),
        "wifi_signal": wifi.get("Signal", 0),
        "uptime": sts.get("Uptime", ""),
        "module": status.get("Module", ""),
    }


def _scan_subnet(
    subnet_prefix: str,
    max_workers: int = 32,
    timeout: float = 2.0,
    verbose: bool = False,
) -> dict[str, dict]:
    """Probe all 254 IPs on a /24 subnet for Tasmota devices.

    Note: Assumes a /24 subnet. The IoT VLAN is expected to be a single
    /24 (e.g. 10.1.90.0/24). If the VLAN spans multiple /24s, this
    function would need to be called once per third-octet.

    Args:
        subnet_prefix: First three octets with trailing dot (e.g. "10.1.90.").
        max_workers: Concurrent HTTP requests.
        timeout: Per-request timeout.
        verbose: Print progress to stderr.

    Returns:
        Mapping of IP address to parsed status dict for responding devices.
    """
    results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures: list[tuple[str, Future[dict | None]]] = []
        for host_num in range(1, 255):
            ip = f"{subnet_prefix}{host_num}"
            futures.append((ip, pool.submit(_fetch_tasmota_status, ip, timeout)))

        for ip, future in futures:
            data = future.result()
            if data is not None:
                parsed = _parse_tasmota_status(data)
                results[ip] = parsed
                if verbose:
                    name = parsed.get("device_name", "?")
                    print(f"  Found Tasmota at {ip}: {name}", file=sys.stderr)

    return results


def scan_tasmota(
    hosts: list[Host],
    cache_path: Path,
    site: Site,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
) -> dict[str, dict]:
    """Scan for Tasmota devices: known hosts + subnet sweep.

    Phase 1: Probe known IoT hosts by their spreadsheet IP.
    Phase 2: Sweep the IoT subnet to find unregistered devices.
    Merge results. Cache to tasmota.json.

    Known hosts are keyed by hostname. Unknown devices are keyed
    as "_unknown/{ip}".

    Args:
        hosts: All hosts from the pipeline.
        cache_path: Path to tasmota.json.
        site: Site configuration (for subnet computation).
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds.
        verbose: Print progress to stderr.

    Returns:
        Mapping of hostname (or _unknown/ip) to Tasmota data dict.
    """
    tasmota_data = load_tasmota_cache(cache_path)

    # Clear stale _unknown/ entries on forced rescan — the sweep will
    # rediscover any that still exist, and stale entries from old IPs
    # would otherwise accumulate indefinitely.
    if force:
        tasmota_data = {
            k: v for k, v in tasmota_data.items()
            if not k.startswith(_UNKNOWN_PREFIX)
        }

    # Check cache freshness
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(
                    f"tasmota.json last updated {age:.0f}s ago, using cache.",
                    file=sys.stderr,
                )
            return tasmota_data

    # Build IP→hostname index for known IoT hosts
    iot_hosts: list[tuple[str, str]] = []  # (hostname, ip)
    ip_to_hostname: dict[str, str] = {}
    for host in hosts:
        if host.sheet_type != "IoT":
            continue
        if host.first_ipv4 is None:
            continue
        ip_str = str(host.first_ipv4)
        iot_hosts.append((host.hostname, ip_str))
        ip_to_hostname[ip_str] = host.hostname

    # Phase 1: Probe known IoT hosts
    if verbose:
        print(
            f"Phase 1: Probing {len(iot_hosts)} known IoT host(s)...",
            file=sys.stderr,
        )

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures: list[tuple[str, str, Future[dict | None]]] = []
        for hostname, ip in iot_hosts:
            futures.append(
                (hostname, ip, pool.submit(_fetch_tasmota_status, ip, 3.0))
            )

        for hostname, ip, future in futures:
            data = future.result()
            if data is not None:
                parsed = _parse_tasmota_status(data)
                tasmota_data[hostname] = parsed
                if verbose:
                    name = parsed.get("device_name", "?")
                    fw = parsed.get("firmware_version", "?")
                    print(
                        f"  {hostname} ({ip}): {name} fw={fw}",
                        file=sys.stderr,
                    )
            elif verbose:
                print(f"  {hostname} ({ip}): no response", file=sys.stderr)

    # Phase 2: Sweep the IoT subnet
    iot_prefix = site.ip_prefix_for_vlan("iot")
    if iot_prefix is not None:
        if verbose:
            print(
                f"Phase 2: Sweeping {iot_prefix}0/24 for unknown devices...",
                file=sys.stderr,
            )
        sweep_results = _scan_subnet(
            iot_prefix, max_workers=32, timeout=2.0, verbose=verbose
        )

        # Merge sweep results — known hosts go under hostname, unknown under _unknown/ip
        for ip, parsed in sweep_results.items():
            if ip in ip_to_hostname:
                # Already captured in phase 1
                continue
            tasmota_data[_unknown_key(ip)] = parsed
    elif verbose:
        print(
            "Phase 2: Skipped — no 'iot' VLAN found in site config.",
            file=sys.stderr,
        )

    save_tasmota_cache(cache_path, tasmota_data)
    return tasmota_data


def load_tasmota_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached Tasmota data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_tasmota_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save Tasmota data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def enrich_hosts_with_tasmota(
    hosts: list[Host],
    tasmota_cache: dict[str, dict],
) -> None:
    """Attach cached Tasmota data to Host objects.

    Modifies hosts in-place by setting host.tasmota_data. Also parses
    the Controls column from host.extra into a tuple of controlled
    hostnames.

    Args:
        hosts: All hosts from the pipeline.
        tasmota_cache: Mapping of hostname to Tasmota data dict.
    """
    for host in hosts:
        info = tasmota_cache.get(host.hostname)
        if info is None:
            continue

        # Parse controls from spreadsheet extra column (comma or newline separated)
        controls_str = host.extra.get("Controls", "")
        controls = tuple(
            c.strip() for c in re.split(r"[,\r\n]", controls_str) if c.strip()
        )

        host.tasmota_data = TasmotaData(
            device_name=info.get("device_name", ""),
            friendly_name=info.get("friendly_name", ""),
            hostname=info.get("hostname", ""),
            firmware_version=info.get("firmware_version", ""),
            mqtt_host=info.get("mqtt_host", ""),
            mqtt_port=info.get("mqtt_port", 1883),
            mqtt_topic=info.get("mqtt_topic", ""),
            mqtt_client=info.get("mqtt_client", ""),
            mqtt_user=info.get("mqtt_user", ""),
            mac=info.get("mac", ""),
            ip=info.get("ip", ""),
            wifi_ssid=info.get("wifi_ssid", ""),
            wifi_rssi=info.get("wifi_rssi", 0),
            wifi_signal=info.get("wifi_signal", 0),
            uptime=info.get("uptime", ""),
            module=info.get("module", ""),
            controls=controls,
        )


def match_unknown_devices(
    hosts: list[Host],
    tasmota_cache: dict[str, dict],
) -> list[tuple[str, str | None]]:
    """Match unknown Tasmota devices to spreadsheet entries by MAC.

    Args:
        hosts: All hosts from the pipeline.
        tasmota_cache: Mapping including "_unknown/{ip}" entries.

    Returns:
        List of (ip, matched_hostname_or_None) tuples for unknown devices.
    """
    # Build MAC → hostname index from known hosts
    mac_to_hostname: dict[str, str] = {}
    for host in hosts:
        for iface in host.interfaces:
            mac_to_hostname[str(iface.mac).upper()] = host.hostname

    matches: list[tuple[str, str | None]] = []
    for key, info in sorted(tasmota_cache.items()):
        if not key.startswith(_UNKNOWN_PREFIX):
            continue
        ip = key[len(_UNKNOWN_PREFIX):]
        device_mac = info.get("mac", "").upper()
        matched = mac_to_hostname.get(device_mac)
        matches.append((ip, matched))

    return matches
