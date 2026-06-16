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
import urllib.error
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING

from gdoc2netcfg.models.addressing import MACAddress
from gdoc2netcfg.models.host import TasmotaData

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.models.network import Site

_UNKNOWN_PREFIX = "_unknown/"


@dataclass(frozen=True)
class TasmotaDiscrepancy:
    """A mismatch between the network and the golden spreadsheet.

    kind is one of: "unknown_device", "ip_mismatch", "duplicate_sheet_mac",
    "duplicate_network_mac", "unidentifiable".
    """

    kind: str
    mac: str
    ip: str
    hostname: str  # sheet hostname when known, else ""
    detail: str

    def format(self) -> str:
        loc = self.hostname or self.mac or self.ip or "?"
        return f"[{self.kind}] {loc}: {self.detail}"


@dataclass(frozen=True)
class TasmotaScanResult:
    """Outcome of a Tasmota scan: per-device data plus discrepancies."""

    data: dict[str, dict]
    discrepancies: list[TasmotaDiscrepancy]


def _unknown_key(mac: str) -> str:
    """Storage key for a device not in the sheet, by its normalized MAC."""
    return f"{_UNKNOWN_PREFIX}{mac}"


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
      StatusSTS.UptimeSec, Uptime, MqttCount
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
        "mqtt_count": sts.get("MqttCount", 0),
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
    baseline: dict[str, dict] | None,
    site: Site,
    *,
    verbose: bool = False,
) -> TasmotaScanResult:
    """Scan the IoT VLAN and identify devices by their spreadsheet MAC.

    Identity comes from the sheet: a device whose MAC matches a sheet IoT
    host is keyed by that host's hostname (regardless of its IP or self-
    reported name); a device whose MAC is not in this site's sheet is keyed
    ``_unknown/<mac>``.  Sheet hosts not seen this scan are carried forward
    from *baseline* (offline hosts keep last-known data) if still in the
    sheet.  Discrepancies (unknown devices, IP mismatches, duplicate MACs,
    unidentifiable devices) are collected, not hidden.

    Returns a TasmotaScanResult(data, discrepancies).  The caller persists
    ``data`` and tombstones whatever is absent from it.
    """
    baseline = baseline or {}
    discrepancies: list[TasmotaDiscrepancy] = []

    # Build the sheet MAC -> hostname index for this site's IoT hosts.
    mac_to_host: dict[str, str] = {}
    valid_known: set[str] = set()
    host_by_name: dict[str, Host] = {}
    known_ips: list[str] = []
    for host in hosts:
        if host.sheet_type != "IoT":
            continue
        valid_known.add(host.hostname)
        host_by_name[host.hostname] = host
        if host.first_ipv4 is not None:
            known_ips.append(str(host.first_ipv4))
        for mac in host.all_macs:
            key = str(mac)
            existing = mac_to_host.get(key)
            if existing is not None and existing != host.hostname:
                discrepancies.append(TasmotaDiscrepancy(
                    kind="duplicate_sheet_mac", mac=key, ip="",
                    hostname=host.hostname,
                    detail=f"MAC also on sheet host {existing}",
                ))
                continue
            mac_to_host[key] = host.hostname

    # Probe known sheet IPs (reliable) and sweep the IoT /24 (discovery);
    # collect every responder keyed by IP.
    found: dict[str, dict] = {}
    if verbose:
        print(f"Probing {len(known_ips)} known IoT IP(s)...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures: dict[str, Future[dict | None]] = {
            ip: pool.submit(_fetch_tasmota_status, ip, 3.0) for ip in known_ips
        }
        for ip, future in futures.items():
            raw = future.result()
            if raw is not None:
                found[ip] = _parse_tasmota_status(raw)

    iot_prefix = site.ip_prefix_for_vlan("iot")
    if iot_prefix is not None:
        if verbose:
            print(f"Sweeping {iot_prefix}0/24...", file=sys.stderr)
        for ip, parsed in _scan_subnet(
            iot_prefix, max_workers=32, timeout=2.0, verbose=verbose
        ).items():
            found.setdefault(ip, parsed)  # probe result wins on duplicate IP
    elif verbose:
        print("Sweep skipped — no 'iot' VLAN in site config.", file=sys.stderr)

    # Group responders by normalized MAC.
    by_mac: dict[str, list[tuple[str, dict]]] = {}
    for ip, parsed in found.items():
        raw_mac = parsed.get("mac", "")
        try:
            mac = str(MACAddress.parse(raw_mac))
        except ValueError:
            discrepancies.append(TasmotaDiscrepancy(
                kind="unidentifiable", mac=raw_mac, ip=ip, hostname="",
                detail=f"device reported an unparseable MAC {raw_mac!r}",
            ))
            continue
        by_mac.setdefault(mac, []).append((ip, parsed))

    data: dict[str, dict] = {}
    seen_hosts: set[str] = set()
    for mac, sightings in sorted(by_mac.items()):
        if len(sightings) > 1:
            ips = ", ".join(sorted(ip for ip, _ in sightings))
            discrepancies.append(TasmotaDiscrepancy(
                kind="duplicate_network_mac", mac=mac, ip=ips, hostname="",
                detail=f"same MAC answered at multiple IPs: {ips}",
            ))
            continue
        ip, parsed = sightings[0]
        matched = mac_to_host.get(mac)
        if matched is not None:
            data[matched] = parsed
            seen_hosts.add(matched)
            host = host_by_name[matched]
            sheet_ip = str(host.first_ipv4) if host.first_ipv4 is not None else ""
            if sheet_ip and parsed.get("ip", "") != sheet_ip:
                discrepancies.append(TasmotaDiscrepancy(
                    kind="ip_mismatch", mac=mac, ip=parsed.get("ip", ""),
                    hostname=matched,
                    detail=f"device at {parsed.get('ip', '?')}, "
                           f"sheet says {sheet_ip}",
                ))
        else:
            data[_unknown_key(mac)] = parsed
            discrepancies.append(TasmotaDiscrepancy(
                kind="unknown_device", mac=mac, ip=ip, hostname="",
                detail=f"device {parsed.get('device_name', '?')!r} at {ip} "
                       f"not in this site's sheet",
            ))

    # Carry forward offline hosts still in the sheet (keep last-known data).
    # Baseline keys not in the sheet (removed hosts) and stale _unknown/ keys
    # are intentionally dropped so the caller tombstones them.
    for key, info in baseline.items():
        if key in valid_known and key not in seen_hosts:
            data[key] = info

    return TasmotaScanResult(data=data, discrepancies=discrepancies)


def enrich_hosts_with_tasmota(
    hosts: list[Host],
    tasmota_cache: dict[str, dict] | None,
) -> None:
    """Attach cached Tasmota data to Host objects.

    Modifies hosts in-place by setting host.tasmota_data. Also parses
    the Controls column from host.extra into a tuple of controlled
    hostnames.

    Args:
        hosts: All hosts from the pipeline.
        tasmota_cache: Mapping of hostname to Tasmota data dict.
    """
    tasmota_cache = tasmota_cache or {}
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
            mqtt_count=info.get("mqtt_count", 0),
            controls=controls,
        )


