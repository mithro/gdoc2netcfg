"""Tasmota device configuration push.

This module handles the write-side of Tasmota management: computing
the desired configuration from host data + pipeline config, detecting
drift against actual device state, and pushing corrections via HTTP.

Separated from tasmota.py (read-only scan/cache/enrich) to maintain
the supplement pattern where supplements are read-only.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.mqtt_credentials import password, username
from gdoc2netcfg.derivations.tasmota_credentials import PREFIX

if TYPE_CHECKING:
    from gdoc2netcfg.config import MqttBrokerConfig, TasmotaConfig
    from gdoc2netcfg.models.host import Host


@dataclass(frozen=True)
class ConfigDrift:
    """A single configuration field that differs from desired state.

    Attributes:
        field: Tasmota command name (e.g. "DeviceName", "MqttHost").
        current: Current value on the device.
        desired: Desired value from pipeline config.
        warning: Non-empty if this change requires manual attention
            (e.g. Topic rename on an HA-connected device).
    """

    field: str
    current: str
    desired: str
    warning: str = ""


def compute_desired_config(
    host: Host,
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
) -> dict[str, str]:
    """Derive the desired Tasmota configuration for a host.

    Args:
        host: Host object with tasmota_data and extra columns.
        mqtt_config: HA Mosquitto broker connection (MqttHost/MqttPort).
        tasmota_config: Tasmota credential secret (derives MqttUser/MqttPassword).

    Returns:
        Mapping of Tasmota command name to desired value.
    """
    desired: dict[str, str] = {}

    # When fn[0] == dn, the HA Tasmota integration uses just the device
    # name as the entity ID: switch.{slugify(dn)}. Setting both to the
    # machine name gives predictable IDs like switch.au_plug_4.
    desired["DeviceName"] = host.machine_name
    desired["FriendlyName1"] = host.machine_name

    desired.update({
        "Hostname": host.machine_name,
        "Topic": host.machine_name,
        "MqttHost": mqtt_config.host,
        "MqttPort": str(mqtt_config.port),
        "MqttUser": username(PREFIX, host),
        "MqttPassword": password(tasmota_config.mqtt_secret, host),
    })

    return desired


def _get_current_value(field: str, tasmota_data) -> str:
    """Extract the current value for a Tasmota command from device data.

    Maps Tasmota command names to TasmotaData field values.
    """
    field_map = {
        "DeviceName": "device_name",
        "FriendlyName1": "friendly_name",
        "Hostname": "hostname",
        "Topic": "mqtt_topic",
        "MqttHost": "mqtt_host",
        "MqttPort": "mqtt_port",
        "MqttUser": "mqtt_user",
        "MqttPassword": None,  # Can't be read back from device
    }
    attr = field_map.get(field)
    if attr is None:
        return ""
    return str(getattr(tasmota_data, attr, ""))


def compute_drift(
    host: Host,
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
) -> list[ConfigDrift]:
    """Compare actual device state against desired configuration.

    Args:
        host: Host with tasmota_data attached.
        mqtt_config: HA Mosquitto broker connection (MqttHost/MqttPort).
        tasmota_config: Tasmota credential secret (derives MqttUser/MqttPassword).

    Returns:
        List of ConfigDrift entries for fields that need updating.
    """
    if host.tasmota_data is None:
        raise ValueError(f"Host {host.hostname} has no tasmota_data")

    desired = compute_desired_config(host, mqtt_config, tasmota_config)
    drifts: list[ConfigDrift] = []

    for field, desired_value in desired.items():
        current = _get_current_value(field, host.tasmota_data)
        # Skip fields we can't read back from the device
        if field == "MqttPassword":
            continue
        if current != desired_value:
            warning = ""
            if field == "Topic" and host.tasmota_data.mqtt_host:
                # Device is already connected to an MQTT broker, so HA
                # has entities registered under the current topic.
                # Changing it would orphan those entities.
                warning = (
                    f"Device is connected to MQTT broker "
                    f"({host.tasmota_data.mqtt_host}); changing Topic "
                    f"will orphan HA entities under topic "
                    f"'{current}'"
                )
            drifts.append(ConfigDrift(
                field=field,
                current=current,
                desired=desired_value,
                warning=warning,
            ))

    return drifts


def _send_tasmota_command(
    ip: str,
    command: str,
    timeout: float = 5.0,
) -> dict | None:
    """Send a command to a Tasmota device via HTTP.

    Args:
        ip: Device IPv4 address.
        command: Tasmota command string (e.g. "DeviceName my-device").
        timeout: HTTP request timeout.

    Returns:
        Parsed JSON response, or None on failure.
    """
    encoded = urllib.parse.quote(command, safe="")
    url = f"http://{ip}/cm?cmnd={encoded}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        print(
            f"Warning: {ip} returned invalid JSON for command",
            file=sys.stderr,
        )
        return None


def configure_tasmota_device(
    host: Host,
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
    dry_run: bool = False,
    verbose: bool = False,
    force: bool = False,
) -> bool:
    """Push desired configuration to a single Tasmota device.

    Computes drift, sends corrective commands, and verifies the result.

    Args:
        host: Host with tasmota_data attached.
        mqtt_config: HA Mosquitto broker connection (MqttHost/MqttPort).
        tasmota_config: Tasmota credential secret (derives MqttUser/MqttPassword).
        dry_run: If True, show changes without applying.
        verbose: Print progress to stderr.
        force: If True, apply changes that would break HA integration
            (e.g. Topic rename on an HA-connected device).

    Returns:
        True if all changes were applied (or no changes needed).
    """
    if host.tasmota_data is None:
        if verbose:
            print(f"  {host.hostname}: no Tasmota data, skipping", file=sys.stderr)
        return False

    ip = host.tasmota_data.ip
    if not ip:
        if verbose:
            print(f"  {host.hostname}: no IP in Tasmota data", file=sys.stderr)
        return False

    drifts = compute_drift(host, mqtt_config, tasmota_config)

    # MqttCount == 0 means the device has never connected to the MQTT
    # broker since boot.  This is a diagnostic signal — likely the
    # password is wrong (it can't be read back, so drift detection
    # can't catch it).  Flag it prominently and ensure credentials
    # are pushed even when there is no other drift.
    mqtt_disconnected = host.tasmota_data.mqtt_count == 0

    if not drifts and not mqtt_disconnected:
        if verbose:
            print(f"  {host.hostname}: OK (no drift)", file=sys.stderr)
        return True

    # Separate safe drifts from those requiring --force
    safe_drifts = [d for d in drifts if not d.warning]
    warned_drifts = [d for d in drifts if d.warning]

    if verbose:
        if drifts:
            print(f"  {host.hostname} ({ip}):", file=sys.stderr)
        for d in safe_drifts:
            print(
                f"    {d.field}: {d.current!r} → {d.desired!r}",
                file=sys.stderr,
            )
        for d in warned_drifts:
            if force:
                print(
                    f"    {d.field}: {d.current!r} → {d.desired!r} (forced)",
                    file=sys.stderr,
                )
            else:
                print(
                    f"    {d.field}: {d.current!r} → {d.desired!r} "
                    f"(SKIPPED: {d.warning} — use --force to apply)",
                    file=sys.stderr,
                )
        if mqtt_disconnected:
            if not drifts:
                print(f"  {host.hostname} ({ip}):", file=sys.stderr)
            print(
                f"    WARNING: MqttCount=0 — device has never connected "
                f"to MQTT broker since boot (uptime {host.tasmota_data.uptime}). "
                f"Pushing MqttUser + MqttPassword.",
                file=sys.stderr,
            )

    if dry_run:
        return True

    # Determine which drifts to actually apply.
    # Skipped (warned) drifts are not counted as failures — they are
    # expected to be resolved by the user via --force or HA reconfiguration.
    drifts_to_apply = safe_drifts
    if force:
        drifts_to_apply = drifts  # All drifts including warned ones

    # Apply drifted fields.  When MqttCount == 0, also push MqttUser +
    # MqttPassword — wrong credentials are the most common cause of a
    # device that looks correctly configured but can't connect to the
    # broker, and MqttPassword can't be read back to detect drift.
    all_ok = True
    desired = compute_desired_config(host, mqtt_config, tasmota_config)
    fields_to_push = {d.field: d.desired for d in drifts_to_apply}
    if mqtt_disconnected:
        fields_to_push["MqttUser"] = desired["MqttUser"]
        fields_to_push["MqttPassword"] = desired["MqttPassword"]

    for field, value in fields_to_push.items():
        # Mask credentials in log output
        if field == "MqttPassword":
            log_display = f"{field} ****"
        else:
            log_display = f"{field} {value}"
        command = f"{field} {value}"
        result = _send_tasmota_command(ip, command)
        if result is None:
            if verbose:
                print(f"    FAILED: {log_display}", file=sys.stderr)
            all_ok = False
        elif verbose:
            print(f"    Applied: {log_display}", file=sys.stderr)

    return all_ok


def configure_all_tasmota_devices(
    hosts: list[Host],
    mqtt_config: MqttBrokerConfig,
    tasmota_config: TasmotaConfig,
    dry_run: bool = False,
    verbose: bool = False,
    force: bool = False,
) -> tuple[int, int]:
    """Push configuration to all Tasmota devices.

    Args:
        hosts: Hosts with tasmota_data attached.
        mqtt_config: HA Mosquitto broker connection (MqttHost/MqttPort).
        tasmota_config: Tasmota credential secret (derives MqttUser/MqttPassword).
        dry_run: If True, show changes without applying.
        verbose: Print progress to stderr.
        force: If True, apply HA-breaking changes (e.g. Topic rename).

    Returns:
        (success_count, fail_count) tuple.
    """
    success = 0
    fail = 0
    for host in hosts:
        ok = configure_tasmota_device(
            host, mqtt_config, tasmota_config, dry_run=dry_run, verbose=verbose,
            force=force,
        )
        if ok:
            success += 1
        else:
            fail += 1

    return success, fail
