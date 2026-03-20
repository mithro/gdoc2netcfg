"""Tasmota Home Assistant integration check.

Queries the Home Assistant REST API to verify that Tasmota devices
are properly registered and reporting state. Each Tasmota device
should appear as switch.tasmota_{topic} in HA.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import HomeAssistantConfig
    from gdoc2netcfg.models.host import Host


def _entity_id_for_host(host: Host) -> str:
    """Derive the expected HA entity ID for a Tasmota host.

    When DeviceName == FriendlyName (which we enforce), the HA Tasmota
    integration uses just the device name as the entity ID:
    switch.{slugify(device_name)}.  Slugify lowercases and replaces
    non-alphanumeric characters with underscores.
    """
    name = host.machine_name
    # Replicate python-slugify behaviour for simple hostnames
    return f"switch.{name.replace('-', '_').replace('.', '_').lower()}"


def check_ha_status(
    hosts: list[Host],
    ha_config: HomeAssistantConfig,
    max_workers: int = 16,
    verbose: bool = False,
) -> dict[str, dict]:
    """Check Home Assistant for Tasmota device entities.

    For each host with tasmota_data, queries the HA REST API for the
    expected entity (switch.tasmota_{topic}). Uses ThreadPoolExecutor
    for parallel requests. Reports existence, state, and last_changed.

    Args:
        hosts: Hosts with tasmota_data attached.
        ha_config: Home Assistant connection config.
        max_workers: Maximum concurrent HA API requests.
        verbose: Print progress to stderr.

    Returns:
        Mapping of hostname to status dict with keys:
        exists, entity_id, state, last_changed.
    """
    # Build work list: (hostname, entity_id) for hosts with tasmota data
    work: list[tuple[str, str]] = []
    for host in sorted(hosts, key=lambda h: h.hostname):
        if host.tasmota_data is None:
            continue
        work.append((host.hostname, _entity_id_for_host(host)))

    if not work:
        return {}

    results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        # Submit all lookups in parallel
        futures: list[tuple[str, str, Future[dict]]] = [
            (hostname, entity_id, pool.submit(_query_ha_entity, ha_config, entity_id))
            for hostname, entity_id in work
        ]

        # Collect results in sorted order, printing as each completes
        for hostname, entity_id, future in futures:
            status = future.result()
            results[hostname] = status

            if verbose:
                if status["exists"]:
                    state = status.get("state", "?")
                    changed = status.get("last_changed", "?")
                    print(
                        f"  {hostname:30s}  {entity_id:40s}  "
                        f"state={state}  last_changed={changed}",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"  {hostname:30s}  {entity_id:40s}  NOT FOUND",
                        file=sys.stderr,
                    )

    return results


def _query_ha_entity(
    ha_config: HomeAssistantConfig,
    entity_id: str,
) -> dict:
    """Query a single entity from the Home Assistant REST API.

    Args:
        ha_config: HA connection config.
        entity_id: Entity ID to look up (e.g. "switch.tasmota_au_plug_10").

    Returns:
        Dict with 'exists' bool, plus 'state', 'last_changed',
        'entity_id' if found.
    """
    url = f"{ha_config.url.rstrip('/')}/api/states/{entity_id}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {ha_config.token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read())
            return {
                "exists": True,
                "entity_id": entity_id,
                "state": data.get("state", "unknown"),
                "last_changed": data.get("last_changed", ""),
                "attributes": data.get("attributes", {}),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "entity_id": entity_id}
        return {"exists": False, "entity_id": entity_id, "error": str(e)}
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as e:
        return {"exists": False, "entity_id": entity_id, "error": str(e)}
