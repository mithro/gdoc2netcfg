"""sensors2mqtt Home Assistant entity status check.

Queries the HA REST API for the sensors2mqtt entities belonging to each
non-blank host and classifies them as fresh / stale / missing.

Freshness rule: among a host's matched entities, take the newest
``last_updated`` timestamp.  fresh = age < freshness_seconds; stale =
age >= freshness_seconds; missing = no matched entities.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from gdoc2netcfg.supplements.tasmota_ha import _fetch_all_states

if TYPE_CHECKING:
    from gdoc2netcfg.config import HomeAssistantConfig
    from gdoc2netcfg.models.host import Host

# The exact metric names published by sensors2mqtt.  Entity IDs are
# ``sensor.<node_id>_<metric>``.  We match by EXACT id (not prefix) to
# prevent bare ``rpi5`` from stealing ``rpi5_netv2_*`` entities.
SENSORS2MQTT_METRICS = frozenset({
    "cpu_temperature", "load_1m", "load_5m", "load_15m",
    "memory_available", "memory_total", "memory_used", "uptime",
    "rp1_temperature", "rp1_voltage_1", "rp1_voltage_2", "rp1_voltage_3",
    "rp1_voltage_4", "throttled", "under_voltage", "frequency_capped",
    "soft_temp_limit", "supply_undervoltage", "throttle_state",
})


def query_status(
    ha_config: HomeAssistantConfig,
    hosts: list[Host],
    freshness_seconds: int,
    now: datetime,
) -> dict[str, dict]:
    """Check HA entity states for each non-blank sensors2mqtt host.

    Args:
        ha_config: Home Assistant connection config (url + token).
        hosts: All hosts; blank ones are filtered internally.
        freshness_seconds: Age threshold in seconds for fresh vs stale.
        now: Reference time for freshness calculation (caller-injected
            so tests are deterministic).

    Returns:
        Dict keyed by ``host.hostname`` for each non-blank host:
        ``{"class": "fresh"|"stale"|"missing",
           "last_updated": datetime|None,
           "selection": "local"|"remote"}``
    """
    from gdoc2netcfg.derivations.sensors2mqtt import classify, select_non_blank
    from gdoc2netcfg.utils.mqtt import node_id

    non_blank = select_non_blank(hosts)
    if not non_blank:
        return {}

    all_states = _fetch_all_states(ha_config)

    # Build entity_id -> state index once.
    entity_index: dict[str, dict] = {e["entity_id"]: e for e in all_states}

    result: dict[str, dict] = {}

    for host in non_blank:
        nid = node_id(host.hostname)

        # Build the exact candidate entity_id set for this host.
        candidate_ids = {f"sensor.{nid}_{m}" for m in SENSORS2MQTT_METRICS}

        # Intersect with what HA actually has.
        matched = [entity_index[eid] for eid in candidate_ids if eid in entity_index]

        if not matched:
            result[host.hostname] = {
                "class": "missing",
                "last_updated": None,
                "selection": classify(host),
            }
            continue

        # Find the newest last_updated among matched entities.
        newest: datetime | None = None
        for entity in matched:
            raw = entity.get("last_updated", "")
            if raw:
                ts = datetime.fromisoformat(raw)
                if newest is None or ts > newest:
                    newest = ts

        if newest is None:
            result[host.hostname] = {
                "class": "missing",
                "last_updated": None,
                "selection": classify(host),
            }
            continue

        # Ensure both are offset-aware for comparison.
        if newest.tzinfo is None:
            newest = newest.replace(tzinfo=timezone.utc)
        age = (now - newest).total_seconds()

        result[host.hostname] = {
            "class": "fresh" if age < freshness_seconds else "stale",
            "last_updated": newest,
            "selection": classify(host),
        }

    return result
