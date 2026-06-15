"""MQTT-safe identity transform shared across MQTT consumers.

`node_id` turns a hostname into an MQTT/HA-safe token (alphanumeric + `_`,
lowercased). It is the canonical per-host key used for entity IDs (mqtt_ha)
and for derived broker credentials (mqtt_credentials).
"""

from __future__ import annotations

import re


def node_id(name: str) -> str:
    """Return an MQTT/HA-safe token: lowercase; every non-alphanumeric char -> `_`.

    >>> node_id("bmc.big-storage")
    'bmc_big_storage'
    >>> node_id("MyHost")
    'myhost'
    """
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()
