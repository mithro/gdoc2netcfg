"""Tasmota per-device MQTT credential derivation.

Pure. Selects the Tasmota devices (those with last-known scan data) and builds
the `{tas-<id>: password}` map for `register-broker`, reusing the shared
credential core. The same `username`/`password` are pushed to each device by
`tasmota_configure.compute_desired_config`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.mqtt_credentials import (
    check_collisions,
    password,
    require_strong_secret,
    username,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

PREFIX = "tas-"


def select_tasmota(hosts: list[Host]) -> list[Host]:
    """Tasmota devices = hosts with last-known scan data (`host.tasmota_data`)."""
    return [h for h in hosts if h.tasmota_data is not None]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{tas-<id>: sha256(secret+<id>)}` for every Tasmota device. Fails loud on a
    weak secret or a node_id collision among the selected devices."""
    require_strong_secret(secret)
    devices = select_tasmota(hosts)
    check_collisions(devices)
    return {username(PREFIX, h): password(secret, h) for h in devices}
