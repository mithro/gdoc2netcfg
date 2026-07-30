"""WiFi-device per-device MQTT credential derivation.

Pure. Selects ALL WiFi-sheet hosts (`sheet_type == 'WiFi'`) — gale pucks,
OpenMesh APs, and future WiFi infrastructure — and builds the
`{wifi-<id>: password}` map for `register-broker`, reusing the shared
credential core.

Logins are issued even for devices that cannot consume them yet (OpenMesh
APs have no MQTT client) — deliberate spare logins, same precedent as the
sensors2mqtt SDR Pis.
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

PREFIX = "wifi-"


def select_wifi_hosts(hosts: list[Host]) -> list[Host]:
    """All WiFi-sheet hosts (pucks, OpenMesh APs, future WiFi infrastructure)."""
    return [h for h in hosts if h.sheet_type == "WiFi"]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{wifi-<id>: sha256(secret+<id>)}` for every WiFi-sheet host. Fails
    loud on a weak secret, an empty selection, or a node_id collision among
    the selected hosts."""
    require_strong_secret(secret)
    selected = select_wifi_hosts(hosts)
    if not selected:
        raise ValueError(
            "no WiFi-sheet hosts found — check the [sheets] wifi source is "
            "configured and fetched"
        )
    check_collisions(selected)
    return {username(PREFIX, h): password(secret, h) for h in selected}
