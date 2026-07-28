"""gwifi puck per-device MQTT credential derivation.

Pure. Selects the gwifi puck devices (those carrying `WifiData`, attached by
`wifi_data.enrich_hosts_with_wifi_data`) and builds the `{gwifi-<id>: password}`
map for `register-broker`, reusing the shared credential core.
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

PREFIX = "gwifi-"


def select_pucks(hosts: list[Host]) -> list[Host]:
    """gwifi pucks = hosts with puck identity data (`host.wifi_data`)."""
    return [h for h in hosts if h.wifi_data is not None]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{gwifi-<id>: sha256(secret+<id>)}` for every puck. Fails loud on a
    weak secret or a node_id collision among the selected pucks."""
    require_strong_secret(secret)
    pucks = select_pucks(hosts)
    check_collisions(pucks)
    return {username(PREFIX, h): password(secret, h) for h in pucks}
