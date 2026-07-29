"""wisp service MQTT credential derivation.

Pure. Selects the single wisp service host (`hostname == "wisp"`, from the
Network sheet) and builds the `{wisp-<id>: password}` map for
`register-broker`, reusing the shared credential core.
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

PREFIX = "wisp-"


def select_wisp(hosts: list[Host]) -> Host:
    """The single wisp service host (`hostname == "wisp"`).

    Matching on hostname (not machine_name) keeps this selecting the real
    service host even when a `wisp.wifi` mirror host (same machine_name
    "wisp", different hostname) is present in the inventory.

    Fails loud if the host is missing or if more than one host claims the
    "wisp" hostname."""
    matches = [h for h in hosts if h.hostname == "wisp"]
    if not matches:
        raise ValueError("no host with hostname 'wisp' found in inventory")
    if len(matches) > 1:
        machine_names = ", ".join(h.machine_name for h in matches)
        raise ValueError(
            f"multiple hosts with hostname 'wisp' found: {machine_names}"
        )
    return matches[0]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{wisp-<id>: sha256(secret+<id>)}` for the wisp host. Fails loud on a
    weak secret or a missing/duplicate wisp host."""
    require_strong_secret(secret)
    wisp = select_wisp(hosts)
    check_collisions([wisp])
    return {username(PREFIX, wisp): password(secret, wisp)}
