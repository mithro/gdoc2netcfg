"""wisp service MQTT credential derivation.

Pure. Selects the single wisp service host (`machine_name == "wisp"`, from the
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
    """The single wisp service host (`machine_name == "wisp"`).

    Fails loud if the host is missing or if more than one host claims the
    "wisp" machine name."""
    matches = [h for h in hosts if h.machine_name == "wisp"]
    if not matches:
        raise ValueError("no host with machine_name 'wisp' found in inventory")
    if len(matches) > 1:
        hostnames = ", ".join(h.hostname for h in matches)
        raise ValueError(
            f"multiple hosts with machine_name 'wisp' found: {hostnames}"
        )
    return matches[0]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{wisp-<id>: sha256(secret+<id>)}` for the wisp host. Fails loud on a
    weak secret or a missing/duplicate wisp host."""
    require_strong_secret(secret)
    wisp = select_wisp(hosts)
    check_collisions([wisp])
    return {username(PREFIX, wisp): password(secret, wisp)}
