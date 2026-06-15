"""sensors2mqtt host selection (Network sheet `Sensors` column) + broker login
building.

Pure. Reads the `Sensors` column from `host.extra` (local/remote/blank) and
builds the `{s2m-<id>: password}` map for `register`, reusing the shared
credential core.
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

PREFIX = "s2m-"
_COLUMN = "Sensors"
_VALID = {"local", "remote", ""}


def classify(host: Host) -> str:
    """Return 'local' / 'remote' / 'blank' for a host's `Sensors` column value.

    Fails loud on an unrecognized non-blank value (never silently skipped)."""
    value = host.extra.get(_COLUMN, "").strip().lower()
    if value not in _VALID:
        raise ValueError(
            f"host {host.hostname}: unrecognized Sensors value "
            f"{value!r} (expected 'local', 'remote', or blank)"
        )
    return "blank" if value == "" else value


def select_local(hosts: list[Host]) -> list[Host]:
    """Hosts running sensors2mqtt locally (get a broker login)."""
    return [h for h in hosts if classify(h) == "local"]


def select_non_blank(hosts: list[Host]) -> list[Host]:
    """Hosts involved with sensors2mqtt at all (checked by `status`)."""
    return [h for h in hosts if classify(h) != "blank"]


def build_logins(secret: str, hosts: list[Host]) -> dict[str, str]:
    """`{s2m-<id>: sha256(secret+<id>)}` for the `local` hosts. Fails loud on a
    weak secret or a node_id collision among the selected hosts."""
    require_strong_secret(secret)
    local = select_local(hosts)
    check_collisions(local)
    return {username(PREFIX, h): password(secret, h) for h in local}
