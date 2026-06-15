"""Pure, deterministic MQTT credential derivation (consumer-agnostic).

Given a per-consumer secret and a host, derives a stable broker
`(username, password)`:  username = f"{prefix}{<id>}",  password =
sha256(secret + <id>) hex, where <id> = node_id(host.hostname). This is a
deterministic KDF (recomputable by Ansible), not a salted password hash.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from gdoc2netcfg.utils.mqtt import node_id

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

# Reject empty / trivially-short secrets; recommend `openssl rand -hex 32`.
_MIN_SECRET_LEN = 32


def credential_key(host: Host) -> str:
    """The canonical per-host key `<id>` — node_id of the unique hostname."""
    return node_id(host.hostname)


def username(prefix: str, host: Host) -> str:
    """`{prefix}{<id>}`, e.g. `s2m-rpi5_iot` / `tas-au_plug_1_iot`."""
    return f"{prefix}{credential_key(host)}"


def password(secret: str, host: Host) -> str:
    """`sha256(secret + <id>)` as 64-char lowercase hex."""
    return hashlib.sha256((secret + credential_key(host)).encode()).hexdigest()


def check_collisions(hosts: list[Host]) -> None:
    """Fail loud if two distinct hosts map to the same `<id>` (node_id is
    not injective)."""
    seen: dict[str, str] = {}
    for host in hosts:
        key = credential_key(host)
        if key in seen and seen[key] != host.hostname:
            raise ValueError(
                f"node_id credentials collide: '{seen[key]}' and '{host.hostname}' "
                f"both map to '{key}'"
            )
        seen[key] = host.hostname


def require_strong_secret(secret: str) -> None:
    """Fail loud on an empty / trivially-short secret (the scheme's security
    rests entirely on the secret's entropy)."""
    if len(secret) < _MIN_SECRET_LEN:
        raise ValueError(
            f"mqtt_secret must be high-entropy (>= {_MIN_SECRET_LEN} chars; "
            "recommend `openssl rand -hex 32`)"
        )
