"""Gale puck identity generator for the wisp netboot infrastructure.

``generate_gwifi_pucks`` produces ``pucks.json``, deployed to
wisp:/etc/gwifi-netboot/pucks.json. Identity only: names, serials, MACs,
fixed IPs. All runtime state (arming, installs, phone-home) is
wisp-internal.

Puck identity is now sourced from ordinary WiFi-sheet hosts (two
interfaces per puck, named 'wan' and 'lan', sharing one IPv4) rather than
the old bespoke 'Google WiFi Pucks' sheet/parser. ``host.wifi_data``
(attached by ``derivations.wifi_data.enrich_hosts_with_wifi_data`` from the
sheet's '#'/'Serial' extra columns) identifies which hosts are pucks.

The output is deterministic (sorted by puck number, no timestamps) so
deploys are idempotent and diffs are clean.

See gwifi-openwrt docs/wisp-netboot-install-design.md (sections 5.3, D7).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import NetworkInventory

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host


def generate_gwifi_pucks(inventory: NetworkInventory) -> str:
    """Generate the pucks.json identity file for wisp's gwifi-netboot.

    Iterates hosts carrying ``wifi_data`` (attached by
    ``enrich_hosts_with_wifi_data``), sorted by puck number. Each puck host
    must have exactly one interface named 'wan' and one named 'lan' — a
    missing interface raises ``ValueError`` naming the host.
    """
    pucks = sorted(
        (h for h in inventory.hosts if h.wifi_data is not None),
        key=lambda h: h.wifi_data.number,
    )
    if not pucks:
        raise ValueError(
            "no puck hosts found — refusing to generate an empty pucks.json "
            "(check the 'wifi' sheet source is configured and fetched, and "
            "that its '#'/'Serial' columns weren't renamed/removed)"
        )
    doc = {
        "version": 1,
        "generated_by": "gdoc2netcfg",
        "pucks": [_puck_entry(host) for host in pucks],
    }
    return json.dumps(doc, indent=2) + "\n"


def _puck_entry(host: Host) -> dict[str, object]:
    """Build one pucks.json entry from a puck host's wan/lan interfaces."""
    by_name = host.interface_by_name
    wan = by_name.get("wan")
    lan = by_name.get("lan")
    if wan is None or lan is None:
        missing = "wan" if wan is None else "lan"
        raise ValueError(
            f"{host.hostname}: puck host missing '{missing}' interface "
            "(pucks.json requires both wan and lan)"
        )
    try:
        wan_ipv4 = wan.ipv4
    except ValueError as e:
        raise ValueError(
            f"{host.hostname}: puck host 'wan' interface has no IPv4 address"
        ) from e
    return {
        "name": host.machine_name,
        "number": host.wifi_data.number,
        "serial": host.wifi_data.serial,
        "eth0": str(wan.mac).upper(),
        "eth1": str(lan.mac).upper(),
        "ip": str(wan_ipv4),
    }
