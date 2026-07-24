"""Gale puck identity generator for the wisp netboot infrastructure.

``generate_gwifi_pucks`` produces ``pucks.json``, deployed to
wisp:/etc/gwifi-netboot/pucks.json. Identity only: names, serials, MACs,
fixed IPs. All runtime state (arming, installs, phone-home) is
wisp-internal.

Puck identity is now sourced from ordinary WiFi-sheet hosts (two
interfaces per puck, named 'wan' and 'lan', sharing one IPv4) rather than
the old bespoke 'Google WiFi Pucks' sheet/parser. ``host.puck_data``
(attached by ``derivations.puck_data.enrich_hosts_with_puck_data`` from the
sheet's '#'/'Serial' extra columns) identifies which hosts are pucks.

The output is deterministic (sorted by puck number, no timestamps) so
deploys are idempotent and diffs are clean.

See gwifi-openwrt docs/wisp-netboot-install-design.md (sections 5.3, D7).
"""

from __future__ import annotations

import json

from gdoc2netcfg.models.host import NetworkInventory


def generate_gwifi_pucks(inventory: NetworkInventory) -> str:
    """Generate the pucks.json identity file for wisp's gwifi-netboot.

    Iterates hosts carrying ``puck_data`` (attached by
    ``enrich_hosts_with_puck_data``), sorted by puck number. Each puck host
    must have exactly one interface named 'wan' and one named 'lan' — a
    missing interface raises ``ValueError`` naming the host.
    """
    pucks = sorted(
        (h for h in inventory.hosts if h.puck_data),
        key=lambda h: h.puck_data.number,
    )
    doc = {
        "version": 1,
        "generated_by": "gdoc2netcfg",
        "pucks": [_puck_entry(host) for host in pucks],
    }
    return json.dumps(doc, indent=2) + "\n"


def _puck_entry(host) -> dict:
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
    return {
        "name": host.machine_name,
        "number": host.puck_data.number,
        "serial": host.puck_data.serial,
        "eth0": str(wan.mac).upper(),
        "eth1": str(lan.mac).upper(),
        "ip": str(wan.ipv4),
    }
