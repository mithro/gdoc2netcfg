"""IPv6 capability detection for network hosts.

Determines whether a host supports IPv6 based on MAC OUI prefix matching
and hardware column regex patterns. Hosts using Espressif/ITEAD chipsets
(ESP8266, ESP32-C3 running Tasmota) typically lack IPv6 support.

Used by the pipeline to:
- Skip IPv6 in DHCP bindings for incapable devices
- Generate TAYGA NAT64 mappings so IPv6 clients can still reach them
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

# IEEE OUI prefixes for Espressif Systems (ESP8266, ESP32, ESP32-C3, etc.)
# and ITEAD (Sonoff devices using Espressif chips).
# Source: https://maclookup.app/vendors/espressif-inc
ESPRESSIF_OUIS: set[str] = {
    "5c:cf:7f",   # Espressif (ESP8266)
    "c4:dd:57",   # Espressif (ESP32-C3)
    "70:03:9f",   # Espressif
    "84:0d:8e",   # Espressif
    "dc:4f:22",   # Espressif / ITEAD (Sonoff)
    "34:98:7a",   # Espressif (Athom IR remotes)
    "e8:db:84",   # Espressif
    "7c:2c:67",   # Espressif (Athom plugs — ESP32-C3)
    "24:ec:4a",   # Espressif (Athom plugs)
    "a4:f0:0f",   # Espressif (ESP32-CAM)
    "e0:8c:fe",   # Espressif (ESP32-CAM)
    "c4:4f:33",   # ITEAD (Sonoff RFBridge, Sonoff SC)
    "88:12:ac",   # Espressif (NSPanel)
}


def _mac_oui(mac_address: str) -> str:
    """Extract the OUI prefix (first 3 octets) from a MAC address."""
    return mac_address[:8].lower()


def detect_ipv6_capability(
    host: Host,
    *,
    hardware_patterns: list[str] | None = None,
    extra_ouis: set[str] | None = None,
) -> bool:
    """Determine whether a host supports IPv6.

    Returns False (incapable) if ANY of:
    - Any interface MAC OUI matches the Espressif/ITEAD set or extra_ouis
    - The 'Hardware' extra field matches any of the hardware_patterns regexes

    Returns True (capable) otherwise.

    Args:
        host: The host to check.
        hardware_patterns: Regex patterns to match against host.extra["Hardware"].
            If None, no hardware pattern matching is performed.
        extra_ouis: Additional OUI prefixes to treat as IPv6-incapable,
            beyond the built-in Espressif set.
    """
    # Check MAC OUI
    all_incapable_ouis = ESPRESSIF_OUIS
    if extra_ouis:
        all_incapable_ouis = ESPRESSIF_OUIS | {oui.lower() for oui in extra_ouis}

    host_ouis = {_mac_oui(str(mac)) for mac in host.all_macs}
    if host_ouis & all_incapable_ouis:
        return False

    # Check hardware column patterns
    if hardware_patterns:
        hardware_value = host.extra.get("Hardware", "")
        if hardware_value:
            for pattern in hardware_patterns:
                if re.search(pattern, hardware_value, re.IGNORECASE):
                    return False

    return True
