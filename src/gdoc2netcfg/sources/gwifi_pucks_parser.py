"""Google WiFi Pucks CSV parser.

Parses the "Google WiFi Pucks" sheet tab into PuckRecord entries for the
gale-puck netboot-install infrastructure (wisp.welland.mithis.com). Only
rows destined for OpenWrt (Firmware == "OpenWRT") with a serial and a MAC
are included — stock "Google Original" pucks must never be known to the
netboot DHCP server.

See gwifi-openwrt docs/wisp-netboot-install-design.md (sections 5.3, D7).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass

# Pucks get deterministic fixed IPs: 10.1.4.<GWIFI_IP_BASE + number>.
GWIFI_SUBNET_PREFIX = "10.1.4"
GWIFI_IP_BASE = 100


@dataclass(frozen=True)
class PuckRecord:
    """One gale puck destined for OpenWrt netboot-install.

    Attributes:
        number: Sheet '#' column (allocator for name and IP)
        name: puck<NN> (zero-padded to 2)
        serial: Device serial number (e.g. '2831HW00VZA')
        eth0: WAN/label MAC, colon-separated uppercase
        eth1: LAN MAC, colon-separated uppercase (derived eth0+1 if absent)
        ip: Fixed IPv4 (10.1.4.<100+number>)
    """

    number: int
    name: str
    serial: str
    eth0: str
    eth1: str
    ip: str


def _normalize_mac(mac: str) -> str:
    return mac.strip().upper()


def _mac_plus_one(mac: str) -> str:
    """Increment the last octet of a MAC (the gale eth0->eth1 pattern).

    The fleet-verified pattern never carries across octets; a wrap of the
    last octet would produce a MAC outside the device's allocation.
    """
    parts = mac.split(":")
    last = int(parts[-1], 16) + 1
    if last > 0xFF:
        raise ValueError(f"eth1 derivation would wrap last octet of {mac}")
    return ":".join(parts[:-1] + [f"{last:02X}"])


def parse_gwifi_pucks(csv_text: str) -> list[PuckRecord]:
    """Parse the Google WiFi Pucks CSV into PuckRecord entries.

    Expected columns (header row): #, Model, Firmware, Serial, MAC, ...,
    eth0, eth1, ... Rows are included only when Firmware == 'OpenWRT' and
    both Serial and MAC are non-empty.

    Raises:
        ValueError: on duplicate puck numbers, duplicate serials, numbers
            outside 1..99, or eth1 derivation wrap.
    """
    lines = csv_text.splitlines()
    if not lines:
        return []

    reader = csv.DictReader(lines)
    records: list[PuckRecord] = []
    seen_numbers: set[int] = set()
    seen_serials: set[str] = set()

    for row in reader:
        firmware = (row.get("Firmware") or "").strip()
        serial = (row.get("Serial") or "").strip()
        mac = (row.get("MAC") or "").strip()
        if firmware != "OpenWRT" or not serial or not mac:
            continue

        number = int((row.get("#") or "").strip())
        if not 1 <= number <= 99:
            raise ValueError(
                f"puck number {number} outside 1..99 (IP scheme is "
                f"{GWIFI_SUBNET_PREFIX}.{GWIFI_IP_BASE}+NN)")
        if number in seen_numbers:
            raise ValueError(f"duplicate puck number {number}")
        seen_numbers.add(number)
        if serial in seen_serials:
            raise ValueError(f"duplicate serial {serial}")
        seen_serials.add(serial)

        eth0 = _normalize_mac((row.get("eth0") or "").strip() or mac)
        eth1_raw = (row.get("eth1") or "").strip()
        eth1 = _normalize_mac(eth1_raw) if eth1_raw else _mac_plus_one(eth0)

        records.append(PuckRecord(
            number=number,
            name=f"puck{number:02d}",
            serial=serial,
            eth0=eth0,
            eth1=eth1,
            ip=f"{GWIFI_SUBNET_PREFIX}.{GWIFI_IP_BASE + number}",
        ))

    return records
