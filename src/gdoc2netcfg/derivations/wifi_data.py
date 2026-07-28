"""wifi-device identity derivation from WiFi-sheet extra columns.

Pure. Reads the `#` (puck number) and `Serial` extra columns that WiFi-sheet
rows carry for netboot-managed devices (both interface rows carry identical
values via sheet formulas) and attaches a typed `WifiData` to the host.
OpenMesh hosts on the same sheet carry neither column and are left
with `wifi_data is None`. Fails loud on partial data, malformed numbers,
machine-name mismatches, and cross-host duplicates -- these all indicate a
sheet data-entry error.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import WifiData

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host


def enrich_hosts_with_wifi_data(hosts: list[Host]) -> None:
    """Attach WifiData to WiFi-sheet hosts carrying '#' + 'Serial' extras.

    Both interface rows of a puck carry the same values (sheet formulas), so
    equal duplicates within one host are fine. Raises ValueError on partial
    data, malformed numbers, name mismatch, or cross-host duplicates.
    """
    seen_numbers: dict[int, str] = {}
    seen_serials: dict[str, str] = {}
    for host in hosts:
        if host.sheet_type != "WiFi":
            continue
        raw_num = host.extra.get("#", "").strip()
        serial = host.extra.get("Serial", "").strip()
        if not raw_num and not serial:
            continue  # OpenMesh etc. -- not a puck row
        if not raw_num or not serial:
            raise ValueError(
                f"{host.hostname}: partial puck data (need both # and Serial)"
            )
        try:
            number = int(raw_num)
        except ValueError as e:
            raise ValueError(
                f"{host.hostname}: non-integer puck number {raw_num!r} in '#' column"
            ) from e
        if not 1 <= number <= 99:
            raise ValueError(f"{host.hostname}: puck number {number} outside 1..99")
        expected = f"puck{number:02d}"
        if host.machine_name != expected:
            raise ValueError(
                f"{host.hostname}: machine {host.machine_name!r} != {expected!r} from #"
            )
        if number in seen_numbers:
            raise ValueError(
                f"{host.hostname}: duplicate puck number {number} "
                f"(already used by {seen_numbers[number]!r})"
            )
        if serial in seen_serials:
            raise ValueError(
                f"{host.hostname}: duplicate puck serial {serial!r} "
                f"(already used by {seen_serials[serial]!r})"
            )
        seen_numbers[number] = host.hostname
        seen_serials[serial] = host.hostname
        host.wifi_data = WifiData(number=number, serial=serial)
