"""IPv4 → IPv6 address generation.

Mapping scheme: 10.AA.BB.CCC → {prefix}AABB::CCC
- AA: second octet, no padding (1-99)
- BB: third octet, zero-padded to 2 digits (01-99)
- CCC: fourth octet, no padding (1-256)

Example: 10.1.10.124 → 2404:e80:a137:110::124
Example: 10.12.80.240 → 2404:e80:a137:1280::240
"""

from __future__ import annotations

from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address
from gdoc2netcfg.models.network import IPv6Prefix


def ipv4_to_ipv6(ipv4: IPv4Address, prefix: IPv6Prefix) -> IPv6Address | None:
    """Convert an IPv4 address to an IPv6 address using the given prefix.

    Returns None if the IPv4 address is not in the 10.0.0.0/8 range
    (only 10.x.x.x addresses have a defined IPv6 mapping).
    """
    octets = ipv4.octets
    if octets[0] != 10:
        return None

    aa = str(octets[1])       # No padding
    bb = str(octets[2]).zfill(2)  # Zero-pad to 2 digits
    ccc = str(octets[3])      # No padding

    # The vanity mapping writes decimal digits literally as hex nibbles;
    # a hextet holds at most 4. 10.1.110.x → '1'+'110' = 1110 fits, but
    # 10.255.0.x (legacy wg endpoints) → '255'+'00' = 5 digits does not:
    # no v6 mapping for those.
    if len(aa + bb) > 4:
        return None

    address = f"{prefix.prefix}{aa}{bb}::{ccc}"
    return IPv6Address(address=address, prefix=prefix.prefix)


def ipv4_to_ipv6_list(
    ipv4: IPv4Address,
    prefixes: list[IPv6Prefix],
) -> list[IPv6Address]:
    """Convert an IPv4 address to IPv6 addresses for all active prefixes.

    Returns empty list if the IPv4 is not mappable (not in 10.0.0.0/8).
    Only uses enabled prefixes.
    """
    results = []
    for prefix in prefixes:
        if not prefix.enabled:
            continue
        addr = ipv4_to_ipv6(ipv4, prefix)
        if addr is not None:
            results.append(addr)
    return results
