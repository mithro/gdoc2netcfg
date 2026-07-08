"""IP → VLAN derivation and VLAN builder.

Determines VLAN assignment based on IP address subnet.
Also provides builder functions to convert VLANDefinition records
(from the VLAN Allocations sheet) into VLAN model objects.
"""

from __future__ import annotations

import ipaddress

from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import VLAN, Site
from gdoc2netcfg.sources.vlan_parser import VLANDefinition


def ip_to_vlan_id(ipv4: IPv4Address, site: Site) -> int | None:
    """Determine the VLAN ID for an IPv4 address.

    Uses the site's VLAN definitions to match:
    1. Global VLANs: second octet matches a global VLAN's ID (e.g. 10.31.X.X → VLAN 31)
    2. Transit VLANs: (second_octet, third_octet) matches transit_match
       (e.g. 10.99.21.X → VLAN 121)
    3. Site VLANs: second octet matches site_octet, third octet falls within
       a VLAN's covered_third_octets (e.g. 10.1.10.X → VLAN 10 for site_octet=1)

    Returns None if the IP doesn't map to a known VLAN.
    """
    a, b, c, d = ipv4.octets

    if a != 10:
        return None

    # Check global VLANs first (match on second octet)
    for vlan in site.vlans.values():
        if vlan.is_global and b == vlan.id:
            return vlan.id

    # Check transit VLANs (match on second + third octet pair)
    for vlan in site.vlans.values():
        if vlan.is_transit and vlan.transit_match:
            match_b, match_c = vlan.transit_match
            if b == match_b and c == match_c:
                return vlan.id

    # Check site-local VLANs (second octet must match site_octet)
    if b != site.site_octet:
        return None

    for vlan in site.vlans.values():
        if not vlan.is_global and not vlan.is_transit and c in vlan.covered_third_octets:
            return vlan.id

    return None


# Third octets holding parked/junk addresses in the site range (ten64's
# unused NICs at 10.X.253/254): interfaces there produce no DNS records
# at all (dns-redesign design §3 removed families). Deliberately narrow —
# other unmapped site-octet subnets (10.1.16 100G, 10.1.21, 10.1.110)
# are real hosts that keep site-scoped records.
PARKED_THIRD_OCTETS = frozenset({253, 254})

# Nets whose DNS zones are delegated to another server entirely (design
# §4: fpgas → tweed's dnsmasq). Their hosts/interfaces get no centrally
# generated records or projections.
# TODO(sheet): drive from a VLAN-Allocations column if one appears.
DELEGATED_NETS = frozenset({"fpgas"})


def ip_to_net(ipv4: IPv4Address, site: Site) -> str | None:
    """Determine the NET (per-network DNS zone label) for ANY IPv4 address.

    The net label names the child zone {net}.{site.domain} that owns the
    address (dns-redesign design §3/§4). Coverage, in order:

    1. Site-octet networks (10.{site_octet}.C.x): third octet → subdomain
       via site.network_subdomains (int, iot, store, ...).
    2. Global VLANs (e.g. 10.41.x.x → 'sm'): second octet == VLAN id.
    3. Transit VLANs (e.g. 10.99.21.x → 'tfpgas'): (second, third) octet
       pair == transit_match.
    4. WireGuard tunnels: 10.98.x.x plus the legacy 10.255.x.x endpoints
       map to 'wg' (the tunnels aren't VLANs, so this is code-level policy;
       TODO(sheet): move to a VLAN-Allocations-style row if one appears).

    Returns None when the address has no net home: parked site-octet
    addresses (no such network — e.g. ten64's 10.1.253/254 NICs, which
    produce no DNS records at all), and non-10/8 addresses (public WAN,
    tailscale CGNAT).
    """
    a, b, c, d = ipv4.octets
    if a != 10:
        return None

    if b == site.site_octet:
        return site.network_subdomains.get(c)

    if b in (98, 255):
        return "wg"

    for vlan in site.vlans.values():
        if vlan.is_global and b == vlan.id:
            return vlan.subdomain
        if vlan.is_transit and vlan.transit_match == (b, c):
            return vlan.subdomain

    return None


def ip_to_subdomain(ipv4: IPv4Address, site: Site) -> str | None:
    """Get the network subdomain for an IP address.

    Uses the site's network_subdomains mapping (third octet → subdomain).
    Only applies to addresses in the site's address space (10.{site_octet}.X.Y).

    Returns None if no subdomain mapping exists.
    """
    a, b, c, d = ipv4.octets
    if a != 10 or b != site.site_octet:
        return None
    return site.network_subdomains.get(c)


# ---------------------------------------------------------------------------
# VLAN builder: VLANDefinition → VLAN model objects
# ---------------------------------------------------------------------------

def _compute_third_octets(ip_range: str, cidr: str, site_octet: int) -> tuple[int, ...]:
    """Compute which third-octet values a VLAN covers from its IP range and CIDR.

    Uses ipaddress.ip_network to determine the full range. For example,
    IP range '10.1.10.X' with CIDR '/21' gives network 10.1.8.0/21,
    which covers third octets 8-15.

    For /24 ranges, returns a single-element tuple with the third octet.
    """
    # Build a concrete network address from the IP range pattern
    # Replace 'X' placeholders with '0' to form a valid address
    base_ip = ip_range.replace("X", "0")
    prefix_len = cidr.lstrip("/")
    try:
        network = ipaddress.ip_network(f"{base_ip}/{prefix_len}", strict=False)
    except ValueError:
        # Fallback: extract third octet from IP range directly
        parts = ip_range.split(".")
        if len(parts) >= 3:
            try:
                return (int(parts[2]),)
            except ValueError:
                pass
        return ()

    # Enumerate all third-octet values the network covers
    first_ip = int(network.network_address)
    last_ip = int(network.broadcast_address)
    first_third = (first_ip >> 8) & 0xFF
    last_third = (last_ip >> 8) & 0xFF
    return tuple(range(first_third, last_third + 1))


def _is_transit_vlan(cidr: str) -> bool:
    """Determine if a VLAN is a point-to-point transit link based on CIDR.

    Transit VLANs use /30 or /31 prefixes (point-to-point links between
    two routers). They are matched by a (second_octet, third_octet) pair
    rather than by second octet alone (global) or site_octet + third octet
    (site-local).
    """
    if not cidr.startswith("/"):
        return False
    try:
        prefix = int(cidr[1:])
        return prefix >= 30
    except ValueError:
        return False


def _parse_transit_match(ip_range: str) -> tuple[int, int] | None:
    """Extract (second_octet, third_octet) from a transit VLAN IP range.

    For example, '10.99.21.X' → (99, 21).
    Returns None if the IP range can't be parsed.
    """
    parts = ip_range.replace("X", "0").split(".")
    if len(parts) >= 3:
        try:
            return (int(parts[1]), int(parts[2]))
        except ValueError:
            pass
    return None


def _is_global_vlan(cidr: str) -> bool:
    """Determine if a VLAN is global based on its CIDR prefix length.

    Args:
        cidr: CIDR suffix including leading slash (e.g. '/16', '/24').

    Global VLANs use /16 or larger prefixes (e.g. 10.31.0.0/16) and are
    addressed by second octet rather than third octet within a site's
    address space.  Site-local VLANs use narrower prefixes (/17 or
    smaller, e.g. /21, /24).

    This makes VLAN classification site-agnostic: the same spreadsheet
    definitions work for any site regardless of which site's IP ranges
    appear in the IP Range column.
    """
    if not cidr.startswith("/"):
        return False
    try:
        prefix = int(cidr[1:])
        return 0 <= prefix <= 16
    except ValueError:
        return False


def build_vlans_from_definitions(
    definitions: list[VLANDefinition],
    site_octet: int,
) -> dict[int, VLAN]:
    """Convert VLANDefinition records into VLAN model objects.

    Computes third_octets from IP Range + CIDR, and detects global VLANs
    by CIDR prefix length (/16 or larger = global).
    """
    vlans: dict[int, VLAN] = {}
    for defn in definitions:
        is_transit = _is_transit_vlan(defn.cidr)
        is_global = not is_transit and _is_global_vlan(defn.cidr)

        if is_global or is_transit:
            third_octets: tuple[int, ...] = ()
        else:
            third_octets = _compute_third_octets(defn.ip_range, defn.cidr, site_octet)

        transit_match = _parse_transit_match(defn.ip_range) if is_transit else None

        vlans[defn.id] = VLAN(
            id=defn.id,
            name=defn.name,
            subdomain=defn.name,
            third_octets=third_octets,
            is_global=is_global,
            is_transit=is_transit,
            transit_match=transit_match,
        )
    return vlans


def build_network_subdomains(vlans: dict[int, VLAN]) -> dict[int, str]:
    """Derive third-octet → subdomain mapping from VLAN definitions.

    For each non-global VLAN, maps all its covered third octets to
    the VLAN's name (used as the subdomain).
    """
    mapping: dict[int, str] = {}
    for vlan in vlans.values():
        if vlan.is_global:
            continue
        for octet in vlan.covered_third_octets:
            mapping[octet] = vlan.name
    return mapping
