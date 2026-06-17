"""Device lookup utilities for finding hosts by hostname, IP, or MAC.

Provides query-type detection, multi-strategy host matching, and
credential field extraction from Host.extra.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from gdoc2netcfg.models.addressing import MACAddress

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host


# --- Query type detection ---------------------------------------------------

# MAC patterns: colon-separated, dash-separated, dot-separated
_MAC_COLON_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
_MAC_DASH_RE = re.compile(r'^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$')
_MAC_DOT_RE = re.compile(r'^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$')

# IPv4 pattern: four dotted decimal octets
_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def detect_query_type(query: str) -> str:
    """Classify a lookup query as 'mac', 'ip', or 'hostname'.

    >>> detect_query_type('aa:bb:cc:dd:ee:ff')
    'mac'
    >>> detect_query_type('10.1.10.1')
    'ip'
    >>> detect_query_type('switch1')
    'hostname'
    """
    q = query.strip()
    if _MAC_COLON_RE.match(q) or _MAC_DASH_RE.match(q) or _MAC_DOT_RE.match(q):
        return "mac"
    if _IPV4_RE.match(q):
        # Validate octets are in 0-255 range
        octets = q.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return "ip"
    return "hostname"


# --- Lookup result ----------------------------------------------------------

@dataclass(frozen=True)
class LookupResult:
    """A host matched by a lookup query.

    Attributes:
        host: The matched Host object.
        match_type: How it was matched — 'exact' (hostname, IP, or MAC) or
            'wildcard' (IP second-octet fallback only).
        match_detail: Human-readable description of what matched.
    """

    host: Host
    match_type: str
    match_detail: str


# --- Matchers ---------------------------------------------------------------

def _match_by_hostname(
    query: str, hosts: list[Host],
) -> list[LookupResult]:
    """Match hosts by exact hostname (case-insensitive).

    Only an exact hostname match counts — no machine_name, prefix, or
    substring matching. Production hostnames are the short compute_hostname
    form (e.g. 'desktop', 'bmc.big-storage', 'au-plug-1.iot'), so a BMC is
    reached by its full 'bmc.<machine>' hostname and an IoT device by its
    '.iot' hostname.
    """
    q = query.lower()
    return [
        LookupResult(
            host=host, match_type="exact",
            match_detail=f"hostname '{host.hostname}'",
        )
        for host in hosts
        if host.hostname.lower() == q
    ]


def _match_by_ip(query: str, hosts: list[Host]) -> list[LookupResult]:
    """Match hosts by IPv4 address.

    Priority order:
    1. Exact match on any interface IPv4
    2. Wildcard second-octet: compare octets 1, 3, 4 only
       (handles 10.X.Y.Z site placeholder pattern)

    Returns results ordered by match quality.
    """
    q_parts = query.split(".")
    exact: list[LookupResult] = []
    wildcard: list[LookupResult] = []

    for host in hosts:
        for iface in host.interfaces:
            ip_str = str(iface.ipv4)
            if query == ip_str:
                exact.append(LookupResult(
                    host=host, match_type="exact",
                    match_detail=f"IP {ip_str} on interface "
                                 f"{iface.name or 'default'}",
                ))
                break  # One match per host for exact
            else:
                ip_parts = ip_str.split(".")
                if (len(q_parts) == 4 and len(ip_parts) == 4
                        and q_parts[0] == ip_parts[0]
                        and q_parts[2] == ip_parts[2]
                        and q_parts[3] == ip_parts[3]
                        and q_parts[1] != ip_parts[1]):
                    wildcard.append(LookupResult(
                        host=host, match_type="wildcard",
                        match_detail=f"IP {ip_str} (second-octet wildcard "
                                     f"match for {query})",
                    ))
                    break  # One match per host for wildcard

    return exact + wildcard


def _match_by_mac(query: str, hosts: list[Host]) -> list[LookupResult]:
    """Match hosts by MAC address.

    Normalizes the query via MACAddress.parse() and compares against
    all MACs on each host.

    Raises ValueError if the query is not a valid MAC address.
    """
    query_mac = MACAddress.parse(query)
    results: list[LookupResult] = []

    for host in hosts:
        for mac in host.all_macs:
            if mac == query_mac:
                results.append(LookupResult(
                    host=host, match_type="exact",
                    match_detail=f"MAC {mac}",
                ))
                break  # One match per host

    return results


# --- Main lookup entry point ------------------------------------------------

def lookup_host(
    query: str, hosts: list[Host],
) -> list[LookupResult]:
    """Look up hosts matching a query string.

    Detects whether the query is a MAC, IP, or hostname, then dispatches
    to the appropriate matcher. Returns results ordered by match quality.
    """
    qtype = detect_query_type(query)

    if qtype == "mac":
        return _match_by_mac(query, hosts)
    elif qtype == "ip":
        return _match_by_ip(query, hosts)
    else:
        return _match_by_hostname(query, hosts)


# --- Suggestions for "did you mean?" ---------------------------------------

def suggest_matches(
    query: str, hosts: list[Host], max_suggestions: int = 5,
) -> list[str]:
    """Suggest close matches for a failed query using fuzzy matching.

    Compares against all hostnames, machine_names, MACs, and IPs.
    Returns up to max_suggestions suggestions.
    """
    candidates: list[str] = []
    for host in hosts:
        candidates.append(host.hostname)
        if host.machine_name != host.hostname:
            candidates.append(host.machine_name)
        for mac in host.all_macs:
            candidates.append(str(mac))
        for iface in host.interfaces:
            candidates.append(str(iface.ipv4))

    return difflib.get_close_matches(
        query, candidates, n=max_suggestions, cutoff=0.4,
    )


# --- Credential field extraction --------------------------------------------

CREDENTIAL_TYPES: dict[str, list[str]] = {
    "password": ["Password"],
    "snmp": ["SNMP Community"],
    "ipmi": ["IPMI Username", "IPMI Password"],
}


def get_credential_fields(
    host: Host,
    credential_type: str | None = None,
    field_name: str | None = None,
) -> dict[str, str]:
    """Extract credential fields from a host's extra data.

    Args:
        host: The host to extract credentials from.
        credential_type: One of 'password', 'snmp', 'ipmi' (uses
            CREDENTIAL_TYPES mapping).
        field_name: An arbitrary extra column name (mutually exclusive
            with credential_type).

    Returns:
        Dict mapping field names to their values. Empty dict if the
        requested fields are not present or are blank.

    Raises:
        ValueError: If credential_type is not a recognized type.
    """
    if field_name is not None:
        value = host.extra.get(field_name, "")
        if value:
            return {field_name: value}
        return {}

    if credential_type is not None:
        if credential_type not in CREDENTIAL_TYPES:
            raise ValueError(
                f"Unknown credential type: {credential_type!r}. "
                f"Valid types: {', '.join(sorted(CREDENTIAL_TYPES))}"
            )
        fields = CREDENTIAL_TYPES[credential_type]
    else:
        # Default to password
        fields = CREDENTIAL_TYPES["password"]

    result: dict[str, str] = {}
    for f in fields:
        value = host.extra.get(f, "")
        if value:
            result[f] = value
    return result


def available_credential_fields(host: Host) -> list[str]:
    """List all non-empty extra field keys on a host.

    Useful for error messages when a requested credential is not found.
    """
    return [k for k, v in host.extra.items() if v]
