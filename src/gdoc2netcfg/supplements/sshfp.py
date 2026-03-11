"""Supplement: SSH host key scanning and SSHFP derivation.

Scans hosts for SSH public keys using ssh-keyscan, caches raw key lines
in ssh_host_keys.json, and derives SSHFP DNS records (RR type 44) from
the cached keys using hashlib. This unified approach supports both the
known_hosts generator and dnsmasq SSHFP dns-rr lines from a single scan.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (SSH daemons).
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
from pathlib import Path

from gdoc2netcfg.models.host import Host
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    check_port_open,
)

# ssh-keyscan key type → SSHFP algorithm number (RFC 4255, RFC 6594, RFC 7479)
_KEY_TYPE_TO_SSHFP_ALGO: dict[str, int] = {
    "ssh-rsa": 1,
    "ssh-dss": 2,
    "ecdsa-sha2-nistp256": 3,
    "ecdsa-sha2-nistp384": 3,
    "ecdsa-sha2-nistp521": 3,
    "ssh-ed25519": 4,
}


def _keyscan_pubkeys(ip: str, hostname: str) -> list[str]:
    """Run ssh-keyscan and return public key lines with hostname substituted.

    Returns lines like "hostname ssh-ed25519 AAAA..."
    """
    try:
        result = subprocess.run(
            ["ssh-keyscan", ip],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = []
        for line in result.stdout.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            lines.append(line.replace(ip, hostname, 1))
        lines.sort()
        return lines
    except subprocess.TimeoutExpired:
        return []


def derive_sshfp_from_host_keys(keys: list[str]) -> list[str]:
    """Derive SSHFP DNS records from raw SSH public key lines.

    Each input line: "hostname key-type base64-key"
    Each output line: "hostname IN SSHFP <algo> <fp_type> <hex_hash>"

    Produces both SHA-1 (fp_type=1) and SHA-256 (fp_type=2) fingerprints
    for each key, matching what ssh-keyscan -D would produce.
    """
    records: list[str] = []

    for key_line in keys:
        parts = key_line.split()
        if len(parts) < 3:
            raise ValueError(
                f"Malformed SSH host key line (expected 'hostname key-type base64-key'): "
                f"{key_line!r}"
            )
        hostname, key_type, b64_key = parts[0], parts[1], parts[2]

        algo = _KEY_TYPE_TO_SSHFP_ALGO.get(key_type)
        if algo is None:
            raise ValueError(
                f"Unknown SSH key type {key_type!r} in host key line for "
                f"{hostname!r} (known types: {sorted(_KEY_TYPE_TO_SSHFP_ALGO)})"
            )

        key_blob = base64.b64decode(b64_key)

        # SHA-1 (fingerprint type 1)
        sha1_hex = hashlib.sha1(key_blob).hexdigest()
        records.append(f"{hostname} IN SSHFP {algo} 1 {sha1_hex}")

        # SHA-256 (fingerprint type 2)
        sha256_hex = hashlib.sha256(key_blob).hexdigest()
        records.append(f"{hostname} IN SSHFP {algo} 2 {sha256_hex}")

    records.sort()
    return records


def load_ssh_host_keys_cache(cache_path: Path) -> dict[str, list[str]]:
    """Load cached SSH host key data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_ssh_host_keys_cache(
    cache_path: Path, data: dict[str, list[str]],
) -> None:
    """Save SSH host key data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_ssh_host_keys(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
    *,
    reachability: dict[str, HostReachability],
) -> dict[str, list[str]]:
    """Scan reachable hosts for SSH public keys.

    Args:
        hosts: Host objects with IPs to scan.
        cache_path: Path to ssh_host_keys.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data from the
            reachability pass. Only reachable hosts are scanned.

    Returns:
        Mapping of hostname → list of SSH public key lines.
    """
    import sys

    host_keys = load_ssh_host_keys_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(
                    f"ssh_host_keys.json last updated {age:.0f}s ago, using cache.",
                    file=sys.stderr,
                )
            return host_keys

    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    for host in sorted_hosts:
        # Skip hosts not in reachability data or not reachable
        host_reach = reachability.get(host.hostname)
        if host_reach is None or not host_reach.is_up:
            continue
        active_ips = list(host_reach.active_ips)

        if verbose:
            print(
                f"  {host.hostname:>{name_width}s} up({','.join(active_ips)}) ",
                end="", flush=True, file=sys.stderr,
            )

        # Check SSH availability on all reachable IPs
        ssh_ips = [ip for ip in active_ips if check_port_open(ip, 22)]

        if not ssh_ips:
            if verbose:
                print("no-ssh", file=sys.stderr)
            continue

        if verbose:
            print(f"with-ssh({','.join(ssh_ips)})", file=sys.stderr)

        # Keyscan all IPs with SSH and merge keys (deduplicated)
        all_keys: set[str] = set()
        for ssh_ip in ssh_ips:
            keys = _keyscan_pubkeys(ssh_ip, host.hostname)
            all_keys.update(keys)

        if all_keys:
            host_keys[host.hostname] = sorted(all_keys)

    save_ssh_host_keys_cache(cache_path, host_keys)
    return host_keys


def enrich_hosts_with_ssh_host_keys(
    hosts: list[Host],
    host_keys_data: dict[str, list[str]],
) -> None:
    """Attach cached SSH host keys and derived SSHFP records to Host objects.

    Modifies hosts in-place by setting host.ssh_host_keys and
    host.sshfp_records (derived from the raw keys).
    """
    for host in hosts:
        keys = host_keys_data.get(host.hostname, [])
        host.ssh_host_keys = keys
        if keys:
            host.sshfp_records = derive_sshfp_from_host_keys(keys)
        else:
            host.sshfp_records = []
