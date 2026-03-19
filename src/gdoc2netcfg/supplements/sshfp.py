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


class SSHKeyscanError(Exception):
    """Error during SSH host key scanning."""


# ssh-keyscan commands to try, in order: (command_args, subprocess_timeout).
# The standard ssh-keyscan tries all modern key types.
# The fallback uses legacy kex algorithms (patched OpenSSH 9.8p1), requests
# only rsa/dsa key types that old daemons support, and allows extra time
# (-T 20) for slow BMCs doing group14 DH math.
_KEYSCAN_COMMANDS: list[tuple[list[str], int]] = [
    (["ssh-keyscan"], 10),
    (
        ["/usr/local/bin/insecure-ssh-keyscan", "-T", "20", "-t", "rsa,dsa"],
        30,  # subprocess timeout must exceed ssh-keyscan's -T 20
    ),
]


def _run_keyscan(
    cmd_args: list[str], ip: str, timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run a single ssh-keyscan command and return the result.

    Raises SSHKeyscanError on timeout.
    """
    try:
        return subprocess.run(
            [*cmd_args, ip],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise SSHKeyscanError(
            f"{cmd_args[0]} {ip} timed out after {timeout} seconds"
        ) from e


def _parse_keyscan_output(
    result: subprocess.CompletedProcess[str],
    ip: str,
    hostname: str,
    binary: str,
) -> list[str]:
    """Parse ssh-keyscan output into hostname-substituted key lines.

    Raises SSHKeyscanError if the output is empty or malformed.

    Non-zero exit codes are accepted when valid key lines are present in
    stdout, because ssh-keyscan exits non-zero when *some* key types fail
    to negotiate (expected for legacy servers that only support rsa/dsa).
    """
    lines = []
    for line in result.stdout.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(None, 2)
        if len(parts) != 3:
            raise SSHKeyscanError(
                f"Malformed {binary} output line for {ip}: {line!r}"
            )
        # Replace the IP field with hostname; use split/rejoin rather
        # than str.replace to avoid matching the IP inside the key blob.
        lines.append(f"{hostname} {parts[1]} {parts[2]}")

    if not lines:
        if result.returncode != 0:
            raise SSHKeyscanError(
                f"{binary} {ip} exited with code {result.returncode}"
                f" (stderr: {result.stderr.strip()!r})"
            )
        raise SSHKeyscanError(
            f"{binary} {ip} exited successfully but returned no key"
            f" lines (stdout had {len(result.stdout)} bytes,"
            f" stderr: {result.stderr.strip()!r})"
        )

    lines.sort()
    return lines


def _keyscan_pubkeys(ip: str, hostname: str) -> list[str]:
    """Run ssh-keyscan and return public key lines with hostname substituted.

    Returns lines like "hostname ssh-ed25519 AAAA..."

    Tries each command in _KEYSCAN_COMMANDS in order. If a command fails
    (no keys, timeout, binary not found), the next is tried. If all
    commands fail, raises SSHKeyscanError with details from each attempt.
    """
    attempts: list[str] = []

    for cmd_args, timeout in _KEYSCAN_COMMANDS:
        try:
            result = _run_keyscan(cmd_args, ip, timeout)
            return _parse_keyscan_output(result, ip, hostname, cmd_args[0])
        except SSHKeyscanError as e:
            attempts.append(f"{cmd_args[0]}: {e}")
        except FileNotFoundError:
            attempts.append(f"{cmd_args[0]}: not found")

    raise SSHKeyscanError(
        f"All ssh-keyscan binaries failed for {ip}:\n"
        + "\n".join(f"  - {a}" for a in attempts)
    )


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

    For hosts with multiple IPs, scans each IP independently and verifies
    all IPs return identical keys. Different keys from different IPs
    indicates a serious misconfiguration and raises an error.

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

    Raises:
        SSHKeyscanError: If any host with an open SSH port fails to
            return keys, or if different IPs for the same host return
            different keys.
    """
    import sys

    host_keys = load_ssh_host_keys_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(
                    f"ssh_host_keys.json last updated {age:.0f}s ago,"
                    f" using cache.",
                    file=sys.stderr,
                )
            return host_keys

    sorted_hosts = sorted(
        hosts, key=lambda h: h.hostname.split(".")[::-1],
    )
    name_width = max(
        (len(h.hostname) for h in sorted_hosts), default=0,
    )

    errors: list[str] = []

    for host in sorted_hosts:
        # Skip hosts not in reachability data or not reachable
        host_reach = reachability.get(host.hostname)
        if host_reach is None or not host_reach.is_up:
            continue
        active_ips = list(host_reach.active_ips)

        if verbose:
            print(
                f"  {host.hostname:>{name_width}s}"
                f" up({','.join(active_ips)}) ",
                end="", flush=True, file=sys.stderr,
            )

        # Check SSH availability on all reachable IPs
        ssh_ips = [
            ip for ip in active_ips if check_port_open(ip, 22)
        ]

        if not ssh_ips:
            if verbose:
                print("no-ssh", file=sys.stderr)
            continue

        if verbose:
            print(
                f"with-ssh({','.join(ssh_ips)})", file=sys.stderr,
            )

        # Scan each IP independently so we can verify consistency
        per_ip_keys: dict[str, list[str]] = {}
        for ssh_ip in ssh_ips:
            try:
                per_ip_keys[ssh_ip] = _keyscan_pubkeys(
                    ssh_ip, host.hostname,
                )
            except SSHKeyscanError as e:
                errors.append(f"{host.hostname} ({ssh_ip}): {e}")
                continue

        if not per_ip_keys:
            # All IPs failed — errors already collected above
            continue

        if len(per_ip_keys) < len(ssh_ips):
            # Some IPs succeeded but others failed — don't store
            # partial results. The errors are already collected.
            continue

        # Verify all IPs returned identical keys
        key_sets = {
            ip: frozenset(keys)
            for ip, keys in per_ip_keys.items()
        }
        unique_sets = set(key_sets.values())
        if len(unique_sets) > 1:
            detail_lines = []
            for ip, keys in sorted(per_ip_keys.items()):
                detail_lines.append(f"  {ip}:")
                for k in keys:
                    detail_lines.append(f"    {k}")
            errors.append(
                f"{host.hostname}: different SSH keys from different"
                f" IPs:\n" + "\n".join(detail_lines)
            )
            continue

        # All IPs agree — use the canonical sorted list
        host_keys[host.hostname] = sorted(
            next(iter(per_ip_keys.values())),
        )

    if errors:
        raise SSHKeyscanError(
            f"{len(errors)} SSH host key scan error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

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
