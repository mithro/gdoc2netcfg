"""SSH known_hosts file generator.

Produces an OpenSSH known_hosts file from cached SSH host keys. Each
line lists all DNS names and IP addresses for a host, followed by the
key type and base64 public key. Deployable to /etc/ssh/ssh_known_hosts.
"""

from __future__ import annotations

from gdoc2netcfg.models.host import NetworkInventory


def generate_known_hosts(inventory: NetworkInventory) -> str:
    """Generate an SSH known_hosts file from the enriched inventory.

    For each host with ssh_host_keys, builds a comma-separated host
    list from all dns_names and all interface IP addresses, then emits
    one line per key in known_hosts format:

        name1,name2,ip1,ip2 key-type base64-key

    Output is sorted by hostname for determinism.
    """
    lines: list[str] = []

    for host in inventory.hosts_sorted():
        if not host.ssh_host_keys:
            continue

        # Build the set of host identifiers (names + IPs)
        host_ids: list[str] = []
        seen: set[str] = set()

        # Add all DNS names
        for dns_name in host.dns_names:
            if dns_name.name not in seen:
                host_ids.append(dns_name.name)
                seen.add(dns_name.name)

        # Add all IP addresses from all interfaces
        for iface in host.interfaces:
            for ip_addr in iface.ip_addresses:
                ip_str = str(ip_addr)
                if ip_str not in seen:
                    host_ids.append(ip_str)
                    seen.add(ip_str)

        if not host_ids:
            raise ValueError(
                f"Host {host.hostname!r} has SSH host keys but no"
                f" DNS names or IP addresses"
            )

        host_list = ",".join(host_ids)

        # Parse each key line and emit known_hosts format
        for key_line in host.ssh_host_keys:
            parts = key_line.split()
            if len(parts) < 3:
                raise ValueError(
                    f"Malformed SSH host key line for {host.hostname!r}: "
                    f"{key_line!r}"
                )
            # parts[0] is the original hostname from scanning, parts[1] is
            # key-type, parts[2] is base64-key
            key_type = parts[1]
            b64_key = parts[2]
            lines.append(f"{host_list} {key_type} {b64_key}")

    return "\n".join(lines) + "\n" if lines else ""
