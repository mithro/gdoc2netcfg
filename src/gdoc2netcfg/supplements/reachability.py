"""Shared network reachability checks.

Provides ping and port-check utilities used by multiple supplements
(SSHFP scanning, SSL certificate scanning, etc.).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import threading

    from gdoc2netcfg.models.host import Host


@dataclass(frozen=True)
class PingResult:
    """Result of pinging a single IP address.

    Truthy when at least one packet was received, so existing
    ``if check_reachable(ip):`` callers keep working.
    """

    transmitted: int
    received: int
    rtt_avg_ms: float | None = None

    def __bool__(self) -> bool:
        return self.received >= 1


def check_reachable(ip: str, packets: int = 10) -> PingResult:
    """Check if a host responds to ICMP ping.

    Args:
        ip: IPv4 or IPv6 address string to ping.
        packets: Number of ping packets to send.

    Returns:
        PingResult with packet counts and latency.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "-A", "-c", str(packets), "-W", "1", ip],
            capture_output=True,
            text=True,
        )
        match = re.search(
            r"(\d+) packets transmitted, (\d+) received", result.stdout
        )
        if match is None:
            return PingResult(packets, 0)
        transmitted = int(match.group(1))
        received = int(match.group(2))
        rtt_avg = None
        if received > 0:
            rtt_match = re.search(
                r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", result.stdout
            )
            if rtt_match:
                rtt_avg = float(rtt_match.group(1))
        return PingResult(transmitted, received, rtt_avg)
    except FileNotFoundError:
        return PingResult(0, 0)


def _detect_ip_version(ip: str) -> int:
    """Return 4 or 6 based on the IP string format."""
    return ipaddress.ip_address(ip).version


def check_port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is open on the host.

    Args:
        ip: IPv4 or IPv6 address string.
        port: TCP port number to check.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open and accepting connections.
    """
    family = socket.AF_INET6 if _detect_ip_version(ip) == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    finally:
        sock.close()


@dataclass(frozen=True)
class InterfaceReachability:
    """Reachability state for a single VirtualInterface."""

    pings: tuple[tuple[str, PingResult], ...] = ()

    @property
    def active_ips(self) -> tuple[str, ...]:
        """IPs that responded to ping."""
        return tuple(addr for addr, pr in self.pings if pr)

    @property
    def active_ipv4(self) -> tuple[str, ...]:
        """Reachable IPv4 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 4)

    @property
    def active_ipv6(self) -> tuple[str, ...]:
        """Reachable IPv6 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 6)

    @property
    def has_ipv4(self) -> bool:
        """True if any IPv4 address is reachable."""
        return len(self.active_ipv4) > 0

    @property
    def has_ipv6(self) -> bool:
        """True if any IPv6 address is reachable."""
        return len(self.active_ipv6) > 0

    @property
    def reachability_mode(self) -> str:
        """'unreachable', 'ipv4-only', 'ipv6-only', or 'dual-stack'."""
        v4 = self.has_ipv4
        v6 = self.has_ipv6
        if v4 and v6:
            return "dual-stack"
        if v4:
            return "ipv4-only"
        if v6:
            return "ipv6-only"
        return "unreachable"


@dataclass(frozen=True)
class HostReachability:
    """Pre-computed reachability state for a single host.

    Stores which IPs responded to ping so multiple supplements can
    skip redundant per-host ping loops.
    """

    hostname: str
    active_ips: tuple[str, ...] = ()
    interfaces: tuple[InterfaceReachability, ...] = ()

    @property
    def is_up(self) -> bool:
        """True if any IP responded to ping."""
        return len(self.active_ips) > 0

    @property
    def active_ipv4(self) -> tuple[str, ...]:
        """Reachable IPv4 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 4)

    @property
    def active_ipv6(self) -> tuple[str, ...]:
        """Reachable IPv6 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 6)

    @property
    def has_ipv4(self) -> bool:
        """True if any IPv4 address is reachable."""
        return len(self.active_ipv4) > 0

    @property
    def has_ipv6(self) -> bool:
        """True if any IPv6 address is reachable."""
        return len(self.active_ipv6) > 0

    @property
    def reachability_mode(self) -> str:
        """'unreachable', 'ipv4-only', 'ipv6-only', or 'dual-stack'."""
        v4 = self.has_ipv4
        v6 = self.has_ipv6
        if v4 and v6:
            return "dual-stack"
        if v4:
            return "ipv4-only"
        if v6:
            return "ipv6-only"
        return "unreachable"


_MODE_LABELS = {
    "dual-stack": "up (v46)",
    "ipv4-only":  "up (v4_)",
    "ipv6-only":  "up (v_6)",
    "unreachable": "down",
}
_LABEL_WIDTH = max(len(v) for v in _MODE_LABELS.values())


_PKT_WIDTH = 5   # e.g. "10/10" — assumes check_reachable(packets=10)
_RTT_WIDTH = 8   # e.g. " 489.2ms"

# ANSI color codes for reachability display
_CLR_HOST = {
    "dual-stack": "92",    # bright green
    "ipv4-only":  "32",    # green
    "ipv6-only":  "33",    # yellow
    "unreachable": "31",   # red
}
_CLR_RTT_GOOD = "32"       # green  (<10ms)
_CLR_RTT_WARN = "33"       # yellow (10-100ms)
_CLR_RTT_BAD  = "91"       # bright red (>100ms)
_CLR_PKT_FULL = "32"       # green  (100%)
_CLR_PKT_ZERO = "31"       # red    (0%)
_CLR_PKT_PARTIAL = "33"    # yellow (partial)


def _print_host_reachability(
    hr: HostReachability,
    *,
    name_width: int,
    ip_width: int,
    cols: int,
    prefix: str,
    use_color: bool = False,
) -> None:
    """Print one host's reachability line(s) to stderr.

    Shared by both the cached display path and the live progressive
    scan so that the output is identical regardless of source.
    """
    import sys

    from gdoc2netcfg.utils.terminal import colorize

    label = _MODE_LABELS.get(hr.reachability_mode, "down")
    host_clr = _CLR_HOST.get(hr.reachability_mode, "31")

    # Pad hostname and label first, then wrap in color.
    name_str = colorize(f"{hr.hostname:>{name_width}s}", host_clr, use_color)
    label_str = colorize(f"{label:<{_LABEL_WIDTH}s}", host_clr, use_color)

    # Build cells from interface ping data.
    all_cells: list[str] = []
    for ir in hr.interfaces:
        for ip_str, ping in ir.pings:
            pkt = f"{ping.received:>2}/{ping.transmitted}"
            if ping.received == ping.transmitted:
                pkt = colorize(pkt, _CLR_PKT_FULL, use_color)
            elif ping.received == 0:
                pkt = colorize(pkt, _CLR_PKT_ZERO, use_color)
            else:
                pkt = colorize(pkt, _CLR_PKT_PARTIAL, use_color)
            if ping.rtt_avg_ms is not None:
                rtt = f"{ping.rtt_avg_ms:>6.1f}ms"
                if ping.rtt_avg_ms < 10:
                    rtt = colorize(rtt, _CLR_RTT_GOOD, use_color)
                elif ping.rtt_avg_ms < 100:
                    rtt = colorize(rtt, _CLR_RTT_WARN, use_color)
                else:
                    rtt = colorize(rtt, _CLR_RTT_BAD, use_color)
            else:
                rtt = " " * _RTT_WIDTH
            all_cells.append(f"{ip_str:<{ip_width}s}  {pkt}  {rtt}")

    if not all_cells:
        print(
            f"  {name_str}"
            f" {label_str}",
            file=sys.stderr,
        )
        return

    first_row = True
    for row_start in range(0, len(all_cells), cols):
        row = "  ".join(all_cells[row_start:row_start + cols])
        if first_row:
            print(
                f"  {name_str}"
                f" {label_str}"
                f"  {row}",
                file=sys.stderr,
            )
            first_row = False
        else:
            print(f"{prefix}{row}", file=sys.stderr)


def print_reachability_status(
    reachability: dict[str, HostReachability],
) -> None:
    """Print per-host reachability status to stderr.

    Uses full ping data from the v2 cache (or live scan) to show
    packet counts and RTT for every IP, identical to live output.
    """
    import shutil
    import sys

    from gdoc2netcfg.utils.terminal import use_color as _use_color

    if not reachability:
        return

    color = _use_color()

    sorted_hosts = sorted(
        reachability.values(),
        key=lambda hr: hr.hostname.split(".")[::-1],
    )
    name_width = max(len(hr.hostname) for hr in sorted_hosts)

    # Gather all IPs from interface ping data for width calculation.
    all_ips: list[str] = []
    for hr in sorted_hosts:
        for ir in hr.interfaces:
            for ip_str, _pr in ir.pings:
                all_ips.append(ip_str)
    ip_width = max((len(ip) for ip in all_ips), default=1)

    prefix_width = 2 + name_width + 1 + _LABEL_WIDTH + 2
    prefix = " " * prefix_width
    cell_width = ip_width + 2 + _PKT_WIDTH + 2 + _RTT_WIDTH
    cell_gap = 2
    term_width = shutil.get_terminal_size().columns
    avail = term_width - prefix_width
    cols = max(2, avail // (cell_width + cell_gap) & ~1)

    print(file=sys.stderr)

    for hr in sorted_hosts:
        _print_host_reachability(
            hr,
            name_width=name_width,
            ip_width=ip_width,
            cols=cols,
            prefix=prefix,
            use_color=color,
        )

    print(file=sys.stderr)


def parse_reachability_dict(
    hosts_data: dict[str, dict],
) -> dict[str, HostReachability]:
    """Convert raw reachability dicts to HostReachability objects.

    *hosts_data* maps hostname to ``{"interfaces": [[{ip, transmitted,
    received, rtt_avg_ms}]]}``.  This is the format stored in both
    the v2 JSON cache and the SQLite database.
    """
    reachability: dict[str, HostReachability] = {}
    for hostname, host_data in hosts_data.items():
        ifaces: list[InterfaceReachability] = []
        for iface_pings in host_data["interfaces"]:
            pings: list[tuple[str, PingResult]] = []
            for entry in iface_pings:
                pings.append((
                    entry["ip"],
                    PingResult(
                        transmitted=entry["transmitted"],
                        received=entry["received"],
                        rtt_avg_ms=entry.get("rtt_avg_ms"),
                    ),
                ))
            ifaces.append(InterfaceReachability(pings=tuple(pings)))
        all_active: list[str] = []
        for ir in ifaces:
            all_active.extend(ir.active_ips)
        reachability[hostname] = HostReachability(
            hostname=hostname,
            active_ips=tuple(all_active),
            interfaces=tuple(ifaces),
        )
    return reachability


def check_all_hosts_reachability(
    hosts: list[Host],
    verbose: bool = False,
    max_workers: int = 64,
    stop_event: threading.Event | None = None,
) -> dict[str, HostReachability]:
    """Ping all IPs for every host in parallel and return reachability state.

    All pings are submitted to a thread pool immediately.  Results are
    collected per-host in sorted order so verbose output stays ordered
    even though the actual pings run concurrently.

    Args:
        hosts: Host objects with IPs to check.
        verbose: Print progress to stderr.
        max_workers: Maximum concurrent ping subprocesses.
        stop_event: If set during the sweep, stop collecting results and
            return what has been gathered so far without blocking on the
            remaining pings.

    Returns:
        Mapping of hostname to HostReachability.
    """
    import sys
    from concurrent.futures import Future, ThreadPoolExecutor

    result: dict[str, HostReachability] = {}
    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    # Pre-compute alignment widths from the known IP strings so we can
    # print each host progressively as its pings complete, rather than
    # waiting for all hosts to finish before displaying anything.
    all_known_ips: list[str] = []
    for host in sorted_hosts:
        for vi in host.virtual_interfaces:
            all_known_ips.extend(vi.all_ips)
    ip_width = max((len(ip) for ip in all_known_ips), default=1)

    if verbose:
        import shutil

        from gdoc2netcfg.utils.terminal import use_color as _use_color

        color = _use_color()
        prefix_width = 2 + name_width + 1 + _LABEL_WIDTH + 2
        prefix = " " * prefix_width
        cell_width = ip_width + 2 + _PKT_WIDTH + 2 + _RTT_WIDTH
        cell_gap = 2
        term_width = shutil.get_terminal_size().columns
        avail = term_width - prefix_width
        cols = max(2, avail // (cell_width + cell_gap) & ~1)

        print(file=sys.stderr)

    pool = ThreadPoolExecutor(max_workers=max_workers)
    aborted = False
    try:
        # Submit all pings up front, deduplicating IPs across interfaces.
        host_futures: list[
            tuple[Host, list[tuple[int, str, Future[PingResult]]]]
        ] = []
        for host in sorted_hosts:
            ip_futures: list[tuple[int, str, Future[PingResult]]] = []
            seen_ips: set[str] = set()
            for vi_idx, vi in enumerate(host.virtual_interfaces):
                for ip_str in vi.all_ips:
                    if ip_str in seen_ips:
                        continue
                    seen_ips.add(ip_str)
                    future = pool.submit(check_reachable, ip_str)
                    ip_futures.append((vi_idx, ip_str, future))
            host_futures.append((host, ip_futures))

        # Collect results in sorted order — blocks on each host's futures
        # while remaining hosts continue pinging in the background.
        # Prints each host as soon as its pings complete.
        for host, ip_futures in host_futures:
            if stop_event is not None and stop_event.is_set():
                aborted = True
                break

            active_ips: list[str] = []
            vi_count = len(host.virtual_interfaces)
            iface_pings: list[list[tuple[str, PingResult]]] = [
                [] for _ in range(vi_count)
            ]

            for vi_idx, ip_str, future in ip_futures:
                ping = future.result()
                iface_pings[vi_idx].append((ip_str, ping))
                if ping:
                    active_ips.append(ip_str)

            iface_reachability = tuple(
                InterfaceReachability(pings=tuple(pings))
                for pings in iface_pings
            )

            hr = HostReachability(
                hostname=host.hostname,
                active_ips=tuple(active_ips),
                interfaces=iface_reachability,
            )
            result[host.hostname] = hr

            # Print this host immediately.
            if verbose:
                _print_host_reachability(
                    hr,
                    name_width=name_width,
                    ip_width=ip_width,
                    cols=cols,
                    prefix=prefix,
                    use_color=color,
                )
    finally:
        # On abort, cancel queued pings and don't block draining the
        # in-flight ones — systemd's cgroup SIGTERM reaps the ping children.
        pool.shutdown(wait=not aborted, cancel_futures=aborted)

    if verbose:
        print(file=sys.stderr)

    return result
