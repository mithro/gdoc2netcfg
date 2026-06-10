"""Supplement: BMC firmware detection via ipmitool.

Probes Supermicro BMCs using ``ipmitool mc info`` to detect the hardware
series (X9, X10, X11, etc.). BMCs on X9 or earlier are reclassified as
``supermicro-bmc-legacy`` so they are excluded from SNMP validation.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (IPMI controllers).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.hardware import (
    HARDWARE_SUPERMICRO_BMC,
    HARDWARE_SUPERMICRO_BMC_LEGACY,
)
from gdoc2netcfg.models.host import BMCFirmwareInfo

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability


def _parse_mc_info(output: str) -> dict[str, str] | None:
    """Parse ipmitool mc info key:value output.

    Returns a dict of field names to values, or None if the output
    cannot be parsed (e.g. connection failure messages).
    """
    result = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key and value:
            result[key] = value
    return result if result else None


def _run_ipmitool_mc_info(
    ip: str,
    username: str = "ADMIN",
    password: str = "ADMIN",
    timeout: int = 10,
) -> dict[str, str] | None:
    """Run ipmitool mc info against a BMC IP.

    Returns parsed key-value dict, or None on failure.
    """
    try:
        result = subprocess.run(
            [
                "ipmitool",
                "-I", "lanplus",
                "-H", ip,
                "-U", username,
                "-P", password,
                "mc", "info",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        return _parse_mc_info(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _try_ipmi_credentials(
    ip: str,
    host: Host,
) -> dict[str, str] | None:
    """Try IPMI credential cascade for a BMC.

    Credential order:
    1. Default ADMIN/ADMIN (Supermicro factory default)
    2. host.extra["IPMI Username"] + host.extra["IPMI Password"] if present

    Returns parsed mc info dict, or None if all attempts fail.
    """
    # Try 1: Default credentials
    result = _run_ipmitool_mc_info(ip, "ADMIN", "ADMIN")
    if result is not None:
        return result

    # Try 2: Custom credentials from spreadsheet
    custom_user = host.extra.get("IPMI Username", "").strip()
    custom_pass = host.extra.get("IPMI Password", "").strip()
    if custom_user and custom_pass:
        if custom_user != "ADMIN" or custom_pass != "ADMIN":
            result = _run_ipmitool_mc_info(ip, custom_user, custom_pass)
            if result is not None:
                return result

    return None


def _extract_series(product_name: str) -> int | None:
    """Extract Supermicro series number from product name.

    Looks for the pattern ``X<digits>`` at the start of the product name
    (e.g. "X11SPM-T(P)F" → 11, "X9SCV-LN4F+" → 9).

    Returns the series number, or None if not parseable.
    """
    match = re.match(r"^X(\d+)", product_name)
    if match:
        return int(match.group(1))
    return None


def _is_snmp_capable(series: int | None) -> bool:
    """Determine if a BMC series supports SNMP.

    X10 and later (AST2400/2500/2600 chips) have an SNMP agent.
    X9 and earlier (ATEN WPCM450 chip) do not.

    When the series is unknown, returns True (conservative — don't
    suppress SNMP validation for unrecognised boards).
    """
    if series is None:
        return True
    return series >= 10


def load_bmc_firmware_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached BMC firmware data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_bmc_firmware_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save BMC firmware data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_bmc_firmware(
    hosts: list[Host],
    baseline: dict[str, dict] | None,
    *,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
) -> dict[str, dict]:
    """Scan reachable Supermicro BMCs for firmware information.

    Only probes hosts with hardware_type == "supermicro-bmc".

    Args:
        hosts: Host objects with hardware_type set.
        baseline: Last-known firmware data (from the DiscoveryDB).  Fresh
            results are merged over it; the caller persists the result.
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data from the
            reachability pass. Only reachable hosts are scanned.

    Returns:
        Mapping of hostname to BMC firmware info dict.
    """
    import sys

    fw_data = dict(baseline or {})

    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    for host in sorted_hosts:
        if host.hardware_type != HARDWARE_SUPERMICRO_BMC:
            continue

        # Skip hosts not in reachability data or not reachable
        host_reach = reachability.get(host.hostname) if reachability else None
        if host_reach is None or not host_reach.is_up:
            continue
        active_ips = list(host_reach.active_ips)

        if verbose:
            print(
                f"  {host.hostname:>{name_width}s} ipmitool({','.join(active_ips)}) ",
                end="", flush=True, file=sys.stderr,
            )

        # Try IPMI on each reachable IP until one succeeds
        for ip in active_ips:
            mc_info = _try_ipmi_credentials(ip, host)
            if mc_info is not None:
                product_name = mc_info.get("Product Name", "")
                firmware_rev = mc_info.get("Firmware Revision", "")
                ipmi_version = mc_info.get("IPMI Version", "")
                series = _extract_series(product_name)

                fw_data[host.hostname] = {
                    "product_name": product_name,
                    "firmware_revision": firmware_rev,
                    "ipmi_version": ipmi_version,
                    "series": series,
                    "snmp_capable": _is_snmp_capable(series),
                }
                if verbose:
                    print(
                        f"ok ({product_name}, series=X{series or '?'})",
                        file=sys.stderr,
                    )
                break
        else:
            if verbose:
                print("no-ipmi", file=sys.stderr)

    return fw_data


def enrich_hosts_with_bmc_firmware(
    hosts: list[Host],
    fw_cache: dict[str, dict] | None,
) -> None:
    """Attach cached BMC firmware info to Host objects.

    Modifies hosts in-place by setting host.bmc_firmware_info.
    """
    fw_cache = fw_cache or {}
    for host in hosts:
        info = fw_cache.get(host.hostname)
        if info is not None:
            host.bmc_firmware_info = BMCFirmwareInfo(
                product_name=info.get("product_name", ""),
                firmware_revision=info.get("firmware_revision", ""),
                ipmi_version=info.get("ipmi_version", ""),
                series=info.get("series"),
                snmp_capable=info.get("snmp_capable", True),
            )


def refine_bmc_hardware_type(hosts: list[Host]) -> None:
    """Reclassify legacy BMCs based on firmware info.

    Hosts with hardware_type == "supermicro-bmc" and
    bmc_firmware_info.snmp_capable == False are reclassified
    as "supermicro-bmc-legacy".
    """
    for host in hosts:
        if host.hardware_type != HARDWARE_SUPERMICRO_BMC:
            continue
        if host.bmc_firmware_info is None:
            continue
        if not host.bmc_firmware_info.snmp_capable:
            host.hardware_type = HARDWARE_SUPERMICRO_BMC_LEGACY
