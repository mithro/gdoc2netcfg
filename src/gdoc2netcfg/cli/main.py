"""CLI entry point for gdoc2netcfg.

Subcommands:
    fetch          Download CSVs from Google Sheets to local cache.
    generate       Run the pipeline and produce output config files.
    validate       Run constraint checks on the data.
    info           Show pipeline configuration.
    reachability   Ping all hosts and report which are up/down.
    sshfp          Scan hosts for SSH fingerprints.
    ssl-certs      Scan hosts for SSL/TLS certificates.
    snmp-host      Scan hosts for SNMP system info and interfaces.
    bmc-firmware   Scan BMCs for firmware info.
    snmp-switch    Scan switches for bridge/topology data via SNMP.
    bridge         Unified switch data (scan, show).
    nsdp           NSDP switch discovery (scan, show).
    password       Look up device credentials by hostname, IP, or MAC.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import PipelineConfig
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.models.switch_data import SwitchData
    from gdoc2netcfg.supplements.reachability import HostReachability


def _load_config(args: argparse.Namespace):
    """Load pipeline config, handling errors."""
    from gdoc2netcfg.config import load_config

    config_path = getattr(args, "config", None)
    try:
        return load_config(config_path)
    except FileNotFoundError:
        path = config_path or "gdoc2netcfg.toml"
        print(f"Error: config file not found: {path}", file=sys.stderr)
        sys.exit(1)


def _fetch_or_load_csvs(config, use_cache: bool = False):
    """Fetch CSVs from sheets or read from cache.

    Returns list of (name, csv_text) tuples.
    """
    from gdoc2netcfg.sources.cache import CSVCache
    from gdoc2netcfg.sources.sheets import fetch_sheet

    cache = CSVCache(config.cache.directory)
    results = []

    for sheet in config.sheets:
        if use_cache and cache.has(sheet.name):
            csv_text = cache.read(sheet.name)
            results.append((sheet.name, csv_text))
        else:
            try:
                data = fetch_sheet(sheet.name, sheet.url)
                cache.write(sheet.name, data.csv_text)
                results.append((sheet.name, data.csv_text))
            except Exception as e:
                print(f"Warning: failed to fetch sheet {sheet.name!r}: {e}", file=sys.stderr)
                if cache.has(sheet.name):
                    print(f"  Using cached version of {sheet.name!r}", file=sys.stderr)
                    csv_text = cache.read(sheet.name)
                    results.append((sheet.name, csv_text))

    return results


def _enrich_site_from_vlan_sheet(config, csv_data: list[tuple[str, str]]) -> None:
    """Parse the VLAN Allocations sheet and populate site VLANs/subdomains.

    Finds the 'vlan_allocations' CSV in csv_data, parses it, builds
    VLAN objects and network_subdomains, and updates config.site in place.
    """
    from gdoc2netcfg.derivations.vlan import build_network_subdomains, build_vlans_from_definitions
    from gdoc2netcfg.sources.vlan_parser import parse_vlan_allocations

    vlan_csv = None
    for name, text in csv_data:
        if name == "vlan_allocations":
            vlan_csv = text
            break

    if vlan_csv is None:
        print("Warning: no vlan_allocations sheet found, VLANs not configured", file=sys.stderr)
        return

    definitions = parse_vlan_allocations(vlan_csv)
    if not definitions:
        print("Warning: vlan_allocations sheet is empty", file=sys.stderr)
        return

    vlans = build_vlans_from_definitions(definitions, config.site.site_octet)
    subdomains = build_network_subdomains(vlans)

    config.site.vlans = vlans
    config.site.network_subdomains = subdomains


def _build_pipeline(config):
    """Run the full build pipeline: parse → derive → validate → enrich.

    Returns (records, hosts, inventory, validation_result).
    """
    from gdoc2netcfg.constraints.validators import validate_all
    from gdoc2netcfg.derivations.host_builder import build_hosts, build_inventory
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bmc_firmware import (
        enrich_hosts_with_bmc_firmware,
        load_bmc_firmware_cache,
        refine_bmc_hardware_type,
    )
    from gdoc2netcfg.supplements.snmp import enrich_hosts_with_snmp, load_snmp_cache
    from gdoc2netcfg.supplements.sshfp import enrich_hosts_with_sshfp, load_sshfp_cache
    from gdoc2netcfg.supplements.ssl_certs import enrich_hosts_with_ssl_certs, load_ssl_cert_cache

    # Fetch or load CSVs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)

    # Enrich site config from VLAN Allocations sheet
    _enrich_site_from_vlan_sheet(config, csv_data)

    # Parse device records (exclude vlan_allocations — not a device sheet)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    if not all_records:
        print("Error: no device records found in any sheet.", file=sys.stderr)
        sys.exit(1)

    # Build hosts (applies all derivations)
    hosts = build_hosts(all_records, config.site)

    # Detect IPv6 capability from MAC OUI and hardware patterns
    from gdoc2netcfg.derivations.ipv6_capability import detect_ipv6_capability

    ipv6_cap = config.ipv6_capability
    extra_ouis = set(ipv6_cap.incapable_ouis) if ipv6_cap.incapable_ouis else None
    hardware_patterns = ipv6_cap.incapable_hardware_patterns or None
    for host in hosts:
        host.ipv6_capable = detect_ipv6_capability(
            host,
            hardware_patterns=hardware_patterns,
            extra_ouis=extra_ouis,
        )

    # Build inventory (aggregate derivations)
    inventory = build_inventory(hosts, config.site)

    # Load SSHFP cache and enrich (don't scan — that's a separate subcommand)
    sshfp_cache = Path(config.cache.directory) / "sshfp.json"
    sshfp_data = load_sshfp_cache(sshfp_cache)
    enrich_hosts_with_sshfp(hosts, sshfp_data)

    # Load SSL cert cache and enrich (don't scan — that's a separate subcommand)
    ssl_cache = Path(config.cache.directory) / "ssl_certs.json"
    ssl_data = load_ssl_cert_cache(ssl_cache)
    enrich_hosts_with_ssl_certs(hosts, ssl_data)

    # Load BMC firmware cache and refine hardware types (don't scan — separate subcommand)
    bmc_fw_cache = Path(config.cache.directory) / "bmc_firmware.json"
    bmc_fw_data = load_bmc_firmware_cache(bmc_fw_cache)
    enrich_hosts_with_bmc_firmware(hosts, bmc_fw_data)
    refine_bmc_hardware_type(hosts)

    # Load SNMP cache and enrich (don't scan — that's a separate subcommand)
    snmp_cache = Path(config.cache.directory) / "snmp.json"
    snmp_data = load_snmp_cache(snmp_cache)
    enrich_hosts_with_snmp(hosts, snmp_data)

    # Load bridge cache and enrich (don't scan — that's a separate subcommand)
    from gdoc2netcfg.supplements.bridge import enrich_hosts_with_bridge_data
    from gdoc2netcfg.supplements.snmp_common import load_json_cache

    bridge_cache_path = Path(config.cache.directory) / "bridge.json"
    bridge_cache = load_json_cache(bridge_cache_path)
    enrich_hosts_with_bridge_data(hosts, bridge_cache)

    # Load NSDP cache and enrich (don't scan — that's a separate subcommand)
    from gdoc2netcfg.supplements.nsdp import enrich_hosts_with_nsdp, load_nsdp_cache

    nsdp_cache_path = Path(config.cache.directory) / "nsdp.json"
    nsdp_cache = load_nsdp_cache(nsdp_cache_path)
    enrich_hosts_with_nsdp(hosts, nsdp_cache)

    # Load Tasmota cache and enrich (don't scan — that's a separate subcommand)
    from gdoc2netcfg.supplements.tasmota import (
        enrich_hosts_with_tasmota,
        load_tasmota_cache,
    )

    tasmota_cache_path = Path(config.cache.directory) / "tasmota.json"
    tasmota_cache = load_tasmota_cache(tasmota_cache_path)
    enrich_hosts_with_tasmota(hosts, tasmota_cache)

    # Validate
    result = validate_all(all_records, hosts, inventory)

    return all_records, hosts, inventory, result


# ---------------------------------------------------------------------------
# Subcommand: fetch
# ---------------------------------------------------------------------------

def cmd_fetch(args: argparse.Namespace) -> int:
    """Download CSVs from Google Sheets to local cache."""
    config = _load_config(args)

    from gdoc2netcfg.sources.cache import CSVCache
    from gdoc2netcfg.sources.sheets import fetch_sheet

    cache = CSVCache(config.cache.directory)
    ok = 0
    fail = 0

    for sheet in config.sheets:
        try:
            data = fetch_sheet(sheet.name, sheet.url)
            cache.write(sheet.name, data.csv_text)
            print(f"  {sheet.name}: fetched ({len(data.csv_text)} bytes)")
            ok += 1
        except Exception as e:
            print(f"  {sheet.name}: FAILED ({e})", file=sys.stderr)
            fail += 1

    print(f"\nFetched {ok} sheets, {fail} failures.")
    return 1 if fail > 0 else 0


# ---------------------------------------------------------------------------
# Subcommand: generate
# ---------------------------------------------------------------------------

def _get_generator(name: str):
    """Get a generator function by name."""
    generators = {
        "dnsmasq_internal": ("gdoc2netcfg.generators.dnsmasq", "generate_dnsmasq_internal"),
        "dnsmasq_external": (
            "gdoc2netcfg.generators.dnsmasq_external",
            "generate_dnsmasq_external",
        ),
        "nagios": ("gdoc2netcfg.generators.nagios", "generate_nagios"),
        "letsencrypt": ("gdoc2netcfg.generators.letsencrypt", "generate_letsencrypt"),
        "nginx": ("gdoc2netcfg.generators.nginx", "generate_nginx"),
        "topology": ("gdoc2netcfg.generators.topology", "generate_topology"),
    }
    if name not in generators:
        return None
    module_path, func_name = generators[name]
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, func_name)


def _resolve_output_path(output_path: str, args: argparse.Namespace) -> Path:
    """Resolve an output path, prepending --output-dir for relative paths."""
    p = Path(output_path)
    output_dir = getattr(args, "output_dir", None)
    if output_dir and not p.is_absolute():
        return Path(output_dir) / p
    return p


def _write_multi_file_output(name, file_dict, gen_config, args):
    """Write a multi-file generator output (dict[str, str]).

    Each key is a relative path, written under the generator's output_dir.
    """
    if args.stdout:
        for rel_path, content in sorted(file_dict.items()):
            print(f"# === {name}: {rel_path} ===")
            print(content)
        return

    output_dir = gen_config.output_dir if gen_config and gen_config.output_dir else name
    base = _resolve_output_path(output_dir, args).resolve()
    total_bytes = 0
    for rel_path, content in sorted(file_dict.items()):
        file_path = (base / rel_path).resolve()
        if not str(file_path).startswith(str(base)):
            print(
                f"  {name}: skipping path traversal: {rel_path}",
                file=sys.stderr,
            )
            continue
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
        total_bytes += len(content)
    print(f"  {name}: wrote {len(file_dict)} files to {output_dir}/ ({total_bytes} bytes)")


def cmd_generate(args: argparse.Namespace) -> int:
    """Run the pipeline and produce output config files."""
    config = _load_config(args)
    _, _, inventory, validation = _build_pipeline(config)

    if validation.has_errors:
        print("Validation errors found:", file=sys.stderr)
        print(validation.report(), file=sys.stderr)
        if not args.force:
            print("Use --force to generate despite errors.", file=sys.stderr)
            return 1

    if validation.warnings:
        print(f"Validation: {len(validation.warnings)} warning(s)", file=sys.stderr)

    # Determine which generators to run
    if args.generators:
        gen_names = args.generators
    else:
        gen_names = list(config.generators.keys())

    generated = 0
    for name in gen_names:
        gen_func = _get_generator(name)
        if gen_func is None:
            print(f"Warning: unknown generator {name!r}", file=sys.stderr)
            continue

        gen_config = config.generators.get(name)

        # Build kwargs for generators that accept extra parameters
        kwargs = {}
        if name == "dnsmasq_external" and gen_config and gen_config.params.get("public_ipv4"):
            kwargs["public_ipv4"] = gen_config.params["public_ipv4"]
        elif name == "dnsmasq_external":
            kwargs["public_ipv4"] = config.site.public_ipv4
        elif name == "letsencrypt" and gen_config:
            for key in ("auth_hook", "dnsmasq_conf_dir", "dnsmasq_conf", "dnsmasq_service"):
                if gen_config.params.get(key):
                    kwargs[key] = gen_config.params[key]
        elif name == "nginx" and gen_config:
            if gen_config.params.get("acme_webroot"):
                kwargs["acme_webroot"] = gen_config.params["acme_webroot"]
            if gen_config.params.get("lua_healthcheck_path"):
                kwargs["lua_healthcheck_path"] = gen_config.params["lua_healthcheck_path"]
            if gen_config.params.get("gdoc2netcfg_dir"):
                kwargs["gdoc2netcfg_dir"] = gen_config.params["gdoc2netcfg_dir"]
            if gen_config.params.get("sites_enabled_dir"):
                kwargs["sites_enabled_dir"] = gen_config.params["sites_enabled_dir"]
        elif name == "topology" and gen_config:
            if gen_config.params.get("show_unknown_macs"):
                kwargs["show_unknown_macs"] = (
                    gen_config.params["show_unknown_macs"].lower() == "true"
                )

        output = gen_func(inventory, **kwargs)

        # Write output: single file (str) or multiple files (dict)
        if isinstance(output, dict):
            _write_multi_file_output(name, output, gen_config, args)
        else:
            output_path = gen_config.output if gen_config and gen_config.output else None
            if output_path and not args.stdout:
                resolved = _resolve_output_path(output_path, args)
                resolved.parent.mkdir(parents=True, exist_ok=True)
                resolved.write_text(output, encoding="utf-8")
                print(f"  {name}: wrote {resolved} ({len(output)} bytes)")
            else:
                if len(gen_names) > 1:
                    print(f"# === {name} ===")
                print(output)

        generated += 1

    if not args.stdout:
        print(f"\nGenerated {generated} config file(s).")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: validate
# ---------------------------------------------------------------------------

def cmd_validate(args: argparse.Namespace) -> int:
    """Run constraint validation on the data."""
    config = _load_config(args)
    records, hosts, inventory, result = _build_pipeline(config)

    print(f"Records: {len(records)}")
    print(f"Hosts:   {len(hosts)}")
    print()
    print(result.report())

    return 1 if result.has_errors else 0


# ---------------------------------------------------------------------------
# Subcommand: info
# ---------------------------------------------------------------------------

def cmd_info(args: argparse.Namespace) -> int:
    """Show pipeline configuration info."""
    config = _load_config(args)

    # Load VLANs from sheet if available
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)

    print(f"Site:   {config.site.name} (site_octet={config.site.site_octet})")
    print(f"Domain: {config.site.domain}")
    print()

    print("Sheets:")
    for sheet in config.sheets:
        print(f"  {sheet.name}: {sheet.url[:60]}...")
    print()

    print("IPv6 prefixes:")
    for prefix in config.site.ipv6_prefixes:
        status = "enabled" if prefix.enabled else "DISABLED"
        print(f"  {prefix.prefix} ({status})")
    print()

    print("VLANs:")
    for vid, vlan in sorted(config.site.vlans.items()):
        print(f"  {vid:>3d}: {vlan.name} (subdomain: {vlan.subdomain})")
    print()

    print("Generators:")
    for name, gen in config.generators.items():
        status = "enabled" if gen.enabled else "disabled"
        output = gen.output or "(stdout)"
        print(f"  {name}: {status}, output={output}")

    return 0


# ---------------------------------------------------------------------------
# Shared reachability helper
# ---------------------------------------------------------------------------

def _load_or_run_reachability(
    config: PipelineConfig,
    hosts: list[Host],
    force: bool = False,
) -> dict[str, HostReachability]:
    """Load cached reachability or run a fresh scan.

    Per-host status is always printed to stderr — either progressively
    during the live scan or from cached data after loading.
    """
    from gdoc2netcfg.supplements.reachability import (
        check_all_hosts_reachability,
        load_reachability_cache,
        print_reachability_status,
        save_reachability_cache,
    )

    cache_path = Path(config.cache.directory) / "reachability.json"

    if not force:
        result = load_reachability_cache(cache_path)
        if result is not None:
            cached, age = result
            print(
                f"Using cached reachability ({age:.0f}s old).",
                file=sys.stderr,
            )
            print_reachability_status(cached)
            return cached

    print("Checking host reachability...", file=sys.stderr)
    reachability = check_all_hosts_reachability(hosts, verbose=True)
    save_reachability_cache(cache_path, reachability)
    return reachability


def _print_reachability_summary(
    reachability: dict[str, HostReachability],
    hosts: list[Host],
) -> None:
    """Print a one-line reachability summary to stderr."""
    hosts_up = sum(1 for r in reachability.values() if r.is_up)
    hosts_down = sum(1 for r in reachability.values() if not r.is_up)
    dual = sum(1 for r in reachability.values() if r.reachability_mode == "dual-stack")
    v4only = sum(1 for r in reachability.values() if r.reachability_mode == "ipv4-only")
    v6only = sum(1 for r in reachability.values() if r.reachability_mode == "ipv6-only")
    parts = [
        f"{dual} v46 - dual-stack",
        f"{v4only} v4_ - IPv4 only",
        f"{v6only} v_6 - IPv6 only",
    ]
    breakdown = f" ({', '.join(parts)})"
    print(
        f"{hosts_up} up{breakdown}, {hosts_down} down, {len(hosts)} total.",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Subcommand: reachability
# ---------------------------------------------------------------------------

def cmd_reachability(args: argparse.Namespace) -> int:
    """Ping all hosts and report which are up/down."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv

    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(
        config, hosts, force=args.force,
    )

    _print_reachability_summary(reachability, hosts)

    return 0


# ---------------------------------------------------------------------------
# Subcommand: sshfp
# ---------------------------------------------------------------------------

def cmd_sshfp(args: argparse.Namespace) -> int:
    """Scan hosts for SSH fingerprints."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.sshfp import (
        enrich_hosts_with_sshfp,
        scan_sshfp,
    )

    # We need a minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    cache_path = Path(config.cache.directory) / "sshfp.json"
    sshfp_data = scan_sshfp(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    enrich_hosts_with_sshfp(hosts, sshfp_data)

    # Report
    hosts_with_fp = sum(1 for h in hosts if h.sshfp_records)
    print(f"\nSSHFP records for {hosts_with_fp}/{len(hosts)} hosts.")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: ssl-certs
# ---------------------------------------------------------------------------

def cmd_ssl_certs(args: argparse.Namespace) -> int:
    """Scan hosts for SSL/TLS certificates."""
    config = _load_config(args)

    from gdoc2netcfg.constraints.ssl_validation import (
        format_ssl_validation_report,
        validate_ssl_certificates,
    )
    from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.ssl_certs import (
        enrich_hosts_with_ssl_certs,
        scan_ssl_certs,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    # Derive DNS names for validation comparison
    for host in hosts:
        derive_all_dns_names(host, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    cache_path = Path(config.cache.directory) / "ssl_certs.json"
    cert_data = scan_ssl_certs(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    enrich_hosts_with_ssl_certs(hosts, cert_data)

    # Report scan results
    hosts_with_cert = sum(1 for h in hosts if h.ssl_cert_info is not None)
    print(f"SSL certificates for {hosts_with_cert}/{len(hosts)} hosts.")

    # Run validation and print report
    validation_result = validate_ssl_certificates(hosts)
    if validation_result.violations:
        print()
        print(format_ssl_validation_report(validation_result))

    return 0


# ---------------------------------------------------------------------------
# Subcommand: snmp-host
# ---------------------------------------------------------------------------

def cmd_snmp_host(args: argparse.Namespace) -> int:
    """Scan hosts for SNMP system info and interfaces."""
    config = _load_config(args)

    from gdoc2netcfg.constraints.snmp_validation import validate_snmp_availability
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bmc_firmware import (
        enrich_hosts_with_bmc_firmware,
        refine_bmc_hardware_type,
        scan_bmc_firmware,
    )
    from gdoc2netcfg.supplements.snmp import (
        enrich_hosts_with_snmp,
        scan_snmp,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    # Scan BMC firmware and reclassify legacy BMCs before SNMP
    bmc_fw_cache = Path(config.cache.directory) / "bmc_firmware.json"
    print("\nScanning BMC firmware...", file=sys.stderr)
    bmc_fw_data = scan_bmc_firmware(
        hosts,
        cache_path=bmc_fw_cache,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )
    enrich_hosts_with_bmc_firmware(hosts, bmc_fw_data)
    refine_bmc_hardware_type(hosts)

    cache_path = Path(config.cache.directory) / "snmp.json"
    print("\nScanning SNMP...", file=sys.stderr)
    snmp_data = scan_snmp(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    enrich_hosts_with_snmp(hosts, snmp_data)

    # Run validation
    validation_result = validate_snmp_availability(hosts, reachability)

    # Report
    hosts_with_snmp = sum(1 for h in hosts if h.snmp_data is not None)
    hosts_up = sum(1 for r in reachability.values() if r.is_up)
    print(f"\nSNMP data for {hosts_with_snmp}/{len(hosts)} hosts "
          f"({hosts_up} reachable).")

    if validation_result.violations:
        print()
        print(validation_result.report())

    return 1 if validation_result.has_errors else 0


# Subcommand: bmc-firmware
# ---------------------------------------------------------------------------

def cmd_bmc_firmware(args: argparse.Namespace) -> int:
    """Scan BMCs for firmware information."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.hardware import (
        HARDWARE_SUPERMICRO_BMC,
        HARDWARE_SUPERMICRO_BMC_LEGACY,
    )
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bmc_firmware import (
        enrich_hosts_with_bmc_firmware,
        refine_bmc_hardware_type,
        scan_bmc_firmware,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    # Scan BMC firmware
    cache_path = Path(config.cache.directory) / "bmc_firmware.json"
    print("\nScanning BMC firmware...", file=sys.stderr)
    fw_data = scan_bmc_firmware(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    # Enrich and refine
    enrich_hosts_with_bmc_firmware(hosts, fw_data)
    refine_bmc_hardware_type(hosts)

    # Report
    bmcs_total = sum(
        1 for h in hosts
        if h.hardware_type in (HARDWARE_SUPERMICRO_BMC, HARDWARE_SUPERMICRO_BMC_LEGACY)
    )
    bmcs_with_info = sum(1 for h in hosts if h.bmc_firmware_info is not None)
    legacy_count = sum(
        1 for h in hosts if h.hardware_type == HARDWARE_SUPERMICRO_BMC_LEGACY
    )

    print(f"\nBMC firmware info for {bmcs_with_info}/{bmcs_total} BMCs.")
    if legacy_count > 0:
        print(f"{legacy_count} legacy BMC(s) detected (X9 or earlier, no SNMP).")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: snmp-switch
# ---------------------------------------------------------------------------

def cmd_snmp_switch(args: argparse.Namespace) -> int:
    """Scan switches for bridge/topology data via SNMP."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bridge import (
        enrich_hosts_with_bridge_data,
        scan_bridge,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    cache_path = Path(config.cache.directory) / "bridge.json"
    print("\nScanning bridge data...", file=sys.stderr)
    bridge_data = scan_bridge(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    enrich_hosts_with_bridge_data(hosts, bridge_data)

    # Run bridge validations
    from gdoc2netcfg.constraints.bridge_validation import (
        validate_lldp_topology,
        validate_mac_connectivity,
        validate_vlan_names,
    )
    from gdoc2netcfg.derivations.host_builder import build_inventory

    inventory = build_inventory(hosts, config.site)

    vlan_result = validate_vlan_names(hosts, config.site)
    mac_result = validate_mac_connectivity(inventory)
    lldp_result = validate_lldp_topology(inventory)

    # Report
    switches_with_data = sum(1 for h in hosts if h.bridge_data is not None)
    total_macs = sum(
        len(h.bridge_data.mac_table) for h in hosts if h.bridge_data is not None
    )
    print(f"\nBridge data for {switches_with_data} switches "
          f"({total_macs} MAC table entries).")

    # Report validation results
    has_errors = False
    validations = [
        ("VLAN names", vlan_result),
        ("MAC connectivity", mac_result),
        ("LLDP topology", lldp_result),
    ]
    for name, vr in validations:
        if vr.violations:
            print(f"\n{name}:")
            print(vr.report())
        if vr.has_errors:
            has_errors = True

    return 1 if has_errors else 0


# ---------------------------------------------------------------------------
# Subcommand: bridge scan
# ---------------------------------------------------------------------------

def cmd_bridge_scan(args: argparse.Namespace) -> int:
    """Scan all switches (SNMP + NSDP) and validate."""
    config = _load_config(args)

    from gdoc2netcfg.constraints.bridge_validation import (
        validate_lldp_topology,
        validate_mac_connectivity,
        validate_vlan_names,
    )
    from gdoc2netcfg.derivations.host_builder import build_hosts, build_inventory
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bridge import (
        enrich_hosts_with_bridge_data,
        scan_bridge,
    )
    from gdoc2netcfg.supplements.nsdp import (
        enrich_hosts_with_nsdp,
        scan_nsdp,
    )

    # Build hosts from cached CSVs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    # SNMP bridge scan
    bridge_cache = Path(config.cache.directory) / "bridge.json"
    print("\nScanning bridge data via SNMP...", file=sys.stderr)
    bridge_data = scan_bridge(
        hosts,
        cache_path=bridge_cache,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )
    enrich_hosts_with_bridge_data(hosts, bridge_data)

    # NSDP scan
    nsdp_cache = Path(config.cache.directory) / "nsdp.json"
    print("\nScanning switches via NSDP...", file=sys.stderr)
    nsdp_data = scan_nsdp(
        hosts,
        cache_path=nsdp_cache,
        force=args.force,
        verbose=True,
    )
    enrich_hosts_with_nsdp(hosts, nsdp_data)

    # Run bridge validations
    inventory = build_inventory(hosts, config.site)
    vlan_result = validate_vlan_names(hosts, config.site)
    mac_result = validate_mac_connectivity(inventory)
    lldp_result = validate_lldp_topology(inventory)

    total = sum(1 for h in hosts if h.switch_data is not None)
    print(f"\n{total} switch(es) with data.")

    # Report validation results
    has_errors = False
    validations = [
        ("VLAN names", vlan_result),
        ("MAC connectivity", mac_result),
        ("LLDP topology", lldp_result),
    ]
    for name, vr in validations:
        if vr.violations:
            print(f"\n{name}:")
            print(vr.report())
        if vr.has_errors:
            has_errors = True

    return 1 if has_errors else 0


# ---------------------------------------------------------------------------
# Subcommand: bridge show
# ---------------------------------------------------------------------------

def cmd_bridge_show(args: argparse.Namespace) -> int:
    """Show cached switch data from all sources."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bridge import enrich_hosts_with_bridge_data
    from gdoc2netcfg.supplements.nsdp import enrich_hosts_with_nsdp, load_nsdp_cache
    from gdoc2netcfg.supplements.snmp_common import load_json_cache

    # Build hosts from cached CSVs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    # Load SNMP bridge cache
    bridge_cache_path = Path(config.cache.directory) / "bridge.json"
    bridge_cache = load_json_cache(bridge_cache_path)
    enrich_hosts_with_bridge_data(hosts, bridge_cache)

    # Load NSDP cache
    nsdp_cache_path = Path(config.cache.directory) / "nsdp.json"
    nsdp_cache = load_nsdp_cache(nsdp_cache_path)
    enrich_hosts_with_nsdp(hosts, nsdp_cache)

    # Collect switches that have unified switch_data
    switches = [h for h in hosts if h.switch_data is not None]

    if not switches:
        print("No switch data cached. Run 'gdoc2netcfg bridge scan' first.")
        return 1

    switches.sort(key=lambda h: h.hostname)

    for host in switches:
        print(f"\n{'='*60}")
        print(host.hostname)
        print("=" * 60)
        _print_switch_data(host.switch_data)

    print(f"\n{len(switches)} switch(es).")
    return 0


# Port name prefixes that identify virtual/internal interfaces
_VIRTUAL_PORT_PREFIXES = ("po", "lag ", "cpu ", "tunnel", "loopback", "logical")


def _human_bytes(n: int) -> str:
    """Format byte count as compact human-readable string."""
    if n < 1_000:
        return f"{n} B"
    if n < 10_000:
        return f"{n / 1_000:.1f} K"
    if n < 1_000_000:
        return f"{n / 1_000:.0f} K"
    if n < 10_000_000:
        return f"{n / 1_000_000:.1f} M"
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.0f} M"
    if n < 10_000_000_000:
        return f"{n / 1_000_000_000:.1f} G"
    return f"{n / 1_000_000_000:.0f} G"


def _is_physical_port(port_id: int, port_name: str | None) -> bool:
    """Return True for physical ports, False for virtual interfaces."""
    if port_name is not None:
        name_lower = port_name.lower()
        if any(name_lower.startswith(p) for p in _VIRTUAL_PORT_PREFIXES):
            return False
    # VLAN SVIs on Cisco use ifIndex >= 100000
    return port_id < 100000


def _natural_sort_key(name: str) -> list:
    """Sort key for names with embedded numbers (gi2 before gi10)."""
    return [
        int(part) if part.isdigit() else part.lower()
        for part in re.split(r"(\d+)", name)
    ]


def _print_switch_data(data: SwitchData) -> None:
    """Print unified switch data, grouped per-port."""
    _POE_ADMIN = {1: "enabled", 2: "disabled"}
    _POE_DETECT = {
        1: "disabled", 2: "searching", 3: "delivering",
        4: "fault", 5: "test", 6: "other-fault",
    }

    # Build port_id -> port_name mapping from port_status
    port_names: dict[int, str] = {
        ps.port_id: ps.port_name
        for ps in data.port_status
        if ps.port_name
    }

    def label_for(pid: int) -> str:
        return port_names.get(pid, f"Port {pid}")

    # Filter to physical ports only and sort naturally
    physical = [
        ps for ps in data.port_status
        if _is_physical_port(ps.port_id, ps.port_name)
    ]
    physical.sort(
        key=lambda ps: (
            _natural_sort_key(ps.port_name) if ps.port_name
            else [ps.port_id]
        )
    )

    # Build per-port lookup tables
    pvid_map = dict(data.port_pvids)
    stats_map = {ps.port_id: ps for ps in data.port_stats}

    lldp_map: dict[int, list[tuple[str, str, str]]] = {}
    if data.lldp_neighbors:
        for port_id, rsys, rport, rmac in data.lldp_neighbors:
            lldp_map.setdefault(port_id, []).append(
                (rsys, rport, rmac)
            )

    poe_map: dict[int, tuple[int, int]] = {}
    if data.poe_status:
        for port_id, admin, detect in data.poe_status:
            poe_map[port_id] = (admin, detect)

    macs_map: dict[int, set[str]] = {}
    if data.mac_table:
        for mac, _vlan_id, port_id, _port_name in data.mac_table:
            macs_map.setdefault(port_id, set()).add(mac)

    # Device info
    if data.model:
        print(f"Model:    {data.model}")
    if data.firmware_version:
        print(f"Firmware: {data.firmware_version}")
    if data.port_count is not None:
        print(f"Ports:    {data.port_count}")
    if data.serial_number:
        print(f"Serial:   {data.serial_number}")

    # Per-port display
    if physical:
        max_lbl = max(len(label_for(ps.port_id)) for ps in physical)
        indent = " " * (max_lbl + 4)

        print("\nPorts:")
        for ps in physical:
            lbl = label_for(ps.port_id)
            pvid = pvid_map.get(ps.port_id)

            if ps.is_up:
                link_part = f"UP {ps.speed_mbps:>5d} Mbps"
            else:
                link_part = "DOWN"

            pvid_str = (
                f"  VLAN {pvid:4d}" if pvid is not None else ""
            )

            # Traffic stats inline (human-readable)
            stats = stats_map.get(ps.port_id)
            if stats and (stats.bytes_rx or stats.bytes_tx):
                err = f"  Err {stats.errors}" if stats.errors else ""
                rx = _human_bytes(stats.bytes_rx)
                tx = _human_bytes(stats.bytes_tx)
                stats_str = f"  RX {rx:>5s}  TX {tx:>5s}{err}"
            else:
                stats_str = ""

            print(
                f"  {lbl:<{max_lbl}}  {link_part:<13s}"
                f"{pvid_str}{stats_str}"
            )

            # PoE sub-line
            poe = poe_map.get(ps.port_id)
            if poe:
                admin_str = _POE_ADMIN.get(poe[0], str(poe[0]))
                detect_str = _POE_DETECT.get(poe[1], str(poe[1]))
                print(f"{indent}PoE: {admin_str}/{detect_str}")

            # LLDP sub-lines
            for rsys, rport, rmac in lldp_map.get(ps.port_id, []):
                if rsys:
                    print(
                        f"{indent}LLDP: {rsys} "
                        f"port={rport} mac={rmac}"
                    )
                else:
                    print(f"{indent}LLDP: mac={rmac} port={rport}")

            # MAC count sub-line
            unique_macs = macs_map.get(ps.port_id)
            if unique_macs:
                n = len(unique_macs)
                if n <= 3:
                    for mac in sorted(unique_macs):
                        print(f"{indent}MAC: {mac}")
                else:
                    print(f"{indent}MACs: {n} learned")

    # VLANs (switch-wide) — translate port IDs to names, filter virtual
    physical_ids = {ps.port_id for ps in physical}
    if data.vlans:

        def _port_set_str(ports: frozenset[int]) -> str:
            named = sorted(
                (label_for(p) for p in ports if p in physical_ids),
                key=_natural_sort_key,
            )
            return ",".join(named)

        print("\nVLANs:")
        for vlan in sorted(data.vlans, key=lambda v: v.vlan_id):
            members = _port_set_str(vlan.member_ports)
            if vlan.name:
                header = f"  VLAN {vlan.vlan_id:4d} {vlan.name!r}"
            else:
                header = f"  VLAN {vlan.vlan_id:4d}"
            parts = [f"{header}: members={{{members}}}"]
            if vlan.tagged_ports:
                parts.append(
                    f"tagged={{{_port_set_str(vlan.tagged_ports)}}}"
                )
            if vlan.untagged_ports:
                parts.append(
                    f"untagged={{{_port_set_str(vlan.untagged_ports)}}}"
                )
            print(" ".join(parts))

    # Switch Config (fields available from NSDP)
    config_items: list[tuple[str, str]] = []
    if data.vlan_engine is not None:
        _VLAN_ENGINE = {
            0: "Disabled", 1: "Basic Port-Based",
            4: "Advanced 802.1Q",
        }
        config_items.append(
            ("VLAN Engine", _VLAN_ENGINE.get(
                data.vlan_engine, str(data.vlan_engine)
            ))
        )
    if data.qos_engine is not None:
        _QOS_ENGINE = {
            0: "Disabled", 1: "Port-Based", 2: "802.1p",
        }
        config_items.append(
            ("QoS Engine", _QOS_ENGINE.get(
                data.qos_engine, str(data.qos_engine)
            ))
        )
    if data.port_mirroring_dest is not None:
        if data.port_mirroring_dest == 0:
            mirror_str = "Disabled"
        else:
            mirror_str = f"Port {data.port_mirroring_dest}"
        config_items.append(("Port Mirroring", mirror_str))
    if data.igmp_snooping_enabled is not None:
        config_items.append((
            "IGMP Snooping",
            "Enabled" if data.igmp_snooping_enabled else "Disabled",
        ))
    if data.broadcast_filtering is not None:
        config_items.append((
            "Broadcast Filtering",
            "Enabled" if data.broadcast_filtering else "Disabled",
        ))
    if data.loop_detection is not None:
        config_items.append((
            "Loop Detection",
            "Enabled" if data.loop_detection else "Disabled",
        ))

    if config_items:
        print("\nSwitch Config:")
        max_label = max(len(label) for label, _ in config_items)
        for label, value in config_items:
            print(f"  {label:<{max_label}}  {value}")


# ---------------------------------------------------------------------------
# Subcommand: nsdp scan
# ---------------------------------------------------------------------------

def cmd_nsdp_scan(args: argparse.Namespace) -> int:
    """Scan Netgear switches via NSDP unicast queries."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.nsdp import (
        NSDP_HARDWARE_TYPES,
        enrich_hosts_with_nsdp,
        scan_nsdp,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    cache_path = Path(config.cache.directory) / "nsdp.json"
    nsdp_data = scan_nsdp(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
    )

    enrich_hosts_with_nsdp(hosts, nsdp_data)

    # Report - count only Netgear switches
    netgear_hosts = [h for h in hosts if h.hardware_type in NSDP_HARDWARE_TYPES]
    hosts_with_nsdp = sum(1 for h in netgear_hosts if h.nsdp_data is not None)
    print(f"\nNSDP data for {hosts_with_nsdp}/{len(netgear_hosts)} Netgear switches.")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: nsdp show
# ---------------------------------------------------------------------------

def cmd_nsdp_show(args: argparse.Namespace) -> int:
    """Show cached NSDP data for Netgear switches."""
    config = _load_config(args)

    from gdoc2netcfg.supplements.nsdp import load_nsdp_cache

    cache_path = Path(config.cache.directory) / "nsdp.json"
    nsdp_data = load_nsdp_cache(cache_path)

    if not nsdp_data:
        print("No NSDP data cached. Run 'gdoc2netcfg nsdp scan' first.")
        return 1

    for hostname in sorted(nsdp_data.keys()):
        data = nsdp_data[hostname]
        print(f"\n{'='*60}")
        print(f"{hostname}")
        print("=" * 60)
        print(f"Model:    {data.get('model', '?')}")
        print(f"MAC:      {data.get('mac', '?')}")
        print(f"Hostname: {data.get('hostname', '?')}")
        print(f"IP:       {data.get('ip', '?')}")
        print(f"Netmask:  {data.get('netmask', '?')}")
        print(f"Gateway:  {data.get('gateway', '?')}")
        print(f"Firmware: {data.get('firmware_version', '?')}")
        print(f"DHCP:     {data.get('dhcp_enabled', '?')}")
        print(f"Ports:    {data.get('port_count', '?')}")
        print(f"Serial:   {data.get('serial_number', '?')}")

        port_status = data.get("port_status", [])
        if port_status:
            from nsdp.types import LinkSpeed

            print("\nPort Status:")
            for port_id, speed_val in port_status:
                speed = LinkSpeed.from_byte(speed_val)
                print(f"  Port {port_id:2d}: {speed.name}")

        port_pvids = data.get("port_pvids", [])
        if port_pvids:
            print("\nPort PVIDs:")
            for port_id, vlan_id in port_pvids:
                print(f"  Port {port_id:2d}: VLAN {vlan_id}")

        # VLAN memberships
        vlan_members = data.get("vlan_members", [])
        if vlan_members:
            print("\nVLAN Memberships:")
            for vlan_id, members, tagged in vlan_members:
                untagged = set(members) - set(tagged)
                print(f"  VLAN {vlan_id:3d}: members={sorted(members)}")
                if tagged:
                    print(f"            tagged={sorted(tagged)}")
                if untagged:
                    print(f"            untagged={sorted(untagged)}")

        # Port statistics
        port_statistics = data.get("port_statistics", [])
        if port_statistics:
            print("\nPort Statistics:")
            for port_id, rx, tx, errors in port_statistics:
                print(f"  Port {port_id:2d}: RX={rx:,} TX={tx:,} Errors={errors}")

    print(f"\n{len(nsdp_data)} switch(es) in cache.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: tasmota scan
# ---------------------------------------------------------------------------

def cmd_tasmota_scan(args: argparse.Namespace) -> int:
    """Scan for Tasmota devices on the IoT VLAN."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.tasmota import (
        enrich_hosts_with_tasmota,
        match_unknown_devices,
        scan_tasmota,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    cache_path = Path(config.cache.directory) / "tasmota.json"
    tasmota_data = scan_tasmota(
        hosts,
        cache_path=cache_path,
        site=config.site,
        force=args.force,
        verbose=True,
    )

    enrich_hosts_with_tasmota(hosts, tasmota_data)

    # Report
    iot_hosts = [h for h in hosts if h.sheet_type == "IoT"]
    hosts_with_data = sum(1 for h in iot_hosts if h.tasmota_data is not None)
    from gdoc2netcfg.supplements.tasmota import _UNKNOWN_PREFIX, _unknown_key

    unknown = [k for k in tasmota_data if k.startswith(_UNKNOWN_PREFIX)]
    print(f"\nTasmota data for {hosts_with_data}/{len(iot_hosts)} IoT hosts.")

    if unknown:
        print(f"\n{len(unknown)} unknown device(s) found on subnet:")
        matches = match_unknown_devices(hosts, tasmota_data)
        for ip, matched in matches:
            name = tasmota_data.get(_unknown_key(ip), {}).get("device_name", "?")
            mac = tasmota_data.get(_unknown_key(ip), {}).get("mac", "?")
            if matched:
                print(f"  {ip} — {name} (MAC {mac}) → matches {matched}")
            else:
                print(f"  {ip} — {name} (MAC {mac}) — not in spreadsheet")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: tasmota show
# ---------------------------------------------------------------------------

def cmd_tasmota_show(args: argparse.Namespace) -> int:
    """Show cached Tasmota device data."""
    config = _load_config(args)

    from gdoc2netcfg.supplements.tasmota import load_tasmota_cache

    cache_path = Path(config.cache.directory) / "tasmota.json"
    tasmota_data = load_tasmota_cache(cache_path)

    if not tasmota_data:
        print("No Tasmota data cached. Run 'gdoc2netcfg tasmota scan' first.")
        return 1

    # Separate known vs unknown
    from gdoc2netcfg.supplements.tasmota import _UNKNOWN_PREFIX

    known = {k: v for k, v in tasmota_data.items() if not k.startswith(_UNKNOWN_PREFIX)}
    unknown = {k: v for k, v in tasmota_data.items() if k.startswith(_UNKNOWN_PREFIX)}

    for hostname, data in sorted(known.items(), key=lambda kv: _natural_sort_key(kv[1].get("device_name", ""))):
        print(f"\n{'='*60}")
        print(f"{hostname}")
        print("=" * 60)
        print(f"  Device Name:  {data.get('device_name', '?')}")
        print(f"  Friendly:     {data.get('friendly_name', '?')}")
        print(f"  Hostname:     {data.get('hostname', '?')}")
        print(f"  IP:           {data.get('ip', '?')}")
        print(f"  MAC:          {data.get('mac', '?')}")
        print(f"  Firmware:     {data.get('firmware_version', '?')}")
        print(f"  Module:       {data.get('module', '?')}")
        print(f"  Uptime:       {data.get('uptime', '?')}")
        print(f"  WiFi SSID:    {data.get('wifi_ssid', '?')}")
        print(f"  WiFi RSSI:    {data.get('wifi_rssi', '?')}%")
        print(f"  WiFi Signal:  {data.get('wifi_signal', '?')} dBm")
        print(f"  MQTT Host:    {data.get('mqtt_host', '?')}")
        print(f"  MQTT Port:    {data.get('mqtt_port', '?')}")
        print(f"  MQTT Topic:   {data.get('mqtt_topic', '?')}")
        print(f"  MQTT Client:  {data.get('mqtt_client', '?')}")

    if unknown:
        print(f"\n{'='*60}")
        print("Unknown devices (not in spreadsheet)")
        print("=" * 60)
        for key in sorted(unknown.keys()):
            ip = key[len(_UNKNOWN_PREFIX):]
            data = unknown[key]
            name = data.get("device_name", "?")
            mac = data.get("mac", "?")
            fw = data.get("firmware_version", "?")
            print(f"  {ip:15s}  {name:20s}  MAC={mac}  fw={fw}")

    print(f"\n{len(known)} known + {len(unknown)} unknown device(s) in cache.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: tasmota configure
# ---------------------------------------------------------------------------

def cmd_tasmota_configure(args: argparse.Namespace) -> int:
    """Push configuration to Tasmota devices."""
    config = _load_config(args)

    if not args.host and not args.configure_all:
        print("Error: specify a hostname or use --all", file=sys.stderr)
        return 1

    if not config.tasmota.mqtt_host:
        print(
            "Error: [tasmota] mqtt_host not configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.tasmota import (
        enrich_hosts_with_tasmota,
        load_tasmota_cache,
    )
    from gdoc2netcfg.supplements.tasmota_configure import (
        configure_all_tasmota_devices,
        configure_tasmota_device,
    )

    # Minimal pipeline to get hosts
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    cache_path = Path(config.cache.directory) / "tasmota.json"
    tasmota_cache = load_tasmota_cache(cache_path)
    enrich_hosts_with_tasmota(hosts, tasmota_cache)

    dry_run = args.dry_run
    force = args.force

    if args.configure_all:
        tasmota_hosts = sorted(
            [h for h in hosts if h.tasmota_data is not None],
            key=lambda h: _natural_sort_key(h.tasmota_data.device_name if h.tasmota_data else h.hostname),
        )
        success, fail = configure_all_tasmota_devices(
            tasmota_hosts, config.tasmota, dry_run=dry_run, verbose=True,
            force=force,
        )
        print(f"\n{success} succeeded, {fail} failed.")
        return 1 if fail > 0 else 0
    else:
        # Find the specific host
        target = None
        for h in hosts:
            if h.hostname == args.host or h.machine_name == args.host:
                target = h
                break
        if target is None:
            print(f"Error: host '{args.host}' not found", file=sys.stderr)
            return 1
        if target.tasmota_data is None:
            print(
                f"Error: no Tasmota data for '{args.host}'. Run 'tasmota scan' first.",
                file=sys.stderr,
            )
            return 1
        ok = configure_tasmota_device(
            target, config.tasmota, dry_run=dry_run, verbose=True,
            force=force,
        )
        return 0 if ok else 1


# ---------------------------------------------------------------------------
# Subcommand: tasmota ha-status
# ---------------------------------------------------------------------------

def cmd_tasmota_ha_status(args: argparse.Namespace) -> int:
    """Check Home Assistant integration for Tasmota devices."""
    config = _load_config(args)

    if not config.homeassistant.url or not config.homeassistant.token:
        print(
            "Error: [homeassistant] url and token must be configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    from gdoc2netcfg.supplements.tasmota_ha import check_ha_status

    # _build_pipeline already loads tasmota cache and enriches hosts
    _records, hosts, _inventory, _result = _build_pipeline(config)

    tasmota_hosts = [h for h in hosts if h.tasmota_data is not None]
    if not tasmota_hosts:
        print("No Tasmota devices found. Run 'tasmota scan' first.")
        return 1

    ha_status = check_ha_status(tasmota_hosts, config.homeassistant, verbose=True)

    ok = sum(1 for s in ha_status.values() if s.get("exists"))
    total = len(ha_status)
    print(f"\n{ok}/{total} Tasmota devices registered in Home Assistant.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: password
# ---------------------------------------------------------------------------

def cmd_password(args: argparse.Namespace) -> int:
    """Look up device credentials by hostname, IP, or MAC."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.utils.lookup import (
        available_credential_fields,
        get_credential_fields,
        lookup_host,
        suggest_matches,
    )

    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    results = lookup_host(args.query, hosts)

    if not results:
        print(f"Error: no device found matching '{args.query}'", file=sys.stderr)
        suggestions = suggest_matches(args.query, hosts)
        if suggestions:
            print("Did you mean?", file=sys.stderr)
            for s in suggestions:
                print(f"  {s}", file=sys.stderr)
        return 1

    if len(results) > 1:
        print(
            f"Note: {len(results)} matches found, using best match.",
            file=sys.stderr,
        )

    best = results[0]
    host = best.host

    cred = get_credential_fields(
        host, args.credential_type, args.field_name,
    )

    if not cred:
        what = args.field_name or args.credential_type or "password"
        print(
            f"Error: no '{what}' credential found for {host.hostname}",
            file=sys.stderr,
        )
        available = available_credential_fields(host)
        if available:
            print("Available fields:", file=sys.stderr)
            for f in available:
                print(f"  {f}", file=sys.stderr)
        return 1

    if args.quiet:
        for value in cred.values():
            print(value)
    else:
        print(f"Host:       {host.hostname}")
        if host.default_ipv4:
            print(f"IP:         {host.default_ipv4}")
        if host.all_macs:
            print(f"MAC:        {host.all_macs[0]}")
        print(f"Matched by: {best.match_detail}")
        print()
        for field_name, value in cred.items():
            print(f"{field_name}: {value}")

    return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="gdoc2netcfg",
        description="Generate network config files from Google Spreadsheet data.",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to gdoc2netcfg.toml (default: ./gdoc2netcfg.toml)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # fetch
    subparsers.add_parser("fetch", help="Download CSVs from Google Sheets to cache")

    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate config files")
    gen_parser.add_argument(
        "generators", nargs="*",
        help="Generator names to run (default: all enabled)",
    )
    gen_parser.add_argument(
        "--output-dir",
        help="Base directory to prepend to all relative output paths",
    )
    gen_parser.add_argument(
        "--stdout", action="store_true",
        help="Print output to stdout instead of writing files",
    )
    gen_parser.add_argument(
        "--force", action="store_true",
        help="Generate even if validation errors exist",
    )

    # validate
    subparsers.add_parser("validate", help="Run constraint validation")

    # info
    subparsers.add_parser("info", help="Show pipeline configuration")

    # reachability
    reach_parser = subparsers.add_parser("reachability", help="Ping all hosts and report up/down")
    reach_parser.add_argument(
        "--force", action="store_true",
        help="Force re-ping even if .cache/reachability.json is <5 min old",
    )

    # sshfp
    sshfp_parser = subparsers.add_parser("sshfp", help="Scan hosts for SSH fingerprints")
    sshfp_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # ssl-certs
    ssl_parser = subparsers.add_parser("ssl-certs", help="Scan hosts for SSL/TLS certificates")
    ssl_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # snmp-host
    snmp_parser = subparsers.add_parser(
        "snmp-host", help="Scan hosts for SNMP system info and interfaces",
    )
    snmp_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # bmc-firmware
    bmc_parser = subparsers.add_parser("bmc-firmware", help="Scan BMCs for firmware info")
    bmc_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # snmp-switch
    snmp_switch_parser = subparsers.add_parser(
        "snmp-switch", help="Scan switches for bridge/topology data via SNMP",
    )
    snmp_switch_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # cron
    cron_parser = subparsers.add_parser("cron", help="Manage scheduled cron jobs")
    cron_subparsers = cron_parser.add_subparsers(dest="cron_command")
    cron_subparsers.add_parser("show", help="Display cron entries that would be installed")
    cron_subparsers.add_parser("install", help="Install cron entries into user's crontab")
    cron_subparsers.add_parser("uninstall", help="Remove gdoc2netcfg cron entries from crontab")

    # bridge (unified switch data: SNMP + NSDP)
    bridge_parser = subparsers.add_parser(
        "bridge", help="Unified switch data (SNMP + NSDP)",
    )
    bridge_subparsers = bridge_parser.add_subparsers(dest="bridge_command")

    bridge_scan_parser = bridge_subparsers.add_parser(
        "scan", help="Scan all switches and validate",
    )
    bridge_scan_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    bridge_subparsers.add_parser("show", help="Show cached switch data")

    # nsdp (with subcommands)
    nsdp_parser = subparsers.add_parser(
        "nsdp", help="NSDP switch discovery and info",
    )
    nsdp_subparsers = nsdp_parser.add_subparsers(dest="nsdp_command")

    nsdp_scan_parser = nsdp_subparsers.add_parser(
        "scan", help="Scan Netgear switches via NSDP",
    )
    nsdp_scan_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    nsdp_subparsers.add_parser("show", help="Show cached NSDP data")

    # tasmota (with subcommands)
    tasmota_parser = subparsers.add_parser(
        "tasmota", help="Tasmota IoT device management",
    )
    tasmota_subparsers = tasmota_parser.add_subparsers(dest="tasmota_command")

    tasmota_scan_parser = tasmota_subparsers.add_parser(
        "scan", help="Scan for Tasmota devices on IoT VLAN",
    )
    tasmota_scan_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    tasmota_subparsers.add_parser("show", help="Show cached Tasmota data")

    tasmota_configure_parser = tasmota_subparsers.add_parser(
        "configure", help="Push configuration to Tasmota devices",
    )
    tasmota_configure_parser.add_argument(
        "host", nargs="?", default=None,
        help="Hostname to configure (omit with --all for all devices)",
    )
    tasmota_configure_parser.add_argument(
        "--all", action="store_true", dest="configure_all",
        help="Configure all known Tasmota devices",
    )
    tasmota_configure_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without applying",
    )
    tasmota_configure_parser.add_argument(
        "--force", action="store_true",
        help="Apply HA-breaking changes (e.g. Topic rename on connected device)",
    )

    tasmota_subparsers.add_parser(
        "ha-status", help="Check Home Assistant integration status",
    )

    # password (device credential lookup)
    pwd_parser = subparsers.add_parser(
        "password", help="Look up device credentials",
    )
    pwd_parser.add_argument(
        "query", help="Device: hostname, MAC address, or IP address",
    )
    pwd_type_group = pwd_parser.add_mutually_exclusive_group()
    pwd_type_group.add_argument(
        "--type", "-t", dest="credential_type",
        choices=["password", "snmp", "ipmi"], default=None,
        help="Credential type to look up (default: password)",
    )
    pwd_type_group.add_argument(
        "--field", "-f", dest="field_name", default=None,
        help="Arbitrary extra column name to look up",
    )
    pwd_parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Output credential value(s) only (for piping/scripting)",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    from gdoc2netcfg.cli.cron import cmd_cron

    # Handle bridge subcommands
    if args.command == "bridge":
        if args.bridge_command == "scan":
            return cmd_bridge_scan(args)
        elif args.bridge_command == "show":
            return cmd_bridge_show(args)
        else:
            bridge_parser.print_help()
            return 0

    # Handle nsdp subcommands
    if args.command == "nsdp":
        if args.nsdp_command == "scan":
            return cmd_nsdp_scan(args)
        elif args.nsdp_command == "show":
            return cmd_nsdp_show(args)
        else:
            nsdp_parser.print_help()
            return 0

    # Handle tasmota subcommands
    if args.command == "tasmota":
        if args.tasmota_command == "scan":
            return cmd_tasmota_scan(args)
        elif args.tasmota_command == "show":
            return cmd_tasmota_show(args)
        elif args.tasmota_command == "configure":
            return cmd_tasmota_configure(args)
        elif args.tasmota_command == "ha-status":
            return cmd_tasmota_ha_status(args)
        else:
            tasmota_parser.print_help()
            return 0

    commands = {
        "fetch": cmd_fetch,
        "generate": cmd_generate,
        "validate": cmd_validate,
        "info": cmd_info,
        "reachability": cmd_reachability,
        "sshfp": cmd_sshfp,
        "ssl-certs": cmd_ssl_certs,
        "snmp-host": cmd_snmp_host,
        "bmc-firmware": cmd_bmc_firmware,
        "snmp-switch": cmd_snmp_switch,
        "cron": cmd_cron,
        "password": cmd_password,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
