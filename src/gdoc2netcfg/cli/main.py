"""CLI entry point for gdoc2netcfg.

Subcommands:
    fetch          Download CSVs from Google Sheets to local cache.
    generate       Run the pipeline and produce output config files.
    validate       Run constraint checks on the data.
    info           Show pipeline configuration.
    reachability   Host reachability scanning and MQTT publishing.
        scan       Ping all hosts and report which are up/down (default).
        publish    Publish reachability to Home Assistant via MQTT.
    sshfp          Scan hosts for SSH fingerprints.
    known-hosts    Scan hosts for SSH host keys (for known_hosts generation).
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
import sqlite3
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


def _enrich_site_from_sheets(config, csv_data: list[tuple[str, str]]) -> None:
    """Enrich config.site from fetched sheets.

    Coordinator: populates VLANs/subdomains from the VLAN Allocations sheet
    and the valid-site list (all_sites) from the Sites sheet.  The two run
    independently so a missing VLAN sheet never skips the site list.
    """
    _enrich_vlans_from_sheet(config, csv_data)
    _enrich_all_sites_from_sheet(config, csv_data)


def _enrich_vlans_from_sheet(config, csv_data: list[tuple[str, str]]) -> None:
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


def _enrich_all_sites_from_sheet(config, csv_data: list[tuple[str, str]]) -> None:
    """Set Site.all_sites from the Sites sheet (the source of truth).

    No TOML fallback.  If a Sites sheet is configured under [sheets] but is
    unavailable or empty, that is a hard error — an empty all_sites would
    silently disable site validation (see ip_remap._validate_site_values).
    If no Sites sheet is configured at all, all_sites is left empty and site
    validation is simply skipped (the historical optional behaviour).
    """
    from gdoc2netcfg.sources.sites_parser import parse_sites, site_config_drift, site_names

    sites_csv = None
    for name, text in csv_data:
        if name == "sites":
            sites_csv = text
            break

    if sites_csv is None:
        if any(s.name == "sites" for s in config.sheets):
            raise ValueError(
                "Sites sheet is configured under [sheets] but unavailable "
                "(fetch failed and no cache); it is the source of truth for all_sites."
            )
        return  # Not configured: all_sites stays empty, site validation skipped.

    sites = parse_sites(sites_csv)
    if not sites:
        raise ValueError("Sites sheet has no valid site rows (all_sites would be empty).")

    config.site.all_sites = site_names(sites)

    # Shadow-check the per-site TOML against the sheet (not yet authoritative).
    info = next((s for s in sites if s.shortname == config.site.name.lower()), None)
    if info is None:
        print(
            f"Warning: site {config.site.name!r} not found in the Sites sheet",
            file=sys.stderr,
        )
        return
    for d in site_config_drift(config.site, info):
        print(f"Warning: {config.site.name} TOML/sheet drift — {d}", file=sys.stderr)


def _build_hosts_from_csvs(config, csv_data: list[tuple[str, str]]):
    """Parse cached CSVs and build hosts — the shared fetch/password path.

    Both ``cmd_fetch`` (to key credentials by hostname) and ``cmd_password``
    (to match a query) MUST build hosts identically, so the credential
    store's keys line up with lookups.  Skips the vlan_allocations sheet
    (not device records).  Callers must run ``_enrich_site_from_sheets``
    first so hostname derivation has VLAN/site data.
    """
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv

    records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records.extend(parse_csv(csv_text, name))
    return build_hosts(records, config.site)


def _save_to_discovery_db(
    config: PipelineConfig,
    scan_type: str,
    save_method: str,
    data: dict,
) -> None:
    """Save supplement scan results to DiscoveryDB.

    Handles the begin_scan/finish_scan lifecycle and cleans up the
    scan row on failure.  Used by all supplement cmd_* functions.
    """
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    with DiscoveryDB(config.cache.discovery_db_path) as db:
        scan_id = db.begin_scan(scan_type)
        try:
            changed = getattr(db, save_method)(scan_id, data)
            db.finish_scan(
                scan_id,
                host_count=len(data),
                changed_count=changed,
            )
        except Exception:
            db.connection.execute(
                "DELETE FROM scans WHERE id = ?", (scan_id,),
            )
            raise


def _save_reachability_to_db(config: PipelineConfig, reachability: dict) -> None:
    """Save a reachability scan and tombstone vanished hosts.

    Same lifecycle as _save_to_discovery_db, plus the tombstone pass — a
    reachability scan covers every inventory host (up or down), so hosts
    present in the DB's latest state but absent from this scan have been
    removed from the inventory and are tombstoned under the same scan row.
    """
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    with DiscoveryDB(config.cache.discovery_db_path) as db:
        scan_id = db.begin_scan("reachability")
        try:
            changed = db.save_reachability(scan_id, reachability)
            changed += db.tombstone_missing_reachability(
                scan_id, set(reachability),
            )
            db.finish_scan(
                scan_id,
                host_count=len(reachability),
                changed_count=changed,
            )
        except Exception:
            db.connection.execute(
                "DELETE FROM scans WHERE id = ?", (scan_id,),
            )
            raise


def _save_tasmota_to_db(config: PipelineConfig, data: dict) -> None:
    """Save a tasmota scan and tombstone vanished device_keys.

    Mirrors _save_reachability_to_db: a tasmota scan's `data` is the full
    present set (matched hosts, _unknown/<mac> markers, carried-forward
    offline hosts), so keys in the DB's latest state but absent from it have
    been removed from the sheet or left the network, and are tombstoned
    under the same scan row.
    """
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    with DiscoveryDB(config.cache.discovery_db_path) as db:
        scan_id = db.begin_scan("tasmota")
        try:
            changed = db.save_tasmota(scan_id, data)
            changed += db.tombstone_missing_tasmota(scan_id, set(data))
            db.finish_scan(
                scan_id, host_count=len(data), changed_count=changed,
            )
        except Exception:
            db.connection.execute(
                "DELETE FROM scans WHERE id = ?", (scan_id,),
            )
            raise


def _load_latest_from_db(config, loader: str):
    """Load the latest supplement data from the DiscoveryDB — the sole source.

    *loader* names a DiscoveryDB ``load_latest_*`` method.  Returns None
    when the databases don't exist or the supplement has no completed scan.
    """
    db = _open_databases(config)
    if db is None:
        return None
    try:
        return getattr(db.discovery, loader)()
    finally:
        db.close()


_SUPPLEMENT_CACHE_MAX_AGE = 300.0


def _fresh_scan_age(config, scan_type: str) -> float | None:
    """Age of the latest completed *scan_type* scan, if fresh enough to reuse.

    Returns the age in seconds when a completed scan younger than the
    cache window exists, else None (no DBs, no completed scan, or stale)
    — i.e. None means a live scan should run.
    """
    db = _open_databases(config)
    if db is None:
        return None
    try:
        age = db.discovery.latest_scan_age(scan_type)
    finally:
        db.close()
    if age is not None and age < _SUPPLEMENT_CACHE_MAX_AGE:
        return age
    return None


def _open_databases(config):
    """Open both SQLite databases read-only if both exist, returning a pair or None.

    The pipeline only *reads* supplement data, so the databases are opened
    read-only — this works even when they are root-owned and the caller is a
    non-root user.  Both files must exist (a read-only open cannot create a
    missing one); otherwise we fall back to the flat-file caches.
    """
    from gdoc2netcfg.storage import open_databases

    if (
        config.cache.config_db_path.exists()
        and config.cache.discovery_db_path.exists()
    ):
        return open_databases(config.cache.directory, read_only=True)
    return None


def _build_pipeline(config):
    """Run the full build pipeline: parse → derive → validate → enrich.

    Returns (records, hosts, inventory, validation_result).

    Loads supplement data from the SQLite databases — the sole source.
    A supplement with no completed scan in the DB (or absent DBs, e.g. a
    fresh site) contributes no enrichment.
    """
    from gdoc2netcfg.constraints.validators import validate_all
    from gdoc2netcfg.derivations.host_builder import build_hosts, build_inventory
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bmc_firmware import (
        enrich_hosts_with_bmc_firmware,
        refine_bmc_hardware_type,
    )
    from gdoc2netcfg.supplements.snmp import enrich_hosts_with_snmp
    from gdoc2netcfg.supplements.sshfp import enrich_hosts_with_ssh_host_keys
    from gdoc2netcfg.supplements.ssl_certs import enrich_hosts_with_ssl_certs

    db = _open_databases(config)

    try:
        # Fetch or load CSVs
        csv_data = _fetch_or_load_csvs(config, use_cache=True)

        # Enrich site config from VLAN Allocations sheet
        _enrich_site_from_sheets(config, csv_data)

        # Parse device records (exclude vlan_allocations — not a device sheet)
        all_records = []
        for name, csv_text in csv_data:
            if name in ("vlan_allocations", "sites"):
                continue
            records = parse_csv(csv_text, name)
            all_records.extend(records)

        if not all_records:
            print("Error: no device records found in any sheet.", file=sys.stderr)
            sys.exit(1)

        # Build hosts (applies all derivations)
        hosts = build_hosts(all_records, config.site)

        # Build inventory (aggregate derivations)
        inventory = build_inventory(hosts, config.site)

        # Load supplement data from the DB — the sole source.  Each
        # load_latest_* returns None if no completed scan exists; the
        # enrichers tolerate None (no enrichment).  Reachability is not
        # loaded here — it's a live-scan gate loaded separately by
        # cmd_reachability.

        enrich_hosts_with_ssh_host_keys(
            hosts, db.discovery.load_latest_ssh_host_keys() if db else None,
        )
        enrich_hosts_with_ssl_certs(
            hosts, db.discovery.load_latest_ssl_certs() if db else None,
        )
        enrich_hosts_with_bmc_firmware(
            hosts, db.discovery.load_latest_bmc_firmware() if db else None,
        )
        refine_bmc_hardware_type(hosts)
        enrich_hosts_with_snmp(
            hosts, db.discovery.load_latest_snmp() if db else None,
        )

        from gdoc2netcfg.supplements.bridge import enrich_hosts_with_bridge_data

        enrich_hosts_with_bridge_data(
            hosts, db.discovery.load_latest_bridge() if db else None,
        )

        from gdoc2netcfg.supplements.nsdp import enrich_hosts_with_nsdp

        enrich_hosts_with_nsdp(
            hosts, db.discovery.load_latest_nsdp() if db else None,
        )

        from gdoc2netcfg.supplements.tasmota import enrich_hosts_with_tasmota

        enrich_hosts_with_tasmota(
            hosts, db.discovery.load_latest_tasmota() if db else None,
        )

        # Validate
        result = validate_all(all_records, hosts, inventory)

        return all_records, hosts, inventory, result
    finally:
        if db:
            db.close()


# ---------------------------------------------------------------------------
# Subcommand: fetch
# ---------------------------------------------------------------------------

def cmd_fetch(args: argparse.Namespace) -> int:
    """Download CSVs from Google Sheets to local cache.

    Credential columns (CREDENTIAL_TYPES) are stripped out of the
    world-readable cache and stored in the root-only credentials.db.
    """
    config = _load_config(args)

    from gdoc2netcfg.sources.cache import CSVCache
    from gdoc2netcfg.sources.credentials import (
        extract_credentials,
        strip_credential_columns,
    )
    from gdoc2netcfg.sources.sheets import fetch_sheet
    from gdoc2netcfg.storage.config_db import ConfigDB
    from gdoc2netcfg.storage.credentials_db import CredentialsDB

    # 1. Fetch every sheet into memory (raw, with credentials).
    raw_csvs: list[tuple[str, str]] = []
    ok = 0
    fail = 0
    for sheet in config.sheets:
        try:
            data = fetch_sheet(sheet.name, sheet.url)
            raw_csvs.append((sheet.name, data.csv_text))
            print(f"  {sheet.name}: fetched ({len(data.csv_text)} bytes)")
            ok += 1
        except Exception as e:
            print(f"  {sheet.name}: FAILED ({e})", file=sys.stderr)
            fail += 1

    # 2. Strip credential columns from each fetched sheet.
    stripped: list[tuple[str, str, list[str]]] = []
    for name, text in raw_csvs:
        clean, present = strip_credential_columns(text)
        stripped.append((name, clean, present))

    has_credential_columns = any(present for _, _, present in stripped)

    # 3. If a credential-bearing sheet was fetched, store credentials FIRST
    #    (before touching the cache) so a failure leaves old state intact.
    #    Skip entirely when no credential columns were seen this run — never
    #    tombstone credentials on a transient fetch failure of that sheet.
    if has_credential_columns:
        _enrich_site_from_sheets(config, raw_csvs)
        hosts = _build_hosts_from_csvs(config, raw_csvs)
        creds = extract_credentials(hosts)
        with CredentialsDB(config.cache.credentials_db_path) as cred_db:
            scan_id = cred_db.begin_scan("csv_credentials")
            try:
                changed = cred_db.save_credentials(scan_id, creds)
                cred_db.finish_scan(
                    scan_id, host_count=len(hosts), changed_count=changed,
                )
            except Exception:
                cred_db.connection.execute(
                    "DELETE FROM scans WHERE id = ?", (scan_id,),
                )
                raise

    # 4. Write the credential-free CSVs to the flat cache.
    cache = CSVCache(config.cache.directory)
    fetched_csvs: list[tuple[str, str]] = []
    for name, clean, _present in stripped:
        cache.write(name, clean)
        fetched_csvs.append((name, clean))

    # 5. Save the credential-free CSVs to ConfigDB.
    if fetched_csvs:
        with ConfigDB(config.cache.config_db_path) as config_db:
            scan_id = config_db.begin_scan("csv_fetch")
            try:
                for sheet_name, csv_text in fetched_csvs:
                    config_db.save_csv(scan_id, sheet_name, csv_text)
                config_db.finish_scan(
                    scan_id,
                    host_count=len(fetched_csvs),
                    changed_count=len(fetched_csvs),
                )
            except Exception:
                config_db.connection.execute(
                    "DELETE FROM scans WHERE id = ?", (scan_id,),
                )
                raise

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
        "known_hosts": ("gdoc2netcfg.generators.known_hosts", "generate_known_hosts"),
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
    post_gen_errors = False
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

        # Post-generation FCrDNS validation for dnsmasq generators
        if name in ("dnsmasq_internal", "dnsmasq_external") and isinstance(output, dict):
            from gdoc2netcfg.generators.dnsmasq_common import validate_dnsmasq_output

            post_result = validate_dnsmasq_output(output)
            if post_result.has_errors:
                post_gen_errors = True
                print(
                    f"  {name}: post-generation FCrDNS validation errors:",
                    file=sys.stderr,
                )
                print(post_result.report(), file=sys.stderr)
                if not args.force:
                    print(
                        f"  {name}: skipping write (use --force to override)",
                        file=sys.stderr,
                    )
                    continue

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
    return 1 if post_gen_errors else 0


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
    _enrich_site_from_sheets(config, csv_data)

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

    The DiscoveryDB is the sole cache: a fresh scan there (<5 min) is
    reused; otherwise a live scan runs and is saved to the DB.
    """
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB
    from gdoc2netcfg.supplements.reachability import (
        check_all_hosts_reachability,
        parse_reachability_dict,
        print_reachability_status,
    )

    if not force:
        db_path = config.cache.discovery_db_path
        if db_path.exists():
            with DiscoveryDB(db_path) as db:
                age = db.latest_scan_age("reachability")
                if age is not None and age < 300:
                    raw = db.load_latest_reachability()
                    if raw is not None:
                        cached = parse_reachability_dict(raw)
                        print(
                            f"Using cached reachability ({age:.0f}s old).",
                            file=sys.stderr,
                        )
                        print_reachability_status(cached)
                        return cached

    print("Checking host reachability...", file=sys.stderr)
    reachability = check_all_hosts_reachability(hosts, verbose=True)

    _save_reachability_to_db(config, reachability)

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
# Subcommand: reachability scan (default)
# ---------------------------------------------------------------------------

def _reachability_build_hosts(config):
    """Shared helper: build hosts from cached CSVs for reachability commands."""
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv

    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    return build_hosts(all_records, config.site)


def cmd_reachability_scan(args: argparse.Namespace) -> int:
    """Ping all hosts and report which are up/down."""
    config = _load_config(args)
    hosts = _reachability_build_hosts(config)

    reachability = _load_or_run_reachability(
        config, hosts, force=args.force,
    )

    _print_reachability_summary(reachability, hosts)

    return 0


# ---------------------------------------------------------------------------
# Subcommand: reachability publish
# ---------------------------------------------------------------------------

def cmd_reachability_publish(args: argparse.Namespace) -> int:
    """Publish reachability data to Home Assistant via MQTT."""
    config = _load_config(args)

    if not config.homeassistant.mqtt.host:
        print(
            "Error: [homeassistant.mqtt] host not configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    if args.daemon:
        if args.force:
            print(
                "Error: --force cannot be used with --daemon "
                "(daemon always scans fresh)",
                file=sys.stderr,
            )
            return 1
        from gdoc2netcfg.supplements.mqtt_ha import run_daemon

        run_daemon(config, interval=args.interval, verbose=True)
        return 0

    # One-shot mode: build hosts, scan, publish, exit
    hosts = _reachability_build_hosts(config)

    reachability = _load_or_run_reachability(
        config, hosts, force=args.force,
    )
    _print_reachability_summary(reachability, hosts)

    from gdoc2netcfg.supplements.mqtt_ha import publish_all_hosts

    # Enrich hosts with tasmota data for power-plug availability linkage
    from gdoc2netcfg.supplements.tasmota import enrich_hosts_with_tasmota

    enrich_hosts_with_tasmota(
        hosts, _load_latest_from_db(config, "load_latest_tasmota"),
    )

    publish_all_hosts(
        hosts, reachability, config.homeassistant.mqtt, verbose=True,
    )

    return 0


# ---------------------------------------------------------------------------
# Subcommand: sshfp
# ---------------------------------------------------------------------------

def _scan_ssh_host_keys_pipeline(
    config: PipelineConfig, force: bool,
) -> tuple[list[Host], dict[str, list[str]]]:
    """Shared pipeline for sshfp and known-hosts commands.

    Builds hosts, runs reachability, scans SSH host keys, and enriches.
    Returns (hosts, host_keys_data).
    """
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.sshfp import (
        enrich_hosts_with_ssh_host_keys,
        raise_for_ssh_errors,
        scan_ssh_host_keys,
    )

    # We need a minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=force)
    _print_reachability_summary(reachability, hosts)

    age = None if force else _fresh_scan_age(config, "ssh_host_keys")
    if age is not None:
        print(
            f"Using cached ssh_host_keys scan ({age:.0f}s old).",
            file=sys.stderr,
        )
        host_keys_data = (
            _load_latest_from_db(config, "load_latest_ssh_host_keys") or {}
        )
        ssh_errors: list[str] = []
    else:
        host_keys_data, ssh_errors = scan_ssh_host_keys(
            hosts,
            _load_latest_from_db(config, "load_latest_ssh_host_keys"),
            verbose=True,
            reachability=reachability,
        )
        # Persist the hosts that scanned BEFORE failing loud, so a single
        # unscannable host can't discard every good result.
        if host_keys_data:
            _save_to_discovery_db(
                config, "ssh_host_keys", "save_ssh_host_keys", host_keys_data,
            )

    enrich_hosts_with_ssh_host_keys(hosts, host_keys_data)

    raise_for_ssh_errors(ssh_errors)

    return hosts, host_keys_data


def cmd_sshfp(args: argparse.Namespace) -> int:
    """Scan hosts for SSH fingerprints."""
    config = _load_config(args)
    hosts, _ = _scan_ssh_host_keys_pipeline(config, force=args.force)

    # Report
    hosts_with_fp = sum(1 for h in hosts if h.sshfp_records)
    print(f"\nSSHFP records for {hosts_with_fp}/{len(hosts)} hosts.")

    return 0


def cmd_known_hosts(args: argparse.Namespace) -> int:
    """Scan hosts for SSH host keys (for known_hosts generation)."""
    config = _load_config(args)
    hosts, _ = _scan_ssh_host_keys_pipeline(config, force=args.force)

    # Report
    hosts_with_keys = sum(1 for h in hosts if h.ssh_host_keys)
    total_keys = sum(len(h.ssh_host_keys) for h in hosts)
    print(f"\nSSH host keys: {total_keys} keys for {hosts_with_keys}/{len(hosts)} hosts.")

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
    _enrich_site_from_sheets(config, csv_data)
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

    age = None if args.force else _fresh_scan_age(config, "ssl_certs")
    if age is not None:
        print(f"Using cached ssl_certs scan ({age:.0f}s old).", file=sys.stderr)
        cert_data = _load_latest_from_db(config, "load_latest_ssl_certs") or {}
    else:
        cert_data = scan_ssl_certs(
            hosts,
            _load_latest_from_db(config, "load_latest_ssl_certs"),
            verbose=True,
            reachability=reachability,
        )
        if cert_data:
            _save_to_discovery_db(config, "ssl_certs", "save_ssl_certs", cert_data)

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
    _enrich_site_from_sheets(config, csv_data)
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
    age = None if args.force else _fresh_scan_age(config, "bmc_firmware")
    if age is not None:
        print(f"Using cached bmc_firmware scan ({age:.0f}s old).", file=sys.stderr)
        bmc_fw_data = _load_latest_from_db(config, "load_latest_bmc_firmware") or {}
    else:
        print("\nScanning BMC firmware...", file=sys.stderr)
        bmc_fw_data = scan_bmc_firmware(
            hosts,
            _load_latest_from_db(config, "load_latest_bmc_firmware"),
            verbose=True,
            reachability=reachability,
        )
        if bmc_fw_data:
            _save_to_discovery_db(
                config, "bmc_firmware", "save_bmc_firmware", bmc_fw_data,
            )
    enrich_hosts_with_bmc_firmware(hosts, bmc_fw_data)
    refine_bmc_hardware_type(hosts)

    age = None if args.force else _fresh_scan_age(config, "snmp")
    if age is not None:
        print(f"Using cached snmp scan ({age:.0f}s old).", file=sys.stderr)
        snmp_data = _load_latest_from_db(config, "load_latest_snmp") or {}
    else:
        print("\nScanning SNMP...", file=sys.stderr)
        snmp_data = scan_snmp(
            hosts,
            _load_latest_from_db(config, "load_latest_snmp"),
            verbose=True,
            reachability=reachability,
        )
        if snmp_data:
            _save_to_discovery_db(config, "snmp", "save_snmp", snmp_data)

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
    _enrich_site_from_sheets(config, csv_data)
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
    age = None if args.force else _fresh_scan_age(config, "bmc_firmware")
    if age is not None:
        print(f"Using cached bmc_firmware scan ({age:.0f}s old).", file=sys.stderr)
        fw_data = _load_latest_from_db(config, "load_latest_bmc_firmware") or {}
    else:
        print("\nScanning BMC firmware...", file=sys.stderr)
        fw_data = scan_bmc_firmware(
            hosts,
            _load_latest_from_db(config, "load_latest_bmc_firmware"),
            verbose=True,
            reachability=reachability,
        )
        if fw_data:
            _save_to_discovery_db(
                config, "bmc_firmware", "save_bmc_firmware", fw_data,
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
    _enrich_site_from_sheets(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    age = None if args.force else _fresh_scan_age(config, "bridge")
    if age is not None:
        print(f"Using cached bridge scan ({age:.0f}s old).", file=sys.stderr)
        bridge_data = _load_latest_from_db(config, "load_latest_bridge") or {}
    else:
        print("\nScanning bridge data...", file=sys.stderr)
        bridge_data = scan_bridge(
            hosts,
            _load_latest_from_db(config, "load_latest_bridge"),
            verbose=True,
            reachability=reachability,
        )
        if bridge_data:
            _save_to_discovery_db(config, "bridge", "save_bridge", bridge_data)

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
    _enrich_site_from_sheets(config, csv_data)
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
    age = None if args.force else _fresh_scan_age(config, "bridge")
    if age is not None:
        print(f"Using cached bridge scan ({age:.0f}s old).", file=sys.stderr)
        bridge_data = _load_latest_from_db(config, "load_latest_bridge") or {}
    else:
        print("\nScanning bridge data via SNMP...", file=sys.stderr)
        bridge_data = scan_bridge(
            hosts,
            _load_latest_from_db(config, "load_latest_bridge"),
            verbose=True,
            reachability=reachability,
        )
        if bridge_data:
            _save_to_discovery_db(config, "bridge", "save_bridge", bridge_data)
    enrich_hosts_with_bridge_data(hosts, bridge_data)

    # NSDP scan
    age = None if args.force else _fresh_scan_age(config, "nsdp")
    if age is not None:
        print(f"Using cached nsdp scan ({age:.0f}s old).", file=sys.stderr)
        nsdp_data = _load_latest_from_db(config, "load_latest_nsdp") or {}
    else:
        print("\nScanning switches via NSDP...", file=sys.stderr)
        nsdp_data = scan_nsdp(
            hosts,
            _load_latest_from_db(config, "load_latest_nsdp"),
            verbose=True,
            last_changed=_load_latest_from_db(config, "nsdp_last_changed"),
        ).data
        if nsdp_data:
            _save_to_discovery_db(config, "nsdp", "save_nsdp", nsdp_data)
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
    from gdoc2netcfg.supplements.nsdp import enrich_hosts_with_nsdp

    # Build hosts from cached CSVs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    # Load cached switch data (SNMP bridge + NSDP) from the DB
    enrich_hosts_with_bridge_data(
        hosts, _load_latest_from_db(config, "load_latest_bridge"),
    )
    enrich_hosts_with_nsdp(
        hosts, _load_latest_from_db(config, "load_latest_nsdp"),
    )

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
        for port_id, rsys, rport, rmac, rdesc in data.lldp_neighbors:
            # Prefer the neighbour's interface name over its port ID
            # (often just a MAC) for display.
            lldp_map.setdefault(port_id, []).append(
                (rsys, rdesc or rport, rmac)
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

            # Traffic stats inline (human-readable).  Counters the
            # switch doesn't expose are None and shown as "-".
            stats = stats_map.get(ps.port_id)
            if stats and (stats.bytes_rx or stats.bytes_tx):
                err = f"  Err {stats.errors}" if stats.errors else ""
                rx = _human_bytes(stats.bytes_rx) if stats.bytes_rx is not None else "-"
                tx = _human_bytes(stats.bytes_tx) if stats.bytes_tx is not None else "-"
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
    _enrich_site_from_sheets(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    age = None if args.force else _fresh_scan_age(config, "nsdp")
    if age is not None:
        print(f"Using cached nsdp scan ({age:.0f}s old).", file=sys.stderr)
        nsdp_data = _load_latest_from_db(config, "load_latest_nsdp") or {}
        scan_result = None
    else:
        scan_result = scan_nsdp(
            hosts,
            _load_latest_from_db(config, "load_latest_nsdp"),
            verbose=True,
            last_changed=_load_latest_from_db(config, "nsdp_last_changed"),
        )
        nsdp_data = scan_result.data
        if nsdp_data:
            _save_to_discovery_db(config, "nsdp", "save_nsdp", nsdp_data)

    enrich_hosts_with_nsdp(hosts, nsdp_data)

    # Report - count only Netgear switches
    netgear_hosts = [h for h in hosts if h.hardware_type in NSDP_HARDWARE_TYPES]
    hosts_with_nsdp = sum(1 for h in netgear_hosts if h.nsdp_data is not None)
    if scan_result is None:
        print(
            f"\nNSDP data cached for {hosts_with_nsdp}/{len(netgear_hosts)} "
            f"Netgear switches.",
        )
    else:
        print(
            f"\n{len(scan_result.responded)}/{len(scan_result.queried)} "
            f"Netgear switch(es) responded.",
        )

    return 0


# ---------------------------------------------------------------------------
# Subcommand: nsdp show
# ---------------------------------------------------------------------------

def cmd_nsdp_show(args: argparse.Namespace) -> int:
    """Show cached NSDP data for Netgear switches."""
    config = _load_config(args)

    nsdp_data = _load_latest_from_db(config, "load_latest_nsdp")

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

def _report_tasmota_discrepancies(discrepancies: list) -> int:
    """Print discrepancies as clear errors; return the process exit code.

    The spreadsheet is the source of truth, so anything the network shows
    that the sheet doesn't sanction is an error, not a hidden warning.
    """
    if not discrepancies:
        return 0
    print(
        f"\nERROR: {len(discrepancies)} discrepancies vs the spreadsheet "
        f"(the golden source of truth):",
        file=sys.stderr,
    )
    for d in discrepancies:
        print(f"  {d.format()}", file=sys.stderr)
    return 1


def cmd_tasmota_scan(args: argparse.Namespace) -> int:
    """Scan for Tasmota devices on the IoT VLAN."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.tasmota import (
        _UNKNOWN_PREFIX,
        enrich_hosts_with_tasmota,
        scan_tasmota,
    )

    # Minimal pipeline to get hosts with IPs.
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        all_records.extend(parse_csv(csv_text, name))
    hosts = build_hosts(all_records, config.site)

    discrepancies: list = []
    age = None if args.force else _fresh_scan_age(config, "tasmota")
    if age is not None:
        print(f"Using cached tasmota scan ({age:.0f}s old).", file=sys.stderr)
        tasmota_data = _load_latest_from_db(config, "load_latest_tasmota") or {}
    else:
        result = scan_tasmota(
            hosts,
            _load_latest_from_db(config, "load_latest_tasmota"),
            site=config.site,
            verbose=True,
        )
        tasmota_data = result.data
        discrepancies = result.discrepancies
        if tasmota_data:
            _save_tasmota_to_db(config, tasmota_data)

    enrich_hosts_with_tasmota(hosts, tasmota_data)

    iot_hosts = [h for h in hosts if h.sheet_type == "IoT"]
    hosts_with_data = sum(1 for h in iot_hosts if h.tasmota_data is not None)
    unknown = [k for k in tasmota_data if k.startswith(_UNKNOWN_PREFIX)]
    print(
        f"\nTasmota data for {hosts_with_data}/{len(iot_hosts)} IoT hosts; "
        f"{len(unknown)} unknown device(s) on the subnet."
    )

    return _report_tasmota_discrepancies(discrepancies)


# ---------------------------------------------------------------------------
# Subcommand: tasmota show
# ---------------------------------------------------------------------------

def cmd_tasmota_show(args: argparse.Namespace) -> int:
    """Show cached Tasmota device data."""
    config = _load_config(args)

    tasmota_data = _load_latest_from_db(config, "load_latest_tasmota")

    if not tasmota_data:
        print("No Tasmota data cached. Run 'gdoc2netcfg tasmota scan' first.")
        return 1

    # Separate known vs unknown
    from gdoc2netcfg.supplements.tasmota import _UNKNOWN_PREFIX

    known = {k: v for k, v in tasmota_data.items() if not k.startswith(_UNKNOWN_PREFIX)}
    unknown = {k: v for k, v in tasmota_data.items() if k.startswith(_UNKNOWN_PREFIX)}

    for hostname, data in sorted(
        known.items(),
        key=lambda kv: _natural_sort_key(kv[1].get("device_name", "")),
    ):
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
        mqtt_count = data.get("mqtt_count", 0)
        mqtt_warn = "  ** MQTT DISCONNECTED **" if mqtt_count == 0 else ""
        print(f"  MQTT Count:   {mqtt_count}{mqtt_warn}")

    if unknown:
        print(f"\n{'='*60}")
        print("Unknown devices (not in spreadsheet)")
        print("=" * 60)
        for key in sorted(unknown.keys()):
            data = unknown[key]
            ip = data.get("ip", "?")
            name = data.get("device_name", "?")
            mac = data.get("mac", key[len(_UNKNOWN_PREFIX):])
            fw = data.get("firmware_version", "?")
            print(f"  {ip:15s}  {name:20s}  MAC={mac}  fw={fw}")

    print(f"\n{len(known)} known + {len(unknown)} unknown device(s) in cache.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: tasmota configure
# ---------------------------------------------------------------------------

def _tasmota_hosts(config):
    """Enriched host list with tasmota_data attached (same path as configure)."""
    from gdoc2netcfg.supplements.tasmota import enrich_hosts_with_tasmota

    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    hosts = _build_hosts_from_csvs(config, csv_data)
    enrich_hosts_with_tasmota(hosts, _load_latest_from_db(config, "load_latest_tasmota"))
    return hosts


def cmd_tasmota_configure(args: argparse.Namespace) -> int:
    """Push configuration to Tasmota devices."""
    config = _load_config(args)

    if not args.host and not args.configure_all:
        print("Error: specify a hostname or use --all", file=sys.stderr)
        return 1

    if not config.homeassistant.mqtt.host:
        print(
            "Error: [homeassistant.mqtt] host not configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    # Fail loud before deriving: an empty/weak secret would otherwise push a
    # password(secret="", host) credential the broker never accepts, breaking
    # the device's MQTT connection (spec §6, strong-secret guard per consumer).
    from gdoc2netcfg.derivations.mqtt_credentials import require_strong_secret
    try:
        require_strong_secret(config.tasmota.mqtt_secret)
    except ValueError as exc:
        print(f"Error: [tasmota] {exc}", file=sys.stderr)
        return 1

    from gdoc2netcfg.supplements.tasmota_configure import (
        configure_all_tasmota_devices,
        configure_tasmota_device,
    )

    hosts = _tasmota_hosts(config)

    dry_run = args.dry_run
    force = args.force

    if args.configure_all:
        tasmota_hosts = sorted(
            [h for h in hosts if h.tasmota_data is not None],
            key=lambda h: _natural_sort_key(
                h.tasmota_data.device_name if h.tasmota_data else h.hostname
            ),
        )
        success, fail = configure_all_tasmota_devices(
            tasmota_hosts, config.homeassistant.mqtt, config.tasmota,
            dry_run=dry_run, verbose=True, force=force,
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
            target, config.homeassistant.mqtt, config.tasmota,
            dry_run=dry_run, verbose=True, force=force,
        )
        return 0 if ok else 1


# ---------------------------------------------------------------------------
# Subcommand: tasmota register-broker
# ---------------------------------------------------------------------------


def cmd_tasmota_register_broker(args: argparse.Namespace) -> int:
    """Register Tasmota broker logins on the HA Mosquitto add-on."""
    from gdoc2netcfg.derivations.tasmota_credentials import PREFIX, build_logins
    from gdoc2netcfg.supplements.mqtt_broker import register_logins

    config = _load_config(args)
    hosts = _tasmota_hosts(config)

    if not config.homeassistant.ssh_host:
        print("Error: [homeassistant] ssh_host not configured", file=sys.stderr)
        return 1

    try:
        logins = build_logins(config.tasmota.mqtt_secret, hosts)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    verify = (
        (config.homeassistant.mqtt.host, config.homeassistant.mqtt.port)
        if not args.dry_run
        else None
    )
    register_logins(
        config.homeassistant.ssh_host,
        PREFIX,
        logins,
        dry_run=args.dry_run,
        prune=args.prune,
        verify=verify,
    )
    return 0


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
# Subcommand: tasmota ha-sync
# ---------------------------------------------------------------------------

def cmd_tasmota_ha_sync(args: argparse.Namespace) -> int:
    """Sync Tasmota device metadata to Home Assistant."""
    config = _load_config(args)

    if not config.homeassistant.url or not config.homeassistant.token:
        print(
            "Error: [homeassistant] url and token must be configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    from gdoc2netcfg.supplements.tasmota_ha import sync_ha_devices

    _records, hosts, _inventory, _result = _build_pipeline(config)

    tasmota_hosts = [h for h in hosts if h.tasmota_data is not None]
    if not tasmota_hosts:
        print("No Tasmota devices found. Run 'tasmota scan' first.")
        return 1

    dry_run = getattr(args, "dry_run", False)
    changes = sync_ha_devices(tasmota_hosts, config.homeassistant, dry_run=dry_run)

    if not changes:
        print("All Tasmota devices already in sync with Home Assistant.")
        return 0

    action = "Would update" if dry_run else "Updated"
    for machine_name, old_val, new_val in changes:
        old_display = f'"{old_val}"' if old_val else "(unset)"
        print(f"  {action} {machine_name:20s}  {old_display} -> \"{new_val}\"")

    print(f"\n{action} {len(changes)} device(s).")
    return 0


# ---------------------------------------------------------------------------
# Subcommands: sensors2mqtt list
# ---------------------------------------------------------------------------


def _sensors2mqtt_hosts(config):
    """Load CSVs and build hosts for sensors2mqtt classification.

    Same fetch/enrich/build path as the ``password`` command (so hostnames
    line up with the rest of the pipeline)."""
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    return _build_hosts_from_csvs(config, csv_data)


def cmd_sensors2mqtt_list(args: argparse.Namespace) -> int:
    """Show sensors2mqtt classification for all hosts."""
    config = _load_config(args)
    hosts = _sensors2mqtt_hosts(config)

    from gdoc2netcfg.derivations.sensors2mqtt import classify

    print(f"{'hostname':<40}  {'sensors'}")
    print("-" * 50)
    for h in sorted(hosts, key=lambda h: h.hostname):
        try:
            classification = classify(h)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        if classification != "blank":
            print(f"{h.hostname:<40}  {classification}")
    return 0


def cmd_sensors2mqtt_register(args: argparse.Namespace) -> int:
    """Register sensors2mqtt broker logins on the HA Mosquitto add-on."""
    from gdoc2netcfg.derivations.sensors2mqtt import PREFIX, build_logins
    from gdoc2netcfg.supplements.mqtt_broker import register_logins

    config = _load_config(args)
    hosts = _sensors2mqtt_hosts(config)

    if not config.homeassistant.ssh_host:
        print("Error: [homeassistant] ssh_host not configured", file=sys.stderr)
        return 1

    try:
        logins = build_logins(config.sensors2mqtt.mqtt_secret, hosts)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    verify = (
        (config.homeassistant.mqtt.host, config.homeassistant.mqtt.port)
        if not args.dry_run
        else None
    )
    register_logins(
        config.homeassistant.ssh_host,
        PREFIX,
        logins,
        dry_run=args.dry_run,
        prune=args.prune,
        verify=verify,
    )
    return 0


def cmd_sensors2mqtt_status(args: argparse.Namespace) -> int:
    """Show sensors2mqtt entity freshness for all non-blank hosts."""
    from datetime import datetime, timezone

    from gdoc2netcfg.supplements.sensors2mqtt_status import query_status

    config = _load_config(args)

    if not config.homeassistant.url or not config.homeassistant.token:
        print(
            "Error: [homeassistant] url and token must be configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    hosts = _sensors2mqtt_hosts(config)
    status = query_status(
        config.homeassistant,
        hosts,
        config.sensors2mqtt.freshness_seconds,
        datetime.now(timezone.utc),
    )

    if not status:
        print("No sensors2mqtt hosts found (no 'local' or 'remote' Sensors column entries).")
        return 0

    print(f"{'hostname':<40}  {'sel':<8}  {'class':<8}  last_updated")
    print("-" * 80)
    for hostname in sorted(status):
        rec = status[hostname]
        lu = rec["last_updated"].isoformat() if rec["last_updated"] else "-"
        print(f"{hostname:<40}  {rec['selection']:<8}  {rec['class']:<8}  {lu}")
    return 0


# ---------------------------------------------------------------------------
# Subcommands: zigbee scan / show / update-sheet
# ---------------------------------------------------------------------------


def cmd_zigbee_scan(args: argparse.Namespace) -> int:
    """Scan Zigbee2MQTT on all configured sites and persist to the DB."""
    config = _load_config(args)

    if not config.zigbee.enabled:
        print(
            "Error: No [zigbee] section configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    from gdoc2netcfg.supplements.zigbee import (
        raise_for_zigbee_errors,
        scan_zigbee,
    )

    age = None if args.force else _fresh_scan_age(config, "zigbee")
    if age is not None:
        print(f"Using cached zigbee scan ({age:.0f}s old).", file=sys.stderr)
        zigbee_data = _load_latest_from_db(config, "load_latest_zigbee") or {}
        errors: list[str] = []
    else:
        try:
            zigbee_data, errors = scan_zigbee(
                config.site.name,
                config.homeassistant.mqtt,
                _load_latest_from_db(config, "load_latest_zigbee"),
                verbose=True,
            )
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        # Persist the sites that scanned BEFORE failing loud, so one
        # unreachable broker can't discard the other site's results.
        if zigbee_data:
            _save_to_discovery_db(config, "zigbee", "save_zigbee", zigbee_data)

    device_count = sum(len(doc["devices"]) for doc in zigbee_data.values())
    print(
        f"\nFound {device_count} Zigbee device(s) across "
        f"{len(zigbee_data)} site(s)."
    )

    raise_for_zigbee_errors(errors)
    return 0


def cmd_zigbee_show(args: argparse.Namespace) -> int:
    """Show cached Zigbee device data."""
    config = _load_config(args)

    from gdoc2netcfg.supplements.zigbee import ZigbeeBridgeInfo, ZigbeeDevice

    zigbee_data = _load_latest_from_db(config, "load_latest_zigbee")
    if not zigbee_data:
        print("No Zigbee data cached. Run 'gdoc2netcfg zigbee scan' first.")
        return 1

    db = _open_databases(config)
    scanned_at = ""
    if db is not None:
        try:
            history = db.discovery.scan_history("zigbee", limit=1)
        finally:
            db.close()
        if history:
            scanned_at = history[0]["finished_at"]

    for site_name, doc in sorted(zigbee_data.items()):
        bridge = ZigbeeBridgeInfo(**doc["bridge"]) if doc["bridge"] else None
        devices = [ZigbeeDevice(**d) for d in doc["devices"].values()]

        print(f"\n{'='*60}")
        print(f"Site: {site_name}  (scanned {scanned_at})")
        print("=" * 60)
        if bridge:
            print(f"  Z2M:         {bridge.z2m_version}")
            print(
                f"  Coordinator: {bridge.coordinator_type} ({bridge.coordinator_ieee})"
            )
            print(f"  Channel:     {bridge.channel}   PAN ID: {bridge.pan_id}")
        print(f"\n  {len(devices)} device(s):")
        for d in sorted(devices, key=lambda x: x.object_id):
            avail = d.availability.upper() if d.availability else "?"
            fw = d.software_build_id or "—"
            print(
                f"  {d.object_id:6s}  {avail:8s}  "
                f"{(d.model_id or d.model):25s}  "
                f"{d.friendly_name:35s}  fw={fw}"
            )

    return 0


def cmd_zigbee_update_sheet(args: argparse.Namespace) -> int:
    """Write cached Zigbee data to the Google Sheet."""
    config = _load_config(args)

    if not config.zigbee.enabled:
        print(
            "Error: No [zigbee] section configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    if not config.spreadsheet_url:
        print(
            "Error: spreadsheet_url must be configured in the [sheets] section of "
            "gdoc2netcfg.toml\n"
            "  Example: spreadsheet_url = "
            '"https://docs.google.com/spreadsheets/d/{ID}/edit"',
            file=sys.stderr,
        )
        return 1

    if (
        not config.sheets_config.credentials_file
        and not config.sheets_config.service_account_file
    ):
        print(
            "Error: [sheets] credentials_file or service_account_file must be "
            "configured in gdoc2netcfg.toml",
            file=sys.stderr,
        )
        return 1

    from gdoc2netcfg.supplements.zigbee import ZigbeeBridgeInfo, ZigbeeDevice
    from gdoc2netcfg.supplements.zigbee_sheet import update_zigbee_sheet

    zigbee_data = _load_latest_from_db(config, "load_latest_zigbee") or {}

    # Each site manages only its own rows: project every configured
    # site's registry view directly (one row per site per device).
    # DB data for a site no longer configured (stale until the next
    # scan tombstones it) is skipped loudly.
    this_site = config.site.name
    configured = {this_site.strip().lower()}
    bridge_infos: dict[str, ZigbeeBridgeInfo | None] = {}
    all_devices: list[ZigbeeDevice] = []
    for site_name, doc in sorted(zigbee_data.items()):
        if site_name.strip().lower() not in configured:
            print(
                f"Skipping site '{site_name}': in the database but not "
                "this site ([zigbee])",
                file=sys.stderr,
            )
            continue
        bridge_infos[site_name] = (
            ZigbeeBridgeInfo(**doc["bridge"]) if doc["bridge"] else None
        )
        all_devices.extend(
            ZigbeeDevice(**device)
            for _ieee, device in sorted(doc["devices"].items())
        )

    if this_site not in zigbee_data:
        print(
            f"Warning: no data for site '{this_site}'. "
            "Run 'gdoc2netcfg zigbee scan' first.",
            file=sys.stderr,
        )
    bridge_infos.setdefault(this_site, None)

    if not all_devices:
        print("No Zigbee data to write. Run 'gdoc2netcfg zigbee scan' first.")
        return 1

    dry_run = getattr(args, "dry_run", False)

    try:
        written = update_zigbee_sheet(
            config,
            all_devices,
            bridge_infos,
            dry_run=dry_run,
            verbose=True,
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    action = "Would write" if dry_run else "Wrote"
    print(f"\n{action} {written} row(s) to '{config.zigbee.sheet_name}'.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: password
# ---------------------------------------------------------------------------

def cmd_password(args: argparse.Namespace) -> int:
    """Look up device credentials by hostname, IP, or MAC."""
    config = _load_config(args)

    from gdoc2netcfg.utils.lookup import (
        available_credential_fields,
        get_credential_fields,
        lookup_host,
        suggest_matches,
    )

    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_sheets(config, csv_data)
    hosts = _build_hosts_from_csvs(config, csv_data)

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

    # Credentials live in the root-only credentials.db, not the cache.
    # Only consult it when a credential field is actually requested, so a
    # --field for a non-credential column stays sudo-free.
    from gdoc2netcfg.sources.credentials import credential_field_names
    from gdoc2netcfg.storage.credentials_db import CredentialsDB
    from gdoc2netcfg.utils.lookup import CREDENTIAL_TYPES

    credential_names = set(credential_field_names())
    if args.field_name is not None:
        requested = {args.field_name}
    elif args.credential_type is not None:
        requested = set(CREDENTIAL_TYPES.get(args.credential_type, []))
    else:
        requested = set(CREDENTIAL_TYPES["password"])

    if requested & credential_names:
        cred_path = config.cache.credentials_db_path
        try:
            with CredentialsDB(cred_path, read_only=True) as cred_db:
                stored = cred_db.load_latest_credentials() or {}
        except FileNotFoundError:
            print(
                "Error: no credential store at "
                f"{cred_path}. Run 'gdoc2netcfg fetch' (as root) first.",
                file=sys.stderr,
            )
            return 1
        except sqlite3.OperationalError:
            print(
                "Error: cannot read the credential store "
                f"{cred_path} — credentials are root-only. Re-run with sudo.",
                file=sys.stderr,
            )
            return 1
        host.extra.update(stored.get(host.hostname, {}))

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
        all_ips = [str(iface.ipv4) for iface in host.interfaces]
        if all_ips:
            print(f"IP:         {', '.join(all_ips)}")
        if host.all_macs:
            print(f"MAC:        {host.all_macs[0]}")
        print(f"Matched by: {best.match_detail}")
        print()
        for field_name, value in cred.items():
            print(f"{field_name}: {value}")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: db (database management and history)
# ---------------------------------------------------------------------------

def cmd_db_info(args: argparse.Namespace) -> int:
    """Show database sizes, scan counts, and status."""
    config = _load_config(args)

    config_path = config.cache.config_db_path
    discovery_path = config.cache.discovery_db_path

    from gdoc2netcfg.storage.base import SchemaVersionError
    from gdoc2netcfg.storage.config_db import ConfigDB
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    # Each database must be opened with its own class — the schema
    # version check compares against the class's SCHEMA_VERSION, so a
    # generic BaseDatabase open (version 1) rejects any upgraded DB.
    for label, db_class, db_path in [
        ("Config", ConfigDB, config_path),
        ("Discovery", DiscoveryDB, discovery_path),
    ]:
        if not db_path.exists():
            print(f"{label} DB: not created yet")
            continue

        size_kb = db_path.stat().st_size / 1024
        print(f"{label} DB: {db_path} ({size_kb:.1f} KB)")

        try:
            with db_class(db_path, read_only=True) as db:
                cur = db.connection.execute(
                    "SELECT scan_type, COUNT(*) as cnt, "
                    "MIN(started_at) as oldest, MAX(started_at) as newest "
                    "FROM scans WHERE finished_at IS NOT NULL "
                    "GROUP BY scan_type ORDER BY scan_type"
                )
                rows = cur.fetchall()
                if rows:
                    for scan_type, cnt, oldest, newest in rows:
                        oldest_date = oldest[:10] if oldest else "?"
                        newest_date = newest[:10] if newest else "?"
                        print(f"  {scan_type}: {cnt} scans ({oldest_date} to {newest_date})")
                else:
                    print("  No completed scans.")
        except SchemaVersionError as e:
            print(f"  Error reading database: {e}", file=sys.stderr)

    return 0


def cmd_db_history(args: argparse.Namespace) -> int:
    """Show scan history."""
    config = _load_config(args)

    from gdoc2netcfg.storage import open_databases

    config_path = config.cache.config_db_path
    discovery_path = config.cache.discovery_db_path

    missing = [p for p in [config_path, discovery_path] if not p.exists()]
    if missing:
        for p in missing:
            print(f"Database not found: {p}", file=sys.stderr)
        print(
            "Databases are created by the reachability daemon, the scan "
            "commands, and 'gdoc2netcfg fetch'.",
            file=sys.stderr,
        )
        return 1

    pair = open_databases(config.cache.directory, read_only=True)
    try:
        # Collect scans from both databases
        all_scans = []
        for db in [pair.config, pair.discovery]:
            scans = db.scan_history(
                scan_type=args.scan_type,
                since=args.since,
                limit=args.limit,
            )
            all_scans.extend(scans)

        # Sort by timestamp descending (most recent first) and limit
        all_scans.sort(key=lambda s: s["started_at"], reverse=True)
        all_scans = all_scans[:args.limit]

        if not all_scans:
            print("No scans found matching criteria.")
            return 0

        # Print table
        print(f"{'Started':<20} {'Type':<18} {'Hosts':>5} {'Changed':>7}")
        print("-" * 53)
        for scan in all_scans:
            started = scan["started_at"][:19].replace("T", " ")
            scan_type = scan["scan_type"]
            hosts = scan.get("host_count") or 0
            changed = scan.get("changed_count") or 0
            print(f"{started:<20} {scan_type:<18} {hosts:>5} {changed:>7}")

        print(f"\n{len(all_scans)} scan(s) shown.")
    finally:
        pair.close()

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

    # reachability (subcommand group: scan, publish)
    reach_parser = subparsers.add_parser(
        "reachability", help="Host reachability scanning and MQTT publishing",
    )
    reach_parser.add_argument(
        "--force", action="store_true",
        help="Force re-ping even if the cached reachability scan is <5 min old",
    )
    reach_subparsers = reach_parser.add_subparsers(dest="reach_command")

    reach_scan_parser = reach_subparsers.add_parser(
        "scan", help="Ping all hosts and report up/down",
    )
    reach_scan_parser.add_argument(
        "--force", action="store_true",
        help="Force re-ping even if the cached reachability scan is <5 min old",
    )

    reach_publish_parser = reach_subparsers.add_parser(
        "publish", help="Publish reachability to Home Assistant via MQTT",
    )
    reach_publish_parser.add_argument(
        "--force", action="store_true",
        help="Force re-ping before publishing",
    )
    reach_publish_parser.add_argument(
        "--daemon", action="store_true",
        help="Run continuously, scanning and publishing on an interval",
    )
    reach_publish_parser.add_argument(
        "--interval", type=int, default=300,
        help="Seconds between scans in daemon mode (default: 300)",
    )

    # sshfp
    sshfp_parser = subparsers.add_parser("sshfp", help="Scan hosts for SSH fingerprints")
    sshfp_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # known-hosts
    known_hosts_parser = subparsers.add_parser(
        "known-hosts", help="Scan hosts for SSH host keys",
    )
    known_hosts_parser.add_argument(
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

    tasmota_ha_sync_parser = tasmota_subparsers.add_parser(
        "ha-sync", help="Sync device metadata (names) to Home Assistant",
    )

    rb = tasmota_subparsers.add_parser(
        "register-broker", help="Register Tasmota broker logins on HA Mosquitto",
    )
    rb.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    rb.add_argument("--prune", action="store_true", help="Remove logins not in current device list")
    tasmota_ha_sync_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be changed without applying",
    )

    # sensors2mqtt (with subcommands)
    s2m_parser = subparsers.add_parser(
        "sensors2mqtt", help="sensors2mqtt MQTT credentials",
    )
    s2m_subparsers = s2m_parser.add_subparsers(dest="s2m_command")
    s2m_subparsers.add_parser("list", help="Show sensors2mqtt host classification")
    s2m_subparsers.add_parser(
        "status", help="Check Home Assistant entity freshness for sensors2mqtt hosts",
    )
    reg = s2m_subparsers.add_parser(
        "register", help="Register sensors2mqtt broker logins on HA Mosquitto",
    )
    reg.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    reg.add_argument("--prune", action="store_true", help="Remove logins not in current host list")

    # zigbee (with subcommands)
    zigbee_parser = subparsers.add_parser(
        "zigbee", help="Zigbee2MQTT device scanning and sheet updates",
    )
    zigbee_subparsers = zigbee_parser.add_subparsers(dest="zigbee_command")

    zigbee_scan_parser = zigbee_subparsers.add_parser(
        "scan", help="Scan Zigbee2MQTT on all configured sites",
    )
    zigbee_scan_parser.add_argument(
        "--force", action="store_true",
        help="Re-scan even if cached data exists",
    )

    zigbee_subparsers.add_parser("show", help="Show cached Zigbee device data")

    zigbee_update_parser = zigbee_subparsers.add_parser(
        "update-sheet", help="Write cached Zigbee data to the Google Sheet",
    )
    zigbee_update_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be written without updating the sheet",
    )

    # db (database management and history)
    db_parser = subparsers.add_parser(
        "db", help="Database management and history queries",
    )
    db_subparsers = db_parser.add_subparsers(dest="db_command")

    db_subparsers.add_parser(
        "info", help="Show database sizes, scan counts, and status",
    )

    db_history_parser = db_subparsers.add_parser(
        "history", help="Show scan history",
    )
    db_history_parser.add_argument(
        "--type", dest="scan_type", default=None,
        help="Filter by scan type (e.g. reachability, ssl_certs)",
    )
    db_history_parser.add_argument(
        "--since", default=None,
        help="Only show scans since this date (ISO 8601, e.g. 2025-06-01)",
    )
    db_history_parser.add_argument(
        "--limit", type=int, default=50,
        help="Maximum number of scans to show (default: 50)",
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

    # Handle db subcommands
    if args.command == "db":
        if args.db_command == "info":
            return cmd_db_info(args)
        elif args.db_command == "history":
            return cmd_db_history(args)
        else:
            db_parser.print_help()
            return 0

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

    # Handle zigbee subcommands
    if args.command == "zigbee":
        if args.zigbee_command == "scan":
            return cmd_zigbee_scan(args)
        elif args.zigbee_command == "show":
            return cmd_zigbee_show(args)
        elif args.zigbee_command == "update-sheet":
            return cmd_zigbee_update_sheet(args)
        else:
            zigbee_parser.print_help()
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
        elif args.tasmota_command == "ha-sync":
            return cmd_tasmota_ha_sync(args)
        elif args.tasmota_command == "register-broker":
            return cmd_tasmota_register_broker(args)
        else:
            tasmota_parser.print_help()
            return 0

    # Handle sensors2mqtt subcommands
    if args.command == "sensors2mqtt":
        if args.s2m_command == "list":
            return cmd_sensors2mqtt_list(args)
        elif args.s2m_command == "register":
            return cmd_sensors2mqtt_register(args)
        elif args.s2m_command == "status":
            return cmd_sensors2mqtt_status(args)
        else:
            s2m_parser.print_help()
            return 0

    # Handle reachability subcommands
    if args.command == "reachability":
        if args.reach_command == "publish":
            return cmd_reachability_publish(args)
        else:
            # Default (no subcommand or "scan") -> scan behavior
            return cmd_reachability_scan(args)

    commands = {
        "fetch": cmd_fetch,
        "generate": cmd_generate,
        "validate": cmd_validate,
        "info": cmd_info,
        "sshfp": cmd_sshfp,
        "known-hosts": cmd_known_hosts,
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
