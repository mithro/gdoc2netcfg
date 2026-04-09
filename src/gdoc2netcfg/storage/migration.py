"""One-time migration from flat-file cache to SQLite databases.

Imports existing .cache/*.csv and .cache/*.json files as initial
historical snapshots.  Intended to be run once via
``uv run gdoc2netcfg db migrate``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from gdoc2netcfg.storage.config_db import ConfigDB
from gdoc2netcfg.storage.discovery_db import DiscoveryDB

# Maps flat-file name (without extension) to (DiscoveryDB method, scan_type)
_DISCOVERY_JSON_FILES: dict[str, tuple[str, str]] = {
    "ssl_certs": ("save_ssl_certs", "ssl_certs"),
    "bmc_firmware": ("save_bmc_firmware", "bmc_firmware"),
    "snmp": ("save_snmp", "snmp"),
    "bridge": ("save_bridge", "bridge"),
    "nsdp": ("save_nsdp", "nsdp"),
    "tasmota": ("save_tasmota", "tasmota"),
}


def import_flat_files(
    cache_dir: Path,
    config_db: ConfigDB,
    discovery_db: DiscoveryDB,
) -> dict[str, int]:
    """Import existing flat-file caches into SQLite databases.

    Returns a dict mapping filename -> number of records imported.
    Skips files that don't exist.  Logs progress to stderr.
    """
    results: dict[str, int] = {}

    # -- CSV files -> ConfigDB --
    for csv_path in sorted(cache_dir.glob("*.csv")):
        sheet_name = csv_path.stem  # e.g. "network", "iot", "vlan_allocations"
        csv_text = csv_path.read_text(encoding="utf-8")
        mtime_iso = _file_mtime_iso(csv_path)

        scan_id = config_db.begin_scan("csv_fetch", started_at=mtime_iso)
        config_db.save_csv(scan_id, sheet_name, csv_text)
        config_db.finish_scan(scan_id, host_count=1, changed_count=1)
        results[csv_path.name] = 1
        print(f"  Imported {csv_path.name} ({len(csv_text)} bytes)", file=sys.stderr)

    # -- SSH host keys (special format: dict[hostname, list[str]]) --
    ssh_path = cache_dir / "ssh_host_keys.json"
    if ssh_path.exists():
        data = _load_json(ssh_path)
        if data:
            mtime_iso = _file_mtime_iso(ssh_path)
            scan_id = discovery_db.begin_scan(
                "ssh_host_keys", started_at=mtime_iso,
            )
            changed = discovery_db.save_ssh_host_keys(scan_id, data)
            discovery_db.finish_scan(
                scan_id, host_count=len(data), changed_count=changed,
            )
            results["ssh_host_keys.json"] = len(data)
            print(
                f"  Imported ssh_host_keys.json ({len(data)} hosts)",
                file=sys.stderr,
            )

    # -- Reachability (v2 format with version envelope) --
    reach_path = cache_dir / "reachability.json"
    if reach_path.exists():
        raw = _load_json(reach_path)
        if isinstance(raw, dict) and raw.get("version") == 2:
            hosts_data = raw.get("hosts", {})
            if hosts_data:
                mtime_iso = _file_mtime_iso(reach_path)
                scan_id = discovery_db.begin_scan(
                    "reachability", started_at=mtime_iso,
                )
                changed = discovery_db.save_reachability(scan_id, hosts_data)
                discovery_db.finish_scan(
                    scan_id,
                    host_count=len(hosts_data),
                    changed_count=changed,
                )
                results["reachability.json"] = len(hosts_data)
                print(
                    f"  Imported reachability.json ({len(hosts_data)} hosts)",
                    file=sys.stderr,
                )
        else:
            print(
                "  Skipping reachability.json (v1 format or invalid)",
                file=sys.stderr,
            )

    # -- Other discovery JSON files (simple dict[hostname, dict] format) --
    for stem, (save_method, scan_type) in _DISCOVERY_JSON_FILES.items():
        json_path = cache_dir / f"{stem}.json"
        if not json_path.exists():
            continue
        data = _load_json(json_path)
        if not data:
            continue

        mtime_iso = _file_mtime_iso(json_path)
        scan_id = discovery_db.begin_scan(scan_type, started_at=mtime_iso)
        changed = getattr(discovery_db, save_method)(scan_id, data)
        discovery_db.finish_scan(
            scan_id, host_count=len(data), changed_count=changed,
        )
        results[json_path.name] = len(data)
        print(
            f"  Imported {json_path.name} ({len(data)} hosts)",
            file=sys.stderr,
        )

    return results


def _load_json(path: Path) -> dict | None:
    """Load a JSON file, returning None on error."""
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Warning: failed to load {path.name}: {e}", file=sys.stderr)
        return None


def _file_mtime_iso(path: Path) -> str:
    """Return the file's modification time as an ISO 8601 UTC string."""
    mtime = path.stat().st_mtime
    dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
    return dt.isoformat()
