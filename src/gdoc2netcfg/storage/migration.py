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
    *,
    import_config: bool = True,
    import_discovery: bool = True,
) -> dict[str, int]:
    """Import existing flat-file caches into SQLite databases.

    Returns a dict mapping filename -> number of records imported.
    Skips files that don't exist.  Set *import_config* or
    *import_discovery* to False to skip a database that already
    has data (avoids duplicate imports).
    """
    results: dict[str, int] = {}

    # -- CSV files -> ConfigDB --
    if not import_config:
        print("  Skipping config import (database already exists)", file=sys.stderr)
    for csv_path in sorted(cache_dir.glob("*.csv")) if import_config else ():
        sheet_name = csv_path.stem  # e.g. "network", "iot", "vlan_allocations"
        csv_text = csv_path.read_text(encoding="utf-8")
        mtime_iso = _file_mtime_iso(csv_path)

        scan_id = config_db.begin_scan("csv_fetch", started_at=mtime_iso)
        config_db.save_csv(scan_id, sheet_name, csv_text)
        # Count data rows (header line is not a data row).
        lines = csv_text.strip().splitlines()
        if len(lines) <= 1:
            raise ValueError(
                f"{csv_path.name} has no data rows (only header or empty). "
                "This usually indicates a failed Google Sheets fetch."
            )
        row_count = len(lines) - 1  # subtract header
        config_db.finish_scan(
            scan_id, host_count=row_count, changed_count=row_count,
        )
        results[csv_path.name] = row_count
        print(
            f"  Imported {csv_path.name} ({row_count} rows, {len(csv_text)} bytes)",
            file=sys.stderr,
        )

    # -- Discovery data --
    if not import_discovery:
        print("  Skipping discovery import (database already exists)", file=sys.stderr)
        return results

    # -- SSH host keys (special format: dict[hostname, list[str]]) --
    ssh_path = cache_dir / "ssh_host_keys.json"
    if ssh_path.exists():
        data = _load_json(ssh_path)
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
        if raw.get("version") != 2:
            raise ValueError(
                f"reachability.json has unsupported format "
                f"(version={raw.get('version')!r}, expected 2). "
                f"Delete the file and re-scan, or convert to v2 format."
            )
        hosts_data = raw["hosts"]
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

    # -- Other discovery JSON files (simple dict[hostname, dict] format) --
    for stem, (save_method, scan_type) in _DISCOVERY_JSON_FILES.items():
        json_path = cache_dir / f"{stem}.json"
        if not json_path.exists():
            continue
        data = _load_json(json_path)

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


def _load_json(path: Path) -> dict:
    """Load a JSON file.  Raises on corrupt or unreadable files."""
    with open(path) as f:
        return json.load(f)


def _file_mtime_iso(path: Path) -> str:
    """Return the file's modification time as an ISO 8601 UTC string."""
    mtime = path.stat().st_mtime
    dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
    return dt.isoformat()
