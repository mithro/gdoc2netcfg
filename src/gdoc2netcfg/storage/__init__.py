"""SQLite storage layer for historical data retention.

Two databases:
- ConfigDB (.cache/config.db): spreadsheet data (CSV, device records, VLANs)
- DiscoveryDB (.cache/discovery.db): supplement scan results

Both use delta-based storage: new rows are inserted only when values
actually change.  The ``scans`` table tracks every scan as an audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gdoc2netcfg.storage.config_db import ConfigDB
from gdoc2netcfg.storage.discovery_db import DiscoveryDB


@dataclass
class DatabasePair:
    """A pair of opened databases for the pipeline."""

    config: ConfigDB
    discovery: DiscoveryDB

    def close(self) -> None:
        self.config.close()
        self.discovery.close()


def open_databases(
    cache_dir: Path,
    *,
    read_only: bool = False,
) -> DatabasePair:
    """Open (or create) both SQLite databases.

    Args:
        cache_dir: Path to the cache directory (e.g. ``.cache/``).
        read_only: If True, open both databases read-only — no write access
            required (lets a non-owner read root-owned DBs).  Both files must
            already exist.

    Returns:
        A ``DatabasePair`` with both databases open and ready.
    """
    config_db = ConfigDB(cache_dir / "config.db", read_only=read_only)
    discovery_db = DiscoveryDB(cache_dir / "discovery.db", read_only=read_only)
    return DatabasePair(config=config_db, discovery=discovery_db)
