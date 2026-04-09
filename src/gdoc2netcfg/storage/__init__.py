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
    migrate: bool = False,
) -> DatabasePair:
    """Open (or create) both SQLite databases.

    Args:
        cache_dir: Path to the cache directory (e.g. ``.cache/``).
        migrate: If True and the databases don't exist, import
            existing flat files as the initial historical snapshot.

    Returns:
        A ``DatabasePair`` with both databases open and ready.
    """
    config_path = cache_dir / "config.db"
    discovery_path = cache_dir / "discovery.db"

    config_is_new = not config_path.exists()
    discovery_is_new = not discovery_path.exists()

    config_db = ConfigDB(config_path)
    discovery_db = DiscoveryDB(discovery_path)

    if migrate and (config_is_new or discovery_is_new):
        from gdoc2netcfg.storage.migration import import_flat_files

        import_flat_files(cache_dir, config_db, discovery_db)

    return DatabasePair(config=config_db, discovery=discovery_db)
